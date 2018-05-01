#!/usr/bin/env python3

import sys
import logging

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from macholib import MachO
from macholib import mach_o
import magic

from os import path

################################################################################

CRYPTO_BACKEND = backends.default_backend()

################################################################################

MACHO_MIME_TYPE = 'application/x-mach-binary'
PE_MIME_TYPE = 'application/x-dosexec'

################################################################################

CERT_TAG = b'\x01'
SIG_TAG = b'\x02'
FLAGS_TAG = b'\x03'

################################################################################

BLESSED_FLAG = 1

################################################################################

def compute_digest(hasher, *args):
    for arg in args:
        if (type(arg) is not list):
            hasher.update(arg)
        else:
            compute_digest(hasher, *arg)

def compute_sha512(*args):
    hasher = hashes.Hash(hashes.SHA512(), CRYPTO_BACKEND)
    compute_digest(hasher, *args)
    return hasher.finalize()

def verify_sha512(v, *args):
    return constant_time.bytes_eq(v, compute_sha256(*args))

################################################################################

def hash_macho0(exe):
    headers = MachO.MachO(exe).headers
    if len(headers) > 1:
        logging.debug('Mach-O binary is FAT')
    with open(exe, 'rb') as f:
        data = bytes()
        for header in headers:
            f.seek(header.offset, 0)
            start, end = sys.maxsize, 0
            for (lc, segment, sections) in header.commands:
                if (mach_o.LC_CODE_SIGNATURE == lc.cmd):
                    logging.warning('Mach-O binary has a signature section')
                # The minimum section offset of all load commands is the start of VMP signing part
                if (lc.cmd in (mach_o.LC_SEGMENT_64, mach_o.LC_SEGMENT) and
                    segment.segname.startswith(mach_o.SEG_TEXT.encode('utf-8'))):
                    for section in sections:
                        start = min(start, section.offset)
                # Expect the String Table is at the end of unsigned binary followed by the code
                # signature, so the end of String Table is the end of VMP signing part
                if (mach_o.LC_SYMTAB == lc.cmd):
                    end = segment.stroff + segment.strsize
            if (start >= end):
                logging.error('Failed to assemble VMP/Mach-O signing body: %d-%d', start, end)
                raise ValueError('Failed to assemble VMP/Mach-O signing body: %d-%d' % (start, end))
            f.seek(start, 1)
            data += f.read(end - start)
        return compute_sha512(data)

def hash_macho(exe, version):
    if (0 == version):
        return hash_macho0(exe)
    else:
        logging.error('Unsupported VMP/Mach-O digest version: %d', version)
        raise ValueError('Unsupported VMP/Mach-O digest version: %d' % version)

################################################################################

def hash_pe0(exe):
    with open(exe, 'rb') as f:
        data = f.read()
        return compute_sha512(data)

def hash_pe(exe, version):
    if (0 == version):
        return hash_pe0(exe)
    else:
        logging.error('Unsupported VMP/PE digest version: %d', version)
        raise ValueError('Unsupported VMP/PE digest version: %d' % version)

################################################################################

class Signature:
    def __init__(self):
        self.version = None
        self.flags = None
        self.cert = None
        self.sig = None

################################################################################

def encode_byte(val):
    return val.to_bytes(1, 'little')

def encode_leb128(val):
    out = b''
    while 0x7f < val:
        out += encode_byte(0x80 | (val & 0x7f))
        val >>= 7
    out += encode_byte(val & 0x7f)
    return out

def encode_bytes(tag, data):
    return tag + encode_leb128(len(data)) + data

def encode_signature(sig):
    out = encode_byte(sig.version)
    out += encode_bytes(CERT_TAG, sig.cert)
    out += encode_bytes(SIG_TAG, sig.sig)
    out += encode_bytes(FLAGS_TAG, sig.flags)
    return out

################################################################################

def sign_bytes(data, key):
    sig = key.sign(data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=20),
        hashes.SHA1()
    )
    return sig

def sign_file(file, version, key, cert, hash_func, flags):
    sig = Signature()
    sig.version = version
    sig.flags = encode_byte(flags)
    sig.cert = cert
    sig.sig = sign_bytes(hash_func(file, version) + sig.flags, key)
    logging.info('Encoding signature data')
    return encode_signature(sig)

################################################################################

def decode_byte(io):
    b = io.read(1)
    if (not b):
        logging.error('Unsupported EOF while reading VMP signature file')
        raise EOFError('Unsupported EOF while reading VMP signature file')
    return int.from_bytes(b, 'little')

def decode_leb128(io):
    shift = 0
    val = 0
    while True:
        b = decode_byte(io)
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val

def decode_bytes(io):
    return io.read(decode_leb128(io))

def decode_entry(io):
    return io.read(1), decode_bytes(io)

def decode_signature(io):
    sig = Signature()
    sig.version = decode_byte(io)
    logging.debug('Decoding signature file with version: %d', sig.version)
    if (sig.version not in range(0, 2)):
        logging.error('Unsupported VMP signature file version: %d', sig.version)
        raise ValueError('Unsupported VMP signature file version: %d' % sig.version)
    end = len(io.getbuffer())
    while io.tell() != end:
        tag, entry = decode_entry(io)
        if (CERT_TAG == tag):
            logging.debug('Decoding certificate entry')
            if (sig.cert):
                logging.error('Duplicate certificate entry in VMP signature file')
                raise ValueError('Duplicate certificate entry in VMP signature file')
            sig.cert = entry
        elif (SIG_TAG == tag):
            logging.debug('Decoding signature entry')
            if (sig.sig):
                logging.error('Duplicate signature entry in VMP signature file')
                raise ValueError('Duplicate signature entry in VMP signature file')
            sig.sig = entry
        elif (FLAGS_TAG == tag):
            logging.debug('Decoding flags entry')
            if (sig.flags):
                logging.error('Duplicate flags entry in VMP signature file')
                raise ValueError('Duplicate flags entry in VMP signature file')
            sig.flags = entry
        else:
            logging.error('Invalid entry tag in VMP signature file')
            raise ValueError('Invalid entry tag in VMP signature file')
    return sig

################################################################################

def load_cert_bytes(file):
    with open(file, 'rb') as f:
        data = f.read()
    if (data.startswith(b'-----BEGIN ')):
        logging.info('Loading PEM certificate: %s', file)
        cert = x509.load_pem_x509_certificate(data, CRYPTO_BACKEND)
    else:
        logging.info('Loading DER certificate: %s', file)
        cert = x509.load_der_x509_certificate(data, CRYPTO_BACKEND)
    return cert.public_bytes(serialization.Encoding.DER)

def load_key(file, password=None):
    with open(file, 'rb') as f:
        data = f.read()
    if (data.startswith(b'-----BEGIN ')):
        logging.info('Loading PEM key: %s', file)
        key = serialization.load_pem_private_key(data, password=password, backend=CRYPTO_BACKEND)
    else:
        logging.info('Loading DER key: %s', file)
        key = serialization.load_der_private_key(data, password=password, backend=CRYPTO_BACKEND)
    return key

################################################################################

def match_name(dir, names):
    for name in names:
        file = path.join(dir, name)
        if (path.exists(file)):
            return name
    logging.error('Could not find a valid Electron package in: %s', dir)
    raise ValueError('Could not find a valid Electron package in: %s' % dir)

def sign(source, target, version, key, cert, hash_func, bless=False):
    if (not target):
        target = source + '.sig'
    sig = sign_file(source, version, key, cert, hash_func, 1 if bless else 0)
    logging.info('Writing signature to: %s', target)
    with open(target, 'wb') as file:
        file.write(sig)

def sign_mac_package(dir, version, key, cert, name):
    app_dir = path.join(dir, name)
    rsrc_dir = path.join(app_dir, 'Contents/Resources')
    fwver_dir = path.join(app_dir, 'Contents/Frameworks/Electron Framework.framework/Versions/A')
    fwbin_path = path.join(fwver_dir, 'Electron Framework')
    fwsig_path = path.join(fwver_dir, 'Resources/Electron Framework.sig')
    sign(fwbin_path, fwsig_path, version, key, cert, hash_macho, True)

def sign_win_package(dir, version, key, cert, name):
    rsrc_dir = path.join(dir, 'resources')
    exe_path = path.join(dir, name)
    sig_path = path.join(dir, name + '.sig')
    sign(exe_path, sig_path, version, key, cert, hash_pe, True)

def sign_package(dir, version, key, cert, names):
    name = match_name(dir, names)
    if ('.app' == path.splitext(name)[1]):
        return sign_mac_package(dir, version, key, cert, name)
    elif ('.exe' == path.splitext(name)[1]):
        return sign_win_package(dir, version, key, cert, name)
    logging.error('Unsupported Electron extension: %s', name)
    raise ValueError('Unsupported Electron extension: %s' % name)

################################################################################

if (__name__ == "__main__"):
    def main():
        import argparse
        from getpass import getpass
        from binascii import hexlify
        parser = argparse.ArgumentParser(description='Generate VMP signatures for Electron packages')
        parser.add_argument('-v', '--verbose', action='count', default=0, help='increase log verbosity level')
        parser.add_argument('-q', '--quiet', action='count', default=3, help='decrease log verbosity level')
        parser.add_argument('-V', '--version', type=int, default=0, help='algorithm version')
        parser.add_argument('-C', '--certificate', required=True, help='signing certificate file')
        parser.add_argument('-P', '--password', default=None, help='signing key password')
        parser.add_argument('-p', '--prompt-password', action='store_true', help='prompt for signing key password')
        parser.add_argument('-K', '--key', required=True, help='signing key file')
        parser.add_argument('-M', '--macos-name', default='Electron.app', help='macOS app name')
        parser.add_argument('-W', '--windows-name', default='electron.exe', help='Windows exe name')
        parser.add_argument('dirs', nargs='+', help='packages to process')
        args = parser.parse_args()
        levels = [0, logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL, sys.maxsize]
        level = levels[max(0, min(args.quiet - args.verbose, len(levels) - 1))]
        logging.basicConfig(level=level, format='%(module)s/%(levelname)s: %(message)s')
        cert = load_cert_bytes(args.certificate)
        if (args.prompt_password):
            args.password = getpass(prompt='Private key password: ')
        key = load_key(args.key, args.password.encode('utf-8') if args.password else None)
        names = [ args.macos_name, args.windows_name ]
        for dir in args.dirs:
            logging.info('Resigning package: %s', path)
            sign_package(dir, args.version, key, cert, names)
    main()

################################################################################
