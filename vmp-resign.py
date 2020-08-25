#!/usr/bin/env python

import sys
import logging

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.exceptions import InvalidSignature

from macholib import MachO
from macholib import mach_o

from os import path
from io import BytesIO

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

SIGNATURE_HASHER = hashes.SHA1()
SIGNATURE_PADDING = padding.PSS(mgf=padding.MGF1(SIGNATURE_HASHER), salt_length=20)

################################################################################

def to_hex(data):
    if isinstance(data, str):
        return data.encode('hex')
    else:
        return data.hex()

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

def hash_elf0(exe):
    with open(exe, 'rb') as f:
        data = f.read()
        return compute_sha512(data)

def hash_elf(exe, version):
    if (0 == version):
        return hash_elf0(exe)
    else:
        logging.error('Unsupported VMP/ELF digest version: %d', version)
        raise ValueError('Unsupported VMP/ELF digest version: %d' % version)

################################################################################

class Signature:
    def __init__(self):
        self.version = None
        self.flags = None
        self.cert = None
        self.sig = None

################################################################################

def encode_byte(val):
    return bytes(bytearray([val]))

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
    logging.debug('Signing data: %s', to_hex(data))
    return key.sign(data, SIGNATURE_PADDING, SIGNATURE_HASHER)

def sign_file(file, version, key, cert, hash_func, flags):
    sig = Signature()
    sig.version = version
    sig.flags = encode_byte(flags)
    sig.cert = cert.public_bytes(serialization.Encoding.DER)
    digest = hash_func(file, version)
    logging.info('Signing file: %s', file)
    logging.debug('File digest: %s', to_hex(digest))
    sig.sig = sign_bytes(digest + sig.flags, key)
    logging.debug('Encoding signature data')
    return encode_signature(sig)

################################################################################

def decode_byte(io):
    b = io.read(1)
    if (not b):
        logging.error('Unsupported EOF while reading VMP signature file')
        raise EOFError('Unsupported EOF while reading VMP signature file')
    return ord(b)

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

def decode_signature(io, end):
    sig = Signature()
    sig.version = decode_byte(io)
    logging.debug('Decoding signature file with version: %d', sig.version)
    if (sig.version not in range(0, 2)):
        logging.error('Unsupported VMP signature file version: %d', sig.version)
        raise ValueError('Unsupported VMP signature file version: %d' % sig.version)
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

def load_pem_cert(data):
    return x509.load_pem_x509_certificate(data, backend=CRYPTO_BACKEND)

def load_der_cert(data):
    return x509.load_der_x509_certificate(data, backend=CRYPTO_BACKEND)

def load_cert(file):
    with open(file, 'rb') as f:
        data = f.read()
    type, loader = ('PEM', load_pem_cert) if (data.startswith(b'-----BEGIN ')) else ('DER', load_der_cert)
    logging.info('Loading %s certificate: %s', type, file)
    return loader(data)

def load_pem_key(data, password=None):
    return serialization.load_pem_private_key(data, password=password, backend=CRYPTO_BACKEND)

def load_der_key(data, password=None):
    return serialization.load_der_private_key(data, password=password, backend=CRYPTO_BACKEND)

def load_key(file, password=None, prompt_password=False):
    password_provided = password is not None
    with open(file, 'rb') as f:
        data = f.read()
    type, loader = ('PEM', load_pem_key) if (data.startswith(b'-----BEGIN ')) else ('DER', load_der_key)
    logging.info('Loading %s key: %s', type, file)
    while True:
        try:
            return loader(data, password)
        except (TypeError, ValueError) as e:
            if password_provided or not prompt_password: raise
            print(e)
            from getpass import getpass
            password = getpass(prompt='Private key password: ').encode('utf-8')

_OID_NAME_MAP = {
    x509.NameOID.COMMON_NAME: 'CN',
    x509.NameOID.COUNTRY_NAME: 'C',
    x509.NameOID.LOCALITY_NAME: 'L',
    x509.NameOID.STATE_OR_PROVINCE_NAME: 'ST',
    x509.NameOID.ORGANIZATION_NAME: 'O',
    x509.NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
    x509.NameOID.SURNAME: 'SN',
    x509.NameOID.GIVEN_NAME: 'GN',
    x509.NameOID.USER_ID: 'UID',
    x509.NameOID.DOMAIN_COMPONENT: 'DC',
}

def mk_names(names):
    entries = []
    for i in names:
        name = _OID_NAME_MAP.get(i.oid, None)
        if name: entries.append('%s=%s' % (name, i.value))
    return entries

def mk_extension_values(func, val):
    entries = []
    func(entries, val)
    return entries

def mk_subject_key_identifier(entries, val):
    if val.digest: entries.append('Digest: %s' % to_hex(val.digest))

def mk_authority_key_identifier(entries, val):
    if val.key_identifier: entries.append('Key ID: %s' % to_hex(val.key_identifier))
    if val.authority_cert_issuer is not None: entries.append('Issuer: %s' % ', '.join(mk_names(val.authority_cert_issuer)))
    if val.authority_cert_serial_number: entries.append('Serial Number: %x' % val.authority_cert_serial_number)

def mk_basic_constraints(entries, val):
    entries.append('CA: %s' % val.ca)
    if val.ca and val.path_length is not None: entries.append('Path Length: %d' % val.path_length)

def mk_key_usage(entries, val):
    if val.digital_signature: entries.append('Digital Signature')
    if val.content_commitment: entries.append('Content Commitment')
    if val.key_encipherment: entries.append('Key Encipherment')
    if val.data_encipherment: entries.append('Data Encipherment')
    if val.key_agreement:
        entries.append('Key Agreement')
        if val.encipher_only: entries.append('Encipher Only')
        if val.decipher_only: entries.append('Decipher Only')
    if val.key_cert_sign: entries.append('Key Cert Sign')
    if val.crl_sign: entries.append('CRL Sign')

_OID_EXT_KEY_USAGE_MAP = {
    x509.ExtendedKeyUsageOID.SERVER_AUTH: "Server Auth",
    x509.ExtendedKeyUsageOID.CLIENT_AUTH: "Client Auth",
    x509.ExtendedKeyUsageOID.CODE_SIGNING: "Code Signing",
    x509.ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-mail Protection",
    x509.ExtendedKeyUsageOID.TIME_STAMPING: "Timestamping",
    x509.ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning",
}

def mk_extended_key_usage(entries, val):
    for i in val: entries.append(_OID_EXT_KEY_USAGE_MAP.get(i, i.dotted_string))

def mk_binary_extension(entries, val):
    entries.append(to_hex(val.value))

def mk_unknown_extension(entries, val):
    entries.append('...')

_OID_EXTENSION_MAP = {
    x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER: ('Subject Key Identifier', mk_subject_key_identifier),
    x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER: ('Authority Key Identifier', mk_authority_key_identifier),
    x509.ExtensionOID.BASIC_CONSTRAINTS: ('Basic Constraints', mk_basic_constraints),
    x509.ExtensionOID.KEY_USAGE: ('Key Usage', mk_key_usage),
    x509.ExtensionOID.EXTENDED_KEY_USAGE: ('Extended Key Usage', mk_extended_key_usage),
    x509.ObjectIdentifier('1.3.6.1.4.1.11129.4.1.2'): ('VMP Develpment <1.3.6.1.4.1.11129.4.1.2>', mk_binary_extension),
    x509.ObjectIdentifier('1.3.6.1.4.1.11129.4.1.3'): ('VMP Persistent <1.3.6.1.4.1.11129.4.1.3>', mk_binary_extension),
}

def mk_extensions(extensions):
    entries = []
    for i in extensions:
        name, func = _OID_EXTENSION_MAP.get(i.oid, (i.oid.dotted_string, mk_unknown_extension))
        if i.critical: name += ' [CRITICAL]'
        entries.append((name, mk_extension_values(func, i.value)))
    return entries

def validate_cert(cert):
    logging.debug('Certificate:')
    logging.debug('  Version: %s' % cert.version.name)
    logging.debug('  Serial Number: %x' % cert.serial_number)
    logging.debug('  Signature Hash Algorithm: %s' % cert.signature_hash_algorithm.name)
    logging.debug('  Issuer: %s' % ', '.join(mk_names(cert.issuer)))
    logging.debug('  Subject: %s' % ', '.join(mk_names(cert.subject)))
    logging.debug('  Not Before: %s' % cert.not_valid_before)
    logging.debug('  Not After: %s' % cert.not_valid_after)
    logging.debug('  Extensions:')
    for ext, vals in mk_extensions(cert.extensions):
        logging.debug('    %s:' % ext)
        for val in vals: logging.debug('      %s' % val)
    cpk = cert.public_key()
    if (not isinstance(cpk, RSAPublicKey)):
        logging.error('Unsupported certificate key type, only RSA keys are allowed')
        raise ValueError('Unsupported certificate key type, only RSA keys are allowed')
    logging.debug('Public Key: RSA %d bit' % cpk.key_size)

def validate_cert_and_key(cert, key):
    validate_cert(cert)
    if (not isinstance(key, RSAPrivateKey)):
        logging.error('Unsupported private key type, only RSA keys are allowed')
        raise ValueError('Unsupported private key type, only RSA keys are allowed')
    logging.debug('Private Key: RSA %d bit', key.key_size)
    if (cert.public_key().public_numbers() != key.public_key().public_numbers()):
        logging.error('Private key does not match the certificate public key')
        raise ValueError('Private key does not match the certificate public key')

################################################################################

def verify_signature(cert, sig, data):
    logging.debug('Verifying data: %s', to_hex(data))
    key = cert.public_key()
    key.verify(sig, data, SIGNATURE_PADDING, SIGNATURE_HASHER)

def verify_file(file, sigdata, hash_func, flags=None):
    with BytesIO(sigdata) as io:
        sig = decode_signature(io, len(sigdata))
    cert = load_der_cert(sig.cert)
    validate_cert(cert)
    if (flags is not None and encode_byte(flags) != sig.flags):
        logging.error('Expected flags differ from signature flags')
        raise ValueError('Expected flags differ from signature flags')
    logging.info('Verifying file: %s', file)
    digest = hash_func(file, sig.version)
    logging.debug('File digest: %s', to_hex(digest))
    verify_signature(cert, sig.sig, digest + sig.flags)

################################################################################

def match_name(dir, names):
    for name in names:
        file = path.join(dir, name)
        if (path.exists(file)):
            return name
    logging.error('Could not find a valid Electron package in: %s', dir)
    raise ValueError('Could not find a valid Electron package in: %s' % dir)

def package_config(dir, names):
    name = match_name(dir, names)
    if ('.app' == path.splitext(name)[1]):
        app_dir = path.join(dir, name)
        fwver_dir = path.join(app_dir, 'Contents/Frameworks/Electron Framework.framework/Versions/A')
        fwbin_path = path.join(fwver_dir, 'Electron Framework')
        fwsig_path = path.join(fwver_dir, 'Resources/Electron Framework.sig')
        return (fwbin_path, fwsig_path, hash_macho)
    elif ('.exe' == path.splitext(name)[1]):
        exe_path = path.join(dir, name)
        sig_path = path.join(dir, name + '.sig')
        return (exe_path, sig_path, hash_pe)
    else:
        exe_path = path.join(dir, name)
        sig_path = path.join(dir, name + '.sig')
        return (exe_path, sig_path, hash_elf)
    logging.error('Unsupported Electron extension: %s', name)
    raise ValueError('Unsupported Electron extension: %s' % name)

################################################################################

def sign(bin_path, sig_path, version, key, cert, hash_func, bless=False):
    sig = sign_file(bin_path, version, key, cert, hash_func, 1 if bless else 0)
    logging.info('Writing signature to: %s', sig_path)
    with open(sig_path, 'wb') as file:
        file.write(sig)

def sign_package(dir, version, key, cert, names):
    bin_path, sig_path, hash_func = package_config(dir, names)
    sign(bin_path, sig_path, version, key, cert, hash_func, True)

def verify(bin_path, sig_path, hash_func, bless=False):
    logging.info('Reading signature from: %s', sig_path)
    with open(sig_path, 'rb') as file:
        sig = file.read()
    verify_file(bin_path, sig, hash_func, 1 if bless else 0)

def verify_package(dir, names):
    bin_path, sig_path, hash_func = package_config(dir, names)
    verify(bin_path, sig_path, hash_func, True)

################################################################################

if (__name__ == "__main__"):
    def main():
        import argparse
        parser = argparse.ArgumentParser(description='Generate VMP signatures for Electron packages')
        parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase log verbosity level')
        parser.add_argument('-q', '--quiet', action='count', default=0, help='Decrease log verbosity level')
        parser.add_argument('-V', '--verbosity', type=int, default=3, help='Set log verbosity level')
        parser.add_argument('-M', '--macos-name', default='Electron.app', help='macOS app name')
        parser.add_argument('-W', '--windows-name', default='electron.exe', help='Windows exe name')
        parser.add_argument('-L', '--linux-name', default='electron', help='Linux binary name')
        parser.add_argument('-A', '--algorithm', type=int, default=0, help='Algorithm version')
        parser.add_argument('-C', '--certificate', default=None, help='Signing certificate file')
        parser.add_argument('-P', '--password', default=None, help='Signing key password')
        parser.add_argument('-n', '--no-prompt-password', dest='prompt_password', default=True, action='store_false', help='Don\'t prompt for signing key password')
        parser.add_argument('-p', '--prompt-password', action='store_true', help='Prompt for signing key password')
        parser.add_argument('-K', '--key', default=None, help='Signing key file')
        parser.add_argument('-Y', '--verify', action='store_true', help='Verify signature')
        parser.add_argument('dirs', nargs='+', help='Packages to process')
        args = parser.parse_args()
        levels = [0, logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL, sys.maxsize]
        level = levels[max(0, min(args.verbosity + args.quiet - args.verbose, len(levels) - 1))]
        logging.basicConfig(level=level, format='%(module)s/%(levelname)s: %(message)s')
        names = [ args.macos_name, args.windows_name, args.linux_name ]
        if (not args.verify):
            if (args.certificate is None or args.key is None):
                parser.error('-C/--certificate and -K/key are required for signing')
            cert = load_cert(args.certificate)
            key = load_key(args.key, args.password.encode('utf-8') if args.password else None, args.prompt_password)
            validate_cert_and_key(cert, key)
            for dir in args.dirs:
                logging.info('Resigning package: %s', dir)
                sign_package(dir, args.algorithm, key, cert, names)
                logging.info('Signed package: %s', dir)
        else:
            if (args.certificate is not None):
                logging.warning('-C/--certificate is ignored for verification')
            if (args.key is not None or args.password is not None or args.prompt_password):
                logging.warning('-K/--key, -P/--password, -n/--no-prompt-password and -p/--prompt-password are ignored for verification')
            for dir in args.dirs:
                logging.info('Verifying package: %s', dir)
                verify_package(dir, names)
                logging.info('Verified package: %s', dir)

    main()

################################################################################
