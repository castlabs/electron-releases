# castLabs Electron Release for Content Security

## Summary

This is a fork of Electron created with the goal of facilitating the use of Google's Widevine Content Decryption Module (CDM) for DRM-enabled playback within Electron, including support for Verified Media Path (VMP) and protected storage of licenses for offline playback scenarios. It is intended to be used as a drop-in replacement for a regular Electron build and currently supports Windows and macOS platforms.

To achieve this the necessary Widevine DRM components will be installed on first launch and enabled as an option for playback of DRM protected content using common EME APIs. By default, if the installation of any Widevine DRM component fails the application will display an error and exit.

The provided builds are VMP-signed for development use, i.e. using Widevine UAT or servers accepting development clients. For production use a license agreement with [Google Widevine](http://www.widevine.com/) is needed to get production certificates for [re-signing the final package](#re-signing).
 
The sections below will describe the additions to the Electron APIs, for anything else refer to the regular Electron documentation:

[Electron README](https://github.com/electron/electron/blob/v1.8.7/README.md)

**NOTE**: The section about Widevine DRM in the regular Electron documentation does not apply to this fork of Electron since the Widevine components are now automatically installed and configured.

## Using Electron for Content Security with npm

To use Electron for Content Security as a replacement for stock Electron for a project it can be referenced directly as a dependency inside `package.json`. To achieve this, replace the stock Electron dependency so that:

```
"dependencies": {
  "electron": "1.7.9"
}
```

becomes:

```
"dependencies": {
  "electron": "https://github.com/castlabs/electron-releases#v1.8.7-hdcp-vmp1010"
}
```

The `#1.8.7-hdcp-vmp1010` part of the URL references a specific release tag for Electron for Content Security, if it is left out the master branch will be tracked instead.

## Using the Widevine CDM in Electron for Content Security

When using the Widevine plugin within Electron the relevant `BrowserWindow` needs to have `plugins` enabled within its `webPreferences`, like this:

#### Example BrowserWindow instantiation

```
const win = new BrowserWindow({
  webPreferences: {
    plugins: true
  }
});
win.loadURL(yourContentURL);
```

## Overriding Widevine CDM installation error handling

To allow custom error handling for Widevine DRM installation errors a new application event, ```widevine-error``` was added, taking one argument which is an ```Error```-instance describing the error that occurred. Installing an event handler for this event will override the default behaviour:

#### Example handler

```
app.on('widevine-error', (err) => {
  app.focus()
  dialog.showErrorBox('Failed to install Widevine components', err.name + ': ' + err.message)
  process.exit(1)
});
```

## Verified Media Path (VMP)

The provided builds are VMP-signed for development use, i.e. using Widevine UAT or servers accepting development clients. For production use a license agreement with [Google Widevine](http://www.widevine.com/) is needed to get production certificates for re-signing the final package.

### Re-signing

We are providing a Python 3 script to make the re-signing process easier. It requires the Python modules: [cryptography](https://pypi.python.org/pypi/cryptography), [macholib](https://pypi.python.org/pypi/macholib) and [file-magic](https://pypi.python.org/pypi/file-magic), all avaliable through the [Python Package Index](https://pypi.python.org/) and easily installed, e.g. using [pip](https://pypi.python.org/pypi/pip). Once VMP signing certificates have been acquired from [Google Widevine](http://www.widevine.com/) the [vmp-resign.py](vmp-resign.py) script, available in the repository, can be used to easily regenerate the required signatures. Basic usage looks as follows:

```
vmp-resign.py -C CERT-PATH [-P KEY-PASS] -K KEY-PATH PKG-PATH [PKG-PATH...]
```

For full usage information execute `vmp-resign.py -h`.

If the application has been renamed as part of the packaging process, e.g. to Player, the new names need to be provided for each platform, using the `-M` and `-W` options:

```
vmp-resign.py -C cert.pem -P "pass" -K key.pem -M Player.app -W Player.exe MacPlayer-v1.0/ WinPlayer-v1.0/
```

**NOTE**: Since VMP-signing and Xcode/VS code-signing may have impact on each other care needs to be taken, in case both are used, to avoid conflicting signatures being generated. With Xcode VMP-signing must be done before code-signing, but in Visual Studio the reverse is true since it stores the code-signature inside a VMP signed PE binary.

**NOTE**: Make sure to use the [vmp-resign.py](vmp-resign.py) tool corresponding to the release in use. If Electron is installed as a node module, using npm, the correct script is available in `node_modules/electron/vmp-resign.py`.

### Special considerations

VMP relies on signatures for certain binaries in the Electron build which puts some additional requirements on custom builds where the binaries are renamed or changed. This is primarily a consideration on Windows since the signature resides in the Electron Framework on macOS which is typically not altered.

On Windows the signature file needs to be named the same as the executable with the addition of a `.sig` extension (i.e. `electron.exe` and `electron.exe.sig`). If the application is renamed, say to Player, both files need to be renamed as follows:

```
electron.exe -> Player.exe
electron.exe.sig -> Player.exe.sig
```

In addition, if the executable is changed in any way, even if it is just adding meta-data or code-signing the executable, the VMP signature will be invalidated and the executable needs to be re-signed.

## DISCLAIMER

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. UPDATES, INCLUDING SECURITY UPDATES, WILL BE PROVIDED ON A BEST-EFFORT BASIS.
