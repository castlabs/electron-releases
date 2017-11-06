# castLabs Electron Release for Content Security

## Summary

This is a fork of Electron created with the goal of facilitating the use of Google's Widevine Content Decryption Module (CDM) for DRM-enabled playback within Electron, including support for Verified Media Path (VMP) and protected storage of licenses for offline playback scenarios. It is intended to be used as a drop-in replacement for a regular Electron build and currently supports Windows and macOS platforms.

To achieve this the necessary Widevine DRM components will be installed on first launch and enabled as an option for playback of DRM protected content using common EME APIs. By default, if the installation of any Widevine DRM component fails the application will display an error and exit.

The sections below will describe the additions to the Electron APIs, for anything else refer to the regular Electron documentation:

[Electron README](https://github.com/electron/electron/blob/v1.8.1/README.md)

**NOTE**: The section about Widevine DRM in the regular Electron documentation does not apply to this fork of Electron since the Widevine components are now automatically installed and configured.

## Overriding Widevine DRM installation error handling

To allow custom error handling for Widevine DRM installation errors a new application event, ```widevine-error``` was added, taking one argument which is an ```Error```-instance describing the error that occurred. Installing an event handler for this event will override the default behaviour:

#### Example handler

```
app.on('widevine-error', (err) => {
  app.focus()
  dialog.showErrorBox('Failed to install Widevine components', err.name + ': ' + err.message)
  process.exit(1)
});
```

## Verified Media Path (VMP) considerations

VMP relies on signatures for certain binaries in the Electron build which puts some additional requirements on custom builds where the binaries are renamed or changed. This is primarily a consideration on Windows since the signature resides in the Electron Framework on macOS which is typically not altered.

On Windows the signature file needs to be named the same as the executable with the addition of a `.sig` extension (i.e. `electron.exe` and `electron.exe.sig`). If the application is renamed, say to MyPlayer, both files need to be renamed as follows:

```
electron.exe -> MyPlayer.exe
electron.exe.sig -> MyPlayer.exe.sig
```

In addition, if the executable is changed in any way, even if it is just adding meta-data or code-signing the executable, the VMP signature will currently be invalidatad and the executable will need to be re-signed.

## DISCLAIMER

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. UPDATES, INCLUDING SECURITY UPDATES, WILL BE PROVIDED ON A BEST-EFFORT BASIS.
