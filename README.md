# castLabs Electron v8.1.0 for Content Security

Check out the [Wiki](https://github.com/castlabs/electron-releases/wiki) for general news and other updates.

## Summary

This is a fork of Electron created with the goal of facilitating the use of Google's Widevine Content Decryption Module (CDM) for DRM-enabled playback within Electron, including support for Verified Media Path (VMP) and protected storage of licenses for offline playback scenarios. It is intended to be used as a drop-in replacement for a regular Electron build and currently has full support for Windows and macOS platforms, with partial support for Linux (lacking support for persistent licenses due to VMP limitations).

To achieve this the necessary Widevine DRM components will be installed on first launch and enabled as an option for playback of DRM protected content using common EME APIs. By default, if the installation of any Widevine DRM component fails the application will display an error and exit ([this can be overridden](#widevine-specific-events)). If it succeeds an [event](#widevine-specific-events) will be emitted to the application indicating that Widevine is ready to be used.

The provided builds are VMP-signed for development use, i.e. using Widevine UAT or servers accepting development clients. For production use a [license agreement with Google Widevine](#licensing) is necessary to get production certificates for [re-signing the final package](#re-signing).
 
The sections below will describe the additions to the Electron APIs, for anything else refer to the regular Electron documentation:

[Electron README](https://github.com/electron/electron/blob/v8.1.0/README.md)

> **NOTE**: The section about Widevine DRM in the regular Electron documentation does not apply to this fork of Electron since the Widevine components are now automatically installed and configured.

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
  "electron": "https://github.com/castlabs/electron-releases#v8.1.0-wvvmp"
}
```

The `#v8.1.0-wvvmp` part of the URL references a specific release tag for Electron for Content Security, if it is left out the master branch will be tracked instead.

## Migrating from an earlier castLabs Electron for Content Security release

Due to a changes in the key system id used between major and/or certain vulnerable versions of the Widevine CDM previously persisted licenses cannot be automatically migrated when such a CDM upgrade occurs. The recommended workaround is to listen for the `widevine-ready` event and then trigger a manual re-fetch of all persisted licenses in case an update was applied, i.e. if  `lastVersion` is not `null` and not equal to `version` (or at least verify the loadability of previously persisted licenses). Also, the first request for a new license, temporary or persistent, after such an upgrade will fail with the CDM error `Rejected with system code (75)` (the same error as when trying to load a session persisted with the previous CDM). This happens because the CDM needs to update the storage to match the new system id. The suggested solution is to simply retry the request in such cases, as all subsequent requests should work as usual.

The more recent Widevine CDMs also support a new VMP status, `PLATFORM_SECURE_STORAGE_SOFTWARE_VERIFIED`, that was not previously available. This status may be required by certain Widevine proxies to allow distribution of persistent licenses, depending on their configuration. To be able to support the new VMP status a recent VMP singning certificate is required. This means that that if you have already applied for a VMP certificate you may need to do so again to get an updated version able to support the new VMP status.

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

## Widevine specific APIs

Widevine CDM verification/installation/update is normally automatically triggered on startup, if this is good enough for your scenario you can skip this section and jump to the section about [Widevine events](#widevine-specific-events). It is possible to stop this from triggering automatically using the command line switch `no-verify-widevine-cdm` and manually triggering the process instead, allowing extra options to be passed. Another command line switch is available to prevent updates of the CDM, `no-update-widevine-cdm`, which can be used in *offline*, e.g. geo-blocking, scenarios to avoid pre-persisted licenses being invalidated by a CDM update. This update behaviour is also possible to control using the  `disableUpdate` option, which takes precedence over the command line switch, with the API described below.

> **WARNING**: Using `disableUpdate` for extended periods of time is not advisable since you may miss a critical CDM update, ultimately rendering the media client unusable!

### `app.verifyWidevineCdm([options])`

* `options` Object (optional)
  * `session` [Session](https://github.com/electron/electron/blob/v8.1.0/docs/api/session.md) (optional)
  * `disableUpdate` boolean (optional)

Initiates asynchronous Widevine CDM verify/install/update procedure and returns no value. Once initiated Widevine related events will be emitted as necessary, namely `widevine-ready`, `widevine-update-pending` & `widevine-error`. Unless the `no-verify-widevine-cdm` command line parameter is set this API is automatically triggered on startup and should not be called manually. If customized options are necessary `no-verify-widevine-cdm` should be set and the API call made once, very early, after the app has received the `ready` event (but before loading any media-related content to avoid potentially requiring a restart).

```javascript
const { app, session } = require('electron');

app.commandLine.appendSwitch('no-verify-widevine-cdm')

// Demonstrating with constant, but this should be set dynamically
let isOffline = false

app.on('ready', () => {
  // Demonstrating with default session, but a custom session object can be used
  app.verifyWidevineCdm({
    session: session.defaultSession,
    disableUpdate: isOffline,
  });

  // Do other early initialization...
});

app.on('widevine-ready', () => {
  // Open media browser window, etc...
});

...
```

## Widevine specific events

As a part of the installation process for the Widevine components certain events will be emitted to the application. These events allow the user to monitor the Widevine status to a certain extent. The events are:

### `widevine-ready` 
 
Emitted once Widevine has been properly installed/updated/registered and is ready to use to be used. Trying to play back protected content prior to the reception of this event will cause errors. This event is always emitted after the `ready` event.

Two arguments are provided indicating the current and last versions of Widevine.

If the `lastVersion` argument is not `null` and is not equal to `version` an update has occured, potentially rendering any persisted licenses unusable, see the [migration section](#migrating-from-an-earlier-castlabs-electron-for-content-security-release) for more information.
 
#### Example
 
```
app.on('widevine-ready', (version, lastVersion) => {
  if (null !== lastVersion) {
    console.log('Widevine ' + version + ', upgraded from ' + lastVersion + ', is ready to be used!');
  } else {
    console.log('Widevine ' + version + ' is ready to be used!');
  }
});
```
 
### `widevine-update-pending` 
 
Emitted when there is a Widevine update available that is pending installation. This event is always emitted after the `ready` event. Once the application is restarted the update will be automatically applied and a `widevine-ready`-event emitted, as usual.
 
Two arguments are provided which contains the current and pending versions of Widevine.
 
#### Example
 
```
app.on('widevine-update-pending', (currentVersion, pendingVersion) => {
  console.log('Widevine ' + currentVersion + ' is ready to be upgraded to ' + pendingVersion + '!');
});
```
 
 ### `widevine-error` 

Emitted when there is a problem with the Widevine installation that cannot be automatically handled. If there are no handlers registered for this event it will show a dialog with the error and terminate the application when it is dismissed. If this is not the desired behaviour a handler needs to be registered to provide customized behaviour. This event is always emitted after the `ready` event.

An argument is provided that contains an `Error`-instance describing the error that occured.

#### Example

```
app.on('widevine-error', (error) => {
  console.log('Widevine installation encountered an error: ' + error);
  process.exit(1)
});
```

## Verified Media Path (VMP)

This fork of Electron provides support for [Verified Media Path (VMP)](https://www.widevine.com/news).  VMP provides a method to verify the autenticity of a device platform by requiring signatures for binary components taking part in the media pipeline. 

The provided builds are VMP-signed for development use, i.e. using Widevine UAT or servers accepting development clients. For production use a license agreement with [Google Widevine](https://www.widevine.com/) is needed to get production certificates for re-signing the final package.

### Licensing

To be able to re-sign your application for your own purposes a license agreement with Google Widevine is required. To start the process you can use the [contact sheet](https://www.widevine.com/contact) on the [Widevine web site](https://www.widevine.com/), or send an e-mail to [widevine@google.com](mailto:widevine@google.com) showing interest in a license agreement and VMP signing. This process may take some time to complete so keep that in mind when planning your product release.

Once a license agreement is in place you will be asked to provide CSRs for development and production VMP certificates. Google will sign and return the certificates enabling them to be used for VMP-signing your applications.

> **NOTE**: Signing with a development certificate will only allow the application to pass VMP validation when using the application with development/UAT servers, **for production use a production VMP signature is required**.

### Re-signing

We are providing a Python script to make the re-signing process easier. It requires the Python modules [cryptography](https://pypi.python.org/pypi/cryptography) and [macholib](https://pypi.python.org/pypi/macholib), both avaliable through the [Python Package Index](https://pypi.python.org/) and easily installed, e.g. using [pip](https://pypi.python.org/pypi/pip). Once VMP signing certificates (in either `PEM` or `DER` file-formats) have been acquired from [Google Widevine](#licensing) the [vmp-resign.py](vmp-resign.py) script, available in the repository, can be used to easily regenerate (and verify) the required signatures. Basic usage looks as follows:

```
vmp-resign.py [-h] [-v] [-q] [-M MACOS_NAME] [-W WINDOWS_NAME]
              [-V VERSION] [-C CERTIFICATE] [-P PASSWORD] [-p] [-K KEY]
              [-Y]
              dirs [dirs ...]
```

For full usage information execute `vmp-resign.py -h`.

If the application has been renamed as part of the packaging process, e.g. to Player, the new names need to be provided for each platform, using the `-M` and `-W` options:

```
vmp-resign.py -C cert.pem -P "pass" -K key.pem -M Player.app -W Player.exe MacPlayer-v1.0/ WinPlayer-v1.0/
```

The signature file (`.sig`) generatered by the script is automatically picked up and verified by Electron and the Widevine CDM. On Windows the `.sig` file resides next to the `.exe` file, but in later releases on macOS it has moved further into the app bundle.

To verify that signatures are vaild the `-Y` option can be used:

```
vmp-resign.py -M Player.app -W Player.exe -Y MacPlayer-v1.0/ WinPlayer-v1.0/
```

Keep in mind that this only verifies the integrity of the executable and signature, it does not currently check that the certificate/key used for signing is actually a valid VMP certificate.

> **NOTE**: Since VMP-signing and Xcode/VS code-signing may have impact on each other care needs to be taken, in case both are used, to avoid conflicting signatures being generated. With Xcode VMP-signing must be done before code-signing, but in Visual Studio the reverse is true since it stores the code-signature inside a VMP signed PE binary.

> **NOTE**: Make sure to use the [vmp-resign.py](vmp-resign.py) tool corresponding to the release in use. If Electron is installed as a node module, using npm, the correct script is available in `node_modules/electron/vmp-resign.py`.

### Special considerations

VMP relies on signatures for certain binaries in the Electron build which puts some additional requirements on custom builds where the binaries are renamed or changed. This is primarily a consideration on Windows since the signature resides in the Electron Framework on macOS which is typically not altered.

On Windows the signature file needs to be named the same as the executable with the addition of a `.sig` extension (i.e. `electron.exe` and `electron.exe.sig`). If the application is renamed, say to Player, both files need to be renamed as follows:

```
electron.exe -> Player.exe
electron.exe.sig -> Player.exe.sig
```

In addition, if the executable is changed in any way, even if it is just adding meta-data or code-signing the executable, the VMP signature will be invalidated and the executable needs to be re-signed. This often happens when using a packager, such as electron-packager or electron-builder, since they usually add an icon or other meta-data to the executable.

## DISCLAIMER

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. UPDATES, INCLUDING SECURITY UPDATES, WILL BE PROVIDED ON A BEST-EFFORT BASIS.
