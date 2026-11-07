# Electron for Content Security

Check out the [Wiki](../../wiki) for general news, guides, and other updates.

> :warning: **Starting with `v46`, the Widevine CDM is no longer installed or updated implicitly at startup. Your app has to call `components.whenReady()` or `components.start()` for that to happen, see [Widevine CDM installation](#widevine-cdm-installation).**
>
> Apps that already wait for `components.whenReady()` before playback, as shown [below](#using), need no changes. Please report any issues you find!

Electron for Content Security (ECS) is a fork of Electron created by Castlabs to facilitate the use of Google's [Widevine Content Decryption Module (CDM)](../../wiki/CDM) for DRM-enabled playback within Electron, including support for [Verified Media Path (VMP)](../../wiki/VMP). It is intended to be used as a drop-in replacement for stock Electron and supports Windows, macOS and Linux, although VMP is not available on Linux.

The sections below will describe the features/modifications that ECS provides, for anything else refer to the regular [Electron documentation](https://www.electronjs.org/docs).

## How does it work?

To achieve Widevine support the [Widevine CDM](../../wiki/CDM) is [installed at runtime](#widevine-cdm-installation) when the app asks for it, and enabled as an option for playback of DRM protected content using common EME APIs. After that, each launch that starts the components API triggers a background update check. If an update is available it is downloaded and applied on the next launch.

The provided builds are VMP-signed for development and can be used with Widevine UAT or other servers accepting development clients. For production use you can sign up for our [EVS service](../../wiki/EVS), to obtain production VMP signing capabilities. Previously a license agreement with Google Widevine was required to get your own VMP signing certificate, but with EVS this is no longer necessary.

## Installing

To install prebuilt ECS binaries, use [npm](https://docs.npmjs.com/). The preferred method is to install ECS as a development dependency in your app:

```
npm install "https://github.com/castlabs/electron-releases#v45.2.1+wvcus" --save-dev
```

Since ECS is not published in the npm package index a GitHub URL is used instead to reference a particular release, just modify the `#` tag at the end to the version you want to use.

> :warning: The above command is just an example, **use a [release](https://github.com/castlabs/electron-releases/releases) of a [currently supported version](https://github.com/castlabs/electron-releases/wiki#supported-versions)** to make sure you have the latest features and security updates!

## Using

Using ECS is very similar to using stock Electron, the main difference being that you should wait for the Widevine CDM installation to complete before opening your `BrowserWindow`. This can be achieved using the new [components API](docs/api/components.md):

```javascript
const {app, components, BrowserWindow} = require('electron');

function createWindow () {
  const mainWindow = new BrowserWindow();
  mainWindow.loadURL('https://shaka-player-demo.appspot.com/');
}

app.whenReady().then(async () => {
  await components.whenReady();
  console.log('components ready:', components.status());
  createWindow();
});
```

To shorten startup, `components.start()` can begin the installation early while the app does other initialization. It also takes options, such as a minimum Widevine CDM version, which requests an immediate update if the installed CDM is older than that:

```javascript
app.whenReady().then(async () => {
  components.start({
    components: { [components.WIDEVINE_CDM_ID]: { minimumVersion: '4.10.2891.0' } }
  });
  // Other initialization...
  await components.whenReady();
  createWindow();
});
```

See the [components API](docs/api/components.md) for all options and details.

## Extensions to Electron

The only visible extensions provided is the new [components API](docs/api/components.md).

### Widevine CDM installation

Nothing is installed or updated until the app calls `components.start()` or `components.whenReady()`. The first call installs the Widevine CDM immediately if no version is available yet, and its options apply for the whole run. Installed versions are checked for updates in the background, and an update takes effect after a restart.

Installation and updates can be turned off by passing `--disable-component-update`, or by setting `components.updatesEnabled` to `false`. A CDM bundled with the app, or given with `--widevine-cdm-path`, can be used instead of the component, see the [components API](docs/api/components.md#widevine-cdm-sources) for details.

## Legal notice / Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. UPDATES, INCLUDING SECURITY UPDATES, WILL BE PROVIDED ON A BEST-EFFORT BASIS.
