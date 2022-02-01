# Electron for Content Security

Check out the [Wiki](../../wiki) for general news, guides, and other updates.

> :warning: **The `v16` series of Electron for Content Security, labeled `wvcus`, moves to using the Component Updater Service to handle installation of the Widevine CDM, and has incompatible API updates compared to the previous `wvvmp` releases.**
>
> See additional updates in the sections below, and please report any issues you find!

Electron for Content Security (ECS) is a fork of Electron created by castLabs to facilitate the use of Google's [Widevine Content Decryption Module (CDM)](../../wiki/CDM) for DRM-enabled playback within Electron, including support for [Verified Media Path (VMP)](../../wiki/VMP) and persistent license storage. It is intended to be used as a drop-in replacement for stock Electron and currently has full support for Windows and macOS platforms, with partial support for Linux (which lacks support for persistent licenses due to VMP limitations on the platform).

The sections below will describe the features/modifications that ECS provides, for anything else refer to the regular [Electron documentation](https://www.electronjs.org/docs).

## How does it work?

To achieve Widevine support the [Widevine CDM](../../wiki/CDM) will be [installed on first launch](#widevine-cdm-installation) and enabled as an option for playback of DRM protected content using common EME APIs. Subsequent launces will trigger a backround update check. If an update is available it will be downloaded and applied on next launch.

The provided builds are VMP-signed for development and can be used with Widevine UAT or other servers accepting development clients. For production use you can sign up for our [EVS service](../../wiki/EVS), to obtain production VMP signing capabilities. Previously a license agreement with Google Widevine was required to get your own VMP signing certificate, but with EVS this is no longer necessary.

## Installing

To install prebuilt ECS binaries, use [npm](https://docs.npmjs.com/). The preferred method is to install ECS as a development dependency in your app:

```
npm install "https://github.com/castlabs/electron-releases#v17.0.0+wvcus" --save-dev
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

## Extensions to Electron

The only visible extensions provided is the new [components API](docs/api/components.md).

### Widevine CDM installation

Component installation/updates are always automatically triggered unless the Component Updater is disabled, e.g. by passing `--disable-component-update`. This is always done on a delay timer, even if there is no version of a component installed.

To make sure the Widevine CDM is promptly installed the `components.whenReady()` API can be used (see example [above](#using)). This forces immediate installation if there isn't already a version of the Widevine CDM available.

## Legal notice / Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. UPDATES, INCLUDING SECURITY UPDATES, WILL BE PROVIDED ON A BEST-EFFORT BASIS.
