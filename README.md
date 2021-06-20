# Electron for Content Security

Check out the [Wiki](../../wiki) for general news, guides, and other updates.

Electron for Content Security (ECS) is a fork of Electron created by castLabs to facilitate the use of Google's [Widevine Content Decryption Module (CDM)](../../wiki/CDM) for DRM-enabled playback within Electron, including support for [Verified Media Path (VMP)](../../wiki/VMP) and persistent license storage. It is intended to be used as a drop-in replacement for stock Electron and currently has full support for Windows and macOS platforms, with partial support for Linux (which lacks support for persistent licenses due to VMP limitations on the platform).

The sections below will describe the features/modifications that ECS provides, for anything else refer to the regular [Electron documentation](https://www.electronjs.org/docs).

## How does it work?

To achieve Widevine support the [Widevine CDM](../../wiki/CDM) will be [installed on first launch](#widevine-cdm-installation) and enabled as an option for playback of DRM protected content using common EME APIs. Subsequent launces will trigger a backround update check. If an update is available it will be downloaded and applied on next launch. During this process certain [events](#widevine-events) are emitted, the two most important being [`widevine-ready`](#event-widevine-ready) and [`widevine-error`](#event-widevine-error).

The provided builds are VMP-signed for development and can be used with Widevine UAT or other servers accepting development clients. For production use you can sign up for our [EVS service](../../wiki/EVS), to obtain production VMP signing capabilities. Previously a license agreement with Google Widevine was required to get your own VMP signing certificate, but with EVS this is no longer necessary.

## Installing

To install prebuilt ECS binaries, use [npm](https://docs.npmjs.com/). The preferred method is to install ECS as a development dependency in your app:

```
npm install "https://github.com/castlabs/electron-releases#v11.0.0-wvvmp" --save-dev
```

Since ECS is not published in the npm package index a GitHub URL is used instead to reference a particular release, just modify the `#` tag at the end to the version you want to use.

> :warning: The above command is just an example, **use a [release](https://github.com/castlabs/electron-releases/releases) of a [currently supported version](https://github.com/castlabs/electron-releases/wiki#supported-versions)** to make sure you have the latest features and security updates!

## Using

Using ECS is very similar to using stock Electron, the main difference being that you should wait for the [`widevine-ready`](#event-widevine-ready) event, instead of using `app.whenReady()` or waiting for the regular `ready` event, before opening your `BrowserWindow`.

```javascript
const { app, BrowserWindow } = require('electron')

function createWindow () {
  const win = new BrowserWindow()
  win.loadURL('https://shaka-player-demo.appspot.com/')
}

app.on('widevine-ready', createWindow)
```

## Extensions to Electron

### Widevine CDM installation

Widevine CDM installation/update is ordinarily automatically triggered on startup, but if more control is necessary, facilities are provided to control this behavior.

#### Parameter: `no-verify-widevine-cdm`

Command line parameter that prevents ECS from automatically triggering the Widevine CDM installation, update, and registration, on startup. This requires the process to be manually triggered instead, using the [`verifyWidevineCdm`](#api-appverifywidevinecdmoptions) API, which also allows extra options to be passed.

#### Parameter: `no-update-widevine-cdm`

Command line parameter that prevents ECS from checking for, and installing, updates on startup. This fills the same function as the `disableUpdate` option of [`verifyWidevineCdm`](#api-appverifywidevinecdmoptions), but has lower precedence in case both are set.

> :warning: **Disabling Widevine CDM updates for extended periods of time is not advisable** since you may miss a critical update, ultimately rendering the media client unusable!

#### Parameter: `widevine-base-dir`

Command line parameter that overrides the base directory in which the Widevine CDM is downloaded and installed. This fills the same function as the `baseDir` option of [`verifyWidevineCdm`](#api-appverifywidevinecdmoptions), but has lower precedence in case both are set.

#### API: `app.verifyWidevineCdm([options])`

* `options` Object (optional)
  * `session` [Session](https://www.electronjs.org/docs/api/session) (optional)
  * `disableUpdate` boolean (optional)
  * `baseDir` string (optional)

Initiates asynchronous Widevine CDM installation, update, and registration, procedure and returns no value. Once initiated Widevine [events](#widevine-events) will be emitted as necessary.

Unless [`no-verify-widevine-cdm`](#parameter-no-verify-widevine-cdm) has been set this API is automatically triggered on startup and **MUST NOT** be called manually. If set, this API can be used to customize the behavior of the install/update operation. It **MUST** be called once, very early, after the app has received the `ready` event, but before loading any media-related content to avoid potentially requiring a restart.

The `disableUpdate` controls if the CDM update check, and pending update installation, is executed. This can be used in *offline*, e.g. geo-blocking, scenarios to avoid pre-persisted licenses being invalidated by an untimely CDM update.

> :warning: **Disabling Widevine CDM updates for extended periods of time is not advisable** since you may miss a critical update, ultimately rendering the media client unusable!

The `baseDir` option controls the path in which the Widevine CDM is downloaded and installed. By default the user application data directory, as returned by `app.getPath('userData')`, is used.

```javascript
const { app, session } = require('electron')

app.commandLine.appendSwitch('no-verify-widevine-cdm')

// Demonstrating with constant, but this should be set dynamically
let isOffline = false

// Demonstrating with the user data directory, which is the default
let widevineDir = app.getPath('userData')

app.on('ready', () => {
  // Demonstrating with default session, but a custom session object can be used
  app.verifyWidevineCdm({
    session: session.defaultSession,
    disableUpdate: isOffline,
    baseDir: widevineDir
  })

  // Do other early initialization...
})

app.on('widevine-ready', () => {
  // Open media browser window, etc...
})
```

### Widevine Events

As a part of the installation and update process for the Widevine CDM certain events will be emitted to the application. These events allow the user to monitor the Widevine status to a certain extent.

#### Event: `widevine-ready`

Emitted once Widevine has been properly registered and is ready to use to be used. Trying to play back protected content prior to the reception of this event will cause errors. This event is always emitted after the `ready` event.

Two arguments are provided indicating the current and last versions of Widevine.

If the `lastVersion` argument is not `null` and is not equal to `version` an update has occured, potentially rendering any persisted licenses unusable, see the [CDM migration](../../wiki/CDM#migrating-from-an-earlier-cdm-version) section for more information.

```javascript
app.on('widevine-ready', (version, lastVersion) => {
  if (null !== lastVersion) {
    console.log('Widevine ' + version + ', upgraded from ' + lastVersion + ', is ready to be used!')
  } else {
    console.log('Widevine ' + version + ' is ready to be used!')
  }
})
```

#### Event: `widevine-update-pending`

Emitted when there is a Widevine CDM update available that is pending installation. This event is always emitted after the `widevine-ready` event. Once the application is restarted the update will be automatically applied, unless updates [have been disabled](#parameter-no-update-widevine-cdm).

Two arguments are provided which contains the current and pending versions of Widevine.

```javascript
app.on('widevine-update-pending', (currentVersion, pendingVersion) => {
  console.log('Widevine ' + currentVersion + ' is ready to be upgraded to ' + pendingVersion + '!')
})
```

#### Event: `widevine-error`

Emitted when there is a problem with the Widevine CDM installation that cannot be automatically handled. If there are no handlers registered for this event it will show a dialog with the error and terminate the application when it is dismissed. If this is not the desired behavior a handler needs to be registered to provide customized behavior. This event is always emitted after the `ready` event.

An argument is provided that contains an `Error`-instance describing the error that occured.

```javascript
app.on('widevine-error', (error) => {
  console.log('Widevine installation encountered an error: ' + error)
  process.exit(1)
})
```

## Legal notice / Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. UPDATES, INCLUDING SECURITY UPDATES, WILL BE PROVIDED ON A BEST-EFFORT BASIS.
