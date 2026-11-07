# components

> Enable apps install and update components, such as the Widevine Content Decryption Module, using the Chromium Component Updater Service.

Process: [Main](https://www.electronjs.org/docs/latest/glossary#main-process)

Currently supported components are:

* Widevine Content Decryption Module

## Platform Notices

macOS, Windows and Linux are supported.

## Usage

Nothing is registered or downloaded until `components.start()` or `components.whenReady()` is called, accessing the `components` module alone has no effect. Wait for `components.whenReady()` before opening any window that needs a component, e.g. for Widevine playback.

`components.start()` can be used to begin the installation early, while the app does other initialization, and `components.whenReady()` to wait for the result later:

```js
const { app, components } = require('electron')

app.whenReady().then(async () => {
  components.start({
    components: { [components.WIDEVINE_CDM_ID]: { minimumVersion: '4.10.2891.0' } }
  })
  // Other initialization...
  await components.whenReady()
  // Open windows that need the Widevine CDM...
})
```

Components are installed once per run. The first `components.start()` or `components.whenReady()` call makes the only attempt, and its options apply for the whole run. Later calls return the same result. Installed components are updated in the background, and an update takes effect after a restart. If the attempt fails, a component installed later in the same run may not be available until restart.

### Widevine CDM sources

A Widevine CDM can come from three sources:

* The component updater, which installs the CDM in the user data directory.
* A CDM bundled with the app, in a `WidevineCdm` directory next to the executable (`Contents/MacOS/WidevineCdm` on macOS). It is used as a pre-installed version of the component, and the component updater uses whichever of the bundled and the installed versions is higher.
* An explicit CDM given with the `--widevine-cdm-path` command line switch, which is only supported for unpackaged apps. It takes precedence over the component, and `components.whenReady()` resolves with it without installing the component.

Use `components.status()` to see which CDM is in use.

### Minimum version

If a component has a `minimumVersion` and the installed or bundled version is older, that version is not used. Instead, an update is requested immediately, and a newer version is used without a restart. If no new enough version is available, the older version is used anyway, and `components.whenReady()` rejects with the `below-minimum` error code.

This can help when background update checks keep getting deferred by the update server, which can leave an outdated component installed. The update requested for a minimum version is not deferred.

The minimum version must be given with the first `components.start()` or `components.whenReady()` call. It is ignored for the Widevine CDM if an explicit `--widevine-cdm-path` CDM is in use.

## Events

The `components` object does not currently emit any events.

## Methods

The `components` object has the following methods:

### `components.start([options])`

* `options` [ComponentsOptions](structures/components-options.md) (optional)

Starts registering all supported components, and installing any that are missing, without waiting for the result. Only the first call has an effect, a later call with different options emits a warning. Use `components.whenReady()` to wait for the result.

This API must be called after the `ready` event is emitted, otherwise it throws.

### `components.status()`

Returns `Record<string, ComponentStatus>` - A record of [ComponentStatus](structures/component-status.md) objects where the keys are component identifiers.

This method can be used to check the state of the supported components. Supported component identifiers are provided as readonly properties (see below). It lists all supported components, also before `components.start()` is called, and does not start anything itself.

This API must be called after the `ready` event is emitted.

### `components.whenReady([required, options])`

* `required` string[] (optional)
* `options` [ComponentsOptions](structures/components-options.md) (optional) - Passed to `components.start()`.

Returns `Promise<ComponentResult[]>` - Fulfilled with an array of [ComponentResult](structures/component-result.md) when all required components are ready to be used.

Calls `components.start(options)`, so the components are started if they were not already. If the components are already installed the promise fulfills as soon as they are registered, otherwise an immediate installation is triggered and the promise fulfills once the missing components have been properly installed. The promise will be rejected with a [ComponentsError](structures/components-error.md) if the installation fails. This in turn has an `errors` property, which is an array of [ComponentError](structures/component-error.md) detailing individual errors that occurred.

The `required` argument can be used to control which components are required to successfully install. If no argument is provided all supported components are implicitly required. An empty array would mean no components are required. In this case the updater promises are still guaranteed to settle before the returned promise resolves, but errors won't cause a promise rejection. Finally, an array of component identifiers may be provided to require a specific component or set of components (any unknown identifiers will yield an error).

This API must be called after the `ready` event is emitted, otherwise the promise is rejected.

## Properties

The `components` object has the following properties:

### `components.updatesEnabled`

A `Boolean` property that is `true` if component updates are enabled, `false` otherwise. The value is persisted in the local state, using the key `component_updates.component_updates_enabled`, and is thus remembered across launches.

If updates are disabled before a component is installed, it will never be installed. If it is disabled after, the component will never be updated. This can be used to create an "offline" mode for component updates by disabling updates after `components.whenReady()` completes. Disabling updates should typically be time limited to avoid outdated components that could stop to function properly.

This API must be called after the `ready` event is emitted.

### `components.WIDEVINE_CDM_ID` _Readonly_

A `String` which is the identifier of the Widevine Content Decryption Module.
