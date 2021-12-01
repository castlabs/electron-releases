# components

> Enable apps install and update components, such as the Widevine Content Decryption Module, using the Chromium Component Updater Service.

Process: Main

Currently supported components are:

* Widevine Content Decryption Module
* Google Widevine Windows CDM (exprimental)

The Google Widevine Windows CDM is still exprimental, and is currently disabled in releases builds.

## Platform Notices

macOS, Windows and Linux are supported. Components installed for the first time on Linux will require a restart before they function because of how sandboxing works there.

## Events

The `components` object does not currently emit any events.

## Methods

The `components` object has the following methods:

### `components.status()`

Returns `Record<string, ComponentStatus>` - A record of [ComponentStatus](structures/component-status.md) objects where the keys are component identifiers.

This method can be used to check the state of any registered components. Supported component identifiers are provided as readonly properties (see below).

This API must be called after the `ready` event is emitted.

### `components.whenReady()`

Returns `Promise<void[]>` - Fulfilled when all components are ready to be used.

If the components are already installed this will happen as soon as they are registered, otherwise an immediate installation will be triggered and the promise will fulfill once the missing components have been properly installed. The promise will be rejected if the installation fails.

This API must be called after the `ready` event is emitted.

## Properties

The `components` object has the following properties:

### `components.updatesEnabled`

A `Boolean` property that is `true` if component updates are enabled, `false` otherwise. The value is persisted in the local state, using the key `component_updates.component_updates_enabled`, and is thus remembered across launches.

If updates are disabled before a component is installed, it will never be installed. If it is disabled after, the component will never be updated. This can be used to create an "offline" mode for component updates by disabling updates after `components.whenReady()` completes. Disabling updates should typically be time limited to avoid outdated components that could stop to function properly.

This API must be called after the `ready` event is emitted.

### `components.WIDEVINE_CDM_ID` _Readonly_

A `String` which is the identifier of the Widevine Content Decryption Module.

### `components.MEDIA_FOUNDATION_WIDEVINE_CDM_ID` _Readonly_

A `String` which is the identifier of the Google Widevine Windows CDM (a.k.a. the Media Foundation Widewine CDM).
