# ComponentStatus Object

* `status` String - Status of component. One of the following values:
  * `not-registered` - `components.start()` has not been called yet.
  * `not-installed` - No version is installed.
  * `new` - A version is installed and no update check has run yet.
  * `checking` - An update check is in progress.
  * `can-update` - A newer version is available.
  * `downloading` - A newer version is being downloaded.
  * `decompressing` - A newer version is being decompressed.
  * `patching` - A newer version is being patched.
  * `updating` - A newer version is being installed.
  * `updated` - A newer version was installed.
  * `up-to-date` - The last update check found no newer version.
  * `update-error` - The last update failed.
  * `not-supported` - The component is not supported (only in a [ComponentError](component-error.md)).
* `title` String | null - Name of component (or `null` if not supported).
* `version` String | null - Version of the component in use (or `null` if none). For the Widevine CDM this is the CDM used for playback, which can be an explicit `--widevine-cdm-path` CDM, and an update only takes effect after a restart, so it can differ from `installedVersion`.
* `installedVersion` String | null - Version of the component installed by the component updater, which includes a bundled version (or `null` if not supported/installed).
* `path` String | null (optional) - Widevine CDM only: path of the CDM library that is used for playback (or `null` if no CDM is registered yet). This can be an explicit `--widevine-cdm-path` CDM rather than the component.
