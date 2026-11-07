# ComponentError Object extends `Error`

* `code` String - Error code. One of the following values:
  * `install-failed` - The component could not be installed or registered.
  * `below-minimum` - No version of at least the minimum version is available. An older version is used, if one is installed.
  * `not-supported` - The component is not supported.
* `detail` ComponentResult - Component result record.
