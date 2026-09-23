# [ USB NUKE CONTROL ]

## [ OVERVIEW ]

Enables or disables the USB storage removal trigger.

## [ STARTUP ]

The root helper accepts exactly one action: `enable` or `disable`. Invalid arguments return status 2. A non-root invocation fails. The desktop USB Nuke window calls this helper through sudo.

It prepares `/run/ph4ntxm` as a root-owned runtime directory. Arming state belongs to the current boot and is not written as a persistent device preference.

## [ RUNTIME ]

Enable removes an old `usb-nuke-triggered` marker, then creates `usb-nuke-armed`. Creation uses a restrictive umask before setting the final marker permissions to `0644`, allowing the desktop to display state while root owns changes.

Disable removes both the armed and triggered markers. Repeating either action is a state-setting operation rather than a toggle based on an assumed previous value.

The helper accepts no device path, serial number or USB identifier. Arming therefore applies to the storage-removal events matched by the installed udev rules, not to a specific drive selected in the dialog.

[The trigger](USB-NUKE-TRIGGER.md) consumes the armed marker by renaming it before starting Panic. This keeps duplicate matching events from independently starting the same armed action.

Disarming changes marker state. It does not cancel a Panic service job that has already been accepted. Likewise, enabling only prepares the removal trigger. It does not itself start Panic or check that the crash kernel is ready.

## [ CHECKS ]

Inspect marker presence and the helper's exit status after an action. Check crash-kernel and Panic prerequisites separately through the session health path.

When investigating unexpected behavior, compare the udev match and trigger state with the user's arm/disarm action. The empty marker has no embedded device identity to inspect.

## [ SOURCE ]

[ph4ntxm-usb-nuke-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke-control)
