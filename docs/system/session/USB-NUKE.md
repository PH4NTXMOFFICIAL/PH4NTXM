# [ USB NUKE ]

## [ OVERVIEW ]

Provides the graphical USB Removal Nuke arming control.

## [ STARTUP ]

The desktop window reads `usb-nuke-armed` when it opens and shows Armed or Disarmed. It uses the shared PH4NTXM styling and offers the corresponding Arm or Disarm action.

Opening the window or pressing Cancel does not change the marker. The initial display is a snapshot, not a continuously refreshed monitor.

## [ RUNTIME ]

The action calls the privileged [USB Nuke Control](USB-NUKE-CONTROL.md) helper through sudo with `enable` or `disable`. Arm works without a password prompt. Disarm opens a graphical prompt for the current session password. Cancelling authentication or entering an incorrect password leaves the armed state unchanged.

Successful completion closes the window. A failed helper call leaves an error dialog so the action is not presented as completed.

Arming creates runtime state for the udev-triggered removal path. The installed udev rules determine which storage-removal events activate the armed trigger.

Although the window describes USB storage removal, the actual scope comes from the installed udev rules. They match qualifying whole USB storage devices. There is no device picker or saved per-drive identity in this UI.

The separate trigger consumes the armed marker and submits Panic when a matching removal occurs. Closing this window afterwards does not disarm the trigger. Disarming through the control helper removes markers but cannot retract an emergency job already submitted to systemd.

Because state is read at window creation, changes from another control path may not be reflected in an already open window. Reopening obtains a new snapshot.

## [ CHECKS ]

After an action, inspect marker state or reopen the window. Use [Health](HEALTH.md) for emergency-path prerequisites rather than treating Armed as proof that every termination dependency is ready.

If the UI reports an error, inspect the helper result and permissions. Testing removal while armed invokes the real emergency behavior.

## [ SOURCE ]

[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)
