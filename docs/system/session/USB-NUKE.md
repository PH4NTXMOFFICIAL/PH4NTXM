# [ USB NUKE ]

## [ OVERVIEW ]

Arms automatic Panic activation when a matching USB storage device is removed. The desktop window, root control helper and udev trigger form one path from the user's choice to emergency termination.

## [ STARTUP ]

The window reads `/run/ph4ntxm/usb-nuke-armed` when it opens and offers Arm or Disarm. Opening it or selecting Cancel leaves the state unchanged. The displayed state is a snapshot, so reopen the window after changes made elsewhere.

The control helper runs as root and accepts exactly one action, `enable` or `disable`. Invalid arguments return status 2. It prepares `/run/ph4ntxm` as a root-owned directory. The arming state belongs to this boot.

## [ RUNTIME ]

Arm calls the helper without a password prompt. It removes an old `usb-nuke-triggered` marker and creates `usb-nuke-armed` with a restrictive umask, then sets `0644` permissions so the desktop can read its state.

Disarm requests the session password through a graphical prompt and removes both markers. Cancelling authentication or entering an incorrect password leaves the armed state unchanged. A successful action closes the window. A failed helper call shows an error. Repeating an action sets the requested state rather than toggling it.

The udev rules match removal of whole `sd*` block devices associated with USB through `ID_BUS` or `ID_PATH`. The kernel-name pattern excludes partitions. There is no selected drive serial or device picker, so any device matching those rules can trigger the armed action.

On removal, the trigger attempts to rename `usb-nuke-armed` to `usb-nuke-triggered`. Only the invocation that consumes the marker proceeds, including when both udev rules match the same event. Without an armed marker, it takes no termination action.

The trigger installs interruption handlers and submits `systemctl --no-block start ph4ntxm-panic.service`. A submission failure restores the armed marker when possible and returns failure. An accepted job removes the handlers and returns without waiting for termination. [Panic](PANIC.md) owns the remaining sequence and its returned-path restoration.

This removal path runs through udev as root and never asks for the session password. It works independently of the window, including while the screen is locked. Closing the window does not disarm it. Disarming cannot retract a Panic job already submitted to systemd.

## [ CHECKS ]

Check both markers, the helper's exit status and the device's udev properties when investigating an unexpected action. The markers contain no device identity.

Arming prepares the trigger without checking crash-kernel readiness. Use [Health](HEALTH.md) for those prerequisites and the Panic journal to see how far a triggered action progressed. Removing matching storage while armed invokes the real emergency sequence.

## [ SOURCE ]

[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)

[ph4ntxm-usb-nuke-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke-control)

[ph4ntxm-usb-nuke.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke.sh)

[99-ph4ntxm-usb-nuke.rules](../../../config/includes.chroot/etc/udev/rules.d/99-ph4ntxm-usb-nuke.rules)
