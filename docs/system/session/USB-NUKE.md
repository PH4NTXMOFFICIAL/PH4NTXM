# [ USB NUKE ]

## [ OVERVIEW ]

Arms automatic Panic activation when a matching USB storage device is removed. The desktop window, root control helper and udev trigger form one path from the user's choice to emergency termination.

## [ STARTUP ]

The window reads `/run/ph4ntxm/usb-nuke-armed` when it opens and offers Arm or Disarm. Opening it or selecting Cancel leaves the state unchanged. The displayed state is a snapshot, so reopen the window after changes made elsewhere.

The control helper runs as root and accepts exactly one action, `enable` or `disable`. Invalid arguments return status 2. It prepares `/run/ph4ntxm` as a root-owned directory. Control updates, removal claims and returned-path restorations use the same protected state lock. The arming state belongs to this boot.

## [ RUNTIME ]

Arm calls the helper without a password prompt. Under the state lock, it invalidates the previous trigger and atomically publishes a fresh `usb-nuke-armed` marker. The marker contains a random transaction token and has `0644` permissions so the desktop can read its state. The token contains no device identity.

Disarm requests the session password through a graphical prompt and removes both markers. Cancelling authentication or entering an incorrect password leaves the armed state unchanged. A successful action closes the window. A failed helper call shows an error. A completed Disarm invalidates old restoration callbacks, so they cannot rearm it. Repeating an action sets the requested state rather than toggling it.

The udev rules match removal of whole `sd*` block devices associated with USB through `ID_BUS` or `ID_PATH`. The kernel-name pattern excludes partitions. There is no selected drive serial or device picker, so any device matching those rules can trigger the armed action.

On removal, the trigger takes the state lock, assigns a fresh token to this attempt and renames `usb-nuke-armed` to `usb-nuke-triggered`. Only the invocation that consumes the marker proceeds, including when both udev rules match the same event. Without an armed marker, it takes no termination action.

The trigger installs interruption handlers before claiming the marker and submits a token-specific `ph4ntxm-usb-nuke-dispatch@.service` instance while holding the state lock. Submission is limited to five seconds, with forced termination one second later if needed. A submission failure or handled interruption attempts to restore only that attempt and returns failure. An accepted job returns without waiting for termination.

Each dispatch instance carries its token as a fixed argument and waits for the existing singleton [Panic](PANIC.md) service. It does not hold the state lock during containment. On return or handled interruption, it restores only a matching trigger with no newer armed marker. The unit also requests the same conditional restoration in its post-stop hook if execution fails or is killed before the normal callback. A subsequent Arm or Disarm invalidates the previous callback. Late jobs cannot restore a newer attempt, and every retry receives a new token.

This removal path runs through udev as root and never asks for the session password. It works independently of the window, including while the screen is locked. Closing the window does not disarm it. Disarming cannot retract a removal claim that has already begun job submission. A job accepted by systemd can still execute if the submitting client is interrupted before receiving its reply; its restoration remains bound to its own token.

## [ CHECKS ]

Check both markers, the helper's exit status, the token-specific dispatch journal and the device's udev properties when investigating an unexpected action. The markers contain no device identity. Boot media has no exemption: its removal triggers the same path when it matches the installed rules.

Arming prepares the trigger without checking crash-kernel readiness. Use [Health](HEALTH.md) for those prerequisites and the Panic journal to see how far a triggered action progressed. Removing matching storage while armed invokes the real emergency sequence.

## [ SOURCE ]

[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)

[ph4ntxm-usb-nuke-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke-control)

[ph4ntxm-usb-nuke.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke.sh)

[ph4ntxm-usb-nuke-dispatch](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke-dispatch)

[USB Nuke state](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-usb-nuke-state.sh)

[USB Nuke dispatch service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-usb-nuke-dispatch@.service)

[99-ph4ntxm-usb-nuke.rules](../../../config/includes.chroot/etc/udev/rules.d/99-ph4ntxm-usb-nuke.rules)
