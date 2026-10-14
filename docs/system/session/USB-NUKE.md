# [ USB NUKE ]

## [ OVERVIEW ]

Arms Panic activation when matching USB storage is removed. The desktop window, root helper and udev trigger connect the operator's choice to emergency termination.

## [ STARTUP ]

The window snapshots `/run/ph4ntxm/usb-nuke-armed` and offers Arm or Disarm. Opening or cancelling changes nothing; reopen after external changes.

The root helper accepts only `enable` or `disable`, returning status 2 for invalid arguments. It prepares protected runtime state and serializes control, removal claims and restoration through one lock. State lasts for this boot.

## [ RUNTIME ]

Arm is passwordless and atomically publishes a fresh `0644` marker containing a random transaction token. Disarm requires the session password and removes both armed/triggered markers. Cancelled or failed authentication leaves state unchanged. Successful actions close the window; errors remain visible.

The udev rules match whole `sd*` block-device removals associated with USB through `ID_BUS` or `ID_PATH`. Partitions are excluded, but no drive serial is selected and boot media has no exemption.

Under the lock, removal claims the armed marker, assigns a fresh attempt token and renames it to `usb-nuke-triggered`. Only that claimant proceeds, including duplicate rule matches. It submits a token-specific dispatch service with a five-second timeout and one-second forced-termination allowance.

Submission failure or handled interruption attempts token-matched restoration and returns failure. Accepted jobs run independently through the singleton [Panic](PANIC.md) service without holding the state lock. Return, interruption or the unit's post-stop hook restores only that attempt when no newer armed state exists.

A later Arm or Disarm invalidates earlier restoration callbacks. Disarm cannot retract a claim already submitting its job; systemd may accept a job even if the client is interrupted before receiving the reply. Per-attempt tokens prevent late callbacks from rearming newer state.

The removal path runs as root without a password, including while the screen is locked. Closing the window does not disarm it.

## [ CHECKS ]

Inspect both markers, helper results, the token-specific dispatch journal and device udev properties. Markers contain no device identity.

Arming does not verify crash-kernel readiness; use [Health](HEALTH.md) for prerequisites. Removing any matching storage while armed invokes the real emergency sequence. If it returns, inspect Panic progress separately from trigger submission/restoration.

## [ SOURCE ]

[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)\
[ph4ntxm-usb-nuke-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke-control)\
[ph4ntxm-usb-nuke.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke.sh)\
[ph4ntxm-usb-nuke-dispatch](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke-dispatch)\
[USB Nuke state](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-usb-nuke-state.sh)\
[USB Nuke dispatch service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-usb-nuke-dispatch@.service)\
[99-ph4ntxm-usb-nuke.rules](../../../config/includes.chroot/etc/udev/rules.d/99-ph4ntxm-usb-nuke.rules)
