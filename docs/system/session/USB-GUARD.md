# [ USB GUARD ]

## [ OVERVIEW ]

Optional USB approval for the live session. USBGuard preserves existing connections and blocks new or reconnected devices until individually approved in the GTK window.

## [ STARTUP ]

Protection is off at boot and is not a Boot Pilot gate. Opening the window changes nothing. Enable requests the session password, saves controller authorization defaults in protected RAM and starts the dedicated service.

Existing devices retain their actual authorization state, preserving input and boot media. Connect new devices only after protection is verified against the service, policy and controller defaults. Stock services, installation policy and broad desktop authorization are disabled or removed during the build.

## [ RUNTIME ]

Every Allow requires the session password. The helper verifies service generation, device ID and exact descriptor identity, then rechecks, authorizes temporarily and verifies through one USBGuard IPC connection. Removal or changed identity invalidates the request. Reconnecting requires approval again.

Root controllers, missing interface evidence and audio/video functions have no approval action. Blocking covers declared HID, storage and network functions too. Existing allowed connections have no revocation button.

Enable, Allow and Disable use `sudo -A -k` with zero authentication lifetime. Cancelled/failed authentication changes nothing. Only the bounded snapshot is passwordless. Closing the window leaves protection running. Generic notifications open the review window without exposing device names/serials or approving anything.

Daemon restart preserves current authorization states. A crash reports degraded protection and leaves controller defaults blocked. Disable stops the service and restores saved defaults only for the same controller inode. Already blocked devices need reconnection. Missing/replaced controllers produce incomplete-restoration errors instead of guessed defaults.

Descriptors and hashes do not authenticate hardware. The kernel enumerates devices before approval, and a new host controller can admit devices before its blocking default is initialized. Kernel/firmware exploits, electrical attacks and host compromise remain outside this control.

## [ CHECKS ]

Inspect the snapshot and service:

```bash
sudo -n /usr/local/sbin/ph4ntxm-usb-guard-control snapshot
systemctl show ph4ntxm-usb-guard.service -p ActiveState -p SubState -p MainPID
```

Test baseline devices, blocked hotplug, cancelled authentication, per-connection approval and unavailable audio/video actions. Check Disable/reconnection separately from daemon failure. Retry incomplete restoration where possible or reboot.

USB Nuke remains independent and can trigger Panic on matching storage removal. Leave it disarmed during ordinary hotplug checks.

## [ SOURCE ]

[ph4ntxm-usb-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-guard)\
[ph4ntxm-usb-guard-monitor](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-guard-monitor)\
[ph4ntxm-usb-guard-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-guard-control)\
[USB Guard broker](../../../config/includes.chroot/usr/lib/ph4ntxm/usb_guard.py)\
[USBGuard IPC client](../../../config/includes.chroot/usr/local/src/ph4ntxm-usb-guard/ph4ntxm-usb-guard-client.cpp)\
[USB Guard service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-usb-guard.service)\
[USBGuard configuration](../../../config/includes.chroot/etc/ph4ntxm-usb-guard.conf)\
[USB Guard build hook](../../../config/hooks/normal/0030-build-ph4ntxm-usb-guard.chroot)
