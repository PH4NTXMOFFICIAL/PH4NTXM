# [ USB NUKE TRIGGER ]

## [ OVERVIEW ]

Handles the armed USB-removal event.

## [ STARTUP ]

The installed udev rules call this helper for removal of matching whole `sd*` block devices associated with USB. Partition names are excluded by the kernel-name pattern.

USB association can match through `ID_BUS` or the device path. More than one matching rule can therefore invoke the helper for the same removal.

## [ RUNTIME ]

The helper first attempts to rename `/run/ph4ntxm/usb-nuke-armed` to `usb-nuke-triggered`. Only the invocation that consumes the armed marker proceeds. Without an armed marker, it performs no termination action.

After consumption, it installs interruption handlers that restore the arm marker when possible. It then submits `systemctl --no-block start ph4ntxm-panic.service`.

If submission fails, it restores the armed state and exits with failure. If systemd accepts the job, it removes those handlers and returns without waiting for the emergency sequence to finish.

The triggered marker records consumption of the arm for a submitted action. [Panic](PANIC.md) owns the later sequence and its returned-path restoration behavior.

The rules and helper do not remember a chosen drive serial. Any removal satisfying the installed storage rules can consume the armed state. 

## [ CHECKS ]

Review the udev properties and rule match when diagnosing an event. Inspect both armed and triggered markers and the Panic journal to identify how far the action progressed.

Check marker state and the installed udev match when inspecting the trigger configuration.

## [ SOURCE ]

[ph4ntxm-usb-nuke.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke.sh)  
[99-ph4ntxm-usb-nuke.rules](../../../config/includes.chroot/etc/udev/rules.d/99-ph4ntxm-usb-nuke.rules)
