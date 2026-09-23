# [ PANIC ]

## [ OVERVIEW ]

Starts emergency containment and termination through the Panic service. The confirmation window and tray provide manual access. An armed [USB Nuke](USB-NUKE.md) event reaches the same backend.

## [ STARTUP ]

The tray offers Nuke PH4NTXM and Quit. Selecting Nuke opens the confirmation application without starting the emergency sequence. Cancel or closing that initial window leaves the session running.

While its tracked confirmation window is open, the tray blocks duplicate launches from that instance. Its tooltip becomes Panic Confirmation Open and a 500 ms timer alternates normal and warning icons. The child-exit callback restores the idle state. Other launchers can still open their own windows.

## [ RUNTIME ]

Activate hides the confirmation view and opens a nondeletable progress window. After processing pending GTK events, the application runs `sudo -n systemctl start ph4ntxm-panic.service`. This exact emergency action remains passwordless. There is no cancel control after activation.

If the command returns failure, the application closes the progress view, restores the confirmation window and shows an error. The root-only service owns the sequence independently of the desktop's lifetime.

Panic first blocks radios and lowers every non-loopback interface on a best-effort basis. It then runs common [Nuke preparation](NUKE-KERNEL.md), which requests Lockdown, terminates the live user, stops RAM seeding and attempts swap/cache and memory cleanup.

If `/sys/kernel/kexec_crash_loaded` reports `1`, the script enables SysRq and requests a crash. A successful transition leaves the current kernel. If execution continues, it waits three seconds and proceeds to fallback poweroff.

The fallback submits `systemctl poweroff --no-block`. Acceptance means the shutdown job was queued. Several containment operations tolerate errors to keep the sequence moving, so that result does not verify completion of every cleanup step.

Handled interruption restores a consumed USB arm marker when possible. If execution returns from the poweroff request, Panic also restores `usb-nuke-triggered` to `usb-nuke-armed`, including after an accepted nonblocking request. A rejected poweroff request returns failure.

Quitting the tray removes only its shortcut. It does not disable the service, disarm USB Nuke or cancel a submitted action. The tray's blinking icon reports an open confirmation window, while actual containment belongs to the service.

## [ CHECKS ]

Use [Health](HEALTH.md) to inspect service wiring and the loaded/locked crash-kernel state during routine diagnostics. Starting Panic intentionally terminates the session.

If activation returns unexpectedly, inspect the Panic journal and distinguish cleanup progress, crash-trigger availability and fallback job acceptance. Some containment steps may already have run before an error reached the window.

## [ SOURCE ]

[ph4ntxm-panic.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-panic.sh)

[ph4ntxm-panic-button](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button)

[ph4ntxm-panic-button-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button-tray)
