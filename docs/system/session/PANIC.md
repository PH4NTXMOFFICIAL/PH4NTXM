# [ PANIC ]

## [ OVERVIEW ]

Requests emergency containment and termination through the singleton Panic service. Manual confirmation and armed [USB Nuke](USB-NUKE.md) dispatches reach the same backend.

## [ STARTUP ]

The tray's Nuke PH4NTXM action opens confirmation. Cancel or closing that window leaves the session running. The tray blocks duplicate launches from its own instance and blinks while confirmation is open; child exit or launch failure restores its idle state.

## [ RUNTIME ]

Activate replaces confirmation with a nondeletable progress window and runs `sudo -n systemctl start ph4ntxm-panic.service`. This exact action remains passwordless, with no cancellation after activation. A returned failure restores confirmation and shows an error. The service runs independently of desktop lifetime.

Common [Nuke preparation](NUKE-KERNEL.md) blocks radios/links, requests Lockdown, terminates the live user, stops RAM seeding and attempts swap/cache/memory cleanup. Preparation allows 30 seconds, with forced termination one second later, so stalled cleanup cannot indefinitely delay the crash attempt.

If `/sys/kernel/kexec_crash_loaded` is `1`, Panic enables SysRq and requests a crash transition. If execution continues, it waits three seconds before submitting `systemctl poweroff --no-block`. Acceptance means a shutdown job was queued, not that every best-effort cleanup step completed.

Handled interruption or rejected poweroff returns failure. Panic does not alter USB arm markers; the calling dispatch owns token-matched restoration, including when a nonblocking poweroff request returns. Later Arm/Disarm invalidates older restoration callbacks.

Quitting the tray removes only the shortcut. It neither disables the service, disarms USB Nuke nor cancels submitted actions. Blinking indicates an open confirmation window, not containment progress.

## [ CHECKS ]

Use [Health](HEALTH.md) for routine inspection of wiring and loaded/locked crash-kernel prerequisites. Starting Panic intentionally terminates the session.

If activation returns, inspect its journal and distinguish cleanup, crash availability and fallback acceptance. Some containment may already have occurred before an error reached the window.

## [ SOURCE ]

[ph4ntxm-panic.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-panic.sh)\
[ph4ntxm-panic-button](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button)\
[ph4ntxm-panic-button-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button-tray)
