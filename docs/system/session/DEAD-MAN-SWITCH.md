# [ DEAD MAN'S SWITCH ]

## [ OVERVIEW ]

An optional silent countdown requests [Panic](PANIC.md) at expiry. Arm, Renew and Disarm require fresh session-password authentication. It starts disarmed on every boot.

## [ STARTUP ]

The root service starts at boot. Open PH4NTXM Dead Man's Switch from the menu, choose 1–1440 minutes and select Arm. The default interval is 15 minutes. Opening the window changes nothing.

The dedicated icon is used by the launcher and window. There are no notifications, tray indicators or automatically opened windows. Countdown and status appear only in the controls you open.

## [ RUNTIME ]

Renew starts the selected interval from the time authorization completes. Disarm cancels an unexpired countdown. A changed state invalidates pending approvals, and reaching the deadline prevents later renewal or cancellation. Authentication itself does not pause the timer.

The deadline uses `CLOCK_BOOTTIME`, so wall-clock jumps cannot reset it. Clock Fuzzer rate adjustments can slightly affect the measured duration. Suspension counts toward expiry. Panic cannot execute while the machine is suspended, but an expired timer requests it after resume. Screen locking and closing or killing the GTK window do not stop the root service.

State remains under `/run/ph4ntxm-dead-man-switch`, with root-only modification and atomic updates. Service restarts preserve the deadline. A systemd watchdog terminates and restarts a stalled userspace monitor. Ordinary live-user processes cannot signal it. Root access, a frozen kernel or unavailable systemd remain outside this protection.

Expiry is recorded before the fixed Panic request. Failed submission is retried. Missing or invalid initialized state appears degraded instead of disarmed. The window retains a known deadline when status becomes unavailable. Submitted Panic remains a separate best-effort emergency operation.

## [ CHECKS ]

Inspect `systemctl status ph4ntxm-dead-man-switch.service` and its boot journal. The service being active does not mean the timer is armed. The window shows the current state and remaining time.

Use an expendable test session for real expiry checks. Closing the window while armed intentionally leaves the countdown running. Reopen the controls and authenticate to disarm before the deadline. A real expiry requests session termination without confirmation.

## [ SOURCE ]

[ph4ntxm-dead-man-switch](../../../config/includes.chroot/usr/local/bin/ph4ntxm-dead-man-switch)\
[ph4ntxm-dead-man-switch-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-dead-man-switch-control)\
[Timer state and service loop](../../../config/includes.chroot/usr/lib/ph4ntxm/dead_man_switch.py)\
[Dead Man's Switch service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-dead-man-switch.service)\
[Build integration](../../../config/hooks/normal/0034-install-ph4ntxm-dead-man-switch.chroot)
