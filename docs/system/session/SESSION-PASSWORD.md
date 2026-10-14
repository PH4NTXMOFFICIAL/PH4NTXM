# [ SESSION PASSWORD ]

## [ OVERVIEW ]

Sets the live user's password before the desktop opens, for screen unlock and administrator actions during this session.

## [ STARTUP ]

Live setup locks the account instead of assigning a public default. LightDM runs password setup after X starts, then checks readiness again before launching XFCE.

The edition-themed screen requires matching passwords of 6–256 characters. Input stays hidden unless Show password is selected. Failed updates allow retry; closing or crashing setup keeps the desktop closed.

GTK runs as unprivileged `lightdm` with a temporary home and no supplementary groups. A root broker validates bounded private-pipe requests and updates only `ph4ntxm` through standard input. Passwords stay out of command arguments and separate files. Temporary X authority is removed on exit; the hash lives in the temporary shadow database and the protected readiness marker contains no password.

## [ RUNTIME ]

General sudo requires the password on each invocation. The [OpSec Process/Radio backends](PH4NTXM-OPSEC-SUITE.md) have a separate parent-process authentication lifetime; no general sudo grace period is enabled.

Lockdown release, USB Nuke disarm and USB Guard Enable/Allow/Disable use graphical password prompts. USB Guard requires fresh authentication for every action; only its bounded snapshot is passwordless.

Panic, Lockdown activation and USB Nuke arming remain passwordless. Wi-Fi setup and enumerated status helpers have narrow exceptions without arbitrary root commands. Cancelled/incorrect authentication leaves protection unchanged; shutdown Nuke runs independently.

## [ CHECKS ]

Health checks password readiness/account state and rejects unrestricted passwordless sudo. Boot Pilot uses the bounded status helper.

Test incorrect/cancelled prompts, screen unlock and protection activation/release in each mode. A new boot requests a new password. Restarting LightDM in the same boot verifies existing readiness and account state instead of resetting them.

## [ SOURCE ]

[ph4ntxm-session-setup](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-setup)\
[ph4ntxm-session-password](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-session-password)\
[ph4ntxm-session-status](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-session-status)\
[ph4ntxm sudo policy](../../../config/includes.chroot/etc/sudoers.d/ph4ntxm)
