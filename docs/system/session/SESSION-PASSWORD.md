# [ SESSION PASSWORD ]

## [ OVERVIEW ]

Sets the live user's password before the desktop opens, for screen unlock and administrator actions during this session.

## [ STARTUP ]

Live setup locks the account instead of assigning a public default. LightDM runs password setup after X starts, then checks readiness again before launching XFCE.

The edition-themed screen requires matching password pairs of 6–256 characters and at most 511 UTF-8 bytes. The optional emergency password must differ from the normal password. Input stays hidden unless Show password is selected. Failed updates allow retry. Closing or crashing setup keeps the desktop closed.

GTK runs as unprivileged `lightdm` with a temporary home and no supplementary groups. A root broker validates bounded private-pipe requests and updates only `ph4ntxm` through standard input. Passwords stay out of command arguments and separate files. Temporary X authority is removed on exit. The normal password hash lives in the temporary shadow database and the protected readiness marker contains no password.

## [ RUNTIME ]

XFCE Screensaver uses one unlock field. The normal password unlocks. An exact emergency match immediately requests Panic without confirmation and denies unlock, even if dispatch fails. Wrong passwords do not trigger Panic. Other authentication dialogs do not check the emergency password. If the normal password later equals it, normal authentication wins.

Only a root-readable salted hash is kept under `/run/ph4ntxm-session-auth` for this boot. Disabling the option removes the previous emergency setting. Restarting LightDM preserves completed setup. This trigger uses Panic's existing best-effort termination and scrub sequence. It does not guarantee physical erasure.

General sudo requires the password on each invocation. The [OpSec Process/Radio backends](PH4NTXM-OPSEC-SUITE.md) have a separate parent-process authentication lifetime. No general sudo grace period is enabled.

Lockdown release, USB Nuke disarm and both USB Guard and Net Guard Enable/Allow/Disable use graphical password prompts. Both guards require fresh authentication for every action. Only their bounded snapshots are passwordless.

Panic, Lockdown activation and USB Nuke arming remain passwordless. Wi-Fi setup and enumerated status helpers have narrow exceptions without arbitrary root commands. Cancelled/incorrect authentication leaves protection unchanged. Shutdown Nuke runs independently.

## [ CHECKS ]

Health checks password readiness/account state and rejects unrestricted passwordless sudo. Boot Pilot uses the bounded status helper.

Test incorrect/cancelled prompts, normal screen unlock and protection activation/release in each mode. In a disposable test image with Panic replaced by a harmless recorder, verify exact emergency matching, wrong-input rejection, lock before sleep and separation from initial login and administrator prompts. A new boot requests a new password. Restarting LightDM in the same boot verifies existing readiness and account state instead of resetting them.

## [ SOURCE ]

[ph4ntxm-session-setup](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-setup)\
[ph4ntxm-session-password](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-session-password)\
[ph4ntxm-session-status](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-session-status)\
[ph4ntxm sudo policy](../../../config/includes.chroot/etc/sudoers.d/ph4ntxm)
