# [ SESSION PASSWORD ]

## [ OVERVIEW ]

Sets the live user's password before the desktop opens. The same password authorizes administrator actions and unlocks the screen during this session.

## [ STARTUP ]

Live user setup locks the account password instead of assigning a public default. LightDM runs the setup broker as its display-setup script after X starts and before launching the user session. A second session-setup check verifies password readiness immediately before the user session starts.

The graphical setup uses the current Abyss or Ghost background and theme. Enter a password of 6 to 256 characters, then confirm it. Input is hidden unless Show password is selected. Start PH4NTXM stays disabled until both fields agree. A failed password update keeps setup open for another attempt. Closing or crashing setup does not start XFCE.

The GTK screen runs as the unprivileged lightdm user with a temporary home and no supplementary groups. A root broker receives a bounded request through private pipes, validates both password fields and updates only the fixed ph4ntxm account. The password is passed directly to the account update program through standard input. It is not placed in command arguments or written to a separate password file. The temporary X authority is removed when setup ends. The account hash lives in the live system's temporary shadow database. A root-owned readiness marker contains no password.

## [ RUNTIME ]

Full sudo access requires the session password on each invocation. There is no shared authentication grace period. Terminal tools use the terminal prompt. Lockdown release and USB Nuke disarm use a graphical prompt.

Panic, Lockdown activation and USB Nuke arming remain passwordless. Wi-Fi setup and enumerated protection-status reads also have narrow exceptions. Those exceptions accept fixed actions rather than a general shell or arbitrary root command.

A cancelled or incorrect authentication request does not release Lockdown or disarm USB Nuke. The shutdown Nuke service continues to run independently of desktop authentication.

## [ CHECKS ]

Health checks the password setup marker and account state, and rejects unrestricted passwordless sudo. Boot Pilot reads its protected status through the bounded helper.

Verify a fresh boot in each mode, including incorrect and cancelled password prompts, screen lock and unlock, Wi-Fi connection, protection activation and release, and a second boot that requests a new password. Restarting LightDM within the same boot checks the existing protected readiness marker and password state instead of resetting the password.

## [ SOURCE ]

[ph4ntxm-session-setup](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-setup)

[ph4ntxm-session-password](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-session-password)

[ph4ntxm-session-status](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-session-status)

[ph4ntxm sudo policy](../../../config/includes.chroot/etc/sudoers.d/ph4ntxm)
