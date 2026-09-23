# [ IDENTITY ]

## [ OVERVIEW ]

Displays the current PH4NTXM session identity.

## [ STARTUP ]

The Identity application gathers its values when the window opens. It reads the selected mode, `/etc/hostname`, `/etc/machine-id` and interface addresses exposed through sysfs.

The window presents a snapshot of the applied session identity.

## [ RUNTIME ]

The graphical view shows the mode, hostname, machine ID, available interface MACs and a clock-profile description. The interface scan excludes loopback and all-zero addresses. Other visible interfaces can appear, including virtual devices.

Unreadable or empty scalar values fall back to `Unknown`, while missing interface information can leave the MAC list empty. The viewer remains useful for inspecting partial startup instead of requiring every identity generator to succeed before opening.

The clock line is descriptive text about the active profile. It is not a measured offset or a live verification of Clock Fuzz. Likewise, displayed identifiers are the values read by the viewer, not a complete audit of seed consistency, bind mounts or service readiness.

`ph4ntxm-identity --print` or `-p` prints the hostname, machine ID, MAC list and clock description to the terminal. The printed form does not include the graphical mode badge.

Detailed Report opens [Health](HEALTH.md) in a separate held terminal. That report performs broader checks. Closing Identity does not stop the report or any randomization service. Reopening Identity gathers a fresh snapshot after runtime changes.

## [ CHECKS ]

Compare reported values with the identity-ready marker and generator journal when checking startup. A visible hostname alone does not establish that every physical MAC was applied.

If a virtual interface appears, compare it with [Ghost Stack](NET-GHOST-STACK.md) before interpreting it as an unexpected physical adapter.

## [ SOURCE ]

[ph4ntxm-identity](../../../config/includes.chroot/usr/local/bin/ph4ntxm-identity)
