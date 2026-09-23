# [ IDENTITY ]

## [ OVERVIEW ]

Displays the current session identity in a desktop window or terminal report. The system tray provides a shortcut to the same viewer.

## [ STARTUP ]

When the window opens, it reads the selected mode, `/etc/hostname`, `/etc/machine-id` and interface addresses exposed through sysfs. Each window holds its own snapshot of those values.

The desktop tray creates an Ayatana indicator with the PH4NTXM Identity icon and Show Identity and Quit actions. Its active state means the shortcut is present. It does not indicate that identity preparation passed its checks.

## [ RUNTIME ]

The graphical view shows the mode, hostname, machine ID, available interface MACs and a clock-profile description. Interface scanning excludes loopback and all-zero addresses. Other visible interfaces, including virtual devices, can appear.

Unreadable or empty scalar values fall back to Unknown. Missing interface information can leave the MAC list empty, allowing inspection of partial startup. The clock line describes the profile rather than measuring its current offset.

`ph4ntxm-identity --print` or `-p` prints the hostname, machine ID, MAC list and clock description. This terminal form does not include the graphical mode badge.

Detailed Report opens [Health](HEALTH.md) in a separate held terminal for broader checks. Closing Identity does not stop that report or any randomization service. Reopening gathers a new snapshot.

Each Show Identity selection can launch another viewer. The tray has no duplicate-window guard, does not poll `identity-ready` and does not change its icon when a MAC or service state changes. Existing viewer windows keep their earlier snapshots.

Launch exceptions are caught without a tray error dialog. Quit ends only the indicator's GTK loop, leaving separately launched viewers and system services running. The normal application launcher remains available.

## [ CHECKS ]

Compare displayed values with `identity-ready` and the generator journal when checking startup. Use [Boot Pilot](BOOT-PILOT.md) and Health to inspect the wider chain, including physical MAC application and service readiness.

If a virtual interface appears, compare it with [Ghost Stack](NET-GHOST-STACK.md). If the tray shortcut opens no window, run the viewer in a terminal to expose its startup error and check the GTK/indicator environment.

## [ SOURCE ]

[ph4ntxm-identity](../../../config/includes.chroot/usr/local/bin/ph4ntxm-identity)

[ph4ntxm-identity-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-identity-tray)
