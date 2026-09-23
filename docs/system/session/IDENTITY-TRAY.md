# [ IDENTITY TRAY ]

## [ OVERVIEW ]

Provides the Identity indicator in the system tray.

## [ STARTUP ]

The identity tray uses an Ayatana application indicator with the PH4NTXM Identity icon. It creates its menu when the desktop process starts and stays available as a shortcut to the viewer.

The indicator's active state means the tray item is present. It is not the result of a hardware-identity readiness check.

## [ RUNTIME ]

Show Identity starts `/usr/local/bin/ph4ntxm-identity` as a separate process. The viewer then gathers the current hostname, machine ID, mode and interface addresses for its own window.

The tray does not read persona seeds, inspect bind mounts or poll `identity-ready`. It also does not change icon state based on a service failure or a changed MAC. Those checks belong to the generator, [Boot Pilot](BOOT-PILOT.md) and [Health](HEALTH.md).

Each selection can launch another viewer. There is no child-instance lock or duplicate-window guard in this tray, unlike the Panic tray's local child tracking. Already open Identity windows retain their own snapshots.

Launch exceptions are caught without a tray error dialog. If selecting Show Identity appears to do nothing, the absence of a new window is not a useful success/failure status for identity preparation.

Quit ends only this indicator's GTK loop. It does not reset the selected identity, stop system services or close separately launched viewer windows. The viewer remains accessible through its normal application launcher.

## [ CHECKS ]

When the shortcut fails, run the viewer from a terminal to expose its startup error and check the desktop's GTK/indicator environment.

For identity correctness, inspect the viewer's values and the underlying service records. The tray's fixed icon should not be used as a live protection indicator.

## [ SOURCE ]

[ph4ntxm-identity-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-identity-tray)
