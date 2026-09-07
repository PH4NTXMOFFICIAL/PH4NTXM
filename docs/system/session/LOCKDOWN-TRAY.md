# [ LOCKDOWN TRAY ]

## [ OVERVIEW ]

Provides Lockdown status and actions in the system tray.

## [ STARTUP ]

Runs as a desktop application indicator and reads the Lockdown status record.

## [ RUNTIME ]

Polls the status record every two seconds and updates the enabled/disabled icon and available menu actions.  
Menu actions invoke the privileged firewall helper; Quit ends the tray process.

## [ SOURCE ]

[ph4ntxm-lockdown-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown-tray)
