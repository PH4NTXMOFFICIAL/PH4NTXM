# [ LOCKDOWN ]

## [ OVERVIEW ]

Provides the graphical Lockdown control.

## [ STARTUP ]

Reads `/run/ph4ntxm-lockdown-status.json` when the control opens.

## [ RUNTIME ]

Shows the enable or disable action according to the current status.  
Sends the request through `sudo` to the firewall helper. The window closes on success; failure displays an error and keeps the control available.

## [ SOURCE ]

[ph4ntxm-lockdown](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown)
