# [ MODE ENVIRONMENT ]

## [ OVERVIEW ]

Exports the active mode to login shells as `PH4NTXM_MODE`.

## [ STARTUP ]

Sourced by login-shell profile processing after session state becomes available.

## [ RUNTIME ]

Reads the runtime mode and validates it against Linux, Windows, and Lonewolf.  
Uses Linux when the value is unavailable or invalid.  
Exports the validated mode for commands started from the shell.  
It reads the existing mode and leaves mode selection to the startup helper.

## [ SOURCE ]

[ph4ntxm-mode.sh](../../../config/includes.chroot/etc/profile.d/ph4ntxm-mode.sh)
