# [ PANIC BUTTON ]

## [ OVERVIEW ]

Provides the operator's emergency Nuke activation window.

## [ STARTUP ]

Runs when the operator opens the emergency control.

## [ RUNTIME ]

The activation button requests `ph4ntxm-panic.service` through `sudo` and displays a progress window.  
A failed request displays an error and makes the control available again.

## [ SOURCE ]

[ph4ntxm-panic-button](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button)
