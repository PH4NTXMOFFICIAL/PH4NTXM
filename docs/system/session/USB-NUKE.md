# [ USB NUKE ]

## [ OVERVIEW ]

Provides the graphical USB Removal Nuke arming control.

## [ STARTUP ]

Reads `/run/ph4ntxm/usb-nuke-armed` when its window opens.

## [ RUNTIME ]

Shows ARM or DISARM according to the runtime armed marker.  
The selected action invokes the privileged USB helper. Successful updates close the window; failed requests display an error.

## [ SOURCE ]

[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)
