# [ USB NUKE TRIGGER ]

## [ OVERVIEW ]

Handles the armed USB-removal event.

## [ STARTUP ]

Invoked by the configured USB storage removal event.

## [ RUNTIME ]

Atomically moves `usb-nuke-armed` to `usb-nuke-triggered` to consume the trigger once, then requests the Panic service asynchronously.  
Restores arming if the service-start request fails or a handled interruption occurs.

## [ SOURCE ]

[ph4ntxm-usb-nuke.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke.sh)
