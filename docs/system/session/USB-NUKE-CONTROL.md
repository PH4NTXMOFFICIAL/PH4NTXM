# [ USB NUKE CONTROL ]

## [ OVERVIEW ]

Enables or disables the USB storage removal trigger.

## [ STARTUP ]

Accepts one root-only `enable` or `disable` request.

## [ RUNTIME ]

Enable creates `/run/ph4ntxm/usb-nuke-armed` and clears old trigger state. Disable removes both state markers.  
The armed marker applies to the session's USB storage-removal rule.

## [ SOURCE ]

[ph4ntxm-usb-nuke-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-usb-nuke-control)
