# [ NET HOTPLUG ]

## [ OVERVIEW ]

Applies the active session's protected MAC to a physical adapter.

## [ STARTUP ]

Receives one interface name as root and validates the device and armed crashkernel state.

## [ RUNTIME ]

Uses the current mode and saved session state.  
The adapter must satisfy its identity and network protection checks before it is reported as protected.  
Derives the target MAC from the appropriate seed and verifies it after application.  
Normal modes also enforce and verify the packet guard; failed completion leaves the interface down.

## [ SOURCE ]

[ph4ntxm-net-hotplug.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-hotplug.sh)
