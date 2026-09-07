# [ DHCP DISPATCHER ]

## [ OVERVIEW ]

Updates the active NetworkManager device after connection or DHCP changes.

## [ STARTUP ]

NetworkManager calls the dispatcher with an interface and event; it handles `up` and `dhcp4-change`.

## [ RUNTIME ]

Reads the protected session DHCP record and current MAC, then applies the mode's in-memory client settings.  
Validates ownership of `session_dhcp`, builds the MAC-based client identifier, and updates the active device settings.  
A failed Lonewolf update disconnects the device; normal-mode update failures are tolerated.

## [ SOURCE ]

[30-ph4ntxm-dhcp](../../../config/includes.chroot/etc/NetworkManager/dispatcher.d/30-ph4ntxm-dhcp)
