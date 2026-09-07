# [ WIFI CONTROL ]

## [ OVERVIEW ]

Provides NetworkManager-backed Wi-Fi listing and connection requests for Boot Pilot.

## [ STARTUP ]

Accepts list or connect requests through the system D-Bus connection to NetworkManager.

## [ RUNTIME ]

Validates the selected access point and credentials.  
Creates a volatile connection with the current MAC preserved, IPv6 disabled, and autoconnect disabled.  
Listing can enable Wi-Fi or request a scan.  
Connection validates device, SSID, BSSID, and security mode against the selected access point, then waits for activation and returns a structured result.

## [ SOURCE ]

[ph4ntxm-wifi-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-wifi-control)
