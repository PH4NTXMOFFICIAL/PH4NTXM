# [ DHCP SESSION GENERATOR ]

## [ OVERVIEW ]

Creates Linux/Windows DHCP settings aligned with the generated hostname and protected interface MAC.

## [ STARTUP ]

Runs before the first network lease request and reads the fixed boot mode and session hostname.

## [ RUNTIME ]

Linux selects the `dhclient` vendor class, a 60-second timeout, and link-layer DUID style. Windows selects `MSFT 5.0`, a 45-second timeout, and a session stable-UUID DUID setting.  
Writes NetworkManager defaults and dhclient configuration through temporary files. Both profiles preserve the existing wired and wireless MAC addresses.  
Records mode, vendor, hostname, timeout, and DUID in `/run/ph4ntxm/session_dhcp`. The separate dispatcher consumes that record for active-device updates.

## [ SOURCE ]

[ph4ntxm-dhcp-session-generator.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-dhcp-session-generator.sh)  
[30-ph4ntxm-dhcp](../../../config/includes.chroot/etc/NetworkManager/dispatcher.d/30-ph4ntxm-dhcp)
