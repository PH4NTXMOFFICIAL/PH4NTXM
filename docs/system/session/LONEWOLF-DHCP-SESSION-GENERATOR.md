# [ LONEWOLF DHCP SESSION GENERATOR ]

## [ OVERVIEW ]

Creates the minimal Lonewolf DHCP configuration before network setup.

## [ STARTUP ]

Runs before the first Lonewolf lease request.

## [ RUNTIME ]

Preserves the session MAC, disables hostname advertisement and IPv6, and writes the timeout and parameter-request state under `/run/ph4ntxm`.  
Writes NetworkManager defaults and dhclient configuration using a 60-second timeout and the selected request list.  
Publishes `session_dhcp` for the dispatcher and later runtime checks.

## [ SOURCE ]

[ph4ntxm-lonewolf-dhcp-session-generator.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-dhcp-session-generator.sh)
