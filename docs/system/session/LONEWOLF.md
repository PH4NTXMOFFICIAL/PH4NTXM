# [ LONEWOLF ]

## [ OVERVIEW ]

Provides the independent Tor-routed PH4NTXM session mode.

## [ STARTUP ]

Initializes a separate seed and hardware chain, applies the Lonewolf network profile, and prepares its local DNS bridge and system Tor.

## [ RUNTIME ]

Supported application TCP traffic follows Tor routing. The firewall blocks arbitrary application UDP and IPv6 while allowing the required local link setup.  
DNS clients use the local bridge on port 53, forwarding to Tor DNSPort 5353. Transparent TCP uses port 9040 and browser SOCKS uses port 9050.  
Tor Browser starts with its private environment after verification and bootstrap. Failed Tor readiness keeps application traffic contained. Boot Pilot checks protection readiness, and termination follows the common Nuke sequence.

## [ SOURCE ]

[lonewolf](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/)  
[ph4ntxm-lonewolf-dns-bridge.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-lonewolf-dns-bridge.sh)  
[ph4ntxm-tor-bootstrap-ready.py](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-tor-bootstrap-ready.py)
