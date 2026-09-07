# [ LINUX ]

## [ OVERVIEW ]

Provides the Linux-aligned PH4NTXM session mode.

## [ STARTUP ]

Initializes the session seed and linked hardware profile, applies Linux network settings, and prepares Firefox ESR, Unbound, and the Packet Transformation Engine.

## [ RUNTIME ]

IP traffic passes through the Packet Transformation Engine and the normal firewall profile. The physical-output guard verifies processed traffic and validates supported raw control frames.  
DHCP uses Linux-aligned client settings. Unbound forwards DNS through authenticated DNS-over-TLS to the configured Quad9 and Mullvad upstreams.  
Firefox ESR inherits the session persona. Network Drift and Ghost Stack provide their normal-mode behavior. Boot Pilot checks protection readiness, and termination follows the common Nuke sequence.

## [ SOURCE ]

[ph4ntxm-net-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-randomization.sh)  
[normal.nft](../../../config/includes.chroot/etc/firewall/normal.nft)  
[ph4ntxm-unbound-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-unbound-randomization.sh)
