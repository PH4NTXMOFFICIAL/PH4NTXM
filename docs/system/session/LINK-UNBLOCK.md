# [ LINK UNBLOCK ]

## [ OVERVIEW ]

Releases physical network interfaces after the required startup checks.

## [ STARTUP ]

Runs after identity, Nuke arming, network configuration, and the mode's required services.

## [ RUNTIME ]

Checks identity, crashkernel state, and the mode's protection services.  
Verifies each adapter's protected MAC before bringing it up.  
Lonewolf additionally requires fresh firewall readiness matching its source manifest.  
Physical adapters pass the hotplug helper, udev settles, and each adapter is checked again before link activation.

## [ SOURCE ]

[ph4ntxm-link-unblock.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-unblock.sh)
