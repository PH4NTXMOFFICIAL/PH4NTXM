# [ LONE WOLF SETUP ]

## [ OVERVIEW ]

Prepares the Lone Wolf resolver and routing policy.

## [ STARTUP ]

Runs only for Lone Wolf before its network path is released.

## [ RUNTIME ]

Stops and runtime-masks Unbound and points local resolution at the DNS bridge.  
Verifies `lonewolf.nft` against its manifest, checks nftables syntax, and loads the dedicated ruleset before requesting connection-tracking cleanup.

## [ SOURCE ]

[ph4ntxm-lonewolf.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf.sh)
