# [ PACKET TRANSFORMATION ENGINE GUARD ]

## [ OVERVIEW ]

Manages and verifies the physical-interface packet guard in Linux and Windows.

## [ STARTUP ]

Used during worker startup, adapter protection, ongoing supervision, and Lockdown transitions.

## [ RUNTIME ]

Checks classifier identity and filter layout, coordinates sealed transitions, and repairs detected invalid state with the affected link down.  
Tracks protected interface state and classifier configuration.  
Readiness depends on verified enforcement; repair and transition actions coordinate interface release with the worker's mode and MAC contract.

## [ SOURCE ]

[ph4ntxm-packet-transformation-engine-guard.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh)
