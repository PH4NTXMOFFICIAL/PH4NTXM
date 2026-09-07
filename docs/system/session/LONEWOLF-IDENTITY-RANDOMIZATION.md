# [ LONEWOLF IDENTITY RANDOMIZATION ]

## [ OVERVIEW ]

Establishes the independent Lonewolf seed, hostname, and physical-interface MACs.

## [ STARTUP ]

Runs under the identity lock during Lonewolf initialization.

## [ RUNTIME ]

Reuses validated boot identity records within the session, applies the hostname and locally administered MACs, and refreshes device state.  
Stores the validated records and writes `identity-ready` after the required setup succeeds.

## [ SOURCE ]

[ph4ntxm-lonewolf-identity-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-identity-randomization.sh)
