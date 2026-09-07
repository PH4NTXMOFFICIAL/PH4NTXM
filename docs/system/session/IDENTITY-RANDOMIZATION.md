# [ IDENTITY RANDOMIZATION ]

## [ OVERVIEW ]

Creates the linked Linux/Windows session identity for hostname, hardware selection, and physical-interface MACs.

## [ STARTUP ]

Validates the machine ID established for the boot and combines it with fresh randomness to derive the session seed.

## [ RUNTIME ]

Selects the hardware ecosystem and derives the hostname and MAC layout from the active profile. Generated values remain shared across the session chain.  
Records identity state under `/run/ph4ntxm` and publishes readiness after successful setup. A failed physical MAC change prevents completion.  
New physical adapters use the separate hotplug helper, which derives and verifies their protected session address before release. Lonewolf has its own identity implementation.

## [ SOURCE ]

[ph4ntxm-identity-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-identity-randomization.sh)  
[ph4ntxm-net-hotplug.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-hotplug.sh)
