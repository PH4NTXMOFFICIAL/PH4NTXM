# [ LONEWOLF HARDWARE RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lonewolf hardware profile from its independent session state.

## [ STARTUP ]

Runs after the independent Lonewolf identity is available.

## [ RUNTIME ]

Derives the vendor ecosystem, model, UUID, and serials from session state.  
Writes product, BIOS, board, chassis, and identifier fields under `fake_dmi`, generates matching modalias and uevent text, and installs the supported read-only DMI mounts.

## [ SOURCE ]

[ph4ntxm-lonewolf-hardware-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-hardware-randomization.sh)
