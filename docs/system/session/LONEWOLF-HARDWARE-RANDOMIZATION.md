# [ LONE WOLF HARDWARE RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lone Wolf hardware profile from its independent session state.

## [ STARTUP ]

Runs after the independent Lone Wolf identity is available.

## [ RUNTIME ]

Selects one shared catalog entry from the Lone Wolf seed and exports it to `hardware_profile`. UUID and serials remain session-specific; BIOS and board identity come from the same model reports as Linux/Windows.
Writes product, BIOS, board, chassis, and identifier fields under `fake_dmi`, generates matching modalias and uevent text, and installs the supported read-only DMI mounts.

## [ SOURCE ]

[ph4ntxm-lonewolf-hardware-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-hardware-randomization.sh)
