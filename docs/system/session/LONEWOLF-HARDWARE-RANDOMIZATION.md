# [ LONE WOLF HARDWARE RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lone Wolf hardware profile from its independent session state.

## [ STARTUP ]

The Lone Wolf one-shot service follows identity randomization and is ordered before network preparation. A missing mode file fails. The other mode chain is skipped.

This stage calls the shared catalog selector with `lonewolf_seed`, then installs `hardware_profile` with `0644` permissions. The seed must be 64 lowercase hexadecimal digits and boot jitter must be 16. New jitter comes from eight random bytes. Malformed saved state stops the script.

## [ RUNTIME ]

The selected catalog entry supplies product, board, BIOS and chassis fields. CPU and graphics choices remain attached to that same entry. The selector matches host architecture and excludes Apple and Google entries from Windows mode. It does not independently draw each field.

UUIDs and serials are derived from the session seed, named inputs and boot jitter. The UUID receives version and variant bits, while product serial formatting follows the selected vendor. The board serial uses its own `brd` draw, prefixed with `MB-`. Product and chassis serials share the session value.

The generated files under `/run/ph4ntxm/fake_dmi` include product name, UUID and SKU. Board identity and serial. BIOS version, date and release. System vendor. And chassis identity. Catalog fields without reported values remain `Not Specified` rather than being invented.

A sanitized modalias combines the same identity fields, and `uevent` contains that modalias. Each output is made `0444`. The script then checks corresponding files under `/sys/class/dmi/id`, skips targets absent on the host and bind-mounts supported targets read-only.

Mount installation is sequential. A mount error attempts to unmount targets already installed by that attempt in reverse order. Generated files remain separate from successful mount exposure, and the cleanup is not a snapshot rollback of an earlier view. Downstream GPU, resource and display generators consume the shared profile.

## [ CHECKS ]

Compare `hardware_profile`, `fake_dmi` and supported `/sys/class/dmi/id` fields together. Then use the native inventory commands described in [Hardware Views](HARDWARE-VIEWS.md) to check the companion reporting layer.

Inspect the service journal for missing inputs or mount failures. A populated `fake_dmi` directory proves generation, not that every supported target was mounted. Session UUIDs and serials should differ from identifiers in the catalog's source reports.

## [ SOURCE ]

[ph4ntxm-lonewolf-hardware-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-hardware-randomization.sh)  
[persona.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/persona.py)
