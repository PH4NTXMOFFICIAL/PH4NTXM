# [ LONE WOLF CORES RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lone Wolf CPU and memory persona from the shared configuration selected by the Lone Wolf seed.

## [ STARTUP ]

The Lone Wolf one-shot service requires and follows its GPU generator. It reads the already-selected `/run/ph4ntxm/hardware_profile` and requires a nonempty `PROFILE_ID`. It does not select another model.

The script measures host capacity through `nproc-real --all` when installed, otherwise `nproc --all`, and reads `MemTotal` from `/proc/meminfo`. These values are passed to the shared `persona.py resources` operation.

## [ RUNTIME ]

The catalog's CPU specification supplies model name, architecture, vendor, family, model number, stepping, feature flags and cache sizes. The shared topology helper derives active resources within host CPU limits while retaining the model's total topology fields.

Memory generation validates the catalog's module layout, slot count, capacity, speeds, ECC widths, form factors and voltage relationships. An inconsistent layout fails instead of producing an unrelated RAM configuration.

Installed RAM is the sum of the selected modules. Usable RAM is the smaller of installed capacity and the greatest power of two not exceeding the host memory total in bytes. A usable result below 128 MiB is rejected. The GiB summary and byte-level usable/installed fields are exported separately, so they should not be treated as interchangeable measurements.

`/run/ph4ntxm/cores_env` also includes memory limits and slots, BIOS attributes, CPU socket/manufacturer information, device class and the profile identifier. Values are emitted as shell-quoted exports for downstream components.

The script writes a temporary file, removes it if resource generation fails, then sets `0644` permissions and renames it into place. CPU reporting and the display chain use this completed environment. Native inventory wrappers use the same fields for their generated views.

## [ CHECKS ]

Compare `PH4_PROFILE_ID` in `cores_env` with `PROFILE_ID` in `hardware_profile`. Check active CPU and usable RAM values against host limits, while comparing installed fields with the catalog configuration.

Use `lscpu`, `free` and [Hardware Views](HARDWARE-VIEWS.md) for consumer checks. If Lone Wolf resource generation fails, inspect the selected profile and catalog validation error before investigating the later CPU or display stages.

## [ SOURCE ]

[ph4ntxm-lonewolf-cores-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-cores-randomization.sh)  
[persona.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/persona.py)  
[cpu_profile.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/cpu_profile.py)
