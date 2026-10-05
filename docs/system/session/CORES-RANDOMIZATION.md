# [ CORES RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Linux/Windows processor and memory capability profile used by protected reporting and downstream components.

## [ STARTUP ]

The Linux/Windows one-shot service requires and follows its GPU generator. It reads the already-selected `/run/ph4ntxm/hardware_profile` and requires a nonempty `PROFILE_ID`. It does not select another model.

The script passes the selected `PROFILE_ID` to the shared `persona.py resources` operation. CPU and RAM values come from that catalog entry rather than host capacity measurements.

## [ RUNTIME ]

The catalog's CPU specification supplies model name, architecture, vendor, family, model number, stepping, feature flags and cache sizes. The shared topology helper reports the full model topology: active and total core counts match, as do active and total thread counts.

Memory generation validates the catalog's module layout, slot count, capacity, speeds, ECC widths, form factors and voltage relationships. An inconsistent layout fails instead of producing an unrelated RAM configuration.

Installed RAM is the sum of the selected modules. The reported usable RAM has the same capacity, even when it exceeds host RAM. `PH4_REPORTED_RAM` expresses this capacity in GiB; `PH4_USABLE_RAM_BYTES` and `PH4_INSTALLED_RAM_BYTES` express it in bytes. These are persona reporting values, not physical allocation limits.

`/run/ph4ntxm/cores_env` also includes memory limits and slots, BIOS attributes, CPU socket/manufacturer information, device class and the profile identifier. Values are emitted as shell-quoted exports for downstream components.

The script writes a temporary file, removes it if resource generation fails, then sets `0644` permissions and renames it into place. CPU reporting and the display chain use this completed environment. Native inventory wrappers use the same fields for their generated views.

## [ CHECKS ]

Compare `PH4_PROFILE_ID` in `cores_env` with `PROFILE_ID` in `hardware_profile`. Check active and total CPU counts against the full catalog topology, and both RAM capacity fields against the sum of its modules.

Use `lscpu`, `free` and [Hardware Views](HARDWARE-VIEWS.md) for consumer checks. If Linux/Windows resource generation fails, inspect the selected profile and catalog validation error before investigating the later CPU or display stages.

## [ SOURCE ]

[ph4ntxm-cores-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-cores-randomization.sh)  
[persona.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/persona.py)  
[cpu_profile.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/cpu_profile.py)
