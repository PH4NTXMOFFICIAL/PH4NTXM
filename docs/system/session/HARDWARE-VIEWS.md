# [ HARDWARE VIEWS ]

## [ OVERVIEW ]

Runs native CPU, RAM and DMI inventory tools with session values. Wrappers cover `dmidecode`, `lscpu`, `free`, `nproc`, `lshw`, `hwinfo`, `inxi`, `fastfetch`, `screenfetch`, `getconf`, `vmstat`, `lsmem`, `lstopo` and hwloc tools. Neofetch is included when installed.

## [ STARTUP ]

Build hooks divert installed inventory executables to their `-real` paths and place the shared wrapper at the normal command paths. The wrapper preserves direct help/version requests and requires `cores_env` for ordinary inventory execution.

A new invocation prepares a temporary hardware snapshot and starts the compiled supervisor. Nested wrapped commands can reuse the existing view's environment instead of creating an unrelated profile.

## [ RUNTIME ]

The shared catalog and resource fields supply CPU topology, cache information, memory layouts and DMI/SMBIOS records. Installed capacity and active resources remain separate: a selected machine can report its module layout while usable memory and active CPUs respect host limits.

`inventory.py` prepares files for a private view, requires the query library and supervisor, and passes the native command and arguments to that supervisor. The native tool still formats its own output. `lscpu` receives the generated sysroot. `lshw` disables its separate CPUID scan. Hwloc tools disable the x86 component so their inputs follow the managed view.

Private mounts supply read-only reporting files. The query library and seccomp supervisor cover supported hardware-query behavior in the launched process and descendants, including static executables through the supervised syscall path. Resource counters can refresh while commands continue reading.

The wrapped set includes `dmidecode`, `lscpu`, `nproc`, `free`, `lshw`, `hwinfo`, `inxi`, `fastfetch`, `screenfetch`, `getconf`, `vmstat`, `lsmem`, `lstopo` and hwloc tools. Neofetch is wrapped when installed. Another application can be launched explicitly:

```bash
ph4ntxm-hardware-run /usr/bin/python3 -c 'import os
print(os.cpu_count())'
```

The supervisor owns the temporary view until participating processes end. Missing profile data, library or supervisor stops setup rather than producing an independent fallback identity.

## [ CHECKS ]

Compare native inventory output with `hardware_profile` and `cores_env`, then test a direct query through `ph4ntxm-hardware-run`. File-based reports and direct-query handling exercise different parts of the implementation.

Include the exact command, arguments and native diagnostics in a report. Distinguish total/installed resources from active/usable fields before treating different numbers as a mismatch.

## [ SOURCE ]

[Catalog](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/personas.json) · [Implementation](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/) · [Installation](../../../config/hooks/live/9995-native-inventory-wrappers.chroot)

Model facts use pinned reports from [linuxhw/DMI contributors](https://github.com/linuxhw/DMI) ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)). The catalog records sources and model/CPU compatibility.  
[wrapper](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/wrapper)  
[inventory.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/inventory.py)  
[supervisor.c](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/supervisor.c)
