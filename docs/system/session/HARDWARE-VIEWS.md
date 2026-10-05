# [ HARDWARE VIEWS ]

## [ OVERVIEW ]

Runs native CPU, RAM and DMI inventory tools with session values. Wrappers cover `dmidecode`, `lscpu`, `free`, `nproc`, `lshw`, `hwinfo`, `inxi`, `fastfetch`, `screenfetch`, `getconf`, `vmstat`, `lsmem`, `lstopo`, hwloc tools and XFCE Task Manager. Neofetch is included when installed.

## [ STARTUP ]

Build hooks divert installed inventory executables to their `-real` paths and place the shared wrapper at the normal command paths. The wrapper preserves direct help/version requests and requires `cores_env` for ordinary inventory execution.

A command-line invocation prepares a temporary hardware snapshot and starts the compiled supervisor. Nested wrapped commands can reuse the existing view's environment instead of creating an unrelated profile.

## [ RUNTIME ]

The shared catalog supplies CPU topology, cache information, memory layouts and DMI/SMBIOS records. Active and total CPU fields report the full model topology. Installed and usable RAM fields report the sum of its modules. These capacities can exceed the host's resources.

`inventory.py` prepares files for a private view, requires the query library and supervisor, and passes the native command and arguments to that supervisor. The native tool still formats its own output. `lscpu` receives the generated sysroot. `lshw` disables its separate CPUID scan. Hwloc tools disable the x86 component so their inputs follow the managed view.

Private mounts supply read-only reporting files. The query library and seccomp supervisor cover supported hardware-query behavior in the launched process and descendants, including static executables through the supervised syscall path. Resource counters can refresh while commands continue reading.

XFCE Task Manager uses the query library without private mounts or the seccomp supervisor. Its CPU and memory totals follow the same persona, and process memory figures are scaled to that capacity. Native process identities and controls remain available. Another application can be launched explicitly:

```bash
ph4ntxm-hardware-run /usr/bin/python3 -c 'import os
print(os.cpu_count())'
```

The supervisor owns the temporary view until participating processes end. Missing profile data, library or supervisor stops setup rather than producing an independent fallback identity.

CPU counters preserve aggregate host activity across the reported logical CPUs. Memory usage is scaled in proportion to host usage.

The supervisor maps reported CPU IDs to allowed host CPUs. On a smaller host, several reported IDs can share one host CPU. Affinity changes must select the complete group; selecting only part returns `EOPNOTSUPP`.

The reporting view does not add physical CPU or RAM capacity. Document Airlock and Media Viewers use actual available RAM for their launch budgets and refuse a managed inventory environment.

## [ CHECKS ]

Compare native inventory output with `hardware_profile` and `cores_env`, then test a direct query through `ph4ntxm-hardware-run`. File-based reports and direct-query handling exercise different parts of the implementation.

Include the exact command, arguments and native diagnostics in a report. Active/total CPU counts and usable/installed RAM capacities should agree with the selected persona. Its capacity and scaled usage figures describe the reporting view, not extra physical resources.

## [ SOURCE ]

[Catalog](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/personas.json) · [Implementation](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/) · [Installation](../../../config/hooks/live/9995-native-inventory-wrappers.chroot)

Model facts use pinned reports from [linuxhw/DMI contributors](https://github.com/linuxhw/DMI) ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)). The catalog records sources and model/CPU compatibility.  
[wrapper](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/wrapper)  
[inventory.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/inventory.py)  
[supervisor.c](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/supervisor.c)
