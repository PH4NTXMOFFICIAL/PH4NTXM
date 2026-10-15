# [ HARDWARE VIEWS ]

## [ OVERVIEW ]

Runs native CPU, RAM and DMI inventory tools with session values. Wrappers cover `dmidecode`, `lscpu`, `free`, `nproc`, `lshw`, `hwinfo`, `inxi`, `fastfetch`, `screenfetch`, `getconf`, `vmstat`, `lsmem`, `lstopo`, hwloc tools and XFCE Task Manager. Neofetch is included when installed.

## [ STARTUP ]

Build hooks divert installed tools to `-real` paths and install the shared wrapper. Help/version requests pass through. Ordinary inventory requires `cores_env`.

CLI launches prepare a temporary hardware snapshot and compiled supervisor. Nested wrappers can reuse the existing environment instead of creating another view.

## [ RUNTIME ]

The catalog supplies CPU topology/caches, memory layouts and DMI/SMBIOS records. Active/total CPUs report the full model. Installed/usable RAM reports its module sum. These capacities may exceed the host.

`inventory.py` requires the query library and supervisor while native tools retain output formatting. `lscpu` receives a generated sysroot. `lshw` disables separate CPUID scanning and hwloc disables its x86 component.

Read-only private mounts, the query library and seccomp supervisor handle supported queries in the launched process and descendants, including static executables. Resource counters can refresh during execution. Missing profile data or runtime components stops setup. The supervisor owns the view until participating processes end.

XFCE Task Manager uses the query library without private mounts or the supervisor. It retains native process controls while reporting persona totals and proportionally scaled memory. Explicit supervised launches use:

```bash
ph4ntxm-hardware-run /usr/bin/python3 -c 'import os
print(os.cpu_count())'
```

CPU counters preserve aggregate host activity. Memory usage scales proportionally. The supervisor maps reported CPU IDs onto allowed host CPUs. When several reported IDs share a host CPU, affinity changes must select the complete group. Partial selections return `EOPNOTSUPP`.

Reporting adds no physical capacity. Airlocks and Media Viewers budget against actual RAM and reject managed inventory environments.

## [ CHECKS ]

Compare native output with `hardware_profile` and `cores_env`, then exercise direct queries through `ph4ntxm-hardware-run`. Include exact commands, arguments and native diagnostics in reports. Check both file-based and direct-query behavior, keeping reported capacities separate from physical resources.

## [ SOURCE ]

[Catalog](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/personas.json) · [Implementation](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/) · [Installation](../../../config/hooks/live/9995-native-inventory-wrappers.chroot)

Model facts use pinned reports from [linuxhw/DMI contributors](https://github.com/linuxhw/DMI) ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)). The catalog records sources and model/CPU compatibility.  
[wrapper](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/wrapper)  
[inventory.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/inventory.py)  
[supervisor.c](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/supervisor.c)
