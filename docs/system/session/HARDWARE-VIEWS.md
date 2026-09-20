# [ HARDWARE VIEWS ]

## [ OVERVIEW ]

Runs native `dmidecode`, `lscpu`, `free`, `nproc`, `lshw`, `hwinfo`, `inxi`, `fastfetch`, `screenfetch`, `getconf`, `vmstat`, `lsmem`, `lstopo` and hwloc inventory tools with session CPU/RAM/DMI values. Neofetch is wrapped when installed at build time. Native fields, formatting, supported options and diagnostics remain in use.

## [ STARTUP ]

A wrapped command starts its own temporary supervisor after reading the session profile. The supervisor exits and removes its snapshot after the last participating process ends.

## [ RUNTIME ]

Linux, Windows and Lone Wolf share one hardware catalog. CPU topology, memory layouts, DMI identity and BIOS/UEFI reporting follow the selected persona. Active CPUs and usable RAM are sized for the host; session serials and UUIDs are generated locally.

Private mount namespaces provide read-only hardware views. Seccomp supplies session values to supported direct hardware-query syscalls in launched programs and their child processes, including static executables. Counters refresh during repeated reads.

Use `ph4ntxm-hardware-run` to launch another application with the same view. For example, ask Python for the available CPU count:

```bash
ph4ntxm-hardware-run /usr/bin/python3 -c 'import os; print(os.cpu_count())'
```

The selected command keeps its normal output format and exit status; the host boot configuration is unchanged.

## [ SOURCE ]

[Catalog](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/personas.json) · [Implementation](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/) · [Installation](../../../config/hooks/live/9995-native-inventory-wrappers.chroot)

Model facts use pinned reports from [linuxhw/DMI contributors](https://github.com/linuxhw/DMI) ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)); the catalog records sources and model/CPU compatibility.
