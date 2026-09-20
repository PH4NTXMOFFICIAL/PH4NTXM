# [ HARDWARE VIEWS ]

## [ OVERVIEW ]

Runs native `dmidecode`, `lscpu`, `free`, `nproc`, `lshw`, `hwinfo`, `inxi`, `fastfetch`, `screenfetch`, `getconf`, `vmstat`, `lsmem`, `lstopo` and hwloc inventory tools with session CPU/RAM/DMI values. Neofetch is wrapped when installed at build time. Native fields, formatting, supported options and diagnostics remain in use.

## [ RUNTIME ]

Linux, Windows and Lone Wolf share one hardware catalog. CPU topology, memory layouts, DMI identity and BIOS/UEFI reporting follow the selected persona. Active CPUs and usable RAM are sized for the host; session serials and UUIDs are generated locally.

Each command uses a read-only hardware snapshot in a private mount namespace. A temporary seccomp supervisor supplies session values to direct hardware-query syscalls, including static executables and child processes. Counters refresh during repeated reads; the supervisor and snapshot are removed after the last participating process exits.

Use `ph4ntxm-hardware-run COMMAND [ARGUMENT...]` to launch another application with the same CPU/RAM/DMI view. The selected command keeps its normal output format and exit status; the host boot configuration is unchanged.

## [ SOURCE ]

[Catalog](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/personas.json) · [Implementation](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/) · [Installation](../../../config/hooks/live/9995-native-inventory-wrappers.chroot)

Model facts use pinned reports from [linuxhw/DMI contributors](https://github.com/linuxhw/DMI) ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)); the catalog records sources and model/CPU compatibility.
