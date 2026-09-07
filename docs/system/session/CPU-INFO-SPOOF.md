# [ CPU INFO SPOOF ]

## [ OVERVIEW ]

Installs the Linux/Windows session CPU persona in selected protected reporting views.

## [ STARTUP ]

Reads the generated hardware and `/run/ph4ntxm/cores_env` profile before constructing CPU and topology data.

## [ RUNTIME ]

Generates architecture, vendor, model, family, stepping, flags, and processor relationships. Intel, AMD, and supported Apple personas use matching identity fields.  
Installs read-only generated views over cpuinfo and selected CPU sysfs lists. Logical processor and thread relationships follow the reported core profile.  
Protected `lscpu`, `nproc`, and `free` commands expose the corresponding session information. Unsupported reporting options receive an explicit error.

## [ SOURCE ]

[ph4ntxm-cpu-spoof.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-cpu-spoof.sh)
