# [ ARM CRASHKERNEL ]

## [ OVERVIEW ]

Arms the reserved Nuke runtime before network release.

## [ STARTUP ]

Runs as root with the Nuke kernel and initramfs available under `/boot/nuke`.

## [ RUNTIME ]

Collects System-RAM ranges from procfs or firmware memmap and rejects an empty or oversized command line.  
Loads the crash runtime with `kexec -p`, then locks further kernel loading. Arming failure blocks the startup gate.

## [ SOURCE ]

[ph4ntxm-arm-crashkernel.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-arm-crashkernel.sh)
