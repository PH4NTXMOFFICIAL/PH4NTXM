# [ NUKE KERNEL ]

## [ OVERVIEW ]

Coordinates session containment and best-effort RAM scrubbing for normal termination and emergency events.

## [ STARTUP ]

Boot prepares and arms the reserved Nuke runtime. Network release requires successful crashkernel arming and loader locking.

## [ RUNTIME ]

The common service loads containment, blocks radios and links, ends the live session, stops memory seeding, disables swap, and runs the allocation scrubber. Cleanup continues across individual failures.  
Normal shutdown reaches the static final hook after service and filesystem cleanup. The armed runtime reconstructs the RAM map and starts the clean kernel with destructive `memtest=17`.  
The inner runtime performs another allocation pass and powers off. Panic and armed USB removal invoke the same common sequence.

## [ SOURCE ]

[ph4ntxm-nuke.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-nuke.sh)  
[ph4ntxm-ram-scrub.c](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-ram-scrub.c)  
[ph4ntxm-arm-crashkernel.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-arm-crashkernel.sh)  
[0091-build-ph4ntxm-nuke.chroot](../../../config/hooks/normal/0091-build-ph4ntxm-nuke.chroot)
