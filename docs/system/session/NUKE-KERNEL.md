# [ NUKE KERNEL ]

## [ OVERVIEW ]

Coordinates session containment and best-effort RAM scrubbing for normal termination and emergency events.

## [ STARTUP ]

The build hook packages two small initramfs stages around the installed kernel. [Arm Crashkernel](ARM-CRASHKERNEL.md) loads the first stage early and locks later loading in the running session.

The common `ph4ntxm-nuke.sh` helper prepares the current system for termination. It requires root and is shared with the emergency flow.

## [ RUNTIME ]

Preparation requests Lockdown with a timeout, then tries the installed Lockdown rules directly if control fails. It blocks radios, lowers non-loopback interfaces and terminates the `ph4ntxm` user, falling back to killing that UID's processes.

It then stops RAM seeding, disables swap, synchronizes, requests cache dropping and runs the allocatable-memory scrub. Most cleanup operations are best effort so one failed step does not prevent later attempts. Returning from this helper does not prove every operation succeeded.

After a crash transition, the first initramfs reconstructs an exact memory map from the ranges passed during arming. It attempts to load the next kernel using the file syscall, then the legacy loading path if necessary.

The second kernel is started with `memtest=17` and the reconstructed map. Its init runs the RAM scrub helper, reports whether the allocatable pass completed and attempts poweroff. Both stages have fallback shutdown/reboot requests if the preferred path returns.

Missing map data or failure to load the second kernel leads to the failure/poweroff branch, not a success report. The stages use the RAM map collected during arming and the following allocatable-memory pass.

## [ CHECKS ]

Before relying on the flow, verify installed artifacts and the loaded/locked crash-kernel state. For build review, check the hook's archive validation and the service wiring alongside the shell helpers.

An accepted Panic request, a loaded crash kernel and a completed scrub are different milestones. Routine documentation checks should not invoke the termination path.

## [ SOURCE ]

[ph4ntxm-nuke.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-nuke.sh)  
[ph4ntxm-ram-scrub.c](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-ram-scrub.c)  
[ph4ntxm-arm-crashkernel.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-arm-crashkernel.sh)  
[0091-build-ph4ntxm-nuke.chroot](../../../config/hooks/normal/0091-build-ph4ntxm-nuke.chroot)
