# [ RAM SCRUB ]

## [ OVERVIEW ]

Provides the native memory scrubber used by the Nuke sequence.

## [ STARTUP ]

Without a shutdown action argument, the compiled helper attempts to overwrite memory it can allocate in the current kernel. It reads `MemAvailable`, falling back to `sysinfo` free RAM when that value is unavailable.

It reserves 128 MiB for the surrounding system. If available memory does not exceed that reserve, the attempt returns failure without claiming a full pass.

## [ RUNTIME ]

The target is allocated in chunks of up to eight MiB. Each private anonymous mapping receives generated data followed by `explicit_bzero`, and is retained until the allocation pass ends. Keeping prior chunks mapped prevents repeatedly reusing only the same small allocation.

The process requests lower scheduling priority, synchronizes before work and marks mappings `MADV_DONTDUMP` on a best-effort basis. Allocation stops when the target is reached or a mapping fails.

Before release, every allocated chunk is explicitly zeroed again and unmapped. The bookkeeping array is also zeroed. The helper returns success only if allocated bytes reached the calculated target. A partial pass returns failure after cleanup.

With `poweroff`, `reboot`, `halt` or `kexec` as its first argument, it first checks for a loaded crash kernel. It enables SysRq and requests the crash transition. If that path cannot be invoked, it attempts the allocatable-memory pass but still returns failure for the shutdown-trigger path.

The userspace pass operates on available allocations above the 128 MiB reserve. [Nuke Kernel](NUKE-KERNEL.md) describes the separate emergency boot stages that use the RAM map collected during arming.

## [ CHECKS ]

Use the call context and return code to distinguish ordinary allocation scrubbing from shutdown-trigger behavior. The emergency init reports whether its allocatable pass completed.

Inspect source and service wiring during routine review. Running the shutdown action is a real termination request, not a harmless self-test.

## [ SOURCE ]

[ph4ntxm-ram-scrub.c](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-ram-scrub.c)
