# [ ARM CRASHKERNEL ]

## [ OVERVIEW ]

Arms the reserved Nuke runtime before network release.

## [ STARTUP ]

The root-only arm stage requires the installed `/boot/nuke/vmlinuz-nuke` and `initrd-nuke.img`. Its early one-shot prepares the emergency kernel before physical networking can be released.

Arming loads an image for a later crash transition. It does not start memory scrubbing or terminate the current session.

## [ RUNTIME ]

The script collects nonzero `System RAM` ranges from `/proc/iomem`. If that produces no usable map, it checks `/sys/firmware/memmap` for equivalent ranges. An empty map fails instead of loading an image with unknown coverage.

Each range is passed as `ph4ntxm.memmap` on the emergency kernel command line. The complete append line is limited to 1800 characters. An oversized map stops the stage.

The image is loaded with `kexec -p`, using the dedicated initramfs. Its command line selects the RAM-root init, disables swap and prepares the restricted emergency boot path, including a single CPU and device reset handling.

After a successful load, the script writes `1` to `kernel.kexec_load_disabled`. This prevents later replacement through the locked loading path in the running kernel. Failure to lock loading is still a stage failure even though the crash image may already be loaded.

The two results remain distinct: a loaded image and a locked loader. [Link Unblock](LINK-UNBLOCK.md) requires both, while [Panic](PANIC.md) later attempts the crash transition when emergency termination is requested.

## [ CHECKS ]

Inspect the arm service journal, `/sys/kernel/kexec_crash_loaded` and `/proc/sys/kernel/kexec_load_disabled`. Both values must be `1` for the release prerequisite.

For failed arming, distinguish missing artifacts, unavailable RAM map, command-line length, kexec loading and loader locking. Checking these files is sufficient for inspection. Triggering a crash is a separate destructive operation.

## [ SOURCE ]

[ph4ntxm-arm-crashkernel.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-arm-crashkernel.sh)
