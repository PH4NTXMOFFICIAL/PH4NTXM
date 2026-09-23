# [ PANIC ]

## [ OVERVIEW ]

Runs the privileged emergency termination path.

## [ STARTUP ]

The root-only Panic service is the execution path behind the confirmation window and armed USB-removal trigger. It operates independently of whether either desktop window remains visible.

Handled interruption restores a consumed USB arm marker when possible, so a failed attempt does not silently leave that trigger consumed.

## [ RUNTIME ]

Panic first blocks radios and lowers every non-loopback interface on a best-effort basis. It then runs the common [Nuke preparation](NUKE-KERNEL.md), which requests Lockdown, terminates the live user, stops RAM seeding and attempts swap/cache and memory cleanup.

If `/sys/kernel/kexec_crash_loaded` reports `1`, the script enables SysRq and writes the crash request. A successful transition leaves the current kernel. If execution continues, the script waits three seconds before proceeding to its fallback.

The fallback asks systemd to power off with `--no-block`. This reports whether the shutdown job was accepted, not whether hardware has already powered down or a complete scrub occurred.

If execution returns from the poweroff request, the script restores any `usb-nuke-triggered` marker to `usb-nuke-armed`. It does so even after an accepted nonblocking shutdown request. A rejected poweroff request ends with failure.

Network lowering and several cleanup operations intentionally tolerate errors to keep the sequence moving. That means a zero exit from an accepted fallback must not be read as individual verification of every containment and memory operation.

## [ CHECKS ]

Inspect the service wiring and prearmed crash state without starting Panic during normal diagnostics. Once activated, session loss and shutdown are intended behavior.

If an attempt returns unexpectedly, distinguish common-cleanup results, crash-trigger availability and poweroff acceptance. The Panic journal identifies the backend steps reached after the control action.

## [ SOURCE ]

[ph4ntxm-panic.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-panic.sh)
