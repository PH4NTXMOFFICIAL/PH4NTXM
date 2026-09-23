# [ LONE WOLF CPU SPOOF ]

## [ OVERVIEW ]

Builds the Lone Wolf CPU reporting view from `cores_env`.

## [ STARTUP ]

The Lone Wolf one-shot service follows and requires its cores generator and runs before the display manager. The script requires readable `cores_env`, a nonempty `lonewolf_seed` and a positive `PH4_REPORTED_CORES` value.

It sources the completed resource profile and asks the shared `inventory.py --cpuinfo` generator to render processor text. The CPU model comes from that profile rather than a separate draw.

## [ RUNTIME ]

Two runtime files supply the mounted view. `/run/ph4ntxm/fake_cpuinfo` contains the generated processor records, including model, features and topology from the shared inventory implementation. `/run/ph4ntxm/fake_online` contains `0` for one reported logical CPU or `0-N` for the full reported range.

Both files receive `0444` permissions. The script uses the CPU text for `/proc/cpuinfo` and the same logical range for `/sys/devices/system/cpu/online`, `present` and `possible`.

For each target, it attempts to unmount an existing overlay, installs the bind mount and remounts it read-only. Targets installed by the current attempt are recorded. On an error, cleanup attempts to unmount those targets in reverse order. This does not restore a previous mount snapshot, and generated files can remain after an unsuccessful installation.

The generated files supply the session CPU reporting view. The companion [Hardware Views](HARDWARE-VIEWS.md) layer supplies native inventory tools, richer topology and supported direct-query behavior. Those consumers and this boot view share `cores_env` so their reported resources can agree.

After success, the service retains its completed state rather than running a polling loop.

## [ CHECKS ]

Compare the processor range in `fake_online` with `PH4_REPORTED_CORES`, then compare the mounted CPU files with their generated sources. Use `findmnt` to distinguish file generation from actual bind mounts.

For a failure, inspect the service journal for missing profile data, inventory generation or mount errors. Native tool output exercises the companion wrapper layer and should be checked separately from reading `/proc/cpuinfo`.

## [ SOURCE ]

[ph4ntxm-lonewolf-cpu-spoof.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-cpu-spoof.sh)  
[inventory.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/inventory.py)
