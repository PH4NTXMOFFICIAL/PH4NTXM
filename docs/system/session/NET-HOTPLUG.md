# [ NET HOTPLUG ]

## [ OVERVIEW ]

Applies the active session's protected MAC to a physical adapter.

## [ STARTUP ]

The root helper accepts one validated interface name. It rejects invalid names and skips interfaces without a physical sysfs device entry. A skipped interface does not receive the `protected` response used by Link Unblock.

Before preparing a physical device, it requires the crash kernel to be loaded and further kexec loading to be disabled. Failure handling attempts to leave the interface down.

## [ RUNTIME ]

Normal modes read the saved persona seed and MAC prefix, then derive the device-specific suffix from the seed and interface name. This keeps newly attached adapters in the same session identity scheme as adapters present during boot.

Lone Wolf uses its independent seed and the per-interface files in `boot_mac`. A missing record is generated with an `02:` prefix and saved with `0600` permissions under the protected directory. Existing records are validated and reused.

If the live MAC differs, the helper lowers the link and changes the address. It reads sysfs back and requires an exact match. A successful command alone is insufficient.

For Linux and Windows, it also calls the packet-engine guard to enforce and verify interface protection. Both operations have to complete before the helper declares success. Lone Wolf follows its separate firewall path rather than installing the normal packet-engine contract.

Only after successful preparation does it print `protected`. The helper does not itself bring the interface up. Link Unblock or the surrounding device flow decides when release is appropriate.

An exit or handled signal before successful completion invokes the down-link failure path. As with other shell traps, an uncatchable kill cannot run that cleanup.

## [ CHECKS ]

Compare the actual adapter MAC with its derived session value and inspect the caller's journal. For normal modes, check guard verification as well as address assignment.

Do not treat an empty successful response as protected: it can mean the interface was skipped. The exact response is part of the contract with the release stage.

## [ SOURCE ]

[ph4ntxm-net-hotplug.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-hotplug.sh)
