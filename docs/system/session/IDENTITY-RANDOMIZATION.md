# [ IDENTITY RANDOMIZATION ]

## [ OVERVIEW ]

Creates the linked Linux/Windows session identity for hostname, hardware selection, and physical-interface MACs.

## [ STARTUP ]

The normal-mode one-shot service follows mode selection, local filesystems, udev and [Link Block](LINK-BLOCK.md). It runs before network preparation and requires mode selection and link blocking to succeed.

The script accepts Linux or Windows, skips Lone Wolf and takes the shared `identity.lock`. If `identity-ready` already contains the current mode, it exits without repeating initialization.

## [ RUNTIME ]

The first pass validates `/etc/machine-id` as a nonzero 32-digit lowercase hexadecimal value and saves `boot_machine_id`. Later setup compares the current machine ID with that saved value. The machine ID is not regenerated from the persona seed.

When `persona_seed` is absent, 32 random bytes and the boot machine ID are hashed into a 64-digit seed. The seed is saved with `0600` permissions and reused within this boot. `persona.py select` uses mode and seed to choose a compatible catalog entry and writes `hardware_profile` through a temporary file.

Hostname templates combine the selected family, SKU, a seeded suffix and an optional name from `/etc/ph4ntxm-namelist`. Missing or empty name lists use `user`. The result is lowercased, sanitized, limited to 32 characters and saved as `boot_hostname`.

`boot_mac` supplies a seeded vendor/family prefix, with a locally administered unicast prefix for the default pool. Each qualifying physical interface receives its own suffix from the seed and interface name. Applying an address lowers the link first, retries up to ten times and reads the address back.

The script updates `/etc/hostname`, the live hostname, the `127.0.1.1` hosts entry and the D-Bus machine-ID link. Any failed physical MAC application prevents completion. After best-effort udev refresh, `identity-ready` is replaced with the active mode. Later adapters use [Net Hotplug](NET-HOTPLUG.md).

## [ CHECKS ]

Compare the hostname and per-interface MACs in [Identity](IDENTITY.md) with the applied system values. The saved `boot_mac` is a prefix source, so its complete address need not equal every adapter's address.

If readiness is missing, inspect the identity service journal for machine-ID, catalog or adapter failures. Existing seed and hostname files can survive an incomplete attempt. They do not by themselves prove completion.

## [ SOURCE ]

[ph4ntxm-identity-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-identity-randomization.sh)  
[ph4ntxm-net-hotplug.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-hotplug.sh)  
[ph4ntxm-identity-randomization.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-identity-randomization.service)  
[persona.py](../../../config/includes.chroot/usr/lib/ph4ntxm/hardware/persona.py)
