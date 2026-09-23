# [ LONE WOLF IDENTITY RANDOMIZATION ]

## [ OVERVIEW ]

Establishes the independent Lone Wolf seed, hostname, and physical-interface MACs.

## [ STARTUP ]

The Lone Wolf one-shot service follows mode selection, udev, local filesystems and [Link Block](LINK-BLOCK.md). It requires mode selection and blocking and runs before network preparation.

It reads the mode, skips other modes and serializes initialization with `identity.lock`. A matching `identity-ready` record makes another invocation exit without rebuilding the identity.

## [ RUNTIME ]

The script validates and saves the boot machine ID, then checks that `/etc/machine-id` still matches the record. A new `lonewolf_seed` hashes 32 random bytes together with that machine ID. A saved seed is reused and must contain 64 lowercase hexadecimal digits.

Seeded hostname selection uses three groups: a common Linux name for 70 percent of draws, a short prefix plus four hexadecimal characters for the next 20 percent, or eight hexadecimal characters for the remainder. The hostname is sanitized, limited to 16 characters and validated before application.

The script updates `/etc/hostname`, the live hostname, the `127.0.1.1` hosts entry and the D-Bus machine-ID link. Hardware catalog selection happens in the following [hardware stage](LONEWOLF-HARDWARE-RANDOMIZATION.md), using the same independent seed.

Physical interfaces receive locally administered addresses beginning with `02:`. The remaining bytes come from the seed and interface name. Unlike normal modes, `boot_mac` is a `0700` directory containing one `0600` address record per interface. Existing records are validated and reused.

Each address change lowers the interface, retries up to ten times and verifies sysfs readback. Any failed adapter prevents readiness. After best-effort synchronization and udev refresh, the script replaces `identity-ready` with `lonewolf`. The saved seed and per-device files also support later hotplug handling.

## [ CHECKS ]

Inspect the service result and compare [Identity](IDENTITY.md) with the live hostname and interface addresses. A matching ready marker causes initialization to be skipped, so it is distinct from a continuous adapter audit.

For incomplete startup, separate machine-ID or seed validation from a physical MAC failure. The independent Lone Wolf state must not be interpreted using the normal-mode single-file `boot_mac` layout.

## [ SOURCE ]

[ph4ntxm-lonewolf-identity-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-identity-randomization.sh)  
[ph4ntxm-lonewolf-identity-randomization.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-lonewolf-identity-randomization.service)
