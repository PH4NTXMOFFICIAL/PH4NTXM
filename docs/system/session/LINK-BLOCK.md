# [ LINK BLOCK ]

## [ OVERVIEW ]

Brings loopback up, takes physical network interfaces down, and disables swap.

## [ STARTUP ]

This early one-shot follows mode selection and local filesystems. It runs before network preparation and remains active after successful completion, recording that the initial blocking stage finished.

Loopback is brought up first. A udev settle request allows up to ten seconds for device discovery, but its failure is tolerated.

## [ RUNTIME ]

The script reads interface names from `ip -o link`, removing any `@` suffix before checking sysfs. Interfaces with a physical `device` entry are lowered. Virtual interfaces without that entry are not part of this pass.

It attempts every qualifying physical interface and remembers failures instead of stopping after the first adapter. This matters on machines with several network devices: one failed operation does not prevent attempts to block the others.

After the interface pass, it runs `swapoff -a`. An unsuccessful link-down operation or swap disable makes the final result fail. Earlier successful operations remain in effect. There is no rollback that brings links back up.

Blocking is only the first stage of the boot flow. Identity, network policy and termination prerequisites are prepared while physical links are held down. [Link Unblock](LINK-UNBLOCK.md) later verifies the required state and releases prepared devices.

The one-shot is not a background monitor. A newly attached device is handled by the hotplug path, and an active service record does not mean all physical links must remain down for the entire session.

## [ CHECKS ]

During early startup, inspect physical link state and `swapon --show`, then check the service result. After successful release, links being up is expected.

If the stage fails, use the journal to distinguish an adapter error from `swapoff` failure. Do not assume all work was undone or repeatedly raise interfaces manually to bypass the next stages.

## [ SOURCE ]

[ph4ntxm-link-block.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-block.sh)
