# [ NET GHOST STACK ]

## [ OVERVIEW ]

Creates bounded local network topology artifacts for Linux and Windows sessions.

## [ STARTUP ]

The normal-mode service follows identity setup and `network.target`. It needs the saved persona seed, boot jitter and MAC data. Lone Wolf skips this stage.

The script creates a fresh `/run/ph4ntxm/ghost_stack` record with `0600` permissions. A seeded Linux decision can skip device creation entirely. An empty record is valid in that case.

## [ RUNTIME ]

The selected draw requests one to three dummy or bridge devices. Linux naming uses the surrounding interface style and seeded alternatives. Windows uses internal names such as `win-0` and `vSwitch-1`, with separate display labels resembling Ethernet or a virtual switch. A label in the record is not necessarily the kernel interface name.

Created interfaces receive derived MAC addresses. Some also receive `/32` addresses from documentation ranges such as `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24`, using `noprefixroute`. Those addresses are local decoration and do not supply an external route.

The script requests loose reverse-path filtering and disables IPv4 forwarding on a best-effort basis. Device creation, address assignment and link activation also tolerate individual failures. A device is recorded if it exists. That does not verify every requested property was applied.

Names already present are skipped. Another run truncates the record but does not first remove previously created devices, so the new file is not a complete inventory of all virtual interfaces left in the system.

This stage changes visible local topology. It does not replace physical MAC preparation, the firewall, packet transformation or the release checks.

## [ CHECKS ]

Compare the record with `ip link` and `ip address`, using the actual device name after any label separator. Inspect address and link state independently when a partial creation is suspected.

For Linux, distinguish the intentional skip from missing inputs or a service failure. Avoid treating a successful one-shot result as proof that every optional dummy or bridge operation succeeded.

## [ SOURCE ]

[ph4ntxm-net-ghost-stack.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-ghost-stack.sh)
