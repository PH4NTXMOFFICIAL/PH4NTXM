# [ DHCP DISPATCHER ]

## [ OVERVIEW ]

Updates the active NetworkManager device after connection or DHCP changes.

## [ STARTUP ]

NetworkManager supplies the interface name and event. The script requires both arguments and handles only `up` and `dhcp4-change`. Other events exit without changes.

Before touching a device, it validates the interface name and confirms its sysfs entry exists. The saved `/run/ph4ntxm/session_dhcp` must be a readable, regular, root-owned file, not a symlink or writable by group or others.

## [ RUNTIME ]

The dispatcher sources the generated session record, requires `nmcli`, then reads the interface's current address from sysfs. A missing or malformed MAC stops the request. The IPv4 client identifier is constructed as `01:<MAC>`, preserving the link to the address already applied by identity setup.

Linux and Windows receive the saved vendor class, hostname, timeout and IPv6 DUID setting. Hostname advertisement is enabled. The script uses `nmcli device modify` to change the active device configuration. It does not generate a new persistent connection profile or a new identity.

Lone Wolf first requires `TIMEOUT=60` and `TOR=enabled` in the record. Its update clears the vendor-class and DHCP hostname fields, disables hostname advertisement, sets the MAC-based client identifier and disables IPv6.

Failure handling differs at the update step. A failed normal-mode `nmcli` update is tolerated. A failed Lone Wolf update attempts `nmcli device disconnect` and exits with failure. Earlier validation failures exit before that update branch. The explicit disconnect is attached to the failed Lone Wolf modification, not every possible error.

The corresponding generator supplies initial defaults before network setup. This dispatcher applies session values again when NetworkManager reports activation or a DHCP change.

## [ CHECKS ]

Match the NetworkManager event with the affected interface and compare its current MAC with the saved profile. Inspect file ownership and permissions before investigating an apparent missing update.

For Lone Wolf, distinguish a rejected session record from a failed device modification and disconnect attempt. For normal modes, a successful dispatcher exit can include a tolerated modification failure. Inspect NetworkManager's resulting device settings as well.

## [ SOURCE ]

[30-ph4ntxm-dhcp](../../../config/includes.chroot/etc/NetworkManager/dispatcher.d/30-ph4ntxm-dhcp)
