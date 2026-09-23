# [ LONE WOLF DHCP SESSION GENERATOR ]

## [ OVERVIEW ]

Creates the minimal Lone Wolf DHCP configuration before network setup.

## [ STARTUP ]

The one-shot service follows Lone Wolf identity randomization and runs before `network-pre.target`. The `mode-lonewolf` marker selects it instead of the normal-mode generator.

The script requires a readable `/run/ph4ntxm/mode`. It exits without changes when the recorded value is not `lonewolf`. A missing mode file is an error. The protected adapter addresses are already supplied by the identity chain.

## [ RUNTIME ]

Lone Wolf uses a 60-second timeout and a minimal dhclient request list: subnet mask, routers, DNS servers, domain name and broadcast address. Its dhclient file sends neither a hostname nor a vendor-class identifier.

NetworkManager receives these defaults:

- IPv4 client identification follows the current MAC.
- DHCP hostname advertisement is disabled for IPv4 and IPv6.
- IPv6 is disabled for the connection.
- Wired and wireless cloned-MAC settings preserve the existing address.

The generator writes three outputs. `/run/ph4ntxm/session_dhcp` contains `MODE`, `TIMEOUT`, `PRL` and `TOR`, with `TOR=enabled` identifying the profile for the dispatcher. This flag does not start Tor or prove that it has bootstrapped. The NetworkManager defaults go to `/run/NetworkManager/conf.d/90-ph4ntxm-session.conf`. Dhclient settings go to `/etc/dhcp/dhclient.conf`.

The session record is `0600`. Both configuration files are `0644`. Temporary files are renamed into place one at a time. A failure can stop the sequence after an earlier output has already been replaced.

The shared [dispatcher](DHCP-DISPATCHER.md) later applies the active device's `01:<MAC>` client identifier, clears vendor and hostname values, and enforces the timeout and disabled IPv6 setting. If that NetworkManager update fails, it attempts to disconnect the device and reports failure.

## [ CHECKS ]

Check the generator's completion result and compare all three outputs with the Lone Wolf profile. Verify the current interface MAC separately. This generator preserves an address rather than assigning one.

For failures on connection or lease renewal, inspect the dispatcher and NetworkManager journal. For application connectivity, continue with the firewall and DNS bridge checks: a valid DHCP configuration and lease do not establish Tor readiness.

## [ SOURCE ]

[ph4ntxm-lonewolf-dhcp-session-generator.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-dhcp-session-generator.sh)  
[ph4ntxm-lonewolf-dhcp-session-generator.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-lonewolf-dhcp-session-generator.service)  
[30-ph4ntxm-dhcp](../../../config/includes.chroot/etc/NetworkManager/dispatcher.d/30-ph4ntxm-dhcp)
