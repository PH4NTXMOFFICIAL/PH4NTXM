# [ LONE WOLF ]

## [ OVERVIEW ]

Provides the independent Tor-routed PH4NTXM session mode.

## [ STARTUP ]

Lone Wolf is selected at boot and uses its own identity/network service chain. It is independent of the Abyss or Ghost desktop edition.

Physical adapters remain blocked while the independent seed, per-interface MACs, kernel settings, dedicated firewall and armed termination prerequisites are prepared.

## [ RUNTIME ]

`lonewolf_seed` drives the selected identity and compatible hardware data. The MAC layout uses one saved address file per physical interface, unlike the normal modes' single prefix record. Hardware, CPU/GPU, core and screen stages share this independent session state.

Network setup disables IPv6 and installs the dedicated Tor policy. Ordinary application TCP is redirected through the transparent proxy, while local DNS reaches Tor through dnsmasq. Arbitrary application UDP is blocked, with explicit DHCP handling for connection setup.

The firewall guard publishes current source/profile readiness and falls back to restrictive policy on validation failures. Link Unblock checks the prepared firewall and identity before raising adapters. Tor bootstrap happens after connectivity becomes available. Requiring it before link release would prevent that bootstrap.

The DNS bridge checks loopback listeners and authenticated Tor bootstrap state before refreshing `tor-ready`. Browser mode verifies the Tor Browser bundle and isolates the ordinary Firefox path. The dedicated launcher then requires current firewall/Tor readiness and starts with a temporary home and restricted environment.

Normal-mode packet transformation, Unbound, Network Drift and Ghost Stack are not the Lone Wolf network chain. Lockdown and the common termination controls remain available through their mode-aware paths.

## [ CHECKS ]

For incomplete startup, distinguish physical connection setup, validated firewall readiness, Tor bootstrap, DNS listeners and browser verification. An active Tor process alone is insufficient.

Use Boot Pilot and Health to identify the failed gate, then inspect the corresponding service and readiness record.

## [ SOURCE ]

[lonewolf](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/)  
[ph4ntxm-lonewolf-dns-bridge.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-lonewolf-dns-bridge.sh)  
[ph4ntxm-tor-bootstrap-ready.py](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-tor-bootstrap-ready.py)
