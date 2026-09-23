# [ PACKET TRANSFORMATION ENGINE GUARD ]

## [ OVERVIEW ]

Manages and verifies the physical-interface packet guard in Linux and Windows.

## [ STARTUP ]

The root guard supports runtime verification, per-interface actions, global sealing/restoration and a background watch mode. It accepts only validated physical interface names in Linux or Windows mode.

Hotplug preparation installs/verifies interface protection before release. The watcher starts after Link Unblock and before NetworkManager, with systemd notification and a ten-second watchdog.

## [ RUNTIME ]

Runtime validation checks root-owned protected binaries, object and manifest. Per-interface verification examines the actual clsact egress layout: the expected direct-action BPF classifier followed by a drop fallback, with no unexpected competing filters.

Identity records bind the loaded program ID/tag to interface index, MAC, mode, hostname and object digest. A familiar interface name alone is not enough when the device or attached classifier has changed.

Seal records which physical links were up, lowers them and applies Lockdown protection. Unseal first prepares all current physical devices, then verifies and raises only the saved eligible links. A restoration failure attempts resealing rather than silently dropping the restrictive state.

Firewall transitions use protected profile/token requests and matching acknowledgements. Completion is published only after the requested transition and interface checks succeed. Cancel removes pending request/acknowledgement state under the global lock.

Every two seconds, the watcher processes requests, checks each physical interface and attempts enforcement when verification fails. Unrecoverable interfaces are held down. Invalid Lockdown state takes the restrictive path.

Healthy passes atomically publish `packet-transformation-engine-guard-ready` with status, profile, interface count and uptime, and notify systemd. Degraded passes clear readiness. Exit cleanup also clears the record and attempts to lower physical links.

## [ CHECKS ]

Check the record's profile and freshness along with classifier identity, not just the presence of a `clsact` qdisc. Guard `stats` provides interface diagnostics. State-changing subcommands are not passive checks.

The guard supervises physical egress protection. It does not replace the native queue worker or the firewall guardian's live-rules audit.

## [ SOURCE ]

[ph4ntxm-packet-transformation-engine-guard.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh)
