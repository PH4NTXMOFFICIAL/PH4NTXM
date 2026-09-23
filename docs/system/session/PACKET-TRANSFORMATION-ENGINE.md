# [ PACKET TRANSFORMATION ENGINE ]

## [ OVERVIEW ]

Applies the active Linux or Windows network profile to supported IP packets while keeping TCP connections consistent. Uses a Rust core, C NFQUEUE adapter, and physical-output TC/eBPF guard.

## [ STARTUP ]

The normal-mode worker starts after identity, kernel network settings and the normal nftables loader, before physical link release. Lone Wolf does not use it.

A prestart guard check verifies the installed native executable, loader and eBPF object against their manifest. The notifying service runs a C NFQUEUE adapter around the Rust transformation core.

## [ RUNTIME ]

Queue 1 supplies inbound packets before connection tracking. Queue 2 supplies outbound packets after destination NAT. Neither queue has bypass enabled. Successful worker verdicts carry `0x50544531`, which the surrounding rules verify.

The adapter validates packet metadata, direction, protocol and copied length. Truncated payloads, unexpected GSO packets and unsupported metadata are dropped rather than forwarded unchanged. Queue ownership, copy settings and drop counters are checked during runtime health passes.

The Rust core parses and validates packets before transformation. It tracks flows for coordinated TCP sequence/acknowledgement, option and related translation, plus UDP and ICMP state. Checksums are finalized after changes. Invalid packets or states outside the supported contract return a drop result.

Outbound network fields follow the selected profile: ordinary TTL/hop-limit values differ between Linux and Windows, while protocol-specific IPv6 control traffic keeps its required handling. Flow tables have explicit capacity limits, and maintenance removes stale entries.

The service uses restart and watchdog supervision with a 512 MiB memory limit. Worker interruption can break existing translated flows. A restarted worker creates fresh in-memory flow state.

The separate physical-interface guard verifies the egress classifier and constrained non-IP/DHCP paths. Together with nftables, it prevents missing worker processing from becoming an unrestricted physical output path.

## [ CHECKS ]

Check worker readiness, both queue registrations, live rules and [engine guard](PACKET-TRANSFORMATION-ENGINE-GUARD.md) state together. Process existence alone does not verify the complete path.

Use the supplied build tests for parser and transformation changes. A service restart on a live session is a traffic-affecting operation, not a passive diagnostic.

## [ SOURCE ]

The build runs Rust unit tests, differential fixtures, parser fuzz-smoke checks, and native self-tests.

[ph4ntxm-packet-transformation-engine](../../../config/includes.chroot/usr/local/src/ph4ntxm-packet-transformation-engine/)
