# [ NET RANDOMIZATION ]

## [ OVERVIEW ]

Applies bounded Linux/Windows kernel TCP/IP values before physical network release.

## [ STARTUP ]

The Linux/Windows service follows system sysctl setup and hardware randomization. It runs before NetworkManager and physical link release. Lone Wolf uses its own script.

Both `persona_seed` and `boot_jitter` must exist and pass format checks. The script also needs `ip` and `sysctl`. It combines those records with runtime entropy, so another invocation can select different values within the same mode's bounds.

## [ RUNTIME ]

Linux starts from TTL/hop limit 64, a lower ephemeral-port range and enabled TCP timestamps. Windows uses 128, ports near the Windows dynamic range and disabled timestamps. Both select cubic congestion control, SACK and window scaling.

The profile also sets SYN retries, FIN timeout, keepalive timing, socket buffer limits, MTU probing, TCP Fast Open, ECN and ICMP rate limiting. Timing and buffer draws stay inside explicit bounds. This is a coordinated profile rather than an unrestricted random sysctl list.

Required writes are read back and compared after whitespace normalization. An unavailable required setting or missing cubic support stops completion. Optional settings such as MPTCP are skipped when absent. If present, their writes still have to pass verification. Earlier successful writes remain when a later check fails.

`/run/ph4ntxm/net/rtt_map` stores locally generated delay metadata with `0600` permissions. The script uses `ip route get 1.1.1.1` to choose a route key. That command does not send a latency probe. The map retains at most 100 entries, and saved values are bounded before reuse.

These records do not apply packet delay. [Network Drift](NET-DRIFT.md) changes qdiscs later, while the [Packet Transformation Engine](PACKET-TRANSFORMATION-ENGINE.md) handles packet-level changes.

## [ CHECKS ]

Check the service result, then read the relevant kernel values with `sysctl`. A seed or RTT map alone does not prove all writes completed.

For a failure, use the journal to find the first rejected setting. Do not interpret generated RTT metadata as measured network latency or assume rerunning restores the previous profile.

## [ SOURCE ]

[ph4ntxm-net-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-randomization.sh)
