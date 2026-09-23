# [ WINDOWS ]

## [ OVERVIEW ]

Provides the Windows-aligned PH4NTXM session mode on the Linux live system.

## [ STARTUP ]

Windows is selected for the boot session before physical network preparation. The mode file and normal-mode marker select the shared normal service chain. The desktop edition is a separate visual choice.

Link Block holds physical adapters down while identity, network policy and emergency termination prerequisites are prepared. The selected profile runs on the shared Debian base.

## [ RUNTIME ]

Identity initialization saves the boot machine ID, creates or reuses `persona_seed`, selects a compatible hardware catalog entry and applies the hostname and per-interface MAC addresses. Hardware, GPU, core, CPU and screen stages derive their related values from that session state.

The kernel network profile uses ordinary TTL/hop limit 128 and the Windows-style upper dynamic-port range. Required sysctl writes are read back. The Packet Transformation Engine adds coordinated packet-level handling, with nftables queues and physical-interface protection enforcing its path.

DNS uses local Unbound and the configured Cloudflare and Google TLS endpoints. Browser policy disables its separate DoH path so the prepared resolver remains relevant. The normal Firefox wrapper validates runtime identity files and builds the selected mode's preferences in a private runtime profile.

After release and connection setup, Network Drift can apply bounded netem timing changes. Ghost Stack supplies optional local virtual topology. Neither replaces the firewall or provides Tor routing.

Lockdown temporarily requests restrictive policy. Disabling it restores this mode's validated normal path. Thermal monitoring, RAM seeding, the OpSec Suite and the armed termination path remain separate session components.

## [ CHECKS ]

Use Boot Pilot for current feature readiness and Health for the underlying checks. Compare a failed component with its generated files and service result instead of assuming the mode marker proves the whole chain completed.

Inspect the packet worker, physical-interface guard and local resolver together when checking the normal network path.

## [ SOURCE ]

[ph4ntxm-net-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-randomization.sh)  
[normal.nft](../../../config/includes.chroot/etc/firewall/normal.nft)  
[ph4ntxm-unbound-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-unbound-randomization.sh)
