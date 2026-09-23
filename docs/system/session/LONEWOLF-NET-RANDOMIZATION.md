# [ LONE WOLF NET RANDOMIZATION ]

## [ OVERVIEW ]

Applies the Lone Wolf TCP/IP profile using its session seed.

## [ STARTUP ]

This one-shot belongs to the Lone Wolf chain, after identity and system sysctl setup and before NetworkManager or link release. Other modes skip it.

The seed must be a root-owned regular file, not a symlink, containing 64 hexadecimal digits. Named draws use that seed, so the same session reproduces the same choices without normal-mode runtime jitter.

## [ RUNTIME ]

The profile sets IPv4 TTL to 64, disables TCP timestamps, Fast Open and ECN, and enables SACK, window scaling and MTU probing. Congestion control is cubic.

The lower ephemeral-port boundary is selected between 30000 and 42000, with 60999 as the upper boundary. SYN retry values range from four to six, FIN timeout from 20 to 40 seconds and keepalive time from 1800 to 5400 seconds. Keepalive interval and probe count are fixed at 30 seconds and five.

Required sysctl writes are checked by reading the result back. ICMP rate limiting uses a seeded value between 500 and 1500. Its readback must remain numeric and inside that range. Missing or rejected required settings prevent successful completion.

IPv6 is disabled for `all`, `default`, loopback and the interfaces currently exposed under `/proc/sys/net/ipv6/conf`. Each per-interface result is checked. This complements the separate Lone Wolf firewall policy. Setting kernel values does not establish Tor routing.

The script applies settings sequentially and has no rollback transaction. A failure can therefore leave earlier settings applied. It does not maintain the normal-mode RTT map or start a netem drift loop.

## [ CHECKS ]

Inspect the service journal and compare the live IPv4, TCP and IPv6 settings with this profile. Check [Lone Wolf Setup](LONEWOLF-SETUP.md) and its firewall guard separately for routing and filtering.

A successful sysctl stage is one prerequisite for release. It does not mean Tor has bootstrapped or that a browser can already reach a destination.

## [ SOURCE ]

[ph4ntxm-lonewolf-net-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-net-randomization.sh)
