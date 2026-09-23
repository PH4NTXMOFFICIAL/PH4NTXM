# [ NFT RULES ]

## [ OVERVIEW ]

Loads the normal Linux/Windows nftables profile.

## [ STARTUP ]

The normal-mode one-shot follows mode selection and local filesystems and runs before network preparation. Lone Wolf skips it and uses its dedicated setup and guard.

The loader checks the installed normal policy against `rules.sha256`, requires strict checksum validation, and runs `nft -c` before loading with `nft -f`. Successful completion remains recorded by the unit.

## [ RUNTIME ]

The policy replaces the nftables ruleset. Non-loopback IPv4 and IPv6 packets enter NFQUEUE 1 on ingress and NFQUEUE 2 on egress, without queue bypass. The output queue is positioned after destination NAT, so the packet engine sees the translated destination.

Verification chains require the worker's verdict mark, `0x50544531`. The inbound path clears it after verification. The outbound path retains it for the physical-interface guard. A missing worker does not turn the queues into an ordinary pass-through path.

Normal-mode IPv4 DNS on TCP or UDP port 53 is redirected to the local resolver. Filtering rejects external DNS traffic that does not follow the intended path, including the corresponding IPv6 route.

Input defaults to drop, with explicit handling for loopback, established traffic, DHCP and ICMP. Forwarding defaults to drop. Permitted output still passes through the transformation contract. An output allow rule is not a worker bypass.

After loading, conntrack cleanup is attempted but its failure is tolerated. Syntax failure prevents loading. Once a valid policy is loaded, this script does not maintain a rollback copy or continuously audit it. [Firewall Guard](FIREWALL-GUARD.md) handles that ongoing work.

## [ CHECKS ]

Check the loader result, live `nft list ruleset`, packet-engine service and guard readiness together. A successful checksum verifies the source policy, not every later live ruleset state.

When traffic stops, distinguish source validation, queue-worker availability and interface protection before changing the rules. The no-bypass behavior is intentional.

## [ SOURCE ]

[ph4ntxm-nft-rules.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-nft-rules.sh)
