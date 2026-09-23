# [ LONE WOLF SETUP ]

## [ OVERVIEW ]

Prepares the Lone Wolf resolver and routing policy.

## [ STARTUP ]

The Lone Wolf setup one-shot follows mode and system sysctl initialization. It runs before Tor and network preparation and remains active after successful completion. Other modes skip it.

It requests that Unbound stop and be runtime-masked, then applies the separate local DNS and Tor-routing configuration.

## [ RUNTIME ]

IPv6 is disabled globally, by default and on current interfaces. Per-interface writes are read back. The dedicated policy and manifest must be regular files rather than symlinks, and the source digest must match its expected SHA-256 value.

The resolver file is replaced through a temporary file with `nameserver 127.0.0.1` and `options edns0`. Rules then pass `nft -c` before being loaded. Conntrack cleanup is best effort. A later nftables error does not roll the resolver file back.

The NAT output path redirects ordinary application DNS to local port 53 and other TCP to Tor's transparent port 9040. Loopback and the Tor account have separate handling to avoid redirecting Tor into itself.

Filtering allows the intended local paths and the Tor account's permitted external TCP traffic, while blocking its access to private/reserved destinations. DHCP has explicit local-network exceptions. IPv6 and arbitrary application UDP are not general Tor transport paths and are blocked by policy.

The DNS bridge forwards local queries toward Tor's DNS listener. Explicit SOCKS clients use port 9050. These roles are related but distinct: installing redirect rules does not establish that any listener is ready or Tor has finished bootstrapping.

[The firewall guard](LONEWOLF-FIREWALL-GUARD.md) audits the applied policy after this one-shot ends.

## [ CHECKS ]

Check setup completion, resolver contents and live nftables rules. Then inspect the firewall guard and DNS bridge for current readiness.

If networking is restricted after a partial setup, identify the failed stage rather than assuming the previous resolver or firewall remains intact. Browser launch requires later Tor readiness checks.

## [ SOURCE ]

[ph4ntxm-lonewolf.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf.sh)
