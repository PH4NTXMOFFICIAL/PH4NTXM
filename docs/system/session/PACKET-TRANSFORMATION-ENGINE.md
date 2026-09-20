# [ PACKET TRANSFORMATION ENGINE ]

## [ OVERVIEW ]

Applies the active Linux or Windows network profile to supported IP packets while keeping TCP connections consistent. Uses a Rust core, C NFQUEUE adapter, and physical-output TC/eBPF guard.

## [ STARTUP ]

Verifies inbound queue 1 and outbound queue 2 before readiness. Bypass is disabled; invalid packets and processing failures are dropped.

## [ RUNTIME ]

Outbound headers follow the session profile. Inbound TCP replies are translated back into the sequence and acknowledgement values expected by the local stack.  
Inbound processing precedes connection tracking; outbound processing follows destination NAT. Verdict marks connect worker processing to subsequent enforcement.  
Maintains TCP sequence, acknowledgement, SACK, timestamp, and window mappings and rebuilds lengths and checksums. Unsupported layouts and missing required mappings are dropped.  
TC/eBPF separately validates raw ARP, EAPOL, and DHCP. The guardian repairs invalid interface enforcement with the link down. Worker restart can require TCP reconnection.

## [ SOURCE ]

The build runs Rust unit tests, differential fixtures, parser fuzz-smoke checks, and native self-tests.

[ph4ntxm-packet-transformation-engine](../../../config/includes.chroot/usr/local/src/ph4ntxm-packet-transformation-engine/)
