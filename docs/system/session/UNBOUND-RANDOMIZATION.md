# [ UNBOUND RANDOMIZATION ]

## [ OVERVIEW ]

Configures and supervises local DNS forwarding for Linux and Windows.

## [ STARTUP ]

Sets `/etc/resolv.conf` to `127.0.0.1` and writes the mode's Unbound configuration. NetworkManager preserves the PH4NTXM resolver choice.

## [ RUNTIME ]

Windows uses Cloudflare and Google DNS-over-TLS upstreams. Linux uses non-blocking Quad9 and Mullvad. Provider authentication names and the system CA bundle validate TLS.  
Configures memory caching, qname minimization, DNSSEC stripping checks, identity hiding, and conservative EDNS sizing. Encrypted forwarding is required and IPv6 upstream DNS is disabled.  
The watchdog checks local resolution every thirty seconds. When a route exists and the listener fails to answer, it requests an Unbound restart.

## [ SOURCE ]

[ph4ntxm-unbound-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-unbound-randomization.sh)
