# [ UNBOUND RANDOMIZATION ]

## [ OVERVIEW ]

Configures and supervises local DNS forwarding for Linux and Windows.

## [ STARTUP ]

The normal-mode service writes the local resolver and mode-specific Unbound configuration before Unbound starts. Lone Wolf skips it and uses its DNS bridge instead.

`/etc/resolv.conf` is replaced through a temporary file with `127.0.0.1` as the resolver. The generated Unbound fragment is also installed through rename with `0644` permissions.

## [ RUNTIME ]

Linux uses the configured Quad9 and Mullvad endpoints. Windows uses Cloudflare and Google endpoints. Every upstream is specified on port 853 with its TLS authentication name. The provider list is selected by mode, not periodically rotated by the monitor.

Unbound listens on loopback, uses IPv4 upstream transport and the system CA bundle, and forwards the root zone over TLS. `forward-first: no` prevents fallback to ordinary recursive resolution when forwarding fails.

The profile hides resolver identity/version, enables QNAME minimization, DNSSEC-stripping and glue hardening, and sets an EDNS buffer of 1232 bytes. It uses two threads, 64 MiB message cache and 128 MiB RRset cache, with configured cache TTL bounds of 600–14400 seconds and prefetching.

After installing the configuration, the process sends systemd its readiness notification. That notification means configuration publication completed. It is not a successful upstream TLS or external DNS test.

The remaining loop sleeps 30 seconds, queries `localhost` through the local resolver and requests an Unbound restart if the query fails while a default route exists. Restart failure is tolerated, followed by another ten-second wait. Without a default route it avoids that restart attempt.

## [ CHECKS ]

Inspect the generated configuration, resolver file and Unbound journal separately from the profile service's status. A local `localhost` response is a liveness check, not proof that an external name resolved over TLS.

If startup fails after resolver replacement, remember that the two files are installed sequentially and there is no shared rollback.

## [ SOURCE ]

[ph4ntxm-unbound-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-unbound-randomization.sh)
