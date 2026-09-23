# [ LONE WOLF DNS BRIDGE ]

## [ OVERVIEW ]

Runs the local dnsmasq bridge for Lone Wolf and supervises Tor DNS readiness.

## [ STARTUP ]

The `ph4ntxm-lonewolf-dns.service` unit follows network-online, Lone Wolf setup and `tor@default`. It requires setup and Tor and runs a notifying, restarting wrapper around dnsmasq.

The wrapper launches dnsmasq in the foreground using the dedicated configuration. dnsmasq binds local port 53, ignores system resolver files and forwards to Tor at `127.0.0.1:5353`. Positive and negative caching are disabled.

## [ RUNTIME ]

Readiness requires TCP and UDP listeners on local port 53, UDP on 5353 and TCP on 9040 and 9050. The wrapper also runs the [Tor bootstrap checker](TOR-BOOTSTRAP-READY.md) as `debian-tor`. Open sockets alone are not enough.

Before the first successful check, it allows up to 180 unsuccessful passes with two-second sleeps. Individual checks also take time, so this is not an exact six-minute wall-clock timeout.

After all checks pass, it atomically publishes `/run/ph4ntxm/tor-ready` with `STATUS=ready`, `BOOTSTRAP=100` and an uptime timestamp. It sends systemd its readiness notification once, then refreshes the record while checks remain successful.

After readiness has been reached, losing a required listener or bootstrap check causes failure rather than returning to an indefinite startup wait. A dead dnsmasq child also ends the wrapper. Cleanup removes the marker, terminates the child and waits for it.

The service restart policy provides another attempt after failure. Consumers still validate marker ownership, contents and freshness. An old file cannot replace a currently healthy bridge.

## [ CHECKS ]

Inspect the wrapper and Tor journals together, then check listener addresses and readiness age. The intended bindings are on loopback, not public interfaces.

A loaded firewall, an active Tor process and a successful bootstrap reply are different checks. This bridge combines them with listener availability, but it does not promise every destination or future circuit will work.

## [ SOURCE ]

[ph4ntxm-lonewolf-dns-bridge.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-lonewolf-dns-bridge.sh)
