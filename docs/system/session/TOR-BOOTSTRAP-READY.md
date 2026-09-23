# [ TOR BOOTSTRAP READY ]

## [ OVERVIEW ]

Checks Tor bootstrap completion through its local control socket.

## [ STARTUP ]

The checker is intended to run as `debian-tor`. A different effective UID fails. It talks to Tor's local Unix control socket and does not send a public connectivity probe.

Before connecting, it checks the cookie and socket with `lstat`. Both must belong to the Tor user and group, neither may be a symlink, and their file types and permission masks must match the expected protected layout.

## [ RUNTIME ]

The authentication cookie must contain exactly 32 bytes. The checker sends its hexadecimal value using Tor control authentication, then requests `GETINFO status/bootstrap-phase`.

The socket timeout is three seconds. Replies are parsed as ASCII with CRLF framing, consistent numeric response codes and bounded line and total reply sizes. Dot-block replies are also bounded. Malformed or oversized protocol data is rejected rather than interpreted as a successful status.

Authentication must end with the expected successful response. The bootstrap reply must have the expected structure and describe `BOOTSTRAP` with both `PROGRESS=100` and `TAG=done`. A merely running Tor process, a percentage below 100 or an unrelated successful control command is insufficient.

After checking, the client sends `QUIT` and returns success. Permission, connection, parsing and incomplete-bootstrap failures return a nonzero result. It does not write the shared Tor readiness record itself.

The [DNS bridge](LONEWOLF-DNS-BRIDGE.md) calls this checker alongside listener checks and owns publication and refresh of `tor-ready`. Separating these roles prevents a one-time control reply from becoming an indefinitely valid session marker.

## [ CHECKS ]

Run diagnostics through the intended service context so the Tor account and control-file permissions are preserved. Inspect the Tor journal when bootstrap remains incomplete.

A successful result establishes the reported bootstrap phase at that moment. The DNS bridge repeats this check alongside listener checks. The firewall guardian verifies the surrounding policy.

## [ SOURCE ]

[ph4ntxm-tor-bootstrap-ready.py](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-tor-bootstrap-ready.py)
