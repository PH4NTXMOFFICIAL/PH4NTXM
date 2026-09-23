# [ TOR BROWSER ]

## [ OVERVIEW ]

Launches Tor Browser for the Lone Wolf session.

## [ STARTUP ]

The launcher refuses root and requires a private runtime directory owned by the desktop UID. The selected mode must be Lone Wolf.

Mode, browser verification, firewall readiness, Tor readiness and both manifests must be protected root-owned regular files. Missing or unsafe state stops launch rather than falling back to ordinary Firefox.

## [ RUNTIME ]

Browser verification must name Lone Wolf and match the current browser-manifest digest. Its uptime must be valid and not in the future. Firewall and Tor readiness have the additional freshness limit of six seconds.

The firewall record must identify the Lone Wolf profile and expected source digest. Tor must report ready with bootstrap 100. The launcher also checks the browser gate, firewall guardian, Tor and DNS services, plus loopback listeners for TCP/UDP 53, UDP 5353 and TCP 9040/9050.

Only `http://`, `https://` and `file://` launch arguments are accepted. Arbitrary browser switches are rejected. An account-level nonblocking lock prevents concurrent sessions through this launcher.

Each launch creates a temporary session directory and private home under `/run/user/UID`. `env -i` builds a small environment containing desktop access, UTC and the system Tor SOCKS endpoint at `127.0.0.1:9050`. Normal GPU/persona and inherited loader variables are not carried into that environment.

The wrapper waits for the browser child and returns its status. Cleanup attempts to stop a remaining child and removes the owned temporary session directory on normal exit or handled signals. An uncatchable kill cannot run that cleanup.

## [ CHECKS ]

Use the printed failure reason to distinguish stale readiness, inactive services, missing listeners, an integrity mismatch or an existing session lock.

These checks run at launch. The firewall guardian and DNS bridge continue supervising their respective policy, bootstrap and listener state during operation.

## [ SOURCE ]

[ph4ntxm-tor-browser](../../../config/includes.chroot/usr/local/bin/ph4ntxm-tor-browser)
