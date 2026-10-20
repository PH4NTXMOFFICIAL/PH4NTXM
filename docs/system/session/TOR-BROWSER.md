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

Each launch creates a temporary session directory and private home under `/run/user/UID`. `env -i` builds a small environment containing desktop access, UTC and the system Tor SOCKS endpoint at `127.0.0.1:9050`. Normal GPU/persona and inherited loader variables are not carried into that environment. The installed browser defaults to the Safest security level.

The browser and children run in a separate process group. The wrapper retains the temporary home and lock across browser restarts, waits for parent browser processes to end and returns the initial launcher's status.

Exit or handled signals request group termination, wait up to five seconds, then request forced termination if needed. Cleanup removes the owned directory only after confirming no live browser processes remain. Otherwise it retains the directory and reports an error. An uncatchable kill cannot run cleanup.

For additional file and desktop isolation, launch the optional [Browser Airlock](BROWSER-AIRLOCK.md) application from PH4NTXM Apps. It uses a separate profile and does not replace this launcher.

## [ CHECKS ]

Use the printed failure reason to distinguish stale readiness, inactive services, missing listeners, an integrity mismatch or an existing session lock.

These checks run at launch. The firewall guardian and DNS bridge continue supervising their respective policy, bootstrap and listener state during operation.

## [ SOURCE ]

[ph4ntxm-tor-browser](../../../config/includes.chroot/usr/local/bin/ph4ntxm-tor-browser)
