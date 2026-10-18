# [ TOR CONNECTION ]

## [ OVERVIEW ]

Selects Direct Tor or obfs4 bridges for the Lone Wolf system Tor instance.

## [ STARTUP ]

Each boot begins without a selection. Tor has no external access until Boot Pilot applies a choice with a fresh session password. Linux and Windows do not use this control.

Configuration and bridge lines stay in protected RAM files under `/run/ph4ntxm-tor-connection`. The Tor preparation unit runs before routing setup and Tor startup. AppArmor stays enabled for Tor and its managed transport.

## [ RUNTIME ]

Open Tor Connection in Boot Pilot. Select Direct Tor, or paste one to eight obfs4 bridge lines with public IPv4 endpoints, valid certificates and `iat-mode`. An optional `Bridge` prefix and relay fingerprint are accepted. Hostnames, IPv6, other transports, duplicate endpoints and arbitrary Tor directives are rejected.

Apply requires the session password every time. Changing or retrying bridges requires pasting their lines again. Cancelling before Apply leaves the current connection unchanged. Applying seals Tor egress, stops its previous instance, verifies configuration and requests startup. Accepted settings do not establish successful bootstrap.

Bridge mode permits only its configured IP and port pairs. Missing, interrupted or failed configuration remains blocked, with no automatic direct fallback. Returning to Direct Tor requires an explicit authenticated choice. The firewall guardian repairs the selected policy, and disabling Lockdown restores that same selection.

Readiness requires matching runtime configuration, effective Tor control settings, bootstrap completion and existing listener checks. Restarting Tor preserves the current session selection. Rebooting discards it.

## [ CHECKS ]

Use Boot Pilot to distinguish an unselected connection, network availability, configuration failure and incomplete bootstrap. A valid bridge line can still point to an unavailable or blocked bridge. Bridges do not guarantee connectivity or conceal Tor use from every observer.

Inspect `ph4ntxm-tor-connection.service`, `tor@default.service` and the Lone Wolf firewall guardian when startup fails. Obtain bridge lines from a trusted source. The interface does not fetch them automatically.

## [ SOURCE ]

[tor_connection.py](../../../config/includes.chroot/usr/lib/ph4ntxm/tor_connection.py)  
[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)
