# [ SESSION GUARD ]

## [ OVERVIEW ]

Optional monitoring checks selected session invariants every 10 seconds. A failed check creates an incident on the first observation. Session Guard warns and offers explicit [Lockdown](LOCKDOWN.md). It never enables Lockdown automatically.

## [ STARTUP ]

The root service starts after the identity mount generators at boot, with monitoring disabled. Open PH4NTXM Session Guard from the menu and select Enable Monitoring. Enable and Disable require fresh session-password authentication. Activation requires healthy checks before capturing the baseline.

## [ RUNTIME ]

The private baseline pins the mode, seed, machine ID, hostname and generated profiles through hashes and protected mount evidence. Checks cover local hostname/D-Bus bindings, catalog/persona consistency, CPU/RAM profiles and exposed CPU views, generated and supported mounted DMI fields, GPU/display profiles, DHCP identity and network settings. Initial validation checks agreement with the generators. Mount checks use the system mount inventory rather than the observer's private mount namespace. Later observations detect changes against the activation baseline.

Physical adapter MAC changes warn even when made manually. Newly observed or recreated adapters have a separate finding. Removal alone does not indicate MAC drift. Stable generated sysctl values remain pinned, while the changing Clock Fuzz tick is validated within mode bounds. Its initial offset and tick remain pinned. Browser sessions, physical resource capacity and Network Drift timing are outside this comparison.

Expected service and firewall transitions appear pending for up to 30 seconds. Failures outside a recognized transition warn immediately. Lone Wolf connection choices and deliberate Lockdown remain valid states.

The window provides adjacent Enable and Disable Lockdown controls according to its current state. Disable requires a fresh session password and verifies restoration. The desktop monitor offers Enable Lockdown, View Details and Dismiss. An unchanged incident is announced once after successful delivery. Active incident descriptions update as failures change. Recovery marks it resolved, and a later recurrence creates a new incident. Closing the window leaves monitoring running. A stale or unavailable observer is reported when monitoring was known to be enabled.

State remains in RAM under `/run/ph4ntxm-session-guard`. Only root can change the private baseline or control socket. The public snapshot excludes baseline values. Service restarts preserve this boot's state, while a new boot starts disabled. An older enabled baseline without the extended identity evidence warns until authenticated Disable and Enable capture a complete baseline.

## [ CHECKS ]

Inspect `systemctl status ph4ntxm-session-guard.service` and its boot journal. The window shows check details and active or resolved incidents. A running service does not mean monitoring is enabled.

This is a sampled observer of selected evidence, not complete host attestation. Existing guardians retain enforcement. Changes between samples and root or kernel compromise can escape detection. Session Guard does not rewrite identity, sysctl, Tor or firewall configuration during checks.

## [ SOURCE ]

[ph4ntxm-session-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-guard)\
[Desktop monitor](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-guard-monitor)\
[Observer and state](../../../config/includes.chroot/usr/lib/ph4ntxm/session_guard.py)\
[Hardware identity checks](../../../config/includes.chroot/usr/lib/ph4ntxm/session_guard_persona.py)\
[Network identity checks](../../../config/includes.chroot/usr/lib/ph4ntxm/session_guard_network.py)\
[Session Guard service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-session-guard.service)\
[Build integration](../../../config/hooks/normal/0036-install-ph4ntxm-session-guard.chroot)
