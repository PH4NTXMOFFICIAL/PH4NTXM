# [ SESSION GUARD ]

## [ OVERVIEW ]

Optional monitoring checks selected session invariants every 10 seconds. A failed check creates an incident on the first observation. Session Guard warns and offers explicit [Lockdown](LOCKDOWN.md). It never enables Lockdown automatically.

## [ STARTUP ]

The root service starts at boot with monitoring disabled. Open PH4NTXM Session Guard from the menu and select Enable Monitoring. Enable and Disable require fresh session-password authentication. Activation requires healthy checks before capturing the baseline.

## [ RUNTIME ]

The private baseline contains hashes of the selected mode, session seed, machine ID and hostname. Checks compare those stable values and inspect identity, clock setup, crash readiness, service outcomes and fresh guardian records. Dynamic Clock Fuzz adjustments, Network Drift values, browser activity and Tor connectivity are not frozen or compared against initial values.

Expected service and firewall transitions appear pending for up to 30 seconds. Failures outside a recognized transition warn immediately. Lone Wolf connection choices and deliberate Lockdown remain valid states.

The window provides adjacent Enable and Disable Lockdown controls according to its current state. Disable requires a fresh session password and verifies restoration. The desktop monitor offers Enable Lockdown, View Details and Dismiss. An unchanged incident is announced once after successful delivery. Recovery marks it resolved, and a later recurrence creates a new incident. Closing the window leaves monitoring running. A stale or unavailable observer is reported when monitoring was known to be enabled.

State remains in RAM under `/run/ph4ntxm-session-guard`. Only root can change the private baseline or control socket. The public snapshot excludes baseline values. Service restarts preserve this boot's state, while a new boot starts disabled.

## [ CHECKS ]

Inspect `systemctl status ph4ntxm-session-guard.service` and its boot journal. The window shows check details and active or resolved incidents. A running service does not mean monitoring is enabled.

This is a sampled observer of selected evidence, not complete host attestation. Existing guardians retain enforcement. Changes between samples and root or kernel compromise can escape detection. Session Guard does not rewrite identity, sysctl, Tor or firewall configuration during checks.

## [ SOURCE ]

[ph4ntxm-session-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-guard)\
[Desktop monitor](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-guard-monitor)\
[Observer and state](../../../config/includes.chroot/usr/lib/ph4ntxm/session_guard.py)\
[Session Guard service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-session-guard.service)\
[Build integration](../../../config/hooks/normal/0036-install-ph4ntxm-session-guard.chroot)
