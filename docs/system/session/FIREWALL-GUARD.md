# [ FIREWALL GUARD ]

## [ OVERVIEW ]

Supervises the normal Linux/Windows firewall and its Lockdown transitions.

## [ STARTUP ]

Uses the selected ruleset, integrity manifest, and shared firewall lock. Each profile is validated before application.

## [ RUNTIME ]

Polls the live ruleset every two seconds and compares its SHA256 fingerprint with the expected state. Normal policy requires inbound queue 1, outbound queue 2, and bypass disabled.  
A detected mismatch removes readiness and activates emergency Lockdown before restoration. Profile application also requests connection-tracking cleanup.  
Publishes `/run/ph4ntxm/firewall-ready` after successful verification. Health and Boot Pilot read this state when evaluating firewall readiness.

## [ SOURCE ]

[ph4ntxm-firewall-guard.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-firewall-guard.sh)  
[firewall](../../../config/includes.chroot/etc/firewall/)
