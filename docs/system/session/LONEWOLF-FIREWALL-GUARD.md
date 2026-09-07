# [ LONEWOLF FIREWALL GUARD ]

## [ OVERVIEW ]

Supervises the Lonewolf or Lockdown firewall profile.

## [ STARTUP ]

Runs continuously while the Lonewolf session is active and observes Lockdown status.

## [ RUNTIME ]

Checks source and active ruleset hashes under the shared firewall lock.  
Publishes fresh firewall readiness after verification. A mismatch removes readiness and activates containment before restoration.

## [ SOURCE ]

[ph4ntxm-lonewolf-firewall-guard.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-firewall-guard.sh)
