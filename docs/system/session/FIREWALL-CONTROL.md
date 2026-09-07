# [ FIREWALL CONTROL ]

## [ OVERVIEW ]

Handles privileged Lockdown enable and disable requests.

## [ STARTUP ]

Accepts one privileged `enable` or `disable` action and reads the fixed boot mode.

## [ RUNTIME ]

Uses a shared firewall lock, validates the selected ruleset, and coordinates normal-mode transitions with the packet guard.  
Publishes the Lockdown status.  
Enable loads Lockdown.  
Disable restores the mode's validated profile.  
Normal-mode transitions seal the packet guard before rules change and unseal after restoration.

## [ SOURCE ]

[ph4ntxm-firewall-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-firewall-control)
