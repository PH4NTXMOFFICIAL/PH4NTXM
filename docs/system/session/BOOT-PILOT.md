# [ BOOT PILOT ]

## [ OVERVIEW ]

Opens at desktop startup to show protection readiness and provide Wi-Fi controls.

## [ STARTUP ]

The desktop opens after session-password setup. Pilot uses bounded passwordless helpers for protected status and Wi-Fi operations, grouping the selected normal or Lone Wolf chain into Identity, Network and System Protection.

Incomplete checks appear as pending under Verifying Boot for the first 30 seconds. This grace period changes presentation, not readiness requirements.

## [ RUNTIME ]

Protection refreshes every two seconds. Identity checks combine generated state, machine-ID consistency, fonts, clock and browser policy with service results. A completed one-shot must have exited successfully and settled inactive/dead or active/exited; continuous services are assessed by role.

Network checks cover derived MACs, DHCP, resolver and protection state. Normal modes inspect packet-engine/firewall, Drift and Ghost Stack. Lone Wolf checks its guardian, fresh Tor readiness and local listeners. While its protected path remains available, Tor bootstrap stays pending beyond the grace period, showing Waiting for Network or Connecting to Tor according to the IPv4 default route.

System checks cover RAM seeding, disabled swap, thermal guard, ConnWatch and loaded/locked Nuke state. Continue requires all feature checks and closes Pilot. Browser launch additionally requires its launcher gates; Lone Wolf Lockdown can permit Continue while restricting Tor Browser. Both actions recheck before proceeding.

The browser button opens Firefox ESR for Linux/Windows or the Tor Browser wrapper for Lone Wolf. Pilot remains open during asynchronous launch verification and displays failures. Tor wrapper acknowledgement allows up to 15 seconds and establishes launch-gate acceptance, not full browser readiness. Firefox is checked briefly for startup failure; successful forwarding to an existing instance is accepted.

Detailed Report opens GTK Health. Wi-Fi refreshes every five seconds, with background scans and connection requests through [Wi-Fi Control](WIFI-CONTROL.md). Missing wireless hardware does not impose a connection requirement on wired-only systems.

## [ CHECKS ]

Follow a failed group to its service journal and runtime records. Check Again refreshes protection and Wi-Fi without rerunning identity generation.

Boot Ready describes the latest local checks, not external connectivity. Closing Pilot leaves guardians running.

## [ SOURCE ]

[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)
