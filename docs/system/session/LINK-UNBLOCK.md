# [ LINK UNBLOCK ]

## [ OVERVIEW ]

Releases physical network interfaces after the required startup checks.

## [ STARTUP ]

This is the final physical-link release stage before NetworkManager. Its service dependencies cover mode selection, identity and network preparation, crash-kernel arming, DHCP and the selected firewall path.

The script requires `identity-ready` to match the current mode, a loaded crash kernel and `kexec_load_disabled=1`. It does not release an adapter merely because a mode file exists.

## [ RUNTIME ]

Linux and Windows require the normal nftables loader and Packet Transformation Engine services to be active. Lone Wolf instead checks its firewall guard and protected readiness record against the source manifest.

For Lone Wolf, the readiness profile must be `lonewolf`, its source digest must match the manifest, and its uptime must be no more than six seconds old and not in the future. A malformed, stale or unprotected file fails the release check.

The script enumerates physical interfaces and calls [Net Hotplug](NET-HOTPLUG.md) for each. It requires the helper's exact `protected` response. Merely returning successfully without that response is insufficient, which excludes devices that the helper did not actually prepare.

It then triggers and settles udev, repeats protection for the selected interfaces and raises them one by one. The second pass covers changes introduced by the device refresh. Failure stops completion, but interfaces already raised earlier in that sequence are not collectively rolled back.

Tor bootstrap is deliberately not a prerequisite for raising the Lone Wolf link: Tor needs networking to bootstrap. Tor readiness is checked later by the DNS bridge and browser launch path.

## [ CHECKS ]

Inspect the unit journal for the specific missing prerequisite or interface failure. Check protected file ownership, freshness and profile together rather than relying on marker presence.

If a partial release occurred, inspect every physical adapter. Bypassing the helper with a manual link-up omits the checks that this stage is intended to enforce.

## [ SOURCE ]

[ph4ntxm-link-unblock.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-unblock.sh)
