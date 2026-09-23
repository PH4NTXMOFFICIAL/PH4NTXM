# [ LOCKDOWN ]

## [ OVERVIEW ]

Provides the graphical Lockdown control.

## [ STARTUP ]

The window reads `/run/ph4ntxm-lockdown-status.json` when it opens and offers Enable or Disable Lockdown according to that snapshot. Missing or unreadable state falls back to Disabled in this UI.

Opening the window and choosing Cancel do not change the firewall. State enforcement belongs to the privileged control helper and background guards.

## [ RUNTIME ]

The action calls `sudo ph4ntxm-firewall-control enable` or `disable`. Enable requests the restrictive Lockdown policy. Disable requests the policy for the current boot mode, not an unfiltered network.

A successful helper result closes the window. A failure shows an error dialog and leaves the original view available. The command-line form accepts `enable` or `disable` and returns success or failure from the same helper path.

The initial state is not continuously refreshed while the window stays open. Another control action can therefore change requested state without updating this existing snapshot.

The JSON is a control/status record, not a live nftables audit. In particular, the helper can write enabled state before later transition steps finish. Background guards separately validate sources, live rules and engine coordination.

The UI's fallback to Disabled on missing or malformed data also differs from the guards' restrictive treatment of invalid protected state. The label should therefore not be used to decide whether traffic is currently passing or whether a ready policy has been published.

## [ CHECKS ]

After an action, inspect the helper result and the relevant firewall guard's fresh profile record. Use [Firewall Control](FIREWALL-CONTROL.md) for transition order and failure behavior.

If the view looks stale, reopen it. Closing the application does not undo a successful Lockdown change or stop the background guard.

## [ SOURCE ]

[ph4ntxm-lockdown](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown)
