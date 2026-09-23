# [ FIREWALL CONTROL ]

## [ OVERVIEW ]

Handles privileged Lockdown enable and disable requests.

## [ STARTUP ]

Enabling Lockdown remains passwordless for immediate isolation. Disabling it requires the session password. The desktop window and tray open a graphical password prompt for that action.

This privileged helper accepts exactly `enable` or `disable`. Here, enable means enabling Lockdown. Disable requests the current mode's normal policy. It validates the protected mode/runtime state and serializes changes with the shared firewall lock.

The normal, Lone Wolf and Lockdown sources are checked against their required manifest or pinned digest before use. Profile selection is never supplied as an arbitrary rules-file path.

## [ RUNTIME ]

Enabling Lockdown cancels an outstanding normal-engine transition, validates the Lockdown source and clears readiness. It writes `enabled: true` to `/run/ph4ntxm-lockdown-status.json`, then seals the normal packet path or lowers physical links if sealing fails.

The helper checks and loads the Lockdown rules and attempts conntrack cleanup. A failed seal remains an error even if rules were loaded. The status file records requested state early, so it cannot by itself prove the final transition completed.

Disabling Lockdown selects the Linux/Windows or Lone Wolf policy. It validates that source, clears readiness and protects the transition before loading the selected rules. On success it writes `enabled: false`. Normal modes then request the packet path to be unsealed.

Rules loading and packet-engine transitions are separate steps. A failure can leave a restrictive intermediate state rather than restore the previous connection. Conntrack cleanup is part of the transition and can interrupt existing connections.

The background firewall guards independently compare requested state, validated sources and live rules. Their fresh readiness records provide information that the UI's simple status JSON does not contain.

## [ CHECKS ]

Use the helper's exit status and journal output when an action fails. Check the relevant guard's profile and readiness freshness before treating a displayed Lockdown state as applied policy.

An unavailable or malformed state file must not be interpreted as evidence that networking is safe to release. The guard and UI have different responsibilities and failure behavior.

## [ SOURCE ]

[ph4ntxm-firewall-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-firewall-control)
