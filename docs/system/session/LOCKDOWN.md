# [ LOCKDOWN ]

## [ OVERVIEW ]

Controls network isolation from the desktop window or system tray. Both use the same privileged firewall helper to enable Lockdown or restore the selected mode's policy.

## [ STARTUP ]

The window reads `/run/ph4ntxm-lockdown-status.json` once when it opens. The tray polls that file every two seconds and updates its icon and available actions. Missing or unreadable state appears as Disabled in these views.

The root helper accepts exactly `enable` or `disable`, validates protected mode/runtime state and serializes changes with the shared firewall lock. Rule sources are checked against their required manifest or pinned digest. Callers cannot supply an arbitrary rules-file path.

## [ RUNTIME ]

Enable works without a password prompt for immediate isolation. Disable requires the session password through a graphical prompt and restores the Linux/Windows or Lone Wolf policy. It does not remove filtering. Cancelling authentication leaves the current policy in place.

To enable Lockdown, the helper cancels an outstanding normal-engine transition, validates the Lockdown source and clears readiness. It writes `enabled: true` to the status file, then seals the normal packet path. If sealing fails, it attempts to lower physical links. It checks and loads the Lockdown rules and attempts conntrack cleanup. A failed seal remains an error even if rule loading succeeds.

To disable Lockdown, the helper selects and validates the current mode's rules, clears readiness and protects the transition before loading them. Success writes `enabled: false`. Normal modes then request the packet path to be unsealed. Conntrack cleanup can interrupt existing connections. A failed transition can leave the system restrictive while a guard recovers.

The window closes after a successful helper result and shows an error on failure. Its command-line form accepts `enable` or `disable` through the same helper path. The tray launches requests asynchronously, so selecting an action is not confirmation that every backend step completed.

The status JSON records requested state and can change before all transition steps finish. Background [normal](FIREWALL-GUARD.md) and [Lone Wolf](LONEWOLF-FIREWALL-GUARD.md) guards independently check protected state, live rules and readiness. Their restrictive handling of invalid state differs from the UI's Disabled fallback.

The window keeps its original snapshot until reopened. The tray follows its polling interval. Closing either interface does not undo the selected policy or stop the guards. Quit removes only the tray process.

## [ CHECKS ]

Check the helper result, guard journal and fresh profile record after a failed action. The icon and JSON alone do not establish that traffic is passing or that the transition completed.

Compare source validation, live rules and packet-engine state to locate the failed stage. Reopen a stale window and allow the tray's next poll to update before interpreting its display.

## [ SOURCE ]

[ph4ntxm-lockdown](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown)

[ph4ntxm-lockdown-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown-tray)

[ph4ntxm-firewall-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-firewall-control)
