# [ LOCKDOWN TRAY ]

## [ OVERVIEW ]

Provides Lockdown status and actions in the system tray.

## [ STARTUP ]

The desktop indicator polls the Lockdown status JSON every two seconds. It selects an enabled/disabled icon and updates which menu action is available according to that value.

Missing or unreadable state is displayed as Disabled. The indicator does not obtain its state by querying live nftables rules.

## [ RUNTIME ]

Enable and Disable launch the Lockdown command path asynchronously. The privileged firewall helper owns validation, locking, rule changes and packet-engine transitions. The tray does not perform those steps itself.

Menu sensitivity follows the last observed state, so a short delay between selecting an action and seeing an updated icon is expected. The subprocess launch itself is not confirmation that the requested policy was fully applied.

Because the JSON can be updated before all backend steps finish, the indicator may show requested state while a guard is still recovering or a helper has returned failure. It does not validate the readiness timestamp, source digest or active rules hash.

Malformed state is especially important to distinguish: the tray's display fallback is Disabled, while the firewall guards use restrictive handling for invalid protected control data. These behaviors serve different purposes and should not be conflated.

Quit removes the tray process only. The selected policy and system guardians keep their own lifecycle. Quitting does not disable Lockdown or restore connectivity.

## [ CHECKS ]

For a change that does not take effect, inspect [Lockdown](LOCKDOWN.md), the control helper result and guard journal. Repeated clicking is not a substitute for identifying the failed backend stage.

Use the indicator as a convenient control and status view. For actual readiness, check the matching firewall profile and fresh protected record.

## [ SOURCE ]

[ph4ntxm-lockdown-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown-tray)
