# [ LONE WOLF FIREWALL GUARD ]

## [ OVERVIEW ]

Supervises the Lone Wolf or Lockdown firewall profile.

## [ STARTUP ]

This Lone Wolf service follows and requires its setup stage. It runs as a notifying, restarting guardian and uses the shared firewall lock to coordinate with control actions.

Policy and manifest must be protected root-owned regular files. Missing Lockdown state selects Lone Wolf. Valid `enabled: true` selects Lockdown, while malformed state also selects Lockdown.

## [ RUNTIME ]

Before applying a profile, the guard compares its source digest with the manifest and checks nftables syntax. It then loads the rules, attempts conntrack cleanup and hashes the live stateless ruleset.

Successful application publishes `/run/ph4ntxm/firewall-ready` atomically. Its fields are `PROFILE`, `SOURCE_SHA256`, `RULESET_SHA256` and `UPTIME_SECONDS`, allowing consumers to compare the source, current profile and recent guardian activity.

Every two seconds, the loop checks requested profile, live rules and the source/manifest relationship. Unexpected changes remove readiness and enter restrictive recovery before another validated profile is applied.

If a trusted Lockdown policy cannot be loaded, an inline emergency ruleset defaults to dropping traffic. That emergency path deliberately leaves readiness absent. Later iterations can recover when a valid source and profile become available.

The process sends systemd its startup notification even if initial enforcement fell back to emergency mode. Therefore, an active guardian process is not the same as a ready Lone Wolf network policy.

Handled exit and interruption remove the readiness record. This guard does not install the normal-mode Packet Transformation Engine. Tor routing and its dedicated ruleset form the Lone Wolf path.

## [ CHECKS ]

Inspect both the service journal and readiness record. A recent record must say `lonewolf` when a consumer expects ordinary Lone Wolf operation. `lockdown` is a different applied state.

For release failures, check source digest, ownership, live rules hash and age. Do not bypass a missing marker simply because systemd reports the guard running.

## [ SOURCE ]

[ph4ntxm-lonewolf-firewall-guard.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-firewall-guard.sh)
