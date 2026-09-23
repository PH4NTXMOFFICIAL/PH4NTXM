# [ FIREWALL GUARD ]

## [ OVERVIEW ]

Supervises the normal Linux/Windows firewall and its Lockdown transitions.

## [ STARTUP ]

The normal-mode guard starts with the normal nftables policy and coordinates with the Packet Transformation Engine guard. Its service restarts the process after exit. Lone Wolf has a separate guardian.

It validates the protected mode file and uses the shared firewall lock. Missing Lockdown state selects normal operation. Malformed or unprotected state selects Lockdown.

## [ RUNTIME ]

Normal policy must pass both manifest validation and the pinned source digest. Lockdown uses its own pinned source. The guard hashes `nft -s list ruleset`, which omits changing counters, so traffic alone does not look like a policy modification.

Before changing the normal packet path, it writes a protected transition request containing a profile and unique token. It waits for a protected acknowledgement with matching values and `STATUS=complete`. An unrelated or stale acknowledgement cannot satisfy the request.

Lockdown first asks the engine guard to seal traffic. If sealing fails, physical links are lowered. The guard loads the verified Lockdown policy or an inline default-drop fallback when the source cannot be trusted. Failed sealing prevents readiness publication.

Normal restoration validates and loads the normal rules, clears conntrack on a best-effort basis and requests the matching engine transition. A failed transition lowers physical links rather than publishing normal readiness.

Every two seconds, the loop compares desired profile and live policy. Unexpected changes clear readiness and trigger restrictive recovery before a validated normal profile can be restored.

The atomic `/run/ph4ntxm/firewall-ready` record contains `PROFILE`, `RULESET_SHA256` and `UPTIME_SECONDS`. Cleanup removes it when the guard exits or handles interruption.

## [ CHECKS ]

Check the profile, protected file metadata and freshness together. A leftover marker or an active process alone is insufficient.

For repeated recovery, inspect source verification and engine-transition acknowledgement separately from nftables syntax. The guard coordinates the queue contract through the engine guard. It does not replace the packet worker.

## [ SOURCE ]

[ph4ntxm-firewall-guard.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-firewall-guard.sh)  
[firewall](../../../config/includes.chroot/etc/firewall/)
