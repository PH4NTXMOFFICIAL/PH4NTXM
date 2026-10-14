# [ OPSEC SUITE ]

## [ OVERVIEW ]

Provides on-demand network, kernel, process, radio, connection-monitoring and file-handling tools. Each reports its own evidence rather than one universal session score.

## [ STARTUP ]

All six menu entries open shared GTK windows in the selected edition, with the active session mode in the header. Terminal commands remain available: `ph4ntxm-opsec-net`, `ph4ntxm-opsec-kernel`, `ph4ntxm-opsec-proc`, `ph4ntxm-opsec-radio`, `ph4ntxm-opsec-connwatch` and `ph4-shred`.

Inspection runs in the background. Check Again refreshes the snapshot; Copy Report copies it. Missing evidence is shown separately from findings. Available remediation requires explicit selection and confirmation.

Process and Radio run as the desktop user and authenticate their privileged backends once per running app. Refreshes and actions reuse that authorization until exit; reopening requires authentication. Sudo binds this exception to the parent process, so direct backend calls from one terminal shell can also reuse it. General sudo retains its per-invocation password requirement.

ConnWatch reads its independent system monitor continuously. Opening or closing the viewer does not control capture.

## [ RUNTIME ]

Network shows routes, resolver state, active connections, IPv6 and namespace visibility. Searchable connections include endpoint/process details. Lockdown requires confirmation through the existing control path.

Kernel shows loaded modules, sysctls and hardening, including crash-kernel arming and loader locking. It accounts for intentional mode-specific TCP, reverse-path and IPv6 settings and does not modify them.

Process flags visible evidence such as memfd execution, deleted/temporary executables, unexpected paths and visibility mismatches. The searchable list supports Review only filtering; available confirmed actions depend on the selected process and finding.

Radio covers Bluetooth, Wi-Fi, modems, monitor mode, NFC and GPS. Nearby Wi-Fi observations use cached data without active scanning. Reading a report does not disable radios; controls require explicit confirmation.

ConnWatch observes inbound TCP SYN attempts to non-loopback local interfaces, without blocking sources. More than 50 attempts per source in five minutes triggers a notice, limited to one per source per five minutes. Tracking is bounded to 2048 sources and 32 ports per source.

Its terminal viewer refreshes every second and shows the top 15 sources; GTK refreshes every 1.5 seconds and includes all saved sources, history and timestamps. Rows above 50 hits are High. An inactive monitor makes the score Unavailable even if old statistics remain.

Shredder lets you mark/unmark files or folders and select one to seven overwrite passes. Execution requires final confirmation of paths and passes, reports progress/results and prevents window closure during the job. CLI marking/listing stays separate from `ph4-shred s` execution. Overwrite is best effort: copy-on-write, snapshots and flash remapping may retain other copies.

## [ CHECKS ]

Read individual findings and unavailable evidence behind scores. For ConnWatch, compare service state and timestamps: statistics update on qualifying traffic, so quiet periods can leave saved rows visible.

Recheck after remediation. These tools complement Boot Pilot and Health; they neither replace startup gates nor continuously enforce every finding.

## [ SOURCE ]

[ph4ntxm](../../../config/includes.chroot/opt/ph4ntxm/)\
[ph4ntxm-opsec-ui](../../../config/includes.chroot/opt/ph4ntxm/ph4ntxm-opsec-ui/)\
[ph4ntxm-opsec-connwatch-gtk](../../../config/includes.chroot/usr/local/bin/ph4ntxm-opsec-connwatch-gtk)\
[ph4ntxm-opsec-connwatch.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-opsec-connwatch.sh)\
[ph4ntxm-opsec-connwatch](../../../config/includes.chroot/usr/local/bin/ph4ntxm-opsec-connwatch)
