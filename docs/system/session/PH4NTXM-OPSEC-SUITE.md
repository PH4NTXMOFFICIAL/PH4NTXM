# [ OPSEC SUITE ]

## [ OVERVIEW ]

Provides on-demand network, kernel, process, radio, connection-monitoring and file-handling tools.

## [ STARTUP ]

The suite groups terminal inspection tools for network, kernel, processes and radios, together with ConnWatch and the file shredder. Each tool reports its own evidence and findings rather than supplying one universal session score.

Opening an inspection tool collects current state. Remediation menus, where provided, require a selected action and confirmation before applying it.

ConnWatch uses a background system monitor for inbound TCP SYN attempts and a separate terminal viewer for runtime statistics. Opening the viewer does not start packet capture.

## [ RUNTIME ]

Network inspects default routes, resolver/backend state, active connections, IPv6 and namespace visibility. Findings can offer the shared Lockdown control path. Connection findings include the endpoint and process details used for review.

Kernel examines loaded modules, sysctl settings and hardening state, including crash-kernel arming and loader locking. Its interpretation accounts for mode-specific TCP, reverse-path and IPv6 values. Some intentional project settings are informational rather than blindly treated as generic hardening failures.

Process inspection reads visible process metadata and flags evidence such as memfd execution, deleted or temporary executables, unexpected paths and visibility mismatches. Available actions depend on the selected finding and process. The operator selects and confirms the remediation.

Radio covers Bluetooth, Wi-Fi, modem, monitor-mode, NFC and GPS state. Nearby Wi-Fi observations use local cached data. Remediation options are explicit actions, so reading the report is distinct from disabling a radio.

ConnWatch monitors inbound TCP SYN attempts addressed to the machine's non-loopback local interfaces. It does not log every established connection or arbitrary UDP traffic.

The monitor tracks each source in a five-minute counting window. More than 50 matching attempts triggers a volume notice, limited to one per source per five minutes. Tracking is bounded to 2048 sources and 32 target ports per source.

The terminal viewer refreshes once per second and displays the top 15 sources, their five-minute counts and observed target ports. Rows above 50 hits are marked High. If the monitor service is inactive, the viewer reports the score as Unavailable even when an older statistics file still exists.

ConnWatch reports and observes activity only. It does not block displayed sources or change firewall policy. Use the network and firewall tools for investigation or remediation.

Shredder maintains marked paths: marking, unmarking and listing are separate from `ph4-shred s`, which executes overwrite/deletion with configurable passes.

Shredder is best effort at the file level. Storage behavior such as copy-on-write, snapshots or flash remapping can retain copies outside the file blocks it overwrites.

## [ CHECKS ]

Read the evidence and individual failures behind a score. Restricted process/module visibility or a failed command can limit what a report establishes.

For ConnWatch, check the monitor service together with statistics and history timestamps. During quiet traffic, saved rows can remain visible because statistics are written when qualifying packets arrive rather than continuously on a timer.

Recheck the affected state after a confirmed remediation. These tools complement Boot Pilot and Health. They do not replace the startup gates or continuously enforce every displayed finding.

## [ SOURCE ]

[ph4ntxm](../../../config/includes.chroot/opt/ph4ntxm/)
[ph4ntxm-opsec-connwatch.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-opsec-connwatch.sh)
[ph4ntxm-opsec-connwatch](../../../config/includes.chroot/usr/local/bin/ph4ntxm-opsec-connwatch)
