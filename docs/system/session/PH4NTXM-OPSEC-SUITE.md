# [ OPSEC SUITE ]

## [ OVERVIEW ]

Provides on-demand network, kernel, process, radio, connection-monitoring and file-handling tools.

## [ STARTUP ]

The suite groups inspection tools for network, kernel, processes and radios, together with ConnWatch and the file shredder. Each tool reports its own evidence and findings rather than supplying one universal session score.

All six menu launchers open GTK windows using the shared PH4NTXM interface and the selected Abyss or Ghost edition. Every window header displays the active session mode from `/run/ph4ntxm/mode`; report access and monitoring state appear in the report evidence. The terminal commands remain available: `ph4ntxm-opsec-net`, `ph4ntxm-opsec-kernel`, `ph4ntxm-opsec-proc`, `ph4ntxm-opsec-radio`, `ph4ntxm-opsec-connwatch` and `ph4-shred`.

Opening an inspection tool collects current state. Check Again collects a new report; Copy Report copies the displayed snapshot. Collection runs in the background while the window stays responsive. Reports retain the existing checks and scores, and show unavailable evidence separately from findings. Remediation controls, where provided, require a selected action and confirmation before applying it.

Process and Radio windows run as the regular desktop user. Each running app requests the administrator password once through its privileged backend, then reuses that authentication for report refreshes and selected remediation until the app exits. Reopening an app requires authentication again. Sudo caches authentication only for these two backends and binds it to the calling process identity; direct backend invocations from the same terminal shell can also reuse authentication while that shell runs. Ordinary sudo commands continue to require a password on every use, and the existing bounded passwordless helpers remain unchanged.

ConnWatch uses a background system monitor for inbound TCP SYN attempts. Its GTK viewer reads the existing runtime statistics and history continuously while the window is open. Opening or closing the viewer does not start or stop packet capture.

## [ RUNTIME ]

Network inspects default routes, resolver/backend state, active connections, IPv6 and namespace visibility. Its GTK pages show findings, searchable connections with endpoint and process details, DNS and routes, and isolation evidence. The Lockdown control requires confirmation and uses the existing control path.

Kernel examines loaded modules, sysctl settings and hardening state, including crash-kernel arming and loader locking. Its interpretation accounts for mode-specific TCP, reverse-path and IPv6 values. Some intentional project settings are informational rather than blindly treated as generic hardening failures.

Its GTK interface shows a report summary, findings, searchable loaded modules, sysctl values and hardening state. The interface does not change kernel settings.

Process inspection reads visible process metadata and flags evidence such as memfd execution, deleted or temporary executables, unexpected paths and visibility mismatches. Its searchable process list includes a Review only filter and evidence for the selected process. Available actions depend on the selected finding and process. The operator selects and confirms the remediation.

Radio covers Bluetooth, Wi-Fi, modem, monitor-mode, NFC and GPS state. Its GTK pages separate findings, radio checks, cached Wi-Fi observations and available actions. Nearby Wi-Fi observations use local cached data without requesting an active scan. Reading the report does not disable a radio; the operator selects and confirms a control.

ConnWatch monitors inbound TCP SYN attempts addressed to the machine's non-loopback local interfaces. It does not log every established connection or arbitrary UDP traffic.

The monitor tracks each source in a five-minute counting window. More than 50 matching attempts triggers a volume notice, limited to one per source per five minutes. Tracking is bounded to 2048 sources and 32 target ports per source.

The terminal viewer refreshes once per second and displays the top 15 sources, their five-minute counts and observed target ports. The GTK viewer refreshes every 1.5 seconds and displays all saved sources, alert history and evidence timestamps. Rows above 50 hits are marked High. If the monitor service is inactive, the viewer reports the score as Unavailable even when an older statistics file still exists.

ConnWatch reports and observes activity only. It does not block displayed sources or change firewall policy. Use the network and firewall tools for investigation or remediation.

Shredder maintains marked paths. Its GTK window lets the operator mark files or folders, review the queue, unmark paths and select one to seven overwrite passes. Overwrite and deletion require a final confirmation showing the target paths and selected passes. The Execution page shows progress and final results, and the window cannot close while an overwrite job is running. The `ph4-shred` terminal workflow remains available; marking, unmarking and listing are separate from `ph4-shred s`, which executes overwrite/deletion.

Shredder is best effort at the file level. Storage behavior such as copy-on-write, snapshots or flash remapping can retain copies outside the file blocks it overwrites.

## [ CHECKS ]

Read the evidence and individual failures behind a score. Restricted process/module visibility or a failed command can limit what a report establishes.

For ConnWatch, check the monitor service together with statistics and history timestamps. During quiet traffic, saved rows can remain visible because statistics are written when qualifying packets arrive rather than continuously on a timer.

Recheck the affected state after a confirmed remediation. These tools complement Boot Pilot and Health. They do not replace the startup gates or continuously enforce every displayed finding.

## [ SOURCE ]

[ph4ntxm](../../../config/includes.chroot/opt/ph4ntxm/)
[ph4ntxm-opsec-ui](../../../config/includes.chroot/opt/ph4ntxm/ph4ntxm-opsec-ui/)
[ph4ntxm-opsec-connwatch-gtk](../../../config/includes.chroot/usr/local/bin/ph4ntxm-opsec-connwatch-gtk)
[ph4ntxm-opsec-connwatch.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-opsec-connwatch.sh)
[ph4ntxm-opsec-connwatch](../../../config/includes.chroot/usr/local/bin/ph4ntxm-opsec-connwatch)
