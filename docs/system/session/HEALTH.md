# [ HEALTH ]

## [ OVERVIEW ]

Produces the categorized PH4NTXM runtime health report.

## [ STARTUP ]

The menu, Boot Pilot and Identity open Health in a GTK window using the shared PH4NTXM interface and the selected Abyss or Ghost edition. The `ph4ntxm-health` terminal command remains available.

The report starts from the current mode and local system state. It does not rerun initialization or automatically repair findings. Collection runs in the background; Check Again gathers a new snapshot and Copy Report copies the full collected report.

## [ RUNTIME ]

Sections inspect the system foundation, identity records and hardware views, CPU/GPU/display data, memory and resource state, networking and termination prerequisites. Missing data is reported separately from a valid value. Overview groups findings by section. Full Report includes every reported check, with section, search and Review only filters; selecting a row shows its complete value.

CPU and RAM labels use the session persona. Memory usage is scaled from actual host usage, while memory-pressure warnings still use the actual usage percentage.

Protection checks combine service state with protected runtime records. Readiness helpers reject duplicate fields, unsafe ownership/permissions, future timestamps and stale records where a freshness limit applies. Normal packet-engine checks and Lone Wolf Tor/DNS checks follow different paths.

The termination section checks target wiring, masked alternate power/swap paths, SysRq and Ctrl+Alt+Del settings, the final shutdown hook, Nuke artifacts, crash reservation, loaded crash image and locked kexec loader. Those are inspections of prerequisites, not an executed wipe test.

Scoring begins at 100. A warning subtracts two, an error six and a critical error fifteen. The score cannot go below zero. Any critical error forces Unsafe / Not Ready and caps the score at 69, regardless of otherwise healthy sections.

Without critical errors, 90 or above is Excellent, 70 or above is Good, and lower scores require attention. The report lists the individual findings and critical gates alongside the score.

Route inspection is local. A route lookup such as `ip route get` does not send a public connectivity probe, and the report is not continuously refreshed. The GTK window and terminal use the same checks and scoring; the GTK frontend reads the structured `ph4ntxm-health --json` output without parsing terminal colors.

## [ CHECKS ]

The access check requires a configured session password and rejects unrestricted passwordless sudo. Protected runtime checks use the bounded session-status helper, without opening arbitrary root files or requesting a password on every refresh.

Start with the failed or critical lines, then inspect their source service or runtime artifact. Rerun the report after a change to obtain a new snapshot.

A readable generated file alone does not prove its corresponding mount, module, listener or guardian is active. Use the paired checks rather than only the final percentage.

## [ SOURCE ]

[ph4ntxm-health](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health)
[ph4ntxm-health-gtk](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health-gtk)
