# [ HEALTH ]

## [ OVERVIEW ]

Produces the categorized PH4NTXM runtime health report.

## [ STARTUP ]

Health is a terminal report gathered when the command runs. Boot Pilot and Identity can open it in a held terminal, keeping the output visible after collection finishes.

The report starts from the current mode and local system state. It does not rerun initialization or automatically repair findings.

## [ RUNTIME ]

Sections inspect the system foundation, identity records and hardware views, CPU/GPU/display data, memory and resource state, networking and termination prerequisites. Missing data is reported separately from a valid value.

Protection checks combine service state with protected runtime records. Readiness helpers reject duplicate fields, unsafe ownership/permissions, future timestamps and stale records where a freshness limit applies. Normal packet-engine checks and Lone Wolf Tor/DNS checks follow different paths.

The termination section checks target wiring, masked alternate power/swap paths, SysRq and Ctrl+Alt+Del settings, the final shutdown hook, Nuke artifacts, crash reservation, loaded crash image and locked kexec loader. Those are inspections of prerequisites, not an executed wipe test.

Scoring begins at 100. A warning subtracts two, an error six and a critical error fifteen. The score cannot go below zero. Any critical error forces Unsafe / Not Ready and caps the score at 69, regardless of otherwise healthy sections.

Without critical errors, 90 or above is Excellent, 70 or above is Good, and lower scores require attention. The report lists the individual findings and critical gates alongside the score.

Route inspection is local. A route lookup such as `ip route get` does not send a public connectivity probe, and the report is not continuously refreshed after printing.

## [ CHECKS ]

The access check requires a configured session password and rejects unrestricted passwordless sudo. Protected runtime checks use the bounded session-status helper, without opening arbitrary root files or requesting a password on every refresh.

Start with the failed or critical lines, then inspect their source service or runtime artifact. Rerun the report after a change to obtain a new snapshot.

A readable generated file alone does not prove its corresponding mount, module, listener or guardian is active. Use the paired checks rather than only the final percentage.

## [ SOURCE ]

[ph4ntxm-health](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health)
