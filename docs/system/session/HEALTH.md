# [ HEALTH ]

## [ OVERVIEW ]

Produces the categorized PH4NTXM runtime health report.

## [ STARTUP ]

The menu, Boot Pilot and Identity open the shared GTK interface in the selected edition. `ph4ntxm-health` remains available in the terminal; GTK consumes its structured `--json` output.

Collection runs in the background. Check Again gathers a new snapshot and Copy Report copies it. Opening Health neither reruns initialization nor repairs findings.

## [ RUNTIME ]

Overview groups findings; Full Report provides section, search and Review only filters with complete row values. Checks cover system foundations, identity/hardware, resources, networking and termination prerequisites. Missing evidence is separate from valid values.

CPU/RAM labels follow the persona and memory usage scales with actual host usage. Pressure warnings use actual usage percentage. Protection checks combine service state with protected records, rejecting unsafe metadata, duplicate fields, future timestamps and expired readiness. Normal and Lone Wolf network checks follow their respective paths.

Termination checks inspect wiring, masked alternate paths, shutdown controls, Nuke artifacts and the loaded/locked crash image. They do not execute a wipe.

Scoring starts at 100: warnings subtract 2, errors 6 and critical errors 15, with a floor of zero. Any critical error forces Unsafe / Not Ready and caps the score at 69. Otherwise, 90+ is Excellent, 70+ is Good and lower scores require attention.

## [ BROWSER CHECK ]

This on-demand tab is separate from the Health score. Linux/Windows open a local Firefox tab comparing HTTP/JavaScript user agents, platform, logical CPUs, languages and disabled WebGL/WebRTC/Web Audio against the persona. Timezone, display values and at most 24 font candidates add context.

Display results depend on scaling, window size and zoom; compare at 100%. Firefox's concurrency cap may report fewer threads than the persona. Font sampling is not a full inventory.

The desktop-user checker uses IPv4 loopback and a unique URL, without external resources or preference changes. Completion, cancellation, timeout or closing Health stops it while leaving Firefox open. Results remain in window memory; Copy Browser Report copies them, and Copy Report includes them.

Lone Wolf instead checks local installation verification, guardian/Tor readiness, listeners and temporary-session evidence. It opens no page, enables no JavaScript and changes no security or remote-control settings. Installed defaults and last-saved preferences do not prove current in-memory settings.

Closed-browser checks explicitly request opening Tor Browser and checking again. Unreadable running-session evidence remains unavailable. When protected process inspection is denied, launcher/profile locks and private files can supply Info evidence without claiming executable/environment verification.

Neither path proves public IP, external DNS routing or anonymity.

## [ CHECKS ]

Health verifies session-password setup and rejects unrestricted passwordless sudo. Protected reads use the bounded status helper without repeated password prompts. Route inspection stays local; `ip route get` sends no connectivity probe.

Follow failed/critical checks to their service or runtime artifact, then refresh after changes. Generated files alone do not establish active mounts, modules, listeners or guardians.

## [ SOURCE ]

[ph4ntxm-health](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health)\
[ph4ntxm-health-gtk](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health-gtk)\
[Browser Check](../../../config/includes.chroot/opt/ph4ntxm/ph4ntxm-opsec-ui/ph4ntxm_opsec_ui/browser_check.py)\
[Tor Browser Check](../../../config/includes.chroot/opt/ph4ntxm/ph4ntxm-opsec-ui/ph4ntxm_opsec_ui/tor_browser_check.py)\
[Browser probe assets](../../../config/includes.chroot/opt/ph4ntxm/ph4ntxm-opsec-ui/ph4ntxm_opsec_ui/browser_check_assets)
