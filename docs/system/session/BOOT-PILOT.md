# [ BOOT PILOT ]

## [ OVERVIEW ]

Opens automatically at desktop startup to show protection readiness and provide Wi-Fi controls.

## [ STARTUP ]

The desktop opens only after the session password has been set. Protected status reads use a bounded helper. Wi-Fi scans and connection requests retain their exact passwordless helper commands, so refreshing the Pilot does not ask for the administrator password.

Boot Pilot opens in the desktop and groups checks into Identity, Network and System Protection. It reads the selected mode and chooses the corresponding normal or Lone Wolf service chain.

For the first 30 seconds, incomplete checks are shown as pending under Verifying Boot. The grace period changes presentation. It does not mark failed prerequisites as ready.

## [ RUNTIME ]

Checks refresh every two seconds. Identity checks combine service results with generated state, machine-ID consistency, fonts, clock application and browser policy. A completed one-shot must have successfully exited its latest invocation and settled as inactive/dead or active/exited. Continuously active units are handled according to their role.

Network checks include derived physical MACs, DHCP mode, local resolver and current protection state. Normal modes inspect packet-engine/firewall state plus Drift and Ghost Stack. Lone Wolf checks its guardian, fresh Tor readiness and the local DNS/proxy listeners.

While the protected local path is available and Tor is bootstrapping, Tor and DNS remain pending beyond the 30-second grace period. The connection line shows Waiting for Network without an active IPv4 default route, or Connecting to Tor with a spinner when that route is present.

System checks cover RAM seeding with no swap, the thermal guard, ConnWatch and the loaded/locked Nuke path. All displayed feature checks must pass before Continue is enabled. The browser button also requires its launcher prerequisites. Lone Wolf lockdown remains a valid protection state, but Tor Browser requires the Lone Wolf firewall profile; Pilot displays the browser restriction while Continue remains available. Both handlers refresh once more before acting.

Continue closes the window. The browser action launches Firefox ESR for Linux/Windows or the dedicated Tor Browser wrapper for Lone Wolf. Pilot stays open during launch verification and shows errors when spawning fails or the launcher refuses to start. The Tor wrapper acknowledges acceptance after its checks and initial process launch, including the private runtime lock and graphical authority. Pilot waits asynchronously for that acknowledgement for at most 15 seconds; acceptance confirms the wrapper launch gate, not full browser readiness. Firefox ESR is checked briefly for launch failure, and a successful exit that forwards to an existing browser is accepted. Detailed Report opens the Health desktop application.

Wi-Fi state refreshes separately every five seconds, with scans and connection requests performed through background helper calls. Supported network selection and password handling go through [Wi-Fi Control](WIFI-CONTROL.md). A missing wireless adapter is displayed without inventing a connection requirement for wired-only systems.

## [ CHECKS ]

Open the failed group's underlying service journal and compare its state files with the check description. Check Again refreshes both protection and Wi-Fi views. It does not rerun all identity generators.

Boot Ready summarizes these local checks at the latest refresh. It is not an external connectivity test, and closing the window does not stop the system guardians.

## [ SOURCE ]

[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)
