# [ THREAT MODEL ]

PH4NTXM targets a state-level threat model focused on tracking, fingerprinting, and continuous monitoring.  
The boot image, build host, and running kernel must be trusted for the protection chain to operate.  
The main objective is reducing session linking and limiting persistent system signals.  
PH4NTXM does not claim to defeat a global observer or a fully compromised host.

## [ SCOPE ]

PH4NTXM protects the user's live session by generating a consistent runtime identity, reducing direct hardware and network exposure, and preventing accidental network fallback.  
The boot image and machine must be trustworthy enough to start the protection chain.  
The system reduces correlation signals, but no operating system can guarantee anonymity by itself.

## [ ASSETS ]

The primary assets protected by PH4NTXM include:

Hardware identifiers: Protected DMI, CPU, GPU, screen, and memory persona views.  
Software identifiers: Hostname, machine ID, MAC address.  
Network identifiers: TCP/IP persona, communication encryption, local DNS resolution.  
Browser identifiers: User-Agent, selected environment telemetry, and common fingerprint surfaces.  
PH4NTXM session data: Kept inside the live environment where configured, with swap disabled before network release and checked again during Nuke.  
Firmware, device caches, and explicitly mounted writable storage remain separate trust boundaries.

## [ ADVERSARY CAPABILITIES ]

The state-level adversary may operate with deep infrastructure control and high-end profiling tools.

Mass surveillance:

Monitors network traffic and collects data at ISP, hotspot, service, or backbone levels.  
Harvests network signatures, DNS behavior, timing, and browser metadata to build broad target profiles.  
Uses passive deep packet inspection to classify hosts and correlate sessions.

Targeted surveillance:

Correlates browser telemetry with low-level hardware and network signatures.  
Analyzes traffic timing and packet layout even when payloads are encrypted.  
Attempts active network manipulation, application exploits, or side-channel attacks against specific targets.

## [ ATTACK SURFACES & MITIGATIONS ]

Boot:

Threat: Modification of the live image or early boot chain.  
Mitigation: Read-only live-media design and deterministic mode templates. Authenticity still depends on trusted image verification and platform boot trust.

Hardware:

Threat: Tracking through user-facing DMI, CPU, GPU, screen, and system information.  
Mitigation: Seed-based persona values in selected protected command/reporting views. Direct kernel, firmware, driver and physical side channels are not universally virtualized.

Network:

Threat: Traffic timing leaks, DNS hijacking, ISP profiling, or accidental firewall bypass.  
Mitigation: nftables default-drop policy, fail-closed Packet Transformation Engine queues plus a physical-egress TC/eBPF raw-bypass guard in Linux and Windows, encrypted local DNS, timing variation, and Tor-only routing in Lonewolf. Full traffic-correlation attacks remain possible.

Userspace:

Threat: Advanced browser tracking through canvas, user-agent, fonts, WebGL, WebRTC, and operator activity.  
Mitigation: Persona-aligned Firefox ESR in Linux/Windows and isolated Tor Browser in Lonewolf. Account use, behavior, and application-level identifiers can still link sessions.

Physical:

Threat: Memory dumps and device capture during operation.  
Mitigation: Armed USB removal trigger, Panic Button, mandatory nuke path, best-effort RAM overwrite and final shutdown scrub. These controls cannot guarantee complete recovery resistance against cold-boot acquisition, DMA, firmware capture, sudden power loss or storage outside the live environment.

## [ FAILURE POLICY ]

Physical network links remain blocked until identity, firewall, packet-processing, clock, and crashkernel readiness gates succeed.  
Linux and Windows require native Packet Transformation Engine provenance for IP egress. Raw DHCP, ARP, and EAPOL cross a separate strict TC/eBPF contract; every other unmarked physical-egress frame is dropped.  
Lonewolf does not allow application clearnet fallback when Tor is unavailable.  
Unexpected firewall state activates Lockdown before restoration.  
PH4NTXM Health and Boot Pilot expose failed runtime chains instead of treating missing state as healthy.

## [ COMPONENT BOUNDARIES ]

Hardware, CPU, GPU, and display personas cover selected reporting surfaces, not complete hardware emulation.  
Browser wrappers configure participating launches; accounts, extensions, and direct executable access remain operator-controlled.  
Packet transformation covers supported packet layouts, while TLS, HTTP, traffic correlation, and application identifiers require separate assessment.  
RAM seeding supplies synthetic noise, not encryption or concealment of genuine secrets. Memory scrub and file overwrite remain best effort.

## [ OUT OF SCOPE ]

Tampered hardware: Malicious BIOS/UEFI implants or hardware-level keyloggers installed through physical access.  
Supply-chain interception: Compromised machines or components modified before deployment.  
Physical hardware injection: Malicious cables or rogue USB devices connected directly to the host.  
Zero-day exploits: Unpatched or unknown vulnerabilities in the kernel, firmware, browser, or hardware architecture.  
Compromised runtime: A root or kernel compromise can disable, bypass, or falsify PH4NTXM controls and status reports.  
Live operator privilege: The `ph4ntxm` account has full passwordless sudo access. Compromise of the live user gives administrative control for the active session.  
Global correlation: A global observer may correlate Tor or direct traffic using timing and volume.  
Advanced side-channel analysis: Acoustic, thermal, electromagnetic, DMA, or power-consumption profiling outside the managed runtime.  
Operator OpSec failure: Real-world identities, credential reuse, account login, unsafe documents, or other human errors during a session.  
Guaranteed physical erasure: RAM scrub and file overwrite are best effort; flash translation layers, snapshots, remapped storage blocks and unavailable memory are not guaranteed to be erased.
