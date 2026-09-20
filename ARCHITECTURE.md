# [ ARCHITECTURE ]

PH4NTXM builds a consistent runtime identity at boot.  
Seed-based generation links identity, hardware, browser, and network profiles across the live session.

## [ SYSTEM LIFECYCLE ]

Boot → Mode Selection → Identity Setup → Hardware Setup → Network Setup → Runtime Enforcement → Operation → Nuke Kernel → Termination.

## [ BUILD EDITIONS ]

Abyss and Ghost select the appearance at build time. Abyss uses PH4NTXM-Abyss for its dark navy desktop; Ghost uses PH4NTXM-Ghost for its light pearl-white desktop. Both retain cyan and magenta accents.

## [ BOOT MODES ]

Selected at boot and fixed for the session.

LINUX: Linux-aligned mode.  
WINDOWS: Windows-aligned mode.  
LONE WOLF: Linux-based Tor routing mode.

## [ IDENTITY ADAPTION ]

LINUX / WINDOWS: A session seed links hostname, hardware persona, and physical-interface MACs. The boot machine ID is validated, not regenerated from the seed.
LONE WOLF: Uses an independent seed and identity chain.  
Hot-plug adapters receive a protected MAC before use; failure keeps the adapter down.

## [ NETWORK ADAPTION ]

LINUX / WINDOWS: Bounded TCP/IP settings follow the session seed and selected network persona.  
LONE WOLF: Uses a smaller independent profile with IPv6 and TCP timestamps disabled; its Tor firewall owns routing.

## [ DNS ADAPTION ]

LINUX / WINDOWS: Local Unbound forwards DNS through authenticated DNS-over-TLS upstreams without plaintext fallback.  
LONE WOLF: DNS is redirected to a local bridge and forwarded through Tor DNSPort. Direct external DNS is not allowed.

## [ DHCP ADAPTION ]

LINUX: Uses dhclient-style vendor and session parameters.  
WINDOWS: Uses Windows-aligned vendor, timeout, and session identifier settings.  
LONE WOLF: Uses minimal DHCP without hostname or vendor-class advertisement. All modes preserve the protected MAC.

## [ HARDWARE ADAPTION ]

LINUX / WINDOWS: A session seed selects a compatible system/CPU/RAM configuration from the shared hardware catalog for DMI and user-facing system views.
LONE WOLF: An independent session seed selects from the same catalog; identifiers remain session-specific.

## [ GPU ADAPTION ]

LINUX / WINDOWS: GPU vendor, renderer, and capabilities follow the hardware persona through environment settings and the GL identity shim.  
LONE WOLF: Generates a separate GPU profile; Tor Browser uses its own clean environment.

## [ CPU & MEMORY ADAPTION ]

LINUX / WINDOWS: CPU model, topology, cache and RAM specifications follow the selected catalog entry. Active CPUs and usable memory are capped to the host.
LONE WOLF: Uses the same resource generator with independent session state. SMBIOS distinguishes installed memory and processor totals from usable memory and active CPUs.

## [ CPU THERMAL ADAPTION ]

CPU temperature is monitored with hysteresis.  
At high temperature the service requests a powersave governor and disables boost, then restores the settings recorded at service startup after recovery.

## [ DISPLAY & SCREEN ADAPTION ]

LINUX / WINDOWS: Persona-aware display metadata, nominal resolution, refresh rate, and pixel ratio are generated for downstream PH4NTXM components.  
LONE WOLF: Display metadata is generated per session with broader variation. Tor Browser uses its own display policy.

## [ BROWSER VIEWPORT ADAPTION ]

LINUX / WINDOWS: Viewport metadata follows the generated display persona with seeded UI offsets and the inherited pixel ratio.  
LONE WOLF: Viewport metadata uses the independent Lone Wolf seed and boot jitter while remaining aligned with the generated screen profile.

## [ CLOCK FUZZING ]

System time receives a mode-specific boot offset followed by bounded tick movement and occasional signed microsecond adjustments. The clock engine inherits the active identity seed and stays supervised for the session.

## [ RAM SEEDING ENGINE ]

A small anonymous memory region is filled with non-zero noise and sparse system-like fragments.  
The engine asks the kernel to keep the region resident and periodically mutates it during the live session.  
This is a volatile noise layer, not encryption or protection for genuine secrets.

## [ PACKET TRANSFORMATION ENGINE ]

LINUX / WINDOWS: A Rust core and C NFQUEUE adapter validate and transform IP packets with bypass disabled.  
TC/eBPF checks physical output and separately validates raw ARP, EAPOL, and DHCP; other unmarked frames are dropped.  
LONE WOLF: Uses its dedicated Tor policy instead.

## [ NETWORK DRIFT ]

LINUX / WINDOWS: Network behavior is shaped from inherited session state with evolving latency, jitter, bounded loss, duplication, and reordering across the active default-route interfaces.  
LONE WOLF: No local shaping is applied; latency is handled through Tor only.

## [ NET GHOST STACK ]

LINUX / WINDOWS: Generates a small session-seeded set of local dummy or bridge interfaces using safe documentation ranges without becoming forwarding paths.  
LONE WOLF: No local interface simulation is used. The stack stays minimal.

## [ SYSTEM HARDENING ]

Kernel settings and systemd service restrictions are applied according to the selected mode and component requirements.

## [ POST-QUANTUM CRYPTOGRAPHY ]

SSH and OpenSSL configurations prefer supported hybrid post-quantum key exchange with classical fallback.  
The negotiated result depends on application support and the peer.

## [ FIREWALL GUARDS ]

Periodically verifies the active Packet Transformation Engine, Tor-only, or Lockdown ruleset.  
Detected changes trigger emergency Lockdown before restoration; readiness requires successful application and verification.

## [ HARDENED BROWSER ]

LINUX / WINDOWS: Firefox ESR inherits the active persona through its runtime wrapper and private profile.  
LONE WOLF: Tor Browser uses system Tor in an isolated runtime environment without the Firefox persona overrides.

## [ DOCUMENT AIRLOCK ]

Selected documents and images are rendered inside a disposable offline KVM guest with no network adapter or shared host directories.  
A bounded host broker validates returned pixels and builds an image-only PDF for preview and explicit export.

## [ IDENTITY ]

Read-only system identity view for the active mode, hostname, machine ID, MAC, clock, and generated persona.  
Extended hardware and identity details are integrated into PH4NTXM Health.

## [ PH4NTXM BOOT PILOT ]

Displays protection state and provides Wi-Fi controls in every mode.  
Continue closes Pilot; the browser button launches Firefox ESR or Tor Browser.  
Both recheck the required protection state before activation.

## [ PH4NTXM HEALTH ]

Unified runtime report for system foundation, privilege state, protection services, identity persona, resources, storage, network egress, OpSec, and termination containment.  
Includes identity details and passive network checks without public probe requests.

## [ LOCKDOWN ]

User-triggered network lockdown that loads a full default-drop ruleset and flushes active connections.  
Accessible through the PH4NTXM GUI and restricted control path.

## [ NUKE KERNEL ]

Normal shutdown, reboot, halt, and poweroff use the common Nuke sequence.  
It isolates networking, terminates the session, attempts RAM scrubbing, and powers off.

## [ PANIC BUTTON ]

Operator-triggered emergency termination after confirmation.  
It immediately isolates radios and network links, then starts the common Nuke sequence.

## [ USB REMOVAL NUKE ]

When armed, removal of a USB storage disk triggers the Panic and Nuke sequence.

## [ SYSTEM WRAPPERS ]

Hardware wrappers share `/usr/lib/ph4ntxm/hardware` and execute native inventory tools with session CPU/RAM/DMI data. A common model table supplies total and active CPU topology in Linux, Windows and Lone Wolf modes and the boot CPU view. Native output formats and diagnostics are preserved. Private mount namespaces and a temporary seccomp supervisor extend the view to direct hardware-query syscalls and descendants; `ph4ntxm-hardware-run` applies the same view to an explicitly launched application.

## [ OPSEC SUITE ]

Diagnostic tools for network, kernel, process, radio, and connection inspection, with explicit operator-triggered remediations where supported.  
`ph4-shred` performs best-effort file overwrite and deletion.
