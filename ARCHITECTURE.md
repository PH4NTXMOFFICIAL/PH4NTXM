# [ ARCHITECTURE ]

PH4NTXM’s architecture is based on identity adaptation.  
On boot, it builds a consistent runtime identity so all system layers match and avoid conflicts.  
Generation is seed-based: each stage reuses values from previous stages to maintain consistency across the system.

## [ SYSTEM LIFECYCLE ]

Boot → Mode Selection → Identity Setup → Hardware Setup → Network Setup → Runtime Enforcement → Operation → Nuke Kernel → Termination.

## [ BOOT MODES ]

Selected at boot and fixed for the session.

LINUX: Linux-aligned mode.  
WINDOWS: Windows-aligned mode.  
LONEWOLF: Linux-based Tor routing mode.

Bootloader selects mode → kernel initializes → identity is built → PH4NTXM starts.

## [ IDENTITY ADAPTION ]

LINUX / WINDOWS: A session seed links hostname, hardware persona, and physical-interface MACs. The boot machine ID is validated, not regenerated from the seed.  
LONEWOLF: Uses an independent seed and identity chain.  
Hot-plug adapters receive a protected MAC before use; failure keeps the adapter down.

## [ NETWORK ADAPTION ]

LINUX / WINDOWS: Bounded TCP/IP settings follow the session seed and selected network persona.  
LONEWOLF: Uses a smaller independent profile with IPv6 and TCP timestamps disabled; its Tor firewall owns routing.

## [ DNS ADAPTION ]

LINUX / WINDOWS: Local Unbound forwards DNS through authenticated DNS-over-TLS upstreams without plaintext fallback.  
LONEWOLF: DNS is redirected to a local bridge and forwarded through Tor DNSPort. Direct external DNS is not allowed.

## [ DHCP ADAPTION ]

LINUX: Uses dhclient-style vendor and session parameters.  
WINDOWS: Uses Windows-aligned vendor, timeout, and session identifier settings.  
LONEWOLF: Uses minimal DHCP without hostname or vendor-class advertisement. All modes preserve the protected MAC.

## [ HARDWARE ADAPTION ]

LINUX / WINDOWS: A session hardware persona is generated from the seed and selected vendor/family profile, then exposed consistently through protected DMI fields and user-facing system views.  
LONEWOLF: The exposed hardware persona is regenerated per session with more variation and remains internally coherent for that session.

## [ GPU ADAPTION ]

LINUX / WINDOWS: GPU vendor, renderer, and capabilities follow the hardware persona through environment settings and the GL identity shim.  
LONEWOLF: Generates a separate GPU profile; Tor Browser uses its own clean environment.

## [ CPU & MEMORY ADAPTION ]

LINUX / WINDOWS: CPU cores and RAM are derived from device class and SKU-based profiles, with small jitter and hard limits based on real system memory to keep results consistent per session.  
LONEWOLF: CPU cores and RAM are selected from allowed ranges per device class using seed + runtime entropy, with higher variation while still staying within hardware constraints.

Protected values are exposed through selected procfs, sysfs, `lscpu`, `nproc`, and `free` views.  

## [ CPU THERMAL ADAPTION ]

CPU temperature is monitored with hysteresis.  
At high temperature the service requests a powersave governor and disables boost, then restores the settings recorded at service startup after recovery.

## [ DISPLAY & SCREEN ADAPTION ]

LINUX / WINDOWS: Persona-aware display metadata, nominal resolution, refresh rate, and pixel ratio are generated for downstream PH4NTXM components.  
LONEWOLF: Display metadata is generated per session with broader variation. Tor Browser uses its own display policy.

## [ BROWSER VIEWPORT ADAPTION ]

LINUX / WINDOWS: Viewport metadata follows the generated display persona with seeded UI offsets and the inherited pixel ratio.  
LONEWOLF: Viewport metadata uses the independent Lonewolf seed and boot jitter while remaining aligned with the generated screen profile.

## [ CLOCK FUZZING ]

System time receives a mode-specific boot offset followed by bounded tick movement and occasional signed microsecond adjustments. The clock engine inherits the active identity seed and stays supervised for the session.

## [ RAM SEEDING ENGINE ]

A small anonymous memory region is filled with non-zero noise and sparse system-like fragments.  
The engine asks the kernel to keep the region resident and periodically mutates it during the live session.  
This is a volatile noise layer, not encryption or protection for genuine secrets.

## [ PACKET TRANSFORMATION ENGINE ]

LINUX / WINDOWS: A Rust core and C NFQUEUE adapter validate and transform IP packets with bypass disabled.  
TC/eBPF checks physical output and separately validates raw ARP, EAPOL, and DHCP; other unmarked frames are dropped.  
LONEWOLF: Uses its dedicated Tor policy instead. Details: [Packet Transformation Engine](docs/system/session/PACKET-TRANSFORMATION-ENGINE.md).

## [ NETWORK DRIFT ]

LINUX / WINDOWS: Network behavior is shaped from inherited session state with evolving latency, jitter, bounded loss, duplication, and reordering across the active default-route interfaces.  
LONEWOLF: No local shaping is applied; latency is handled through Tor only.

## [ NET GHOST STACK ]

LINUX / WINDOWS: Generates a small session-seeded set of local dummy or bridge interfaces using safe documentation ranges without becoming forwarding paths.  
LONEWOLF: No local interface simulation is used. The stack stays minimal.

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
LONEWOLF: Tor Browser uses system Tor in an isolated runtime environment without the Firefox persona overrides.

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

When armed, USB storage removal triggers the Panic and Nuke sequence.  
The armed trigger applies to USB storage disks.

## [ SYSTEM WRAPPERS ]

Selected user-facing hardware views including `dmidecode`, `lscpu`, `free`, and `nproc` expose controlled session persona data.  
Unsupported bypass-style views receive an explicit error.

## [ OPSEC SUITE ]

Diagnostic tools for network, kernel, process, radio, and connection inspection, with explicit operator-triggered remediations where supported.  
`ph4-shred` performs best-effort file overwrite and deletion.
