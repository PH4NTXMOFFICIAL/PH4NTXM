# [ ARCHITECTURE ]

## [ OVERVIEW ]

PH4NTXM builds a linked runtime identity at boot and applies it through several cooperating layers. Identity generators prepare the session values. Wrappers expose selected hardware and browser views. Network workers and guardians enforce the selected traffic path. Desktop tools report those states and request explicit actions.

The shared state is the connection between these layers. A generated file, a completed service and a fresh readiness record each mean something different. The system checks them together where required.

## [ SOURCE AND BUILD LAYOUT ]

`config/includes.chroot` contains the files installed into the live system: services, helpers, application launchers, policies and component sources. Build hooks compile or install the components and their wrappers, while package lists supply the required distribution packages.

`editions/abyss` and `editions/ghost` supply appearance overlays. `build.sh` validates the selection, prepares an independent tree under `build/<edition>`, runs live-build and publishes the ISO/checksum under `output/`. A per-edition lock prevents two builds from modifying the same working tree.

Both editions share the protection chain and boot modes. XFCE uses Picom's XRender backend, with XFWM compositing disabled. The shared configuration supplies rounded corners and 95 percent opacity for ordinary non-terminal windows. Terminals keep their separate opacity setting. Vsync, shadows and blur are disabled in the shared Picom configuration.

See [Build Editions](docs/build/BUILD-EDITIONS.md) for the build overlay details.

## [ MODE AND BOOT FLOW ]

The boot parameter `ph4ntxm.mode` selects `linux`, `windows` or `lonewolf`. Mode initialization writes `/run/ph4ntxm/mode` and the corresponding normal/Lone Wolf marker used by unit conditions. Missing or invalid boot selection falls back to Linux at this initialization stage. Later components validate the initialized mode rather than freely switching profiles.

The main ordering is:

Select and contain:

Initialize mode, lower physical network links and disable swap. Load the emergency crash kernel and lock later kexec loading.

Prepare identity:

Validate the boot machine ID, create or reuse the mode's seed, select the hardware persona and apply hostname/MAC state.

Prepare consumers:

Generate related hardware, GPU, CPU/resource, screen, browser, DHCP and kernel-network data along their service dependencies.

Prepare the network path:

Load normal nftables rules and start the packet worker, or install the dedicated Lone Wolf policy and firewall guardian. Clock and resolver preparation are also part of the release dependencies.

Release prepared adapters:

Verify mode-specific prerequisites, run hotplug protection, refresh udev, verify again and raise physical links before NetworkManager connection setup.

Supervise operation:

Guardians maintain the network contract. In Lone Wolf, connectivity lets Tor bootstrap before its DNS/browser readiness can be established. Boot Pilot presents the combined desktop checks.

These stages form a dependency graph, not one strictly serial script. Tor bootstrap cannot precede the connection it needs, and a successful link release does not mean every desktop feature is already ready. [Boot Flow](docs/system/session/BOOTFLOW.md) describes the component sequence.

## [ RUNTIME STATE AND READINESS ]

Most generated system state lives under `/run/ph4ntxm`. Private browser and file-handling sessions use the desktop user's `/run/user/UID` directory.

| State | Producer and purpose |
| --- | --- |
| `mode`, mode markers | Select the service branch and mode-aware consumers. |
| `persona_seed` / `lonewolf_seed` | Link the normal or independent Lone Wolf session draws. |
| `boot_machine_id`, `boot_hostname`, `boot_mac`, `identity-ready` | Preserve identity inputs and record completed identity initialization. Lone Wolf uses a per-interface `boot_mac` directory. |
| `hardware_profile`, `fake_dmi`, `cores_env`, `gpu_env` | Carry the chosen model, generated identifiers and resource/display capabilities. |
| `screen_env`, `browser_env`, `fonts-active` | Supply participating desktop and browser views. |
| `session_dhcp`, `clock-fuzz-profile` | Record DHCP choices and clock-engine state. |
| `firewall-ready`, engine-guard readiness, `tor-ready` | Describe recently checked profiles and guardian activity. |

Seeds and sensitive session records use restrictive permissions. Many consumers require root-owned, non-symlink files without group/other write access. Several generators publish through temporary-file rename. Separate output files are still separate updates, not one global transaction.

A one-shot can finish successfully without leaving a process running. A guardian can be running while enforcement is degraded. Readiness consumers therefore inspect profile, content and freshness as appropriate. Firewall/Tor consumers commonly reject records older than six seconds or dated in the future. Lockdown's UI status JSON records control state and is not equivalent to a fresh ruleset verification.

## [ LINKED IDENTITY AND HARDWARE VIEWS ]

Linux and Windows identity initialization validates the existing boot machine ID and derives a new seed when one is absent. The catalog selector chooses a compatible system entry. Hostname and physical-interface MAC values follow that seed. Lone Wolf uses an independent seed and per-interface locally administered MAC records.

The catalog ties DMI, CPU, RAM and graphics specifications together. Hardware generation supplies session UUIDs and serials, while resource generation retains the chosen model's installed/total specifications and bounds active CPUs and usable RAM to the host. Installed capacity and usable memory are deliberately separate fields.

The dependency chain carries the selected profile through GPU and resource generation into CPU and screen consumers. Missing or inconsistent catalog data fails the relevant stage instead of selecting an unrelated replacement specification.

Inventory wrappers run native tools with generated reporting files, private mounts, a query library and a seccomp supervisor. This keeps native output formatting while extending supported hardware-query handling to descendants. `ph4ntxm-hardware-run` applies that view to an explicitly launched application.

[Hardware Views](docs/system/session/HARDWARE-VIEWS.md) and [Cores Randomization](docs/system/session/CORES-RANDOMIZATION.md) describe the reporting boundary and installed-versus-usable fields.

## [ GRAPHICS, SCREEN, FONTS AND BROWSER ]

GPU generation exports the selected vendor/renderer profile for participating environment settings and the GL identity shim. Screen stages produce nominal display metadata, refresh rate, pixel ratio and viewport data. The generated values feed the desktop and browser reporting paths.

Font setup builds the active Fontconfig profile. Its random selection is performed on each run independently of the hardware seed. The generated font set and the browser environment must be present before the normal browser wrapper launches.

Linux and Windows use Firefox ESR through a diverted command wrapper. It validates protected runtime files, obtains the installed Firefox version and substitutes the mode template into a private runtime profile. Unresolved identity placeholders stop launch. A nonblocking lock prevents concurrent wrapper sessions, and normal launches reuse that boot session's profile.

Lone Wolf's browser gate verifies the Tor Browser installation and restricts the ordinary Firefox path. Its launcher checks browser integrity state, current firewall/Tor readiness and loopback listeners, then creates a fresh temporary home. It starts with an explicitly built environment and system Tor at `127.0.0.1:9050`, without the normal Firefox persona overrides.

See [Browser](docs/system/session/BROWSER.md), [Browser Mode](docs/system/session/BROWSER-MODE.md) and [Tor Browser](docs/system/session/TOR-BROWSER.md).

## [ NORMAL NETWORK PATH ]

Linux and Windows first apply bounded kernel TCP/IP settings. Ordinary TTL/hop-limit values are 64 and 128 respectively. Ports, retry timing, timestamps and other settings follow the selected profile. Required writes are read back. Runtime entropy means another normal network-generation run can choose new values within those bounds.

DHCP generation writes the mode's client parameters and NetworkManager configuration. Linux and Windows use different vendor and session settings while preserving the already prepared MAC. The dispatcher and physical hotplug helper keep later connection/device handling aligned with that state.

The packet path has three cooperating parts:

| Layer | Responsibility |
| --- | --- |
| nftables | Queue non-loopback IP traffic without bypass, validate worker provenance and apply filtering/DNS redirects. |
| Rust core with C NFQUEUE adapter | Validate packet/queue metadata, transform supported packets, maintain related flow state and finalize checksums. |
| Physical TC/eBPF guard | Verify marked IP egress and separately constrain raw ARP, EAPOL and DHCP. Reject other unmarked output. |

Inbound queue 1 runs before connection tracking. Outbound queue 2 runs after destination NAT. Accepted worker output carries the `0x50544531` mark. The inbound verifier clears it, while outbound processing retains it for physical egress checks. Missing worker processing does not become a queue-bypass route.

Unbound listens locally and forwards DNS over authenticated TLS, with mode-specific upstream lists and no ordinary recursive fallback. Firefox policy disables its separate DoH path. Resolver configuration readiness and successful external resolution are distinct checks.

After connection setup, Network Drift periodically replaces eligible routed interfaces' root qdiscs with bounded netem delay, loss, duplication and reordering. Ghost Stack creates optional local dummy/bridge topology. The RTT map stores locally generated delay metadata. The virtual interfaces use documentation address ranges with `noprefixroute`.

See [Packet Transformation Engine](docs/system/session/PACKET-TRANSFORMATION-ENGINE.md), [DHCP](docs/system/session/DHCP-SESSION-GENERATOR.md) and [Unbound](docs/system/session/UNBOUND-RANDOMIZATION.md).

## [ LONE WOLF NETWORK PATH ]

Lone Wolf disables IPv6 and uses its own sysctl, DHCP, firewall and DNS stages. DHCP omits hostname/vendor-class advertisement while preserving the prepared MAC. It does not use the normal packet worker, Network Drift or Ghost Stack.

The dedicated NAT policy redirects application DNS to local port 53 and ordinary application TCP to Tor's transparent port 9040. Tor's account has its own controlled external TCP path. DHCP has explicit connection-setup exceptions. Arbitrary application UDP is blocked.

The DNS bridge exposes local TCP/UDP 53 and forwards to Tor DNSPort 5353 without dnsmasq caching. Readiness also requires transparent/SOCKS listeners and an authenticated control-socket reply reporting bootstrap 100 with `TAG=done`. The bridge refreshes `tor-ready` while those checks pass and removes it on failure.

The firewall guardian checks the policy independently. Its process can be active under emergency default-drop rules while ordinary Lone Wolf readiness is absent. Browser launch requires the ready profile, not just a running guardian or Tor process.

See [Lone Wolf Setup](docs/system/session/LONEWOLF-SETUP.md) and [DNS Bridge](docs/system/session/LONEWOLF-DNS-BRIDGE.md).

## [ GUARDIANS AND LOCKDOWN ]

Firewall guardians compare requested profile, trusted source policy and a hash of the live stateless ruleset. Unexpected changes clear readiness and trigger restrictive recovery before a validated profile is restored. Lone Wolf includes the source digest in its readiness contract. Normal modes also coordinate with the packet-engine guard.

The engine guard checks actual egress classifier layout and program identity against the physical interface and session data. Its two-second loop can reapply protection or hold affected links down. Exit cleanup clears readiness and attempts physical link containment.

Lockdown uses a shared firewall lock and mode-aware helper. Normal-path transitions seal interfaces before changing policy and restore eligible saved links only after preparation and verification. Profile/token acknowledgements prevent an old transition response from satisfying a new request.

Transitions apply policy and interface changes in sequence. On failure, recovery keeps the restrictive state while the guardian works to restore a verified profile. Conntrack cleanup can interrupt existing connections. Readiness is published after verification.

See [Firewall Control](docs/system/session/FIREWALL-CONTROL.md) and [Engine Guard](docs/system/session/PACKET-TRANSFORMATION-ENGINE-GUARD.md).

## [ CLOCK, THERMAL AND MEMORY SERVICES ]

Clock Fuzz applies a mode-bounded initial offset, then maintains tick variation and occasional small adjustments. Valid saved state lets a restarted engine resume without repeating the initial offset. Its readiness notification follows the required clock operations and profile publication.

CPU Lockdown records initial governor/boost settings, requests powersave and disabled boost at 85°C, and attempts restoration at 70°C or below. The service attempts writes to available controls and tolerates unsupported or rejected driver settings.

RAM Seeding allocates one percent of reported RAM, fills its private mapping with noise and sparse synthetic fragments, and periodically mutates it. It tries whole-region locking, then smaller chunks. The allocation stays active during operation and is released when Nuke preparation stops the seeding service before scrubbing.

Kernel settings and systemd restrictions follow each component's needs. SSH and OpenSSL configuration prefer supported hybrid post-quantum key exchanges with classical fallback. The application and peer negotiate the supported exchange.

## [ DOCUMENT AND MEDIA ISOLATION ]

Document Airlock validates local input and trusted guest artifacts before starting a disposable offline KVM guest. The guest has no network adapter or shared host home. A bounded protocol returns RGB pages. The host broker checks framing, dimensions and total size before building a new raster PDF.

The UI previews those pages and exports only to a new filename. The exported PDF contains the rendered page images without the original active document structure or metadata. Cancellation, timeout or invalid output ends conversion. KVM, private tmpfs storage, sufficient memory and disabled swap are prerequisites.

Media Viewers use a different boundary: offline namespaces, read-only selected files, a private bus/home and nested Xephyr display. A separate audio process receives fixed-format PCM. A transient user service applies memory, swap, task and CPU limits, and cleanup stops the session's processes. The selected source files remain read-only throughout playback.

See [Document Airlock](docs/system/session/DOCUMENT-AIRLOCK.md) and [Media Viewers](docs/system/session/MEDIA-VIEWERS.md) for limits and checks.

## [ OPERATOR VIEWS AND DIAGNOSTICS ]

Boot Pilot refreshes identity, network and system checks, provides Wi-Fi selection and enables Continue/browser actions only after its checks pass. During the first 30 seconds, incomplete checks appear as pending while services settle. Wi-Fi connections use volatile NetworkManager profiles, preserve the prepared MAC and do not enable autoconnect.

Identity is a snapshot of selected identifiers. Health collects a broader local report, including resources, guardian state and termination wiring. Critical findings force its Unsafe / Not Ready result even when other sections pass.

The OpSec Suite includes Network, Kernel, Process, Radio, ConnWatch and Shredder. Each component collects and presents its own evidence and findings, with confirmed remediation actions where supported.

See [Applications](docs/system/session/PH4NTXM-APPLICATIONS.md), [Health](docs/system/session/HEALTH.md) and [OpSec Suite](docs/system/session/PH4NTXM-OPSEC-SUITE.md).

## [ CONTAINMENT AND TERMINATION ]

Early arming loads the dedicated crash image using the discovered System RAM ranges, then locks kexec loading. Physical release checks require both a loaded image and a locked loader.

Normal termination targets invoke the common Nuke preparation: request Lockdown, block radios/links, terminate the live user, stop RAM seeding, disable swap and attempt cache and allocatable-memory cleanup. The final shutdown hook and Panic path can request the armed crash transition.

The first emergency initramfs reconstructs the memory map and loads the next kernel with `memtest=17`. The following init performs another allocatable-memory scrub and attempts poweroff, with fallback termination requests if the preferred path returns. Several containment steps are best effort so one failure does not prevent later attempts.

Panic Button requires an explicit activation in its confirmation window. USB Nuke instead consumes an armed marker when udev reports a matching whole USB storage device removal. The marker arms all storage removals matching the installed udev rules. The trigger submits the Panic service, which owns the subsequent containment and termination sequence.

The emergency kernel uses the RAM map collected during arming, followed by the allocatable-memory scrub. See [Nuke Kernel](docs/system/session/NUKE-KERNEL.md), [Panic](docs/system/session/PANIC.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
