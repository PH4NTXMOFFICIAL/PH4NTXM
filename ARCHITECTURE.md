# [ ARCHITECTURE ]

## [ OVERVIEW ]

PH4NTXM builds a linked runtime identity at boot and applies it through several cooperating layers. Identity generators prepare the session values. Wrappers expose selected hardware and browser views. Network workers and guardians enforce the selected traffic path. Desktop tools report those states and request explicit actions.

The shared state is the connection between these layers. A generated file, a completed service and a fresh readiness record each mean something different. The system checks them together where required.

## [ SOURCE AND BUILD LAYOUT ]

`config/includes.chroot` supplies installed services, helpers, launchers, policies and component sources. Build hooks compile or install them. Package lists supply distribution packages.

`build.sh` combines the shared configuration with `editions/abyss` or `editions/ghost` in a locked, independent `build/<edition>` workspace. It runs live-build and retains that edition's latest ISO/checksum.

Both editions share the protection chain and boot modes. XFCE uses Picom GLX for rounded windows, selective opacity and background blur, with XFWM compositing disabled. [Build Editions](docs/build/BUILD-EDITIONS.md) describes appearance settings and overlays.

## [ MODE AND BOOT FLOW ]

The boot parameter `ph4ntxm.mode` selects `linux`, `windows` or `lonewolf`. Initialization falls back to Linux for a missing or invalid selection, writes `/run/ph4ntxm/mode` and creates the branch marker. Later components validate this recorded mode.

The main dependency stages are:

1. Select and contain: lower physical links, disable swap, load the emergency crash kernel and lock further kexec loading.
2. Prepare identity: validate the boot machine ID, establish the mode's seed, select hardware and apply hostname/MAC state.
3. Prepare consumers: generate related hardware, GPU, CPU/resource, screen, browser, DHCP and kernel-network data.
4. Prepare networking: load the normal nftables/packet-worker path or Lone Wolf's dedicated policy and guardian, alongside clock/resolver prerequisites.
5. Release adapters: verify prerequisites, apply hotplug protection, refresh udev, verify again and raise links before NetworkManager.
6. Supervise operation: guardians maintain protection while Boot Pilot combines desktop checks. Lone Wolf establishes Tor/DNS readiness after connectivity permits bootstrap.

This is a dependency graph, not one serial script. Link release does not establish readiness for every desktop feature. See [Boot Flow](docs/system/session/BOOTFLOW.md).

## [ RUNTIME STATE AND READINESS ]

Most generated system state lives under `/run/ph4ntxm`. Private browser and file-handling sessions use RAM-backed `/run/user/UID` or `/tmp`, depending on the component.

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

Session setup optionally stores a root-only emergency password hash in `/run/ph4ntxm-session-auth`. Only XFCE Screensaver's dedicated PAM service checks it after normal authentication fails. An exact match immediately requests Panic and denies unlock. Login, sudo and guard authentication remain separate.

## [ LINKED IDENTITY AND HARDWARE VIEWS ]

Linux and Windows identity initialization validates the existing boot machine ID and derives a new seed when one is absent. The catalog selector chooses a compatible system entry. Hostname and physical-interface MAC values follow that seed. Lone Wolf uses an independent seed and per-interface locally administered MAC records.

The catalog ties DMI, CPU, RAM and graphics specifications together. Hardware generation supplies session UUIDs and serials. Resource generation reports the chosen model's full CPU topology and installed RAM capacity: active/total CPU counts and usable/installed RAM capacities agree with that entry, even when they exceed the host.

The dependency chain carries the selected profile through GPU and resource generation into CPU and screen consumers. Missing or inconsistent catalog data fails the relevant stage instead of selecting an unrelated replacement specification.

Command-line inventory wrappers run native tools with generated reporting files, private mounts, a query library and a seccomp supervisor. This keeps native output formatting while extending supported hardware-query handling to descendants. XFCE Task Manager uses the query library for persona totals and scaled memory figures while retaining native process controls. `ph4ntxm-hardware-run` applies the supervised view to an explicitly launched application.

[Hardware Views](docs/system/session/HARDWARE-VIEWS.md) and [Cores Randomization](docs/system/session/CORES-RANDOMIZATION.md) describe the reporting boundary, persona resource fields and CPU affinity mapping.

## [ GRAPHICS, SCREEN, FONTS AND BROWSER ]

GPU generation exports the selected vendor/renderer profile for participating environment settings and the GL identity shim. Screen stages produce nominal display metadata, refresh rate, pixel ratio and viewport data. The generated values feed the desktop and browser reporting paths.

Font setup builds the active Fontconfig profile by selecting complete families on each run, independently of the hardware seed. Windows includes the installed Microsoft fonts and available Cascadia Code/Mono families. The generated font set and the browser environment must be present before the normal browser wrapper launches.

Linux and Windows use Firefox ESR through a diverted command wrapper. It validates protected runtime files, obtains the installed Firefox version and substitutes the mode template into a private runtime profile. Unresolved identity placeholders stop launch. A nonblocking lock keeps one browser session, while subsequent launches forward supported arguments to that session. Normal launches reuse the boot session's profile.

Lone Wolf's browser gate verifies the Tor Browser installation and restricts the ordinary Firefox path. Its launcher checks browser integrity state, current firewall/Tor readiness and loopback listeners, then creates a fresh temporary home. It starts with an explicitly built environment and system Tor at `127.0.0.1:9050`, without the normal Firefox persona overrides. Safest is the default security level, and browser restarts retain the temporary session until the browser closes.

See [Browser](docs/system/session/BROWSER.md), [Browser Mode](docs/system/session/BROWSER-MODE.md) and [Tor Browser](docs/system/session/TOR-BROWSER.md).

## [ NORMAL NETWORK PATH ]

Linux and Windows first apply bounded kernel TCP/IP settings. Ordinary TTL/hop-limit values are 64 and 128 respectively. Ports, retry timing, timestamps and other settings follow the selected profile. Required writes are read back. Runtime entropy means another normal network-generation run can choose new values within those bounds.

DHCP generation writes the mode's client parameters and connection defaults for NetworkManager's internal DHCP client. Linux and Windows use different vendor and session settings while preserving the already prepared MAC. The dispatcher and physical hotplug helper keep later connection/device handling aligned with that state.

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

The dedicated NAT policy redirects application DNS to local port 53 and ordinary application TCP to Tor's transparent port 9040. Tor's account has its own controlled external TCP path. Each boot waits for an authenticated Direct Tor or obfs4 choice. Bridge mode limits that path to the selected public IPv4 endpoints, with RAM-only configuration and no automatic direct fallback. DHCP has explicit connection-setup exceptions. Arbitrary application UDP is blocked. OnionShare uses system Tor through a restricted Unix control broker instead of starting bundled Tor.

The DNS bridge exposes local TCP/UDP 53 and forwards to Tor DNSPort 5353 without dnsmasq caching. Readiness also requires transparent/SOCKS listeners, current connection configuration and authenticated control-socket replies matching that configuration and reporting bootstrap 100 with `TAG=done`. The bridge refreshes `tor-ready` while those checks pass and removes it on failure.

The firewall guardian checks the policy independently. Its process can be active under emergency default-drop rules while ordinary Lone Wolf readiness is absent. Browser launch requires the ready profile, not just a running guardian or Tor process.

See [Lone Wolf Setup](docs/system/session/LONEWOLF-SETUP.md) and [DNS Bridge](docs/system/session/LONEWOLF-DNS-BRIDGE.md).

## [ GUARDIANS AND LOCKDOWN ]

Firewall guardians compare requested profile, trusted source policy and a hash of the live stateless ruleset. Unexpected changes clear readiness and trigger restrictive recovery before a validated profile is restored. Lone Wolf includes the source digest in its readiness contract. Normal modes also coordinate with the packet-engine guard.

The engine guard checks actual egress classifier layout and program identity against the physical interface and session data. Its two-second loop can reapply protection or hold affected links down. Exit cleanup clears readiness and attempts physical link containment.

Lockdown uses a shared firewall lock and mode-aware helper. Normal-path transitions seal interfaces before changing policy and restore eligible saved links only after preparation and verification. Profile/token acknowledgements prevent an old transition response from satisfying a new request.

Transitions apply policy and interface changes in sequence. On failure, recovery keeps the restrictive state while the guardian works to restore a verified profile. Conntrack cleanup can interrupt existing connections. Readiness is published after verification.

See [Lockdown](docs/system/session/LOCKDOWN.md) and [Engine Guard](docs/system/session/PACKET-TRANSFORMATION-ENGINE-GUARD.md).

## [ CLOCK, THERMAL AND MEMORY SERVICES ]

Clock Fuzz applies a mode-bounded initial offset, then maintains tick variation and occasional small adjustments. Valid saved state lets a restarted engine resume without repeating the initial offset. Its readiness notification follows the required clock operations and profile publication.

CPU Lockdown records initial governor/boost settings, requests powersave and disabled boost at 85°C, and attempts restoration at 70°C or below. The service attempts writes to available controls and tolerates unsupported or rejected driver settings.

RAM Seeding allocates one percent of physical RAM reported by native `sysinfo`, fills its private mapping with noise and sparse synthetic fragments, and periodically mutates it. It tries whole-region locking, then smaller chunks. The allocation stays active during operation and is released when Nuke preparation stops the seeding service before scrubbing.

Kernel settings and systemd restrictions follow each component's needs. SSH and OpenSSL configuration prefer supported hybrid post-quantum key exchanges with classical fallback. The application and peer negotiate the supported exchange.

## [ DOCUMENT, ARCHIVE AND MEDIA ISOLATION ]

Document Airlock uses a trusted disposable KVM guest without networking or a shared home. A bounded protocol returns RGB pages. The host validates framing, dimensions and size before previewing and exporting a new raster PDF without the original active structure or metadata.

Archive Airlock reuses the guest infrastructure to list archives and stream one selected regular file into a private RAM workspace. Unsafe paths, links and special files are blocked. After the guest exits, supported files open through isolated viewers or a read-only text preview. Unpacking does not sanitize their contents.

Both Airlocks require KVM, private tmpfs storage and disabled swap. Passwords for supported encrypted inputs travel through private channels, outside command arguments, environment variables and logs. Decryption stays in the guest. Failed output is discarded and retries use fresh guests. Archive and document passwords remain separate, and exported raster PDFs are unencrypted.

Media Viewers use offline namespaces, a private bus/home and nested Xephyr display with read-only inputs. A separate process receives fixed-format audio. Transient user services bound memory, swap, tasks and CPU. These tools budget against actual available RAM and reject managed inventory environments.

[Vault](docs/system/session/VAULT.md) collects selected files in private tmpfs and writes standard age-encrypted ZIP bundles on explicit Export. Manual unlock and review reuse the Airlock guest. A separate, bounded crypto sandbox handles encryption without persisting system configuration or profiles.

[Metadata Cleaner](docs/system/session/METADATA-CLEANER.md) inspects and cleans selected RAM copies with Debian mat2 inside an offline, resource-limited sandbox. Reports compare supported metadata before and after. Explicit Export preserves originals and refuses replacement of existing files.

[App Airlock](docs/system/session/APP-AIRLOCK.md) runs applications and scripts offline in private namespaces with a nested Xephyr display and bounded user services. It shares the host kernel, reuses an explicit RAM workspace and requires stopped execution before exporting regular files.

See [Document Airlock](docs/system/session/DOCUMENT-AIRLOCK.md), [Archive Airlock](docs/system/session/ARCHIVE-AIRLOCK.md), [Vault](docs/system/session/VAULT.md) and [Media Viewers](docs/system/session/MEDIA-VIEWERS.md) for format support, limits and cleanup.

## [ OPERATOR VIEWS AND DIAGNOSTICS ]

Boot Pilot combines identity, network and system readiness before enabling Continue. Browser launch also requires its launcher gates. It provides Wi-Fi controls using volatile NetworkManager profiles that preserve the prepared MAC and disable autoconnect.

Identity displays a snapshot of selected identifiers. Health collects resources, guardian state and termination prerequisites. Critical findings force Unsafe / Not Ready. Its separate Browser Check uses a local Firefox comparison page in normal modes and local Tor Browser evidence in Lone Wolf, without changing browser policy.

[Disk access](docs/system/session/DISK-ACCESS.md) uses a narrow UDisks Polkit rule to require the live user's password for each ordinary desktop filesystem mount. Authentication is not retained between mounts. USB hardware authorization remains independent.

[USB Guard](docs/system/session/USB-GUARD.md) optionally preserves current USB connections and blocks new devices pending password-authenticated approval. [Net Guard](docs/system/session/NET-GUARD.md) optionally gates outbound live-user IP sockets through BPF LSM and cgroup egress checks, independently of nftables. Grants bind to exact process executions. Activation invalidates existing sockets and daemon failure retains denial. Both controls are off at boot and use temporary approvals.

[Session Guard](docs/system/session/SESSION-GUARD.md) optionally checks generated persona consistency, exposed CPU/DMI views, adapter MACs, DHCP/network identity, service outcomes and guardian readiness every 10 seconds. Its root service pins stable evidence at activation and validates intentional Clock Fuzz changes within mode bounds. It records specific incidents and offers explicit Lockdown through desktop notifications, with no automatic response.

The OpSec Suite provides Network, Kernel, Process, Radio, ConnWatch and Shredder. Each presents its own evidence, with confirmed actions where supported.

See [Applications](docs/system/session/PH4NTXM-APPLICATIONS.md), [Health](docs/system/session/HEALTH.md) and [OpSec Suite](docs/system/session/PH4NTXM-OPSEC-SUITE.md).

## [ CONTAINMENT AND TERMINATION ]

Early arming loads the dedicated crash image using the discovered System RAM ranges, then locks kexec loading. Physical release checks require both a loaded image and a locked loader.

Normal termination targets invoke the common Nuke preparation: request Lockdown, block radios/links, terminate the live user, stop RAM seeding, disable swap and attempt cache and allocatable-memory cleanup. The final shutdown hook and Panic path can request the armed crash transition.

The first emergency initramfs reconstructs the memory map and loads the next kernel with `memtest=17`. The following init performs another allocatable-memory scrub and attempts poweroff, with fallback termination requests if the preferred path returns. Several containment steps are best effort so one failure does not prevent later attempts.

Panic Button requires confirmation. USB Nuke triggers the same backend on any matching whole USB storage removal, including boot media. A shared lock and per-attempt tokens protect Arm, Disarm and restoration from stale callbacks.

[Dead Man's Switch](docs/system/session/DEAD-MAN-SWITCH.md) keeps an optional root-owned countdown in RAM using boot time, including suspension. Fresh password authorization controls Arm, Renew and Disarm. Expiry requests Panic without confirmation, notifications or tray indicators. Systemd restarts failed or frozen userspace monitoring without resetting the deadline.

See [Nuke Kernel](docs/system/session/NUKE-KERNEL.md), [Panic](docs/system/session/PANIC.md), [USB Nuke](docs/system/session/USB-NUKE.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
