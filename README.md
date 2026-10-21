<p align="center">
  <img src="docs/assets/branding/banner.png" alt="PH4NTXM Banner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-cyan" alt="Platform">
  <img src="https://img.shields.io/badge/Build-Manual-cyan" alt="Build">
  <img src="https://img.shields.io/badge/License-GPL3-cyan" alt="License">
  <img src="https://img.shields.io/github/stars/PH4NTXMOFFICIAL/PH4NTXM?style=social" alt="Stars">
  <img src="https://img.shields.io/badge/OpSec-Active-magenta" alt="OpSec">
</p>

# [ PH4NTXM OFFICIAL REPOSITORY ]

Codename: Most Wanted.

## [ OVERVIEW ]

PH4NTXM is a Debian-based Linux operating system that runs live from USB. Once the system has fully loaded into RAM, you can safely remove the boot media.

## [ DISPOSABLE SESSIONS ]

Every boot creates a disposable session for your selected mode. The Adaptive Identity Engine checks the boot machine ID and creates a seed linking the hostname, MAC addresses and reported hardware. Browser and network settings use the relevant session values to keep the profile consistent.

At shutdown, Nuke blocks networking, ends the live user's programs and attempts RAM scrubbing before powering off. The session is discarded. The next boot creates a new one.

The setup screen asks you to choose and confirm a session password for screen unlock and administrator actions. An optional, different emergency password immediately requests Panic when entered at screen unlock, without confirmation. It has no special effect in other password prompts. Password setup repeats on each boot.

## [ BOOT MODES ]

Choose a mode in the boot menu. It stays active until shutdown. All three modes use the same Debian desktop and PH4NTXM tools.

## [ LINUX ]

Linux uses a Linux-aligned identity profile with matching hardware details, browser settings and network behavior. The browser is Firefox ESR. Application connections pass directly through PH4NTXM's Packet Transformation Engine and firewall. DNS uses encrypted connections to external resolvers.

## [ WINDOWS ]

Windows uses a Windows-aligned identity profile with matching hardware details, browser settings and network behavior. The browser is Firefox ESR. Application connections pass directly through PH4NTXM's Packet Transformation Engine and firewall. DNS uses encrypted connections to external resolvers.

## [ LONE WOLF ]

Lone Wolf uses an independent Linux-aligned identity profile with a dedicated Tor network configuration. The browser is Tor Browser. Supported application connections pass through Tor under PH4NTXM's dedicated firewall rules. DNS also passes through Tor.

Each boot waits for a password-authenticated Direct Tor or obfs4 bridge choice in Boot Pilot. Bridge mode permits only the selected public IPv4 endpoints and never automatically falls back to direct Tor. Settings remain in RAM.

Tor Browser opens after the protection and Tor readiness checks pass. If Tor becomes unavailable, the firewall blocks direct application connections. IPv6 and application UDP traffic are blocked outside the permitted connection-setup rules.

## [ DESKTOP TOOLS ]

Check your system:

Boot Pilot shows readiness, connects to Wi-Fi and opens your mode's browser.

Identity displays current identifiers.

Health provides detailed reports and a mode-aware Browser Check.

The OpSec Suite adds network, kernel, process and radio inspection, connection monitoring and file shredding.

Browse with controlled file access:

Browser Airlock optionally runs Firefox or Tor Browser with isolated file and desktop access. Open it from PH4NTXM Apps, import selected files and explicitly export downloads from private RAM. The usual browser shortcuts keep their existing behavior.

Open documents, archives and media:

Document Airlock converts supported documents into a previewable raster PDF. Supported encrypted documents unlock inside the offline guest.

Archive Airlock inspects archives and opens selected files through isolated viewers. Supported encrypted ZIP entries unlock inside the offline guest.

Image and media viewers provide separate offline sandboxes.

Vault keeps explicitly selected files in private RAM and exports encrypted `.ph4vault` copies for manual use in a later session.

Metadata Cleaner compares supported metadata before and after offline cleaning, then exports a separate copy.

App Airlock runs applications and scripts offline with selected files in a private RAM workspace. Stop execution before explicitly exporting results.

Clipboard Guard optionally clears copied content after a chosen timeout, with separate coverage for middle-click selections. It starts disabled, reads only ownership metadata and keeps no clipboard history. Closing its controls leaves enabled protection running.

Review devices and application networking:

Opening an unmounted disk through the desktop requires the session password. After unmounting, the next mount asks again. Mounted files remain accessible.

USB Guard optionally preserves current USB connections and blocks new devices pending approval. Enable, Allow and Disable require the session password. Approvals are temporary.

Net Guard optionally requires approval for each live-user process execution before outbound IP access. Enable, Allow and Disable require the session password. Approvals are temporary.

Session Guard optionally checks generated identity consistency and protection readiness every 10 seconds. It warns about detected failures and monitored MAC changes. Enable and Disable require the session password. Lockdown remains an explicit action.

Block networking or end the session:

Lockdown blocks network traffic. Disabling it restores your mode's rules.

Panic Button requests emergency termination after confirmation.

Armed USB Nuke triggers the same sequence when matching storage is removed.

Dead Man's Switch optionally requests Panic when an authenticated countdown expires. Arm, Renew and Disarm require the session password. The silent timer continues after closing its window or locking the screen.

See the [component pages](docs/README.md) for supported formats, controls, limits and troubleshooting.

## [ EDITIONS ]

ABYSS: dark navy, cyan and magenta. The default PH4NTXM appearance.

GHOST: pearl-white surfaces with the same cyan and magenta accents.

Both share the custom icons, cursor theme, rounded windows and subtle transparency. Choose the appearance you prefer. Every boot mode and protection component is included in either edition.

The edition is selected when building the ISO. See [Build Editions](docs/build/BUILD-EDITIONS.md) for the appearance details.

## [ GETTING STARTED ]

Build your edition on Debian 13 `trixie` amd64:

```bash
sudo apt update
sudo apt install git live-build
git clone https://github.com/PH4NTXMOFFICIAL/PH4NTXM.git
cd PH4NTXM
sudo ./build.sh --edition abyss
```

Prefer Ghost? Use `sudo ./build.sh --edition ghost` for the last command.

Your completed ISO and checksum appear under `build/<edition>/`. Follow [INSTALLATION.md](INSTALLATION.md) to verify the image and prepare your boot media.

On your first boot, start with Boot Pilot and follow the protection checks before opening the browser.

PH4NTXM is intended to boot directly on a physical computer. Virtual machines are useful for development and functional checks. Document and Archive Airlock additionally need hardware virtualization enabled and access to KVM, Linux's virtualization support.

## [ DOCUMENTATION ]

Want to see how the pieces connect? Start with [ARCHITECTURE.md](ARCHITECTURE.md). For a particular feature, the [documentation index](docs/README.md) leads to its behavior, checks and source.

- [INSTALLATION.md](INSTALLATION.md). Build and boot-media instructions.
- [THREAT_MODEL.md](THREAT_MODEL.md). The model behind the system and its scope.
- [SECURITY.md](SECURITY.md). Security reporting and review.
- [DISTRIBUTION.md](DISTRIBUTION.md). The distribution model.
- [CONTRIBUTING.md](CONTRIBUTING.md). How to contribute.
- [TRADEMARKS.md](TRADEMARKS.md) / [LEGAL_NOTICE.md](LEGAL_NOTICE.md). Project identity and legal notices.

## [ CONTRIBUTING ]

Audits, testing, validation and patches are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution details and policy.

## [ SUPPORT ]

PH4NTXM is an independent project. Optional donations support ongoing development and research.

Monero (XMR):

43p2cFkaNaaTn2GGgjUab94Qu3TqRWHxbZcmojuqTPZ2WMp8WJS5iKB5AJJtqYRmwRE9Cx3RBHLgiZxByMj2f5HoA6gMS2h

## [ LICENSE & LEGAL ]

PH4NTXM is licensed under GNU GPL v3.0.  
The project is intended for lawful security research and controlled environments.  
Operators remain responsible for compliance with local laws.

## [ CONTACT ]

Email: [ph4ntxmofficial@proton.me](mailto:ph4ntxmofficial@proton.me)  
PGP: ph4ntxm-public-key.asc  
Encrypted communication is preferred.
