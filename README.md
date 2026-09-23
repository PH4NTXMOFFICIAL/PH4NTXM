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

<p align="center">
  <a href="https://iguru.gr/ph4ntxm-proto-elliniko-debian-live-linux-gia-cybersecurity-kai-privacy/"><img src="https://img.shields.io/badge/iGuru.gr-Featured-cyan" alt="Featured on iGuru.gr"></a>
  <a href="https://linuxsecurity.com/features/ph4ntxm-linux-disposable-identity"><img src="https://img.shields.io/badge/LinuxSecurity.com-Featured-gold" alt="Featured on LinuxSecurity.com"></a>
</p>

# [ PH4NTXM OFFICIAL REPOSITORY ]

Codename: Most Wanted.

## [ OVERVIEW ]

PH4NTXM is a Debian-based Linux operating system that runs live from USB. Once the system has fully loaded into RAM, you can safely remove the boot media.

## [ DISPOSABLE SESSIONS ]

Every boot creates a new, disposable session based on your selected mode. The Adaptive Identity Engine first checks the boot machine ID and creates a random seed, the starting value used to build the session identity. From there, the setup stages generate the computer name and MAC addresses and prepare the reported hardware details, including processor, memory, graphics and screen information. Browser and network settings use the relevant session values and mode to keep the resulting profile consistent.

The session is used once and is not saved for reuse. At shutdown, Nuke blocks networking, ends the live user's programs and starts best-effort available RAM scrub before powering off. The temporary session is discarded. Your next boot creates a new one.

At boot, the PH4NTXM setup screen asks you to choose and confirm a password for this session. Select Start PH4NTXM to open the desktop. Use it to unlock the screen and authorize administrator actions. Emergency protection stays available without a password prompt. The next boot asks you to choose a password again.

## [ BOOT MODES ]

Choose a mode in the boot menu. It stays active until shutdown. All three modes use the same Debian desktop and PH4NTXM tools.

## [ LINUX ]

Linux uses a Linux-aligned identity profile with matching hardware details, browser settings and network behavior. The browser is Firefox ESR. Application connections pass directly through PH4NTXM's Packet Transformation Engine and firewall. DNS uses encrypted connections to external resolvers.

## [ WINDOWS ]

Windows uses a Windows-aligned identity profile with matching hardware details, browser settings and network behavior. The browser is Firefox ESR. Application connections pass directly through PH4NTXM's Packet Transformation Engine and firewall. DNS uses encrypted connections to external resolvers.

## [ LONE WOLF ]

Lone Wolf uses an independent Linux-aligned identity profile with a dedicated Tor network configuration. The browser is Tor Browser. Supported application connections pass through Tor under PH4NTXM's dedicated firewall rules. DNS also passes through Tor.

Tor Browser opens after the protection and Tor readiness checks pass. If Tor becomes unavailable, the firewall blocks direct application connections. IPv6 and application UDP traffic are blocked outside the permitted connection-setup rules.

## [ DESKTOP TOOLS ]

Check your system:

Boot Pilot shows protection status, helps you connect to Wi-Fi and opens the browser for your mode. Identity displays the current identifiers, and Health explains the checks in more detail. The OpSec Suite includes Network, Kernel, Process, Radio, ConnWatch and Shredder for inspection, monitoring and confirmed remediation actions where supported.

Open documents and media separately from your desktop files:

Document Airlock converts supported documents in a temporary environment without network access. Preview the pages, then export a new PDF made from those page images. Image and media viewers also use isolated offline environments to open the files you select.

Block networking or start an emergency shutdown:

Enable Lockdown to block network traffic, then disable it to restore your mode's network rules. Panic Button starts emergency termination after confirmation. USB Nuke lets a matching storage-device removal trigger the same sequence when armed.

Each tool has a dedicated [component page](docs/README.md) when you want to understand its behavior or follow a reported issue.

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

Your completed ISO and checksum appear under `output/`. Follow [INSTALLATION.md](INSTALLATION.md) to verify the image and prepare your boot media.

On your first boot, start with Boot Pilot and follow the protection checks before opening the browser.

PH4NTXM is intended to boot directly on a physical computer. Virtual machines are useful for development and functional checks. Document Airlock additionally needs hardware virtualization enabled and access to KVM, Linux's virtualization support.

## [ DOCUMENTATION ]

Want to see how the pieces connect? Start with [ARCHITECTURE.md](ARCHITECTURE.md). For a particular feature, the [documentation index](docs/README.md) leads to its behavior, checks and source.

- [INSTALLATION.md](INSTALLATION.md). Build and boot-media instructions.
- [THREAT_MODEL.md](THREAT_MODEL.md). The model behind the system and its scope.
- [SECURITY.md](SECURITY.md). Security reporting and review.
- [DISTRIBUTION.md](DISTRIBUTION.md). The distribution model.
- [CONTRIBUTING.md](CONTRIBUTING.md). How to contribute.
- [TRADEMARKS.md](TRADEMARKS.md) / [LEGAL_NOTICE.md](LEGAL_NOTICE.md). Project identity and legal notices.

## [ CONTRIBUTING ]

Contributions are welcome.  
Auditing, testing, validation work, and patches are always appreciated.  
Thanks for the contributions, we’ll review them, and if they fit the model, we’ll add them.  
See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution details and policy.

## [ SUPPORT ]

PH4NTXM is an independent project.  
Donations are optional and never required, and it is fully understood that many may not be able to contribute.  
If you choose to support the project, it is genuinely appreciated and directly helps ongoing development and research.  

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
