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

PH4NTXM is a Linux Live Operating System with an embedded Adaptive Identity Engine.  
Each session is stateless, disposable, and non-reusable.  
It’s built for environments where compromise and deep inspection are expected.  
PH4NTXM builds a linked identity that stays consistent during execution.  
Every boot starts fresh and the operator selects a boot mode.  
PH4NTXM builds the required identity profile and applies the matching environment characteristics.  
The session is then exposed to the user, ready for use.

## [ BOOT MODES ]

During boot, on the GRUB menu, you can choose between:

LINUX: Linux-aligned profile.  
WINDOWS: Windows-aligned profile.  
LONE WOLF: Linux-aligned Tor system-wide profile.

The selected mode is fixed for the complete live session.

## [ PH4NTXM ]

PH4NTXM keeps the linked identity model across the complete runtime chain.  
Identity, hardware, GPU, screen, browser, DHCP, network, DNS, firewall, and timing values follow the active session profile.  
Linux and Windows traffic is fail-closed through the Packet Transformation Engine.  
Lone Wolf uses a dedicated Tor-only firewall and DNS bridge with no clearnet fallback.  
PH4NTXM Boot Pilot and PH4NTXM Health report the main protection chains from their real runtime state.  
Normal shutdown and emergency controls use the common Nuke Kernel sequence.

## [ EDITIONS ]

ABYSS: The default dark navy appearance, using PH4NTXM-Abyss with cyan and magenta accents.  
GHOST: A light pearl-white appearance, using PH4NTXM-Ghost with cyan and magenta accents.

Choose the edition when building the ISO. Both editions include the same system components, protection settings, and Linux, Windows and Lone Wolf boot modes. Each ISO contains only its selected PH4NTXM theme and backgrounds; both editions remain available in this repository.

See [BUILD EDITIONS](docs/build/BUILD-EDITIONS.md) for appearance details and source layout.

## [ GETTING STARTED ]

Build on Debian 13 `trixie` amd64:

```bash
sudo apt update
sudo apt install git live-build
git clone https://github.com/PH4NTXMOFFICIAL/PH4NTXM.git
cd PH4NTXM
sudo ./build.sh --edition abyss
```

For Ghost, use `sudo ./build.sh --edition ghost` as the build command instead.

Run commands in order and stop if one fails. The build script runs `lb config` and `lb build`, then copies the completed ISO and checksum into a new directory under `output/`.  
See [INSTALLATION.md](INSTALLATION.md) for rebuild and USB instructions.

## [ EXECUTION REQUIREMENTS ]

PH4NTXM is intended for bare-metal use.  
Virtualized environments compromise its security model.

## [ DOCUMENTATION ]

[ARCHITECTURE.md](ARCHITECTURE.md)  
[THREAT_MODEL.md](THREAT_MODEL.md)  
[DISTRIBUTION.md](DISTRIBUTION.md)  
[INSTALLATION.md](INSTALLATION.md)  
[TRADEMARKS.md](TRADEMARKS.md)  
[LEGAL_NOTICE.md](LEGAL_NOTICE.md)  
[CONTRIBUTING.md](CONTRIBUTING.md)  
[SECURITY.md](SECURITY.md)

Component documentation is available in [docs](docs/README.md).

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
