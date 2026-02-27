# PH4NTXM — Official Public Repository

PH4NTXM is a **live-only, stateless operating system** engineered for high-risk forensic research environments.  
It is designed for security professionals operating under the assumption of **inevitable compromise, seizure, or deep forensic inspection**.

> **EXIT EQUALS ERASURE.**

---

## 📄 Documentation

- Technical Overview → TECHNICAL-OVERVIEW.md
- Operational Tools → OPERATIONAL-TOOLS.md
- Distribution → DISTRIBUTION.md

---

## ⚡ Operational Architecture

The system is engineered around **14 core pillars of volatility and forensic resistance**.

### 🛡️ Identity & Fingerprint Armor

- **Identity Dissolution**  
  Hardware IDs, hostnames, and machine fingerprints are regenerated every boot.

- **Dynamic Personas**  
  Automatic generation of region-agnostic operational identities.

- **Clock & Temporal Fuzzing**  
  Subtle clock offsets to disrupt timestamp-based session correlation.

---

### 🌐 Network Untraceability

- **Network Stack Fuzzing**  
  Randomized TCP behavior and packet-level characteristics to prevent passive fingerprinting.

- **Rotating DNS System**  
  New resolver selection at every boot to mitigate metadata tracking.

- **Lockdown Mode**  
  Instant hardware-level network isolation (kill-switch).

- **Tor & Brave Integration**  
  Hardened, anonymous browsing paths enabled by default.

---

### ☣️ Memory & State Destruction

- **Amnesic Live Execution**  
  Entire operating system runs exclusively in volatile RAM. No persistence by design.

- **Nuke Kernel**  
  Dedicated panic kernel (`kexec`) ensuring irreversible memory wiping on exit.

- **Decoy RAM Seeding**  
  Continuous memory contamination with cryptographic noise to defeat cold-boot and post-mortem analysis.

- **USB Removal Nuke**  
  Physical media removal triggers immediate, destructive teardown.

---

### 🔒 System Hardening

- **Sensor Lockdown**  
  Kernel-level detachment of microphone, camera, and audio drivers.

- **Hardened Baseline**  
  ASLR enforcement, namespace restriction, and privileged interface lockout.

- **Volatile Firewall**  
  Real-time brute-force defense operating strictly in-memory.

---

## 🛠 Build Specifications

| Feature      | Specification                          |
|--------------|----------------------------------------|
| Base System  | Debian / XFCE (Hardened)               |
| Architecture | AMD64                                  |
| Execution    | RAM-only (USB removal ready)           |
| Networking   | Tor & Brave by default                 |
| Defense      | Kernel-level sensor lockout            |

---

## 🛡 Licensing & Source Code

PH4NTXM is a **commercial, proprietary operating system**.  
This repository **does not** host source code or binaries for public distribution.

- **Distribution**: Controlled and on-demand  
- **Auditability**: Full source code is provided **only to verified licensees** for independent audit and verification  
- **Terms**: Reproduction or unauthorized redistribution is strictly prohibited

---

## 📩 Contact & Ordering

To request access or verify a build, establish a secure connection using the PGP-encrypted channel below:

- **Email**: `ph4ntxmos@proton.me`  
- **PGP Key**: Available in `ph4ntxm-public-key.asc` within this repository

> **Note**  
> Only PGP-encrypted communications from secure providers will be processed.  
> Clear all metadata from attachments before transmission.

---

## 📜 Legal

PH4NTXM is provided for **lawful security research and authorized auditing only**.  
The operator assumes **all responsibility** for the use of this system.
