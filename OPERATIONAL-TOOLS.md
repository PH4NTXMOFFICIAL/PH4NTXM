# PH4NTXM — Operational Tools

## Overview

This document lists the operational tools included in the default PH4NTXM runtime environment.

All operational tooling integrated into PH4NTXM is presented with custom-designed PH4NTXM application icons for consistent visual identification inside the environment. These tools exist only within the live runtime session and are not persistently installed.

Tool availability may vary depending on build configuration, runtime profile, or operational requirements.

---

## 1. Environmental Security

System hardening and defensive controls protecting the runtime environment.

```
ufw
fail2ban
nftables
unbound
cryptsetup
secure-delete
```

Capabilities:

* Host firewalling and traffic filtering
* Intrusion mitigation
* Secure DNS resolution
* Encrypted device interaction
* Controlled data destruction

---

## 2. Identity & Anonymity

Tools supporting traffic routing, metadata hygiene, and observable identity control.

```
tor
torbrowser-launcher
wireguard-tools
proxychains4
onionshare
macchanger
exiftool
```

Capabilities:

* Network origin abstraction
* Multi-hop routing
* MAC address randomization
* Metadata inspection and removal
* Anonymous file transfer

---

## 3. Reconnaissance & Enumeration

Network and target discovery utilities focused on intelligence gathering.

```
nmap
masscan
dnsutils
whois
traceroute
nikto
dirb
gobuster
whatweb
arp-scan
```

Capabilities:

* Host discovery
* Service enumeration
* DNS intelligence
* Web surface mapping
* Network topology analysis

---

## 4. Network Capture & Analysis

Traffic inspection and low-level network interaction.

```
tcpdump
wireshark
netcat-openbsd
```

Capabilities:

* Packet capture and inspection
* Protocol analysis
* Raw socket communication
* Network debugging

---

## 5. Web Application Testing & Exploitation

Tools for testing application behavior and identifying vulnerabilities.

```
wfuzz
sqlmap
burpsuite
```

Capabilities:

* Input fuzzing
* Automated injection testing
* Intercepting proxy analysis
* Web request manipulation and inspection

---

## 6. Credential & Password Operations

Authentication analysis and password auditing utilities.

```
hydra
john
hashcat
crunch
```

Capabilities:

* Password auditing
* Hash analysis
* Credential testing
* Wordlist generation

---

## 7. Wireless Operations

Wireless network interaction and analysis.

```
aircrack-ng
```

Capabilities:

* Wireless packet capture
* Network auditing
* WPA/WEP analysis

---

## 8. Binary & Artifact Inspection

Tools for examining files, firmware, and unknown binaries.

```
binwalk
file
```

Capabilities:

* Firmware extraction
* Binary structure identification
* Artifact analysis

---

## 9. Exploitation Frameworks

Integrated frameworks supporting controlled exploitation and security research workflows.

```
metasploit-framework
```

Capabilities:

* Exploit development and testing
* Payload generation
* Post-exploitation research
* Modular security assessment workflows

---
