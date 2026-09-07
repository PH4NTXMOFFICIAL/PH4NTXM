# [ OPERATIONAL TOOLS ]

## [ OVERVIEW ]

Groups the tools selected for the PH4NTXM live environment.

## [ STARTUP ]

Package lists define the installed tools. Burp Suite and Metasploit use build-installed launch wrappers and may download components on first use.

## [ RUNTIME ]

Network inspection uses nmap, masscan, tcpdump, Wireshark, DNS utilities, and discovery tools.  
Web testing includes Nikto, dirb, gobuster, WhatWeb, wfuzz, sqlmap, and Burp Suite. Credential work uses Hydra, John, Hashcat, and Crunch.  
Wireless and artifact inspection include aircrack-ng, binwalk, and file. Routing and metadata tools include Tor, WireGuard, ProxyChains, OnionShare, macchanger, and ExifTool.  
Execution follows the active mode's network policy.

## [ SOURCE ]

[ph4ntxm-tools.list.chroot](../../../config/package-lists/ph4ntxm-tools.list.chroot)  
[0090-install-burpsuite-wrapper.chroot](../../../config/hooks/normal/0090-install-burpsuite-wrapper.chroot)  
[0092-install-metasploit-wrapper.chroot](../../../config/hooks/normal/0092-install-metasploit-wrapper.chroot)
