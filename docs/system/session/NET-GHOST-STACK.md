# [ NET GHOST STACK ]

## [ OVERVIEW ]

Creates bounded local network topology artifacts for Linux and Windows sessions.

## [ STARTUP ]

Uses the persona seed and boot jitter to select interface names and the generated device set.

## [ RUNTIME ]

Creates dummy and bridge interfaces with session-aligned MAC addresses. Synthetic addressing uses documentation ranges, including `192.0.2.0/24` and `198.51.100.0/24`.  
Where assigned, addresses use `/32` and `noprefixroute`. The generated topology remains local with IP forwarding disabled.  
Records successfully created devices under `/run/ph4ntxm` so reporting reflects actual runtime artifacts. The normal-mode stack keeps its intended loose reverse-path filtering.

## [ SOURCE ]

[ph4ntxm-net-ghost-stack.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-ghost-stack.sh)
