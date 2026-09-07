# [ OPSEC SUITE ]

## [ OVERVIEW ]

Provides on-demand network, kernel, process, radio, connection, and file-handling tools.

## [ STARTUP ]

Diagnostic launchers run within the live session. Supported remediation actions use their corresponding privileged control paths.

## [ RUNTIME ]

Network inspects routes, DNS, sockets, and namespace state. Kernel checks selected hardening and module settings. Process examines executable paths and verifies process identity before freeze or termination.  
Radio reads wireless device state and offers supported disable actions. ConnWatch reports inbound SYN observations from its background monitor.  
Shredder performs best-effort file overwrite and deletion, retaining files when overwrite fails. Reports and monitor history remain session-local. The live operator retains passwordless sudo.

## [ SOURCE ]

[ph4ntxm](../../../config/includes.chroot/opt/ph4ntxm/)  
[ph4ntxm-opsec-connwatch.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-opsec-connwatch.sh)  
[ph4ntxm-opsec-connwatch](../../../config/includes.chroot/usr/local/bin/ph4ntxm-opsec-connwatch)
