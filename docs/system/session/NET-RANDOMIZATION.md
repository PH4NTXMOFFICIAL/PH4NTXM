# [ NET RANDOMIZATION ]

## [ OVERVIEW ]

Applies bounded Linux/Windows kernel TCP/IP values before physical network release.

## [ STARTUP ]

Reads the persona seed, boot jitter, and runtime entropy. The selected mode defines the base network profile.

## [ RUNTIME ]

Configures ports, retries, FIN and keepalive timing, socket buffers, MTU probing, ECN, congestion control, ICMP limits, TTL, and hop limit.  
Writes required settings and reads them back. Missing optional sysctls are skipped; failed required settings prevent successful completion.  
Locally generated delay metadata is kept in `/run/ph4ntxm/net`. Rerunning the service can select new values. The Packet Transformation Engine handles the separate packet-level transformation stage.

## [ SOURCE ]

[ph4ntxm-net-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-randomization.sh)
