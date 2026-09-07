# [ NET DRIFT ]

## [ OVERVIEW ]

Applies changing netem timing and packet variation to Linux/Windows default-route interfaces.

## [ STARTUP ]

Combines the normal persona seed, boot jitter, and runtime entropy. Qualifying interfaces need an IPv4 address and default route.

## [ RUNTIME ]

Delay, jitter, and loss change every 20–59 seconds. Delay spans 5–150 milliseconds, jitter 1–50 milliseconds, and loss 0–5 percent.  
Wireless jitter is capped at ten milliseconds and loss at one percent. Duplication is 0.02 percent and reordering 0.05 percent.  
Recognized loopback, container, tunnel, bridge, and ghost-interface names are skipped. Handled shutdown attempts cleanup of managed root qdiscs; forced termination can leave them installed.

## [ SOURCE ]

[ph4ntxm-net-drift.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-drift.sh)
