# [ OPSEC CONNWATCH MONITOR ]

## [ OVERVIEW ]

Monitors inbound TCP SYN attempts addressed to local interfaces.

## [ STARTUP ]

Runs as the background ConnWatch service and refreshes the local address list.

## [ RUNTIME ]

Maintains bounded per-source observations and rolling runtime records consumed by the ConnWatch interface.  
Counts source hits and target ports in five-minute windows.  
Writes statistics and bounded alert history under `/run/ph4ntxm-opsec-connwatch` and can notify the desktop when the activity threshold is reached.

## [ SOURCE ]

[ph4ntxm-opsec-connwatch.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-opsec-connwatch.sh)
