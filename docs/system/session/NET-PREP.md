# [ NET PREP ]

## [ OVERVIEW ]

Prepares local network state during startup.

## [ STARTUP ]

Runs during network preparation using the live kernel's routing and neighbor state.

## [ RUNTIME ]

Requests route-cache and neighbor-cache cleanup, then sets `tcp_no_metrics_save=1` to disable saving TCP metrics.  
Completes even when an individual cleanup or sysctl request fails.

## [ SOURCE ]

[ph4ntxm-net-prep.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-prep.sh)
