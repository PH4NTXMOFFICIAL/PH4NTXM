# [ LINK BLOCK ]

## [ OVERVIEW ]

Brings loopback up, takes physical network interfaces down, and disables swap.

## [ STARTUP ]

Runs at the start of the protected network sequence.

## [ RUNTIME ]

Waits briefly for udev, enumerates devices with a physical device entry, and attempts to lower each link.  
Collects failures and reports an unsuccessful startup result if any physical interface remains unblocked or swap cannot be disabled.

## [ SOURCE ]

[ph4ntxm-link-block.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-block.sh)
