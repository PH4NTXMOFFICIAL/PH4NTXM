# [ MODE ]

## [ OVERVIEW ]

Reads the boot mode from the kernel command line and writes `/run/ph4ntxm/mode`.

## [ STARTUP ]

Runs during early startup and reads `ph4ntxm.mode=` from `/proc/cmdline`.

## [ RUNTIME ]

Accepts Linux, Windows, or Lonewolf and defaults to Linux for an invalid value.  
Writes the mode atomically and replaces the normal/Lonewolf marker so later service conditions select the correct chain.

## [ SOURCE ]

[ph4ntxm-mode.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-mode.sh)
