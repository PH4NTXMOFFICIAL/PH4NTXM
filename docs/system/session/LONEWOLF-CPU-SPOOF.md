# [ LONEWOLF CPU SPOOF ]

## [ OVERVIEW ]

Builds the Lonewolf CPU reporting view from `cores_env`.

## [ STARTUP ]

Runs after the Lonewolf cores profile is written.

## [ RUNTIME ]

Builds CPU model, feature, and topology text from the generated profile.  
Installs read-only bind mounts for cpuinfo and the CPU online, present, and possible lists. Partial mount failures trigger cleanup of mounts already installed.

## [ SOURCE ]

[ph4ntxm-lonewolf-cpu-spoof.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-cpu-spoof.sh)
