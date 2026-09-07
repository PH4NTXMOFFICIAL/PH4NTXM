# [ LONEWOLF SCREEN RANDOMIZATION ]

## [ OVERVIEW ]

Generates Lonewolf display metadata from the GPU, device class, seed, and boot jitter.

## [ STARTUP ]

Runs after the Lonewolf GPU and cores environments are available.

## [ RUNTIME ]

Uses hardware and graphics class to select nominal resolution, refresh rate, pixel ratio, and display identity.  
Publishes the selected dimensions, scale, and display-class fields atomically to `/run/ph4ntxm/screen_env`.

## [ SOURCE ]

[ph4ntxm-lonewolf-screen-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-screen-randomization.sh)
