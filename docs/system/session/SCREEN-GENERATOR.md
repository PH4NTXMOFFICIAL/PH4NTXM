# [ SCREEN GENERATOR ]

## [ OVERVIEW ]

Derives browser viewport metadata from the generated display profile.

## [ STARTUP ]

Runs in Linux and Windows after `screen_env` and `persona_seed` are present.

## [ RUNTIME ]

Uses session state and bounded UI offsets to write `/run/ph4ntxm/browser_env`.  
Reads nominal dimensions, pixel ratio, and display identifiers.  
Applies bounded width and height offsets, determines display count, and installs `browser_env` atomically.

## [ SOURCE ]

[ph4ntxm-screen-generator.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-screen-generator.sh)
