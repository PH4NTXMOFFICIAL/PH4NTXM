# [ LONEWOLF SCREEN GENERATOR ]

## [ OVERVIEW ]

Derives Lonewolf viewport metadata from the generated screen profile.

## [ STARTUP ]

Runs after Lonewolf `screen_env` is available.

## [ RUNTIME ]

Reads nominal dimensions and pixel ratio, derives CSS viewport dimensions with seeded UI offsets, and clamps the resulting values.  
Publishes the completed viewport metadata atomically to `/run/ph4ntxm/browser_env`.

## [ SOURCE ]

[ph4ntxm-lonewolf-screen-generator.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-screen-generator.sh)
