# [ FONTS RANDOMIZATION ]

## [ OVERVIEW ]

Builds a mode-specific Fontconfig profile under `/run/ph4ntxm/fonts-active`.

## [ STARTUP ]

Uses the active mode and installed font files.  
Rebuilds the session's active font directory on each run.

## [ RUNTIME ]

Selects available extra fonts, applies mode-specific inclusion rules, and refreshes the font cache for that profile.  
Linux selects extra fonts, Windows combines Microsoft fonts with selected compatible extras, and Lonewolf selects a smaller extra set.  
The generated `fonts.conf` defines the search paths and rejected font groups.

## [ SOURCE ]

[ph4ntxm-fonts-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-fonts-randomization.sh)
