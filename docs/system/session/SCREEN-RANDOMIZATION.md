# [ SCREEN RANDOMIZATION ]

## [ OVERVIEW ]

Generates Linux/Windows nominal display metadata aligned with the hardware and GPU persona.

## [ STARTUP ]

Reads the device class, GPU profile, and session state before selecting the display characteristics.

## [ RUNTIME ]

Chooses dimensions, refresh rate, pixel ratio, connector identity, and optional secondary-display metadata within the device profile. Laptop, desktop, gaming, and supported Apple personas receive matching combinations.  
Writes the generated state under `/run/ph4ntxm` for the separate viewport generator and other consumers. The viewport stage derives bounded UI offsets and reported browser dimensions.  
Linux/Windows Firefox uses the selected profile settings while the display metadata remains shared with participating reporting components.

## [ SOURCE ]

[ph4ntxm-screen-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-screen-randomization.sh)  
[ph4ntxm-screen-generator.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-screen-generator.sh)
