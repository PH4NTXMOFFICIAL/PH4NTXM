# [ CLOCK FUZZ ]

## [ OVERVIEW ]

Applies a mode-specific boot-time clock offset and maintains bounded timing variation during the session.

## [ STARTUP ]

Reads the mode and its identity seed, mixes in the kernel boot identifier, and acquires the lifetime engine lock before applying initial settings.

## [ RUNTIME ]

Linux offsets span ±20 seconds, Windows ±60 seconds, and Lonewolf ±90 seconds.  
Tick ranges are 9994–10006, 9988–10012, and 9985–10015 respectively. Periodic events introduce signed 10–41 millisecond adjustments.  
The profile is saved atomically under `/run/ph4ntxm/clock-fuzz-profile`. Restart resumes validated state without repeating the initial offset.  
Readiness requires successful initial application. NTP disablement is requested; its failure is tolerated.

## [ SOURCE ]

[ph4ntxm-clock-fuzz.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-clock-fuzz.sh)
