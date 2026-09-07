# [ LONEWOLF NET RANDOMIZATION ]

## [ OVERVIEW ]

Applies the Lonewolf TCP/IP profile using its session seed.

## [ STARTUP ]

Runs before Lonewolf network release with a protected `lonewolf_seed`.

## [ RUNTIME ]

Derives bounded ports, retries, timers, and ICMP settings from named seed inputs.  
Disables TCP timestamps and IPv6, including existing interface settings. Writes the required sysctls and verifies the resulting values.

## [ SOURCE ]

[ph4ntxm-lonewolf-net-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-net-randomization.sh)
