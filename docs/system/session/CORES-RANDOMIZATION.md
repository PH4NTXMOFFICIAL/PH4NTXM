# [ CORES RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Linux/Windows processor and memory capability profile used by protected reporting and downstream components.

## [ STARTUP ]

Reads the hardware persona, device family, SKU, and session seed. Device class and hardware era define the permitted capability ranges.

## [ RUNTIME ]

Selects reported cores, threads, and RAM within the profile's bounds. Reported RAM is clamped to usable host memory.  
CPU vendor, architecture, family, model, stepping, and features follow the selected hardware ecosystem. Older and compact profiles receive appropriate capability ceilings.  
Writes `/run/ph4ntxm/cores_env` for CPU reporting, GPU, screen, browser, and other consumers. Values are shared through this completed runtime environment.

## [ SOURCE ]

[ph4ntxm-cores-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-cores-randomization.sh)
