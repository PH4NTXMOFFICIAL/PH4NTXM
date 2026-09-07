# [ HARDWARE RANDOMIZATION ]

## [ OVERVIEW ]

Builds the Linux/Windows hardware persona used by DMI reporting and downstream identity components.

## [ STARTUP ]

Reads the active mode and session profile. Vendor, device family, and model constrain the generated hardware ecosystem.

## [ RUNTIME ]

Generates BIOS identity, product family and SKU, motherboard, chassis, UUID, and serial fields. Apple and Google ecosystems are restricted to Linux-aligned personas.  
The generated modalias and uevent text follow the same DMI identity. Supported identity files are exposed through read-only runtime mounts.  
State lives under `/run/ph4ntxm/fake_dmi`. CPU, GPU, display, and protected reporting components consume these values for their own profiles.

## [ SOURCE ]

[ph4ntxm-hardware-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-hardware-randomization.sh)
