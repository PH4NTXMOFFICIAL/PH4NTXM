# [ HARDWARE RANDOMIZATION ]

## [ OVERVIEW ]

Builds the Linux/Windows hardware persona used by DMI reporting and downstream identity components.

## [ STARTUP ]

Reads the active mode and session profile. Vendor, device family, and model constrain the generated hardware ecosystem.

## [ RUNTIME ]

Uses one catalog entry for product, motherboard and chassis identity, with session UUID and serial fields. BIOS and board identity come from model reports; optional fields absent from the source remain unspecified. Apple and Google ecosystems are restricted to Linux-aligned personas.
The generated modalias and uevent text follow the same DMI identity. Supported identity files are exposed through read-only runtime mounts.
State lives under `/run/ph4ntxm/fake_dmi`. CPU, GPU, display, and protected reporting components consume these values for their own profiles.

## [ SOURCE ]

[ph4ntxm-hardware-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-hardware-randomization.sh)
