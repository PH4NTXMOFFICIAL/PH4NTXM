# [ CORES RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Linux/Windows processor and memory capability profile used by protected reporting and downstream components.

## [ STARTUP ]

Reads the selected configuration from the shared hardware catalog.

## [ RUNTIME ]

Exports model-specific CPU topology and memory specifications. Active CPUs and usable RAM are capped to the host; installed RAM remains a supported configuration.
CPU vendor, architecture, family, model, stepping, features and cache sizes follow the same model.
Writes `/run/ph4ntxm/cores_env` for CPU reporting, GPU, screen, browser, and other consumers. Values are shared through this completed runtime environment.

## [ SOURCE ]

[ph4ntxm-cores-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-cores-randomization.sh)
