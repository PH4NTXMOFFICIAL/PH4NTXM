# [ LONEWOLF CORES RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lonewolf CPU and memory persona from its seed, boot jitter, and device class.

## [ STARTUP ]

Runs after the Lonewolf hardware identity provides the product and device class.

## [ RUNTIME ]

Writes the processor, RAM, architecture, and model fields to `/run/ph4ntxm/cores_env`.  
Selects bounded processor and RAM values, aligns CPU model fields with the hardware ecosystem, and publishes the completed environment atomically for downstream reporting.

## [ SOURCE ]

[ph4ntxm-lonewolf-cores-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-cores-randomization.sh)
