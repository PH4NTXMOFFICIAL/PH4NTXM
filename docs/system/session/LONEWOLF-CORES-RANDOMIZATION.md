# [ LONE WOLF CORES RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lone Wolf CPU and memory persona from the shared configuration selected by the Lone Wolf seed.

## [ STARTUP ]

Runs after the Lone Wolf hardware identity provides the product and device class.

## [ RUNTIME ]

Writes the processor, RAM, architecture, and model fields to `/run/ph4ntxm/cores_env`.
Uses the same CPU/RAM catalog as Linux and Windows. Active CPUs and usable memory respect host limits; installed memory and processor totals retain the selected configuration. Publishes the completed environment atomically.

## [ SOURCE ]

[ph4ntxm-lonewolf-cores-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-cores-randomization.sh)
