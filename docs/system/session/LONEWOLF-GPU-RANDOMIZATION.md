# [ LONEWOLF GPU RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lonewolf GPU persona, keeping vendor, family, renderer, and graphics capabilities aligned.

## [ STARTUP ]

Validates the Lonewolf seed and boot jitter. Reads the generated DMI product and vendor to determine device class.

## [ RUNTIME ]

Business, ultrabook, gaming, consumer, desktop, Apple, and server profiles select from their allowed GPU families. Seeded choices determine vendor, family, and renderer.  
Intel uses Mesa and AMD uses Mesa/RADV settings. Supported Apple models receive their matching Intel or AMD renderer. Server profiles use the ASPEED family. NVIDIA uses its proprietary loader only with the required gaming profile and runtime support.  
Writes capabilities, extension settings, renderer, vendor, and GL shim environment atomically to `/run/ph4ntxm/gpu_env`.

## [ SOURCE ]

[ph4ntxm-lonewolf-gpu-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-gpu-randomization.sh)
