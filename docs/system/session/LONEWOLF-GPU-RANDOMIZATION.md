# [ LONE WOLF GPU RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lone Wolf GPU persona, keeping vendor, family, renderer, and graphics capabilities aligned.

## [ STARTUP ]

Validates the Lone Wolf session state and reads the shared `hardware_profile`.

## [ RUNTIME ]

Uses the renderer assigned to the selected catalog configuration, without an independent GPU-model draw.
Intel uses Mesa and AMD uses Mesa/RADV settings. Intel-based Apple models retain their matching Intel renderer. NVIDIA uses its proprietary loader when the required runtime support is present.
Writes capabilities, extension settings, renderer, vendor, and GL shim environment atomically to `/run/ph4ntxm/gpu_env`.

## [ SOURCE ]

[ph4ntxm-lonewolf-gpu-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-gpu-randomization.sh)
