# [ GPU RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Linux/Windows GPU persona, keeping vendor, family, renderer, and graphics capabilities aligned.

## [ STARTUP ]

Reads the renderer assigned to the selected configuration in `hardware_profile`.

## [ RUNTIME ]

Uses the catalog renderer consistently with the CPU and system model.
Intel uses Mesa and AMD uses Mesa/RADV settings. NVIDIA uses its proprietary loader when the required runtime support is present, otherwise Mesa. The amd64 catalog uses Intel-based Apple configurations.
Writes GL/GLSL capabilities, extension settings, vendor, renderer, and shim environment atomically to `/run/ph4ntxm/gpu_env`. Participating processes inherit this profile.

## [ SOURCE ]

[ph4ntxm-gpu-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-gpu-randomization.sh)
