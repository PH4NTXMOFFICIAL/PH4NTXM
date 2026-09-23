# [ GPU RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Linux/Windows GPU persona, keeping vendor, family, renderer, and graphics capabilities aligned.

## [ STARTUP ]

The normal-mode one-shot service follows and requires hardware randomization. It reads `hardware_profile` and `persona_seed`, requiring both `PROFILE_ID` and the catalog's `GPU_MODEL` before writing an output.

The renderer is fixed by the chosen hardware configuration. The remaining seeded choice selects an additional extension mask, not another GPU model.

## [ RUNTIME ]

Vendor and family determine the graphics settings:

| Profile | Stack/settings |
| --- | --- |
| Intel | Mesa, GL 4.6 / GLSL 460 |
| AMD | Mesa/RADV, GL 4.6 / GLSL 460 |
| NVIDIA | GL 4.6 / GLSL 460. NVIDIA loader only when module and library are present |
| Apple Intel | Mesa, GL 4.1 / GLSL 410 |
| ASPEED/Matrox | Mesa, GL 3.1 / GLSL 140 |

The NVIDIA branch checks `/sys/module/nvidia` and the `libGLX_nvidia.so` library cache entry. Without both, it selects Mesa. The script also has an Apple non-Intel branch, while the current amd64 catalog uses Intel-based Apple configurations.

Mesa outputs include version, renderer, vendor and extension overrides. The NVIDIA loader branch writes its loader and vendor/renderer variables. Both export the shared `PH4NTXM_GPU_*` and GL identity fields.

The generated shell environment also prepends `/usr/local/lib/libph4ntxm-gl-spoof.so` to `LD_PRELOAD` when it is not already listed. The complete temporary file is changed from `0600` to `0644` and renamed to `/run/ph4ntxm/gpu_env`.

These settings supply the GPU profile to participating launches and reporting tools. Missing inputs or required write failures stop publication of the new environment.

## [ CHECKS ]

Compare the renderer in `gpu_env` with `hardware_profile`, then check the selected loader's availability and the consuming process's environment. The profile's existence alone does not prove that an application received it.

[GPU Environment](GPU-ENVIRONMENT.md) handles login-shell import. [Browser](BROWSER.md) describes the separate wrapper that prepares Firefox's runtime preferences.

## [ SOURCE ]

[ph4ntxm-gpu-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-gpu-randomization.sh)
