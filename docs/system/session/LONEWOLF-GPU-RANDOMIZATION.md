# [ LONE WOLF GPU RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Lone Wolf GPU persona, keeping vendor, family, renderer, and graphics capabilities aligned.

## [ STARTUP ]

The Lone Wolf one-shot service follows its hardware generator. It requires a 64-digit lowercase `lonewolf_seed`, 16-digit `boot_jitter`, readable `hardware_profile`, and nonempty profile and GPU model fields.

The seed and jitter are validated prerequisites. The renderer itself is taken directly from the selected catalog entry, so it stays aligned with the system and CPU model.

## [ RUNTIME ]

Intel profiles select Mesa, AMD selects Mesa/RADV, and NVIDIA selects its proprietary loader only when the kernel module and `libGLX_nvidia.so` are present. Otherwise NVIDIA uses Mesa. These branches use GL 4.6 and GLSL 460. ASPEED and Matrox use GL 3.1 and GLSL 140.

Vendor strings follow the GPU family. Intel UHD uses `Intel Inc.`, while Iris/Xe use `Intel Open Source Technology Center`. AMD, NVIDIA, ASPEED and Matrox use their corresponding strings. Extension masks follow the selected branch.

The output includes Mesa version, extension, vendor and renderer overrides, the `__GL_*` identity variables, and an NVIDIA loader variable when selected. Shared `PH4NTXM_GPU_*` and GL identity exports let other PH4NTXM components consume the same profile.

The environment adds `/usr/local/lib/libph4ntxm-gl-spoof.so` to `LD_PRELOAD` once, preserving existing entries. A temporary file is written, made `0644` and renamed to `/run/ph4ntxm/gpu_env`. A required validation or write failure stops the new publication.

The following resource and screen stages read this shared output. Login shells can also import it through [GPU Environment](GPU-ENVIRONMENT.md). Tor Browser is launched with its own explicit environment, so these desktop exports should not be confused with normal Firefox persona overrides inside Tor Browser.

## [ CHECKS ]

Compare `gpu_env` with `hardware_profile`, including family, renderer and selected stack. Check NVIDIA module/library availability when the stack differs from the catalog vendor name.

If desktop and browser observations differ, inspect each launch environment. Use [Tor Browser](TOR-BROWSER.md) to assess its clean environment and readiness checks separately.

## [ SOURCE ]

[ph4ntxm-lonewolf-gpu-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-gpu-randomization.sh)
