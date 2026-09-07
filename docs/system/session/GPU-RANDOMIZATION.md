# [ GPU RANDOMIZATION ]

## [ OVERVIEW ]

Generates the Linux/Windows GPU persona, keeping vendor, family, renderer, and graphics capabilities aligned.

## [ STARTUP ]

Reads the selected hardware profile and persona seed. Device family constrains the GPU families available to the generator.

## [ RUNTIME ]

Selects a matching Intel, AMD, NVIDIA, or supported Apple renderer. Named seed inputs keep selection repeatable for the profile.  
Intel uses Mesa and AMD uses Mesa/RADV settings. NVIDIA uses its proprietary loader when the required runtime support is present, otherwise Mesa. Apple profiles select the matching Intel or Asahi-oriented settings.  
Writes GL/GLSL capabilities, extension settings, vendor, renderer, and shim environment atomically to `/run/ph4ntxm/gpu_env`. Participating processes inherit this profile.

## [ SOURCE ]

[ph4ntxm-gpu-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-gpu-randomization.sh)
