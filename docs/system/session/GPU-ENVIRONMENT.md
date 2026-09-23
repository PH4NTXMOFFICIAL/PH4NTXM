# [ GPU ENVIRONMENT ]

## [ OVERVIEW ]

Loads the generated GPU environment into login shells.

## [ STARTUP ]

Login-shell profile processing sources `/etc/profile.d/ph4ntxm-gpu-env.sh`. The helper checks whether `/run/ph4ntxm/gpu_env` is a file and, when it is, sources it into the current shell.

The generated file comes from [GPU Randomization](GPU-RANDOMIZATION.md) or its [Lone Wolf counterpart](LONEWOLF-GPU-RANDOMIZATION.md), which run earlier in their respective chains.

## [ RUNTIME ]

Sourcing imports the generated exports directly: renderer/vendor identity, stack settings, the shared `PH4NTXM_GPU_*` fields and the GL shim preload expression. Commands started from that shell can then inherit those values.

The GPU generator selects and publishes the completed environment. This profile imports that shared output into shell-launched processes.

The existence test is not a separate readability or format check. An absent file is not sourced, while errors sourcing an existing file can surface during profile processing. The helper itself has no recovery or readiness marker.

Environment inheritance is per process. An application already running keeps its earlier environment. Desktop entries, services and launchers that construct their own environment must be checked at that launch point. In particular, Tor Browser uses an explicit permitted environment instead of simply inheriting every desktop export.

The generated preload expression avoids adding a second copy of the PH4NTXM GL shim when it is already listed.

## [ CHECKS ]

Compare `gpu_env` with the exported variables in a newly opened login shell, then inspect the application launched from that shell. Separate a missing profile, a sourcing error and an application that intentionally clears its environment.

If the profile is absent or inconsistent with hardware selection, inspect the generator's service result. Re-sourcing an environment is not a substitute for repairing an incomplete GPU generation stage.

## [ SOURCE ]

[ph4ntxm-gpu-env.sh](../../../config/includes.chroot/etc/profile.d/ph4ntxm-gpu-env.sh)
