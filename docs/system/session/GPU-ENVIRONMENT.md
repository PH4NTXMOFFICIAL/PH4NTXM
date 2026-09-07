# [ GPU ENVIRONMENT ]

## [ OVERVIEW ]

Loads the generated GPU environment into login shells.

## [ STARTUP ]

Sourced by login-shell profile processing.

## [ RUNTIME ]

Sources `/run/ph4ntxm/gpu_env` when that file exists.  
Imports the existing GPU environment into that shell so participating child processes inherit its exported renderer and stack settings.

## [ SOURCE ]

[ph4ntxm-gpu-env.sh](../../../config/includes.chroot/etc/profile.d/ph4ntxm-gpu-env.sh)
