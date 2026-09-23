# [ BROWSER ]

## [ OVERVIEW ]

Linux and Windows use a wrapped Firefox ESR profile. Lone Wolf uses the dedicated Tor Browser launcher.

## [ STARTUP ]

Browser preparation starts with the mode gate, followed by the selected policy and user setup. The installed Firefox command is a wrapper around the diverted `firefox-esr-real` executable.

The wrapper validates the root-owned mode file. Linux and Windows continue through the normal profile path. Lone Wolf delegates to the dedicated Tor Browser launcher. Invalid or missing mode state stops launch.

## [ RUNTIME ]

Normal modes use `/run/user/UID/ph4ntxm-firefox-profile`, with `0700` directory permissions and a nonblocking account-level lock. A second concurrent wrapper session is rejected. This profile is reused within the runtime session rather than recreated on every normal browser launch.

The wrapper obtains the installed Firefox major version and reads protected `browser_env`, `cores_env` and `gpu_env` files. These must be readable regular files, owned by root and not writable by group or others. Required DPR, core count and architecture values are validated.

It copies the mode's `user.js` template to a temporary file, substitutes DPR, cores, architecture and Firefox version, and rejects unresolved placeholders. The completed file is installed as `0600` through rename, avoiding a partially written final preferences file.

The active Fontconfig directory and configuration are exported before launching the real browser with the explicit profile and `--no-remote`. Policy generation, selected fonts and runtime identity data therefore have to agree before this wrapper can start normally.

Lone Wolf follows a different lifecycle: a verified Tor Browser bundle, current firewall/Tor readiness and a fresh temporary home. Its launcher deliberately starts from a restricted environment instead of importing the normal Firefox persona variables.

## [ CHECKS ]

For launch failures, inspect the wrapper's terminal message and identify whether mode, lock, state files, version detection, fonts or template substitution failed.

Check the wrapper result together with the selected mode and generated preferences. Linux and Windows use the normal network path. Lone Wolf delegates to its Tor launcher.

## [ SOURCE ]

[ph4ntxm-browser-mode.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-mode.sh)  
[ph4ntxm-browser-policy.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-policy.sh)  
[9996-browser-wrapper.chroot](../../../config/hooks/normal/9996-browser-wrapper.chroot)  
[ph4ntxm-tor-browser](../../../config/includes.chroot/usr/local/bin/ph4ntxm-tor-browser)
