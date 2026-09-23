# [ MODE ]

## [ OVERVIEW ]

Reads the boot mode from the kernel command line and writes `/run/ph4ntxm/mode`.

## [ STARTUP ]

`ph4ntxm-mode.service` runs after local filesystems and before `sysinit.target`. It is a one-shot service whose completed state remains available to later dependencies.

The script creates `/run/ph4ntxm` and reads the kernel command line. Mode selection belongs to this early stage. Later shell helpers consume the recorded result.

## [ RUNTIME ]

The initial value is `linux`. The script scans command-line arguments for `ph4ntxm.mode=` and accepts only `linux`, `windows` or `lonewolf`. An unsupported final value falls back to Linux. If the argument appears more than once, the last occurrence encountered supplies the value that is validated.

It removes both existing mode markers, writes the selected token and newline through a temporary file, sets permissions to `0644`, then renames the file to `/run/ph4ntxm/mode`.

It next creates one empty marker:

- `mode-normal` selects the shared Linux/Windows service conditions.
- `mode-lonewolf` selects the independent Lone Wolf chain.

The mode file and marker are replaced separately. A failure between those steps can leave a readable mode without its matching marker, which is why downstream checks use service completion and their own prerequisites.

The service records the boot choice. It does not reconfigure an already-running session when a user changes a shell variable. [Mode Select](MODE-SELECT.md) reads the file for callers, while [Mode Environment](MODE-ENVIRONMENT.md) exports a validated token to login shells.

## [ CHECKS ]

Compare `ph4ntxm.mode=` in `/proc/cmdline`, the mode file and the single expected marker. Linux and Windows should share `mode-normal`. Lone Wolf should have `mode-lonewolf`.

If state is missing or inconsistent, inspect `journalctl -b -u ph4ntxm-mode.service`. A fallback value printed by a reader is not evidence that this startup stage completed.

## [ SOURCE ]

[ph4ntxm-mode.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-mode.sh)  
[ph4ntxm-mode.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-mode.service)
