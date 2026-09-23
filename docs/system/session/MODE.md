# [ MODE ]

## [ OVERVIEW ]

Records the boot mode and makes that choice available to services, command callers and login shells. Selection happens once at startup. The reader and environment helpers consume the recorded result.

## [ STARTUP ]

`ph4ntxm-mode.service` runs after local filesystems and before `sysinit.target`. It is a one-shot service whose completed state remains available to later dependencies.

The script creates `/run/ph4ntxm` and scans the kernel command line for `ph4ntxm.mode=`. It starts with `linux` and accepts only `linux`, `windows` or `lonewolf`. If the argument appears more than once, the last occurrence supplies the value to validate. An unsupported final value falls back to Linux.

## [ RUNTIME ]

The startup script removes existing mode markers, writes the selected token and newline to a temporary file, sets `0644` permissions and renames it to `/run/ph4ntxm/mode`. It then creates `mode-normal` for Linux/Windows or `mode-lonewolf` for the independent Lone Wolf chain.

The file and marker are replaced separately. An interrupted setup can leave a readable token without its matching marker. Downstream checks therefore use service completion and their own prerequisites.

For command callers, `/usr/lib/ph4ntxm/ph4ntxm-mode-select.sh` copies the existing regular file to standard output unchanged. It prints `linux` only when the regular-file check fails. An empty file stays empty, malformed contents pass through, and a read error returns failure. This reader neither exports a variable nor starts any services.

For login shells, `/etc/profile.d/ph4ntxm-mode.sh` reads one line with `IFS=` and `read -r`, validates the exact lowercase token and exports it as `PH4NTXM_MODE`. An unreadable file, failed read or unsupported value becomes `linux`. This validation differs from the command reader's direct output.

Child processes inherit the exported mode from their launching shell. Already-running applications keep their earlier environment, and separate launchers can supply their own values. Changing a shell variable does not rewrite the mode file, switch markers or reconfigure the active session.

Neither reader is a readiness check. A Linux fallback can mean the startup record was unavailable. The protection chain still has to complete independently.

## [ CHECKS ]

Compare `/proc/cmdline`, `/run/ph4ntxm/mode` and the single expected marker. Linux and Windows share `mode-normal`. Lone Wolf uses `mode-lonewolf`.

If they disagree, inspect `journalctl -b -u ph4ntxm-mode.service`. For shell differences, compare `printf '%s\n' "$PH4NTXM_MODE"` in a newly opened login shell with the file and the command reader's output and exit status.

## [ SOURCE ]

[ph4ntxm-mode.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-mode.sh)

[ph4ntxm-mode.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-mode.service)

[ph4ntxm-mode-select.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-mode-select.sh)

[ph4ntxm-mode.sh](../../../config/includes.chroot/etc/profile.d/ph4ntxm-mode.sh)
