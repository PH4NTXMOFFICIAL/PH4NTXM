# [ FONTS RANDOMIZATION ]

## [ OVERVIEW ]

Builds a mode-specific Fontconfig profile under `/run/ph4ntxm/fonts-active`.

## [ STARTUP ]

The one-shot service runs after mode selection and is ordered after the hardware generators, before the display manager. It rebuilds `/run/ph4ntxm/fonts-active` from font files already installed in the image.

The script creates the active directory and removes its previous entries before selecting the new set. A missing mode file defaults to Linux. An unsupported token exits after that cleanup.

## [ RUNTIME ]

Selection uses shell randomness and `shuf` on each run, rather than a saved identity-seed draw:

- Linux selects up to 1–10 extra font files.
- Windows includes the installed Microsoft fonts and up to 1–5 extras matching Arimo, Tinos, Cousine, Noto or OpenSans names.
- Lone Wolf selects up to 1–3 extra font files.

The requested count can exceed the number of available candidates. Selected files are linked into the active directory. Individual link failures are tolerated. Source fonts are not rewritten or installed by this script.

The generated `fonts.conf` always searches the active directory. Linux and Lone Wolf also include the system TrueType and OpenType directories while rejecting Microsoft fonts and the listed local/user font paths. Their small extra selection therefore does not describe the complete available font set.

Windows uses the active directory and rejects the listed non-profile system groups and user paths. The script then runs `fc-cache -f` with `FONTCONFIG_PATH` and `FONTCONFIG_FILE` pointing at this configuration.

The directory is rebuilt in place, not exchanged as a completed directory transaction. A selection, write or cache failure can leave an incomplete profile. Participating launchers must receive the Fontconfig environment for these settings to affect their font lookup.

## [ CHECKS ]

Check the service result, active links and generated `fonts.conf` together. Compare requested selection rules with the source fonts actually present in the image.

For an application mismatch, inspect its launch environment and whether it was already running before the rebuild. Recreating this profile can choose another set. It is not a passive inspection command.

## [ SOURCE ]

[ph4ntxm-fonts-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-fonts-randomization.sh)  
[ph4ntxm-fonts-randomization.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-fonts-randomization.service)
