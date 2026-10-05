# [ FONTS RANDOMIZATION ]

## [ OVERVIEW ]

Builds a mode-specific Fontconfig profile under `/run/ph4ntxm/fonts-active`.

## [ STARTUP ]

The one-shot service runs after mode selection and is ordered after the hardware generators, before the display manager. It rebuilds `/run/ph4ntxm/fonts-active` from font files already installed in the image.

A missing mode file defaults to Linux. Unsupported modes leave the active profile unchanged. Supported modes select source fonts before clearing previous entries.

## [ RUNTIME ]

Selection uses shell randomness and `shuf` on each run, rather than a saved identity-seed draw:

- Linux requests 1–10 extra font families.
- Windows includes installed Microsoft TrueType fonts and available Cascadia Code/Mono fonts, plus 1–5 families from Arimo, Tinos, Cousine, Noto or Open Sans.
- Lone Wolf requests 1–3 extra font families.

The requested count can exceed the number of available families. Selection includes every installed file in each chosen family, grouping Open Sans Condensed with Open Sans. Selected files are linked into the active directory. Link failures stop the script. Source fonts are not rewritten or installed by this script.

The generated `fonts.conf` always searches the active directory. Linux and Lone Wolf also include the system TrueType and OpenType directories while rejecting Microsoft fonts and the listed local/user font paths. Their small extra selection therefore does not describe the complete available font set.

Windows uses the active directory and rejects the listed non-profile system groups and user paths. The script then runs `fc-cache -f` with `FONTCONFIG_PATH` and `FONTCONFIG_FILE` pointing at this configuration.

The directory is rebuilt in place, not exchanged as a completed directory transaction. A link, write or cache failure can leave an incomplete profile. Participating launchers must receive the Fontconfig environment for these settings to affect their font lookup.

## [ CHECKS ]

Check the service result, active links and generated `fonts.conf` together. Compare requested selection rules with the source fonts actually present in the image.

For an application mismatch, inspect its launch environment and whether it was already running before the rebuild. Recreating this profile can choose another set. It is not a passive inspection command.

## [ SOURCE ]

[ph4ntxm-fonts-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-fonts-randomization.sh)  
[ph4ntxm-fonts-randomization.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-fonts-randomization.service)
