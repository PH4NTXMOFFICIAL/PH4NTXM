# [ SCREEN RANDOMIZATION ]

## [ OVERVIEW ]

Generates Linux/Windows nominal display metadata aligned with the hardware and GPU persona.

## [ STARTUP ]

The normal-mode one-shot service follows and requires both GPU and cores generation. The script reads `gpu_env`, `cores_env`, `hardware_profile` and `persona_seed` before selecting the nominal display layout.

Laptop profiles use a laptop form factor. Desktop and server profiles use desktop. An unsupported class stops generation.

## [ RUNTIME ]

The seed drives named choices for connector availability, panel selection and secondary displays. Laptop layouts start with `eDP-1` and optional HDMI/DP connectors. Desktop layouts use external connectors, with Apple preferring DP. If no primary is selected, the script supplies an internal or HDMI primary according to form factor.

Intel panels generally use 1920×1080 at 60 Hz. AMD/NVIDIA laptop choices include 1080p or 1440p at 144 Hz and 2560×1600 at 120 Hz. Their external choices include 1440p at 144/165 Hz or 4K at 60 Hz. Apple external panels use 2560×1440 at 60 Hz.

Secondary-display selection has its own seeded decision and records dimensions and refresh rate when present. Pixel ratio follows primary width: 1.5 at 2500 pixels or more, 1.25 from 1920, otherwise 1.0.

`/run/ph4ntxm/screen_env` contains primary/secondary names, primary dimensions and refresh rate, pixel ratio, device class, form factor and optional secondary resolution. The script writes shell-quoted exports to a temporary file, makes it `0644` and renames it into place.

The output supplies display metadata to participating consumers. The separate [Screen Generator](SCREEN-GENERATOR.md) derives viewport metadata from the completed screen profile.

## [ CHECKS ]

Compare the selected panel and scale with the GPU and device class in the input profiles. Check `screen_env` before checking `browser_env`: the viewport stage has its own service result.

If the physical desktop resolution differs, first distinguish generated reporting metadata from actual display-server configuration. Missing input files or an unsupported device class should be investigated in the preceding stages.

## [ SOURCE ]

[ph4ntxm-screen-randomization.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-screen-randomization.sh)  
[ph4ntxm-screen-generator.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-screen-generator.sh)
