# [ LONE WOLF SCREEN RANDOMIZATION ]

## [ OVERVIEW ]

Generates Lone Wolf display metadata from the GPU, device class, seed, and boot jitter.

## [ STARTUP ]

The Lone Wolf one-shot service follows and requires GPU and cores generation. It validates the independent seed and boot jitter and reads `gpu_env`, `cores_env` and `hardware_profile`.

Named choices hash seed, jitter and a selection label, keeping the display choice tied to this session's hardware chain.

## [ RUNTIME ]

The hardware family maps to a display class: business, consumer, ultrabook, Apple desktop, desktop or server. An unrecognized family stops generation instead of receiving an unrelated panel.

Business choices range from 1366×768 to 2560×1440 at 60 Hz. Consumer choices include 1366×768, 1600×900 and 1920×1080. Ultrabooks can use 1080p, 2560×1600 or 2880×1800. Apple desktop choices include 1440p, 4K and 5K. Servers use 1080p at 60 Hz.

GPU checks constrain the selected refresh rate. Non-AMD/NVIDIA branches are capped at 60 Hz. Intel non-Apple-desktop widths of 3500 or more are reduced to 2560×1440 at 60 Hz.

The primary name is `DISPLAY-1`. Desktop, server and Apple desktop use pixel ratio 1.0. Business/consumer scale can rise to 1.25 at higher widths, while ultrabooks use 1.25 or 1.5. This generator does not create a secondary-display field.

The completed `screen_env` exports dimensions, scale, primary identity, device/display classes, GPU vendor and refresh rate. A temporary file is made `0644` and renamed into place. [Lone Wolf Screen Generator](LONEWOLF-SCREEN-GENERATOR.md) then derives viewport metadata. Tor Browser retains its own display policy.

## [ CHECKS ]

Compare the hardware family, display class and resulting dimensions together. Verify GPU constraints before treating a reduced resolution or refresh rate as an inconsistency.

Check the service result and completed `screen_env`, then inspect the viewport stage separately. These generators produce session metadata rather than applying a monitor mode through the display server.

## [ SOURCE ]

[ph4ntxm-lonewolf-screen-randomization.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-screen-randomization.sh)
