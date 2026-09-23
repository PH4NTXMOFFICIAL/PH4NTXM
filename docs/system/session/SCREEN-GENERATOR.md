# [ SCREEN GENERATOR ]

## [ OVERVIEW ]

Derives browser viewport metadata from the generated display profile.

## [ STARTUP ]

The normal-mode one-shot service follows screen randomization, cores generation and CPU reporting before the display manager. It requires readable `screen_env` and a nonempty `persona_seed`.

Input defaults are 1920×1080, pixel ratio 1.0, primary `unknown` and secondary `none`. Empty secondary values also take the `none` default.

## [ RUNTIME ]

Named draws combine the seed, primary/secondary names and dimensions. The generator derives a viewport from the selected screen rather than choosing another display model.

The horizontal interface allowance is 0–15 pixels. The vertical allowance starts at 60–99 pixels. An 8-percent seeded branch adds another 80. Width and height are subtracted from nominal dimensions, then clamped to at least 320×200 and no larger than the source screen.

Pixel ratio is processed separately. Values 1.0 and 1.25 remain unchanged. A 1.5 input takes a seeded 30-percent branch to 1.25. A 2.0 input becomes 1.5. Other values pass through. In this normal-mode generator, viewport dimensions are not divided by the selected pixel ratio.

Display count is one when the resolved secondary value is `none`, otherwise two. `/run/ph4ntxm/browser_env` carries nominal screen size, viewport size, pixel ratio, display count and display names as shell-quoted exports.

The script writes a temporary file, sets `0644` permissions and renames it into place. Failed required input or write operations stop the new output. The generated file supplies downstream preferences and reporting.

## [ CHECKS ]

Compare `browser_env` with `screen_env`, accounting for the interface allowance and separate pixel-ratio adjustment. Check display names as well as dimensions when diagnosing display count.

If Firefox does not reflect the intended profile, inspect both this service's completion and the [browser wrapper](BROWSER.md) launch. File generation and consumption by a particular process are separate steps.

## [ SOURCE ]

[ph4ntxm-screen-generator.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-screen-generator.sh)
