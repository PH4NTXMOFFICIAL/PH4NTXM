# [ LONE WOLF SCREEN GENERATOR ]

## [ OVERVIEW ]

Derives Lone Wolf viewport metadata from the generated screen profile.

## [ STARTUP ]

The Lone Wolf one-shot service follows its screen, cores and CPU reporting services before the display manager. It requires readable `screen_env` and a valid 64-digit lowercase `lonewolf_seed`.

It inherits nominal dimensions and pixel ratio, defaulting to 1920×1080 and 1.0 when fields are absent. Primary defaults to `DISPLAY-1`. Secondary defaults to `none`.

## [ RUNTIME ]

Seeded draws combine the independent seed, source dimensions and named offsets. Horizontal allowance is 0–15 pixels. Vertical allowance follows the width's textual range: 90–129 pixels for 3xxx/4xxx widths, 80–109 for 2xxx widths, and 70–89 otherwise.

The allowances are subtracted from nominal dimensions. Unlike the normal-mode generator, Lone Wolf then divides each remaining dimension by the inherited pixel ratio and truncates the result to an integer. Width and height are clamped to at least 320×200 and no larger than the nominal screen.

The pixel ratio itself is preserved. Display count is one when the resolved secondary name is `none`, otherwise two. The usual screen generator supplies only a primary display, so its output normally follows the single-display path.

`/run/ph4ntxm/browser_env` exports nominal size, calculated viewport, pixel ratio, display count and both display names. Values are shell-quoted, written to a temporary file, made `0644` and renamed into place.

The generated record keeps viewport metadata aligned with the Lone Wolf screen profile. Tor Browser follows its independent display policy. A missing or invalid seed stops generation before a new completed record is published.

## [ CHECKS ]

Compare `screen_env` and `browser_env`, applying both the interface allowance and pixel-ratio division when checking dimensions. Check the service result if the output is missing or left from an earlier attempt.

Assess Tor Browser's actual window separately through its launch policy. The existence of this metadata is not evidence that every browser surface reports it.

## [ SOURCE ]

[ph4ntxm-lonewolf-screen-generator.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/lonewolf/ph4ntxm-lonewolf-screen-generator.sh)
