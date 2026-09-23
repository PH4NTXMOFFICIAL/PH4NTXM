# [ BUILD EDITIONS ]

## [ OVERVIEW ]

Abyss is the default dark navy edition. Ghost is the light pearl-white edition. Both use the same packages, protection settings, and Linux, Windows and Lone Wolf boot modes. The edition selects appearance at build time.

## [ SOURCE ]

| Source | Purpose |
| --- | --- |
| `config/` | Shared packages, hooks, services and session components. |
| `editions/abyss/config/` | PH4NTXM-Abyss theme, artwork and appearance settings. |
| `editions/ghost/config/` | PH4NTXM-Ghost theme, artwork and appearance settings. |
| `editions/<name>/edition.json` | Edition name and required theme/background paths. |
| `build.sh`, `auto/build`, `tools/` | Build entry points and preparation. |

Preparation copies the shared configuration and selected edition into `build/<edition>/config/`. Each ISO includes only its selected PH4NTXM theme and backgrounds. Both editions remain in the repository. Shared icons, cursors and distribution fallback themes are retained.

Boot menu entries remain in the shared configuration. Edition-specific GRUB and Syslinux appearance files belong under `editions/<name>/config/bootloaders/`.

Keep source, artwork, build tools and required tests in Git. Generated build trees, package caches and exported images are excluded.

## [ BUILD ]

Run the chosen command from the repository root:

ABYSS: `sudo ./build.sh --edition abyss`  
GHOST: `sudo ./build.sh --edition ghost`

Omitting `--edition` selects Abyss. Repository-root `sudo lb config` followed by `sudo lb build` also selects Abyss through `auto/build`. Add `--prepare-only` to inspect configuration without building, or pass extra live-build options after `--`.

The wrapper runs `lb config` and `lb build` in the selected workspace. Rebuilds clean that edition's previous build while retaining its package cache. Checks reject unsafe workspaces, leftover mounts and concurrent builds of the same edition.

Successful builds export `ph4ntxm-<edition>-amd64.hybrid.iso`, manifests and `SHA256SUMS` into `output/<edition>-<UTC timestamp>-<sequence>/`, for example `abyss-20260919T153000Z-001`. Each edition has a persistent counter in `output/.<edition>-sequence`. Deleting old exports or cleaning the build does not reset it. Keep these counter files to retain numbering. Interrupted exports may leave gaps. Existing exports and the other edition's build are preserved. See [INSTALLATION](../../INSTALLATION.md#-cleanup-and-outputs-) for cleanup details and [DISTRIBUTION](../../DISTRIBUTION.md) for source verification and distribution policy.

## [ APPEARANCE ]

Abyss pairs deep navy surfaces and pale text with blue glass ribbons. Ghost pairs pearl-white surfaces and dark text with clear glass ribbons. Both use cyan and magenta accents across GTK 2, GTK 3, XFWM, LightDM, the panel and PH4NTXM applications.

Each edition supplies matching desktop, login and bootloader artwork. Both keep Lyra-blue-dark (modified for PH4NTXM) and custom icons, LyraB cursors and terminal backgrounds at 85% opacity. Selecting another XFCE theme manually does not switch the complete edition. Build the desired edition to apply all appearance settings together.

Picom starts with the XFCE session through [ph4ntxm-picom](../../config/includes.chroot/usr/local/bin/ph4ntxm-picom). Both editions use XRender, a 16-pixel corner radius and 95% opacity for normal windows. XFCE Terminal keeps its own background opacity. VSync, shadows and blur are disabled. XFWM compositing is disabled in both editions. The shared [picom.conf](../../config/includes.chroot/etc/skel/.config/picom/picom.conf) also excludes menus, tooltips, the desktop and docks from rounded corners.

The shared icon palette uses cyan `#00ABFF` and magenta `#FF3DFB`. Connection icons use magenta for active states and cyan for inactive states. Batteries use a cyan shell with magenta charge bars. Keep the custom artwork in `Lyra-blue-dark/apps/scalable/` intact when updating the rest of the icon theme.

## [ VALIDATION ]

The build runs Airlock and media-viewer unit tests and Packet Transformation Engine Rust, differential, fuzz-smoke and native self-tests. Before a release, build both editions and check their UEFI and BIOS menus, LightDM, panel, terminal and application dialogs.

Inspect shared changes in both prepared configurations and edition changes in their selected overlay. Check rounded corners, normal-window and terminal opacity, icon states and contrast on both backgrounds. Record the source revision and edition with the result so appearance reports can be matched to the tested build.
