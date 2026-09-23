# [ BROWSER MODE ]

## [ OVERVIEW ]

Selects the browser for the boot mode, verifies the Lone Wolf browser tree and installs matching system and live-user launchers.

## [ STARTUP ]

The root one-shot service follows local filesystems and mode selection and runs before the display manager. It checks the mode file's ownership and permissions before accepting `linux`, `windows` or `lonewolf`.

It removes old Tor verification state, clears previous masks and masks both browser directories before exposing the selected browser. LightDM's pre-start helper later installs the selected panel launcher into the live user's home.

## [ RUNTIME ]

Masking bind-mounts an empty runtime directory over a browser path and verifies `ro`, `nosuid`, `nodev` and `noexec` options. Linux/Windows unmask `/usr/lib/firefox-esr`. Lone Wolf unmasks `/opt/ph4ntxm/tor-browser`.

Lone Wolf verification checks launchers, executables, packaging metadata and the icon. The browser tree must be root-owned, contain no symlinks or special file types and use the expected permissions. Writable or special-permission entries are rejected.

A sorted SHA256 list of all browser files is compared with the installed manifest, including checks for unexpected files. The manifest and version file must also pass protected-file checks.

Success replaces the system and skeleton panel templates through temporary files. Lone Wolf then writes `/run/ph4ntxm/tor-browser-verified` with `MODE`, `MANIFEST_SHA256` and `UPTIME_SECONDS`. On error, readiness is removed and exposed browser directories are masked again where possible. Mount failures can affect that cleanup.

The user-setup helper reads the root-owned, non-symlink mode file and selects the Firefox or Tor panel template. Lone Wolf also requires the verification marker to exist. Full tree verification belongs to the preceding service.

The destination is `/home/ph4ntxm/.config/panel/launcher-9/firefox-esr.desktop` in every mode, including when it launches Tor Browser. Account data comes from `getent passwd ph4ntxm`. The username must match, UID must be positive, GID numeric and home exactly `/home/ph4ntxm`.

The home and existing launcher directories must be directories rather than symlinks. The helper prepares the path with the live account's ownership and `0755` permissions and confirms the resolved destination directory. The selected template must be a root-owned regular file without a symlink. A temporary copy receives live-user ownership and `0644` permissions before replacing the destination.

Failed account, path or template checks stop installation. This step copies the launcher without starting the browser or refreshing an already-running panel. [Tor Browser](TOR-BROWSER.md) separately checks current firewall and bootstrap readiness at launch.

## [ CHECKS ]

Inspect `ph4ntxm-browser-mode.service`, the selected desktop entries and actual browser mounts. In Lone Wolf, check the verification record and manifest before investigating proxy readiness.

If the panel launcher is absent or stale, compare its command and ownership with the selected template and inspect account/path validation. A verified installation and a copied launcher do not establish a current Tor connection.

## [ SOURCE ]

[ph4ntxm-browser-mode.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-mode.sh)

[ph4ntxm-browser-mode.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-browser-mode.service)

[ph4ntxm-browser-user-setup.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-user-setup.sh)
