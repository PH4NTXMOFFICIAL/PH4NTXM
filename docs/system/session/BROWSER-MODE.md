# [ BROWSER MODE ]

## [ OVERVIEW ]

Selects the mode's browser, verifies the Lone Wolf browser tree and installs matching system/live-user launchers.

## [ STARTUP ]

The root one-shot follows local filesystems and mode selection, before the display manager. It validates protected mode state, clears previous verification/masks and masks both browser directories before exposing the selected one. LightDM's pre-start helper later copies the selected panel launcher into the live home.

## [ RUNTIME ]

Masking bind-mounts an empty directory and verifies `ro,nosuid,nodev,noexec`. Linux/Windows expose `/usr/lib/firefox-esr`; Lone Wolf exposes `/opt/ph4ntxm/tor-browser`.

Lone Wolf checks launchers, executables, metadata and icon. The tree must be root-owned with expected permissions and no symlinks, special files or writable entries. A sorted SHA256 inventory must match the protected manifest, including unexpected-file detection.

Success replaces system/skeleton panel templates through temporary files and publishes `tor-browser-verified` with mode, manifest digest and uptime. Failure removes readiness and attempts remasking; mount failures can limit cleanup.

User setup reads the protected mode and selects its template; Lone Wolf also requires the verification marker. Full tree verification belongs to the preceding service.

The panel destination remains `/home/ph4ntxm/.config/panel/launcher-9/firefox-esr.desktop` even for Tor. Account lookup must identify `ph4ntxm` with positive UID, numeric GID and exactly that home. Existing directories must not be symlinks; the helper verifies the resolved destination and installs a protected regular template through a temporary `0644` copy with live-user ownership.

Account/path/template failure stops installation. Copying does not launch the browser or refresh a running panel. [Tor Browser](TOR-BROWSER.md) checks current firewall/bootstrap readiness separately at launch.

## [ CHECKS ]

Inspect the service, actual browser mounts and selected desktop entries. In Lone Wolf, compare the verification record with the manifest before investigating proxy readiness.

For absent/stale panel entries, check command, ownership and path validation. Installation verification and launcher copying do not establish a current Tor connection.

## [ SOURCE ]

[ph4ntxm-browser-mode.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-mode.sh)\
[ph4ntxm-browser-mode.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-browser-mode.service)\
[ph4ntxm-browser-user-setup.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-user-setup.sh)
