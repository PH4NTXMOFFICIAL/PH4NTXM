# [ BROWSER MODE ]

## [ OVERVIEW ]

Selects Firefox ESR or Tor Browser and installs the corresponding desktop entries.

## [ STARTUP ]

The root one-shot service follows local filesystems and mode selection and runs before the display manager. It validates the mode file's ownership and permissions before accepting `linux`, `windows` or `lonewolf`.

Existing Tor verification state is removed at the start. The script clears previous masks, then masks both browser directories before exposing the selected browser.

## [ RUNTIME ]

Masking bind-mounts an empty runtime directory over the browser path and verifies `ro`, `nosuid`, `nodev` and `noexec` mount options. Linux and Windows unmask `/usr/lib/firefox-esr`. Lone Wolf unmasks `/opt/ph4ntxm/tor-browser`.

Lone Wolf verification checks required launchers, executables, packaging metadata and the browser icon. The tree must be root-owned, contain no symlinks or special file types, and use the expected directory and file permissions. Writable or special-permission entries are rejected.

The verifier generates a sorted SHA256 list for all browser files and compares it with the installed manifest. This checks the complete listed tree, including unexpected files. It also validates the manifest and version file themselves as protected files.

On success, the selected system and skeleton panel templates replace their desktop entries through temporary files. Lone Wolf then writes `/run/ph4ntxm/tor-browser-verified` with `MODE`, `MANIFEST_SHA256` and `UPTIME_SECONDS`. This record identifies verification of the installed browser. Tor bootstrap and firewall freshness are checked later by the launcher.

The error path removes readiness and attempts to mask exposed browser directories again. Mount failures can also affect this cleanup, so the service result and actual mounts matter. The live user's panel copy is handled separately by [Browser User Setup](BROWSER-USER-SETUP.md).

## [ CHECKS ]

Check `ph4ntxm-browser-mode.service`, the selected desktop entries and actual browser mounts. In Lone Wolf, inspect the verification record and manifest result before investigating proxy readiness.

An installed browser and a verified tree are different states. A verification record also does not establish a current Tor connection. Follow [Tor Browser](TOR-BROWSER.md) for launch checks.

## [ SOURCE ]

[ph4ntxm-browser-mode.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-mode.sh)  
[ph4ntxm-browser-mode.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-browser-mode.service)
