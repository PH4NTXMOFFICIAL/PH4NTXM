# [ BROWSER USER SETUP ]

## [ OVERVIEW ]

Installs the selected browser's panel launcher into the live user's home.

## [ STARTUP ]

The helper runs as root once the live account and browser mode are available. It reads the root-owned, non-symlink mode file and chooses the Firefox panel template for Linux/Windows or the Tor panel template for Lone Wolf.

Lone Wolf additionally requires the browser-verification marker to exist. Full verification belongs to [Browser Mode](BROWSER-MODE.md). This helper installs the resulting launcher.

## [ RUNTIME ]

The destination is `/home/ph4ntxm/.config/panel/launcher-9/firefox-esr.desktop`. The filename stays the same in all modes, even when its contents launch Tor Browser.

Account information comes from `getent passwd ph4ntxm`. The username must match, the UID must be positive, the GID must be numeric, and the home must be exactly `/home/ph4ntxm`. The home must be a directory rather than a symlink.

Existing `.config`, `panel` and `launcher-9` paths must be directories rather than symlinks. The helper creates or prepares them with the live account's UID/GID and `0755` permissions, then confirms that the resolved launcher directory is the expected path.

The selected template under `/usr/lib/ph4ntxm/browser-mode` must be a root-owned regular file and not a symlink. It is installed into a temporary file with the live account's ownership and `0644` permissions, then renamed over the destination.

A failed account, path or template check stops installation. The helper does not start the browser, change its verified files, select another mode or refresh an already-running panel itself.

## [ CHECKS ]

Compare the destination's command and ownership with the template selected by the current mode. Inspect account and directory validation when the launcher is absent or remains unchanged.

For Lone Wolf, distinguish missing verification state from an installation failure. A correctly copied launcher still depends on the Tor Browser launcher's runtime firewall and bootstrap checks.

## [ SOURCE ]

[ph4ntxm-browser-user-setup.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-user-setup.sh)
