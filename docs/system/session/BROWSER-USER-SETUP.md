# [ BROWSER USER SETUP ]

## [ OVERVIEW ]

Installs the selected browser's panel launcher into the live user's home.

## [ STARTUP ]

Runs as root after the live account and browser mode are prepared.

## [ RUNTIME ]

Selects the Firefox or Tor panel template for the active mode. Lonewolf requires Tor Browser verification state.  
Checks the live account, home ownership, and destination directories, then installs the launcher atomically with the user's UID and GID.

## [ SOURCE ]

[ph4ntxm-browser-user-setup.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-user-setup.sh)
