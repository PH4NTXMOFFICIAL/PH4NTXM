# [ BROWSER MODE ]

## [ OVERVIEW ]

Selects Firefox ESR or Tor Browser and installs the corresponding desktop entries.

## [ STARTUP ]

Runs as root after mode selection.  
Uses the browser metadata and desktop templates under `/usr/lib/ph4ntxm/browser-mode`.

## [ RUNTIME ]

Begins with both browser directories masked, then exposes the selected browser.  
In Lonewolf, verifies the Tor Browser files against the installed manifest before publishing readiness and records the manifest hash under `/run/ph4ntxm/tor-browser-verified`.

## [ SOURCE ]

[ph4ntxm-browser-mode.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-mode.sh)
