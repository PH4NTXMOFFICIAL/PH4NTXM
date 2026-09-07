# [ BROWSER ]

## [ OVERVIEW ]

Linux and Windows use a wrapped Firefox ESR profile. Lonewolf uses the dedicated Tor Browser launcher.

## [ STARTUP ]

Browser mode selects the installed browser and desktop entries. Firefox launch reads the active persona and prepares a private runtime profile.

## [ RUNTIME ]

Firefox settings align User-Agent, architecture, concurrency, scale, fonts, and graphics with the generated persona.  
The wrapper holds a session lock and atomically installs the resolved preferences. Firefox retains its own profile lock.  
Telemetry, speculative requests, WebGL, disk cache, and selected background services are restricted. Network-backed Safe Browsing and its URL-reputation checks are disabled.  
Tor Browser uses system Tor, verified runtime state, and a clean environment.

## [ SOURCE ]

[ph4ntxm-browser-mode.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-mode.sh)  
[ph4ntxm-browser-policy.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-policy.sh)  
[9996-browser-wrapper.chroot](../../../config/hooks/normal/9996-browser-wrapper.chroot)  
[ph4ntxm-tor-browser](../../../config/includes.chroot/usr/local/bin/ph4ntxm-tor-browser)
