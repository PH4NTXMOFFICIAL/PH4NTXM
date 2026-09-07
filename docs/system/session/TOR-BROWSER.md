# [ TOR BROWSER ]

## [ OVERVIEW ]

Launches Tor Browser for the Lonewolf session.

## [ STARTUP ]

Runs for Lonewolf after the installed browser manifest has been verified.

## [ RUNTIME ]

Checks verified browser state, protection readiness, completed Tor bootstrap, and the expected local listeners.  
Builds the permitted launch environment and starts Tor Browser with a private runtime home against the system Tor service.

## [ SOURCE ]

[ph4ntxm-tor-browser](../../../config/includes.chroot/usr/local/bin/ph4ntxm-tor-browser)
