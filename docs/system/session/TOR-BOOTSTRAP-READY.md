# [ TOR BOOTSTRAP READY ]

## [ OVERVIEW ]

Checks Tor bootstrap completion through its local control socket.

## [ STARTUP ]

Called by the Lonewolf DNS supervisor as the Tor service account.

## [ RUNTIME ]

Runs as `debian-tor`, verifies local control socket and cookie ownership, and authenticates with the cookie.  
Requests `GETINFO status/bootstrap-phase` and requires progress 100 with the done tag. Invalid replies, permissions, or incomplete bootstrap produce a failed result.

## [ SOURCE ]

[ph4ntxm-tor-bootstrap-ready.py](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-tor-bootstrap-ready.py)
