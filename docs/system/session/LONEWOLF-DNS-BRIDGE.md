# [ LONEWOLF DNS BRIDGE ]

## [ OVERVIEW ]

Runs the local dnsmasq bridge for Lonewolf and supervises Tor DNS readiness.

## [ STARTUP ]

Starts dnsmasq with the Lonewolf bridge configuration and keeps it as a supervised child process.

## [ RUNTIME ]

Checks TCP/UDP port 53, Tor DNSPort 5353, TransPort 9040, SOCKS 9050, and Tor bootstrap completion.  
Publishes `/run/ph4ntxm/tor-ready` and refreshes readiness every two seconds while checks pass. Loss of a required check after startup ends the supervisor and clears readiness.

## [ SOURCE ]

[ph4ntxm-lonewolf-dns-bridge.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-lonewolf-dns-bridge.sh)
