# [ BROWSER POLICY ]

## [ OVERVIEW ]

Writes the Firefox enterprise policy for Linux and Windows.

## [ STARTUP ]

Runs for Linux and Windows after the runtime mode is available.

## [ RUNTIME ]

Configures telemetry, updates, passwords, permissions, networking, and hardware acceleration in `/etc/firefox/policies/policies.json`.  
Writes a temporary policy file before installing the completed `policies.json`.

## [ SOURCE ]

[ph4ntxm-browser-policy.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-policy.sh)
