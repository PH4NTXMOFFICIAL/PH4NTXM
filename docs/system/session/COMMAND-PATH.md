# [ COMMAND PATH ]

## [ OVERVIEW ]

Sets the login shell's command search path.

## [ STARTUP ]

Sourced by login-shell profile processing.

## [ RUNTIME ]

Places `/usr/local/sbin` and `/usr/local/bin` before the standard sbin and bin directories, giving PH4NTXM's local command wrappers priority during command lookup.

## [ SOURCE ]

[ph4ntxm-path.sh](../../../config/includes.chroot/etc/profile.d/ph4ntxm-path.sh)
