# [ LINK JITTER ]

## [ OVERVIEW ]

Adds a randomized delay before the network-release sequence proceeds.

## [ STARTUP ]

Runs as a one-shot dependency before network release.

## [ RUNTIME ]

Waits between two and seven seconds, then exits successfully.  
Selects a fresh integer delay with `shuf`.  
Completion releases this timing dependency for the next startup stage.

## [ SOURCE ]

[ph4ntxm-link-jitter.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-jitter.sh)
