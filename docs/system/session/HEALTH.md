# [ HEALTH ]

## [ OVERVIEW ]

Produces the categorized PH4NTXM runtime health report.

## [ STARTUP ]

Runs when the operator opens PH4NTXM Health.

## [ RUNTIME ]

Reads the active mode, services, identity, hardware, network, resources, and termination state from local runtime records and checks.  
Groups results by subsystem and reports warnings, errors, severity counts, and an overall score.

## [ SOURCE ]

[ph4ntxm-health](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health)
