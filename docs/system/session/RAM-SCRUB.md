# [ RAM SCRUB ]

## [ OVERVIEW ]

Provides the native memory scrubber used by the Nuke sequence.

## [ STARTUP ]

Called by the common Nuke service for allocation scrubbing and by the final shutdown hook with a termination action.

## [ RUNTIME ]

Supports allocation scrubbing and the final shutdown transition to the armed crashkernel.  
In ordinary mode it overwrites available memory allocations.  
With a shutdown action it first requests the armed crashkernel; if that fails, it attempts allocation scrubbing and returns failure.

## [ SOURCE ]

[ph4ntxm-ram-scrub.c](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-ram-scrub.c)
