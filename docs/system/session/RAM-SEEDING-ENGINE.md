# [ RAM SEEDING ENGINE ]

## [ OVERVIEW ]

Maintains a small anonymous memory region filled with changing synthetic noise.

## [ STARTUP ]

Targets approximately one percent of RAM reported by the kernel's `sysinfo()` call. Allocates a private anonymous mapping for the active process.

## [ RUNTIME ]

Fills the region with non-zero bytes and inserts bounded fragments resembling file, protocol, or application markers. Selected pages are mutated periodically.  
Requests memory locking for the mapping and attempts smaller lock requests if the full request fails. Available resources determine locking success.  
Stopping the service releases the mapping. Shutdown ordering stops the seeder before the common Nuke scrub so those pages can become available for overwrite.

## [ SOURCE ]

[ph4ntxm-ram-seeding-engine.c](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-ram-seeding-engine.c)
