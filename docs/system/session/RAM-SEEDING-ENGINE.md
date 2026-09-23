# [ RAM SEEDING ENGINE ]

## [ OVERVIEW ]

Maintains a small anonymous memory region filled with changing synthetic noise.

## [ STARTUP ]

The compiled engine runs as a background service and allocates a private anonymous mapping sized to one percent of RAM reported by `sysinfo`. It requires a valid page size and at least one page of target space.

Initial noise state comes from nonblocking `getrandom`, with time/PID fallback if a full seed is unavailable. Allocation failure exits rather than starting an empty loop.

## [ RUNTIME ]

The entire mapping is filled with generated noise. Zero bytes are replaced during that fill, then sparse fragments resembling common file signatures, protocol strings, paths and application data are inserted at changing offsets.

The fragments are generated from the engine's built-in string set inside its own allocation. Some insertions also include pointer-shaped values into that same mapping.

The engine requests `MADV_WILLNEED` and `MADV_RANDOM`, then tries to lock the full mapping into RAM. If that fails, it attempts locking in one-MiB chunks. Chunk failures are tolerated, so process liveness does not establish that every page was locked.

Each loop touches a sparse set of pages, changes its fragment offset state and sometimes reseeds fragments. It sleeps for 300–599 seconds between passes.

The common Nuke sequence stops this service before its available-memory scrub. Stopping the engine releases its allocation before the separate scrub stage runs.

## [ CHECKS ]

Check the service result, process mapping size and locked-memory accounting when validating deployment. A running process with lower locked memory can reflect the tolerated `mlock` fallback.

For termination behavior, follow [Nuke Kernel](NUKE-KERNEL.md) and [RAM Scrub](RAM-SCRUB.md), which run after seeding stops.

## [ SOURCE ]

[ph4ntxm-ram-seeding-engine.c](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-ram-seeding-engine.c)
