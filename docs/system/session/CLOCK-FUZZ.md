# [ CLOCK FUZZ ]

## [ OVERVIEW ]

Applies a mode-specific boot-time clock offset and maintains bounded timing variation during the session.

## [ STARTUP ]

The notify service follows mode and identity setup and must become ready before network release. It opens `/run/ph4ntxm/clock-fuzz.lock` for its lifetime. Another invocation exits successfully when that lock is already held.

Linux and Windows read `persona_seed`. Lone Wolf reads `lonewolf_seed`. Named draws mix the seed, kernel boot ID and an internal counter.

## [ RUNTIME ]

The mode controls the permitted initial offset, tick range and interval between updates:

| Mode | Initial offset | Tick range | Update interval |
| --- | --- | --- | --- |
| Linux | ±20 seconds | 9994–10006 | 720–1500 seconds |
| Windows | ±60 seconds | 9988–10012 | 480–1200 seconds |
| Lone Wolf | ±90 seconds | 9985–10015 | 420–900 seconds |

The script requests NTP disablement but tolerates failure of that request. It checks any saved profile for matching mode, valid numeric bounds and `SKEW_APPLIED=1`. Valid saved state resumes the recorded tick without applying the initial clock offset again.

Without valid saved state, it selects an offset, changes system time and chooses the initial tick. `adjtimex` applies the tick, then the profile is written through a temporary file with `0644` permissions. Only after those steps does the service notify readiness.

Each loop sleeps, moves the tick by −1, 0 or +1 within the mode's bounds, and occasionally applies a signed 10–41 millisecond offset. The draw selects that adjustment with a 1-in-40, 1-in-25 or 1-in-18 chance for Linux, Windows or Lone Wolf respectively.

The record stores mode, original offset, initial/current tick, bounds and the applied marker. Failed required clock operations stop the process. Systemd is configured to restart it.

## [ CHECKS ]

Read `clock-fuzz-profile` with the service result and current-boot journal. The file records engine choices, while a running service maintains later adjustments.

When comparing timestamps across machines, retain the active mode and account for its deliberate offset. A restart with a valid profile should not repeat the initial offset. An absent or invalid profile follows initialization again.

## [ SOURCE ]

[ph4ntxm-clock-fuzz.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-clock-fuzz.sh)  
[ph4ntxm-clock-fuzz.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-clock-fuzz.service)
