# [ CPU LOCKDOWN ]

## [ OVERVIEW ]

Monitors CPU temperature and requests supported power controls during thermal events.

## [ STARTUP ]

The thermal guard records the current governors from readable cpufreq policies before entering its monitoring loop. It also saves Intel's `no_turbo` value, or the generic boost value when that is the available interface.

These saved values are the baseline for restoration. They are not a fixed performance profile selected by the session persona.

## [ RUNTIME ]

Every ten seconds, the guard reads numeric temperatures from the available thermal zones and takes the highest. Values below 1000 are treated as degrees and converted to millidegrees. Unreadable and invalid entries are skipped.

At 85°C or above, it requests `powersave` for the saved CPU policies, disables Intel turbo and disables generic boost where writable. Once throttled, it keeps that state until a valid positive reading reaches 70°C or below. This gap prevents repeated switching around a single threshold.

Restoration writes the original governor for each saved policy and the saved turbo/boost value. It does not simply assume the original state was `performance` or that boost was enabled.

Writes are best effort: unavailable or unwritable controls are skipped, and write failures are tolerated. The internal throttled flag therefore records that a throttle pass was attempted, not verified hardware readback.

Normal exit and handled interrupt/termination attempt baseline restoration. An uncatchable kill cannot run those handlers. If no valid positive temperature is available, the loop cannot use that absence as a cool reading to restore a throttled state.

## [ CHECKS ]

Compare thermal readings with live governor and boost files when diagnosing throttling. An active service alone does not prove every driver accepted the requested policy.

This guard manages thermal behavior. It is separate from reported CPU/core identity and does not change the selected hardware persona.

## [ SOURCE ]

[ph4ntxm-cpu-lockdown.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-cpu-lockdown.sh)
