# [ CPU LOCKDOWN ]

## [ OVERVIEW ]

Monitors CPU temperature and requests supported power controls during thermal events.

## [ STARTUP ]

Records the governor and boost state present when the service starts. Available thermal zones provide the readings used by the monitoring loop.

## [ RUNTIME ]

Samples temperatures every ten seconds and uses the highest reading. At 85°C it requests powersave and disables supported turbo or boost controls.  
Recovery occurs at a positive reading of 70°C or lower, restoring the recorded settings. The separated thresholds avoid rapid policy switching.  
Intel P-State and generic boost controls are supported. Driver and permission failures are tolerated while monitoring continues.

## [ SOURCE ]

[ph4ntxm-cpu-lockdown.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-cpu-lockdown.sh)
