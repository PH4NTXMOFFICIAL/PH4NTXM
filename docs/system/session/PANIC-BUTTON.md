# [ PANIC BUTTON ]

## [ OVERVIEW ]

Provides the operator's emergency Nuke activation window.

## [ STARTUP ]

The application opens a confirmation window for emergency Nuke activation. It does not start Panic on launch. Cancel or closing the initial window leaves the session running.

The window uses the shared PH4NTXM stylesheet and presents activation as an explicit action, separate from the tray shortcut that opened it.

## [ RUNTIME ]

Activate hides the confirmation window and opens a nondeletable progress window. The application processes pending GTK events so that view can appear before it calls the privileged command.

It runs `sudo systemctl start ph4ntxm-panic.service` and checks the returned status. The actual containment and termination sequence belongs to that system service, not to GTK or the lifetime of the tray process.

If the command returns failure, the progress window is destroyed, the original window is shown again and an error dialog appears. The failure path allows the user to see that activation was not reported successful.

If the service starts its intended sequence, the live user's applications may be terminated and the machine may leave the current kernel. The progress window acknowledges activation while the system service runs the sequence.

There is no cancel control after activation in the progress window. Closing the original confirmation before activation and stopping an already submitted system service are different operations.

## [ CHECKS ]

For routine inspection, review service availability and the loaded/locked crash-kernel state through [Health](HEALTH.md). 

If the action returns with an error, inspect the Panic service journal and helper permissions. The backend can have completed some best-effort containment steps before a later failure.

## [ SOURCE ]

[ph4ntxm-panic-button](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button)
