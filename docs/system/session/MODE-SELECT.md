# [ MODE SELECT ]

## [ OVERVIEW ]

Prints the mode recorded in `/run/ph4ntxm/mode`.

## [ STARTUP ]

Callers run `/usr/lib/ph4ntxm/ph4ntxm-mode-select.sh` when they need the recorded mode on standard output. It is a short-lived reader, with no background loop, interactive choice or systemd readiness notification.

## [ RUNTIME ]

The helper checks whether `/run/ph4ntxm/mode` is a regular file. When it is, `cat` copies its contents to standard output. When it is not, the helper prints `linux` followed by a newline.

The existing contents are passed through unchanged. This reader does not validate the token, strip extra lines or replace an empty file with the fallback. An existing file that cannot be read makes `cat` fail, and the script returns failure. The fallback applies to the file check, not every read error.

The output is meant for the calling command. No environment variable is exported to the parent shell, no marker is created, and no identity or network service is started.

The name refers to reading the selected mode. Actual selection happens in [Mode](MODE.md), which parses the boot argument and writes canonical state. [Mode Environment](MODE-ENVIRONMENT.md) has separate validation and fallback behavior for shell exports. These readers should not be treated as interchangeable readiness checks.

## [ CHECKS ]

Compare the helper's output and exit status with the mode file and `ph4ntxm-mode.service`. A printed Linux fallback can mean that the file is absent, not that Linux startup succeeded.

If a caller sees an empty or unexpected value, inspect the file first. Its contents pass through directly, so changing the caller's environment will not repair the underlying record.

## [ SOURCE ]

[ph4ntxm-mode-select.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-mode-select.sh)
