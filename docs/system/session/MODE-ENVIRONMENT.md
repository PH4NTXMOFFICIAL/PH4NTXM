# [ MODE ENVIRONMENT ]

## [ OVERVIEW ]

Exports the active mode to login shells as `PH4NTXM_MODE`.

## [ STARTUP ]

Login-shell profile processing sources `/etc/profile.d/ph4ntxm-mode.sh`. The code runs in that shell, allowing the exported value to reach commands launched from it. It is not a service and does not supervise the mode file.

## [ RUNTIME ]

The helper starts with `/run/ph4ntxm/mode` as its source. If the file is readable, it reads one line into `PH4NTXM_MODE` using `IFS=` and `read -r`. A failed read selects `linux`. An unreadable file does the same.

The value is then checked against the exact lowercase tokens `linux`, `windows` and `lonewolf`. Anything else becomes `linux`, including an empty or malformed token. Only this validated value is exported.

Child processes inherit the value from their launching shell. Already-running programs keep their own environment, and a program that supplies a separate environment can use different values. Changing the variable in a terminal does not rewrite `/run/ph4ntxm/mode` or switch the service markers selected during boot.

Unlike [Mode Select](MODE-SELECT.md), this helper reads one line and validates it. Both depend on the canonical state written by [Mode](MODE.md), but neither establishes that the corresponding protection chain is ready. The Linux fallback keeps shell initialization usable when state is unavailable.

## [ CHECKS ]

In the affected login shell, compare `printf '%s\n' "$PH4NTXM_MODE"` with `/run/ph4ntxm/mode`. Check when the profile was sourced if a newly opened shell differs from an existing process.

For missing state, inspect `ph4ntxm-mode.service` and its marker files. A valid shell variable alone does not establish successful mode initialization.

## [ SOURCE ]

[ph4ntxm-mode.sh](../../../config/includes.chroot/etc/profile.d/ph4ntxm-mode.sh)
