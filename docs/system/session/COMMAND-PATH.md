# [ COMMAND PATH ]

## [ OVERVIEW ]

Sets the login shell's command search path.

## [ STARTUP ]

Login-shell profile processing sources `/etc/profile.d/ph4ntxm-path.sh`. Its export changes command lookup for that shell and for children that inherit the environment. There is no generator, daemon or runtime state file behind this helper.

## [ RUNTIME ]

The helper replaces PATH with this fixed order:

```text
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

The local directories come first so installed PH4NTXM commands and wrappers can be found before commands with the same name in the standard directories. The previous PATH is replaced rather than extended, so additional directories from an earlier environment are not retained by this assignment.

Build hooks install the wrappers. This profile gives their directories precedence during shell command lookup.

An explicit path such as `/usr/bin/tool` does not use PATH to select the executable. Services and applications that provide their own environment also need to be assessed at their launch point. The profile therefore explains terminal lookup, while build hooks and the individual launchers explain which wrappers actually exist.

The same distinction matters when comparing a command started in a login shell with one launched by a desktop entry or systemd unit.

## [ CHECKS ]

Read `printf '%s\n' "$PATH"` in the affected shell and use `command -v` for the command being investigated. Compare the resolved executable with the desktop entry or service's explicit command.

If lookup differs, check the launching environment before editing the wrapper. An expected PATH and a missing executable are different problems.

## [ SOURCE ]

[ph4ntxm-path.sh](../../../config/includes.chroot/etc/profile.d/ph4ntxm-path.sh)
