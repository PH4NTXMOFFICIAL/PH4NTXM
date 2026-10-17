# [ APP AIRLOCK ]

## [ OVERVIEW ]

PH4NTXM App Airlock runs installed applications and commands in a disposable offline desktop. It shares the host kernel through a process sandbox. It does not use the Document and Archive Airlock KVM guest.

## [ STARTUP ]

Open **PH4NTXM App Airlock** from PH4NTXM Apps or run `ph4ntxm-app-airlock`. Run `ph4ntxm-app-airlock --check` to verify prerequisites. The normal X11 desktop account, private runtime, working user service manager, RAM-backed `/tmp`, disabled swap and sufficient available RAM are required. Missing isolation stops startup.

## [ RUNTIME ]

Import up to 32 nonempty regular files, at most 64 MiB combined. Originals stay unchanged. Select an imported file to pass it to an application's desktop file argument. Typed commands refer to imported files through `/workspace` paths.

Application or command lists installed desktop entries without an application allowlist and also accepts a typed command with arguments. Commands run without an implicit shell. Root access, system package installation, networking and host device access remain unavailable. Applications that require those facilities may not work, and compatibility is not guaranteed.

Private namespaces, a syscall filter and a nested Xephyr display isolate execution from the host home, mounted disks, session buses, audio and direct desktop display. The isolated desktop has its own clipboard. Camera and microphone lockdown remains unchanged.

Save work under `/workspace`. This RAM workspace is reused across launches until Clear Workspace or Close. The private application home is discarded after each run. Graphical desktop entries open directly. Terminal entries and typed commands retain their output in an isolated terminal until it closes or Stop is requested. GSettings preferences stay in memory. Terminal completion does not verify that the contained command succeeded.

The transient user service limits memory to at most 768 MiB, tasks to 128, CPU to 200 percent and runtime to two hours, with zero worker swap. Stop terminates the owned application processes before listing or exporting results.

Outputs include regular workspace files and edited import copies. Export accepts at most 64 MiB per file and 128 MiB combined, with a 256-entry review limit and eight levels of subdirectories. Existing destinations are refused and new files use mode 0600. Export preserves untrusted content rather than sanitizing it. A workspace that exceeds review limits must be cleared before another launch.

Clear Workspace removes the stopped workspace. Close stops execution and removes its private RAM files. Cleanup failures remain visible for retry. Launcher termination stops the isolated processes. Uncatchable termination can leave RAM files until cleanup or reboot. This is not a guarantee of physical memory erasure.

## [ CHECKS ]

Test application selection, typed commands, imported file arguments, command quoting, unavailable applications, workspace reuse and explicit export. Check that host files, host clipboard, buses, audio and network remain unavailable. Test existing destinations, file limits, malformed outputs, Stop, Close during startup and cleanup failure. A successful launch is not a security review of the executed code.

## [ SOURCE ]

[ph4ntxm-app-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-app-airlock)\
[app_airlock.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-app-airlock/app_airlock.py)\
[Native guard](../../../config/includes.chroot/usr/local/src/ph4ntxm-app-airlock/guard.c)\
[Build hook](../../../config/hooks/normal/0032-build-ph4ntxm-app-airlock.chroot)
