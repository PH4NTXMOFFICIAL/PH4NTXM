# [ BROWSER AIRLOCK ]

## [ OVERVIEW ]

Optional containment for browser sessions launched through the Browser Airlock application. It shares the host kernel and preserves the selected network policy while limiting file and desktop access.

## [ STARTUP ]

Open **PH4NTXM Apps → PH4NTXM Browser Airlock** or run `ph4ntxm-browser-airlock`. Linux and Windows use Firefox ESR. Lone Wolf uses Tor Browser after its integrity and network readiness checks. Boot Pilot, panel shortcuts, desktop links and the default browser continue using their existing launchers. Browser Airlock does not register default URL or file associations. A local X11 desktop, private runtime, working user services, RAM-backed temporary storage, disabled swap and Landlock ABI 6 are required. Missing isolation stops launch.

## [ RUNTIME ]

Private filesystem, user, process, IPC and UTS namespaces, a nested Xephyr display and a private bus isolate the browser from host files, mounted disks, clipboard and session buses. A fixed native setuid bootstrap creates private process and mount namespaces, restores the protected CPU identity in normal modes, then permanently drops root privileges before starting unprivileged Bubblewrap. The browser and display run as the live user. No privileged browser process remains. Landlock scopes block host abstract Unix sockets and signals. Firefox's native child sandbox remains enabled. The browser parent retains existing networking and localhost access for Tor and Browser Check.

Linux and Windows keep the generated identity, selected fonts, Fontconfig and GL inputs. Their Airlock Firefox profile remains in RAM within the boot, separate from the default browser profile, with existing privacy preferences unchanged. Cookies, logins and history are not copied between the two profiles. Each new Tor controller uses a fresh home and the verified bundle without normal Firefox persona overrides. A private native `getconf` command and a read-only mount of the verified Tor executable support the upstream architecture check inside that home. The installed Tor bundle and host hardware wrappers remain unchanged.

Import Files copies up to 32 selected regular files, at most 64 MiB combined, into read-only `/workspace/imports`. Import remains available while browsing. A local file explicitly passed to `ph4ntxm-browser-airlock` is copied before opening inside the browser. Originals remain unchanged.

Downloads stay under private `/workspace/downloads`. Use Downloads, stop the browser, review files and explicitly export selected copies. Resume retains the current profile. Export allows 512 MiB per file and 1 GiB combined, with bounded depth and entry counts. Existing destinations and unsafe file types are refused. Export does not sanitize content.

Closing stops owned processes before clearing the session home and workspace. Unexported downloads require explicit discard. The Airlock Firefox profile is retained separately until reboot. The default browser profile is unaffected. Cleanup failures remain visible. An uncatchable kill can leave private RAM files until cleanup or reboot.

The browser service has bounded memory, tasks, CPU and runtime, with zero worker swap.

## [ CHECKS ]

Run `ph4ntxm-browser-airlock --check` from the desktop account. Verify the menu entry, normal browser shortcuts, Airlock startup, a second Airlock URL request, expected identity/fonts, imports, stopped-session export, Resume and Close in the ISO. Verify the default browser and Airlock use separate profiles. In Lone Wolf, keep only one Tor Browser session open when running Health Browser Check so the observer can identify its profile unambiguously. The build runs guard, bootstrap, profile, backend, controller, display and Tor observer tests. The bootstrap test checks compilation and caller privileges. Its native fixture uses a disposable private mount namespace and reports a skip when namespace capability is unavailable or the build chroot has no mount point at `/`. Validate the built ISO in each selected mode.

If browsing stops unexpectedly, inspect `/tmp/ph4ntxm-browser-airlock.*/state.json` before using Resume. The record distinguishes browser-worker and display exits, retains bounded diagnostic output and includes available cgroup memory counters. Recorded OOM kills are reported as failures, including the sandbox limit when it was reached, even if the supervisor received a stop signal or a child returned zero. Memory pressure without a recorded kill does not turn a clean stop into a memory failure. Startup waits are bounded and identify the display or session bus that failed to become ready.

## [ SOURCE ]

[Menu entry](../../../config/includes.chroot/usr/share/applications/ph4ntxm-browser-airlock.desktop)\
[Entry](../../../config/includes.chroot/usr/local/bin/ph4ntxm-browser-airlock)\
[Backend](../../../config/includes.chroot/usr/local/src/ph4ntxm-browser-airlock/browser_airlock.py)\
[Profiles](../../../config/includes.chroot/usr/local/src/ph4ntxm-browser-airlock/browser_profiles.py)\
[Controller](../../../config/includes.chroot/usr/local/src/ph4ntxm-browser-airlock/browser_controller.py)\
[Native guard](../../../config/includes.chroot/usr/local/src/ph4ntxm-browser-airlock/guard.c)\
[Bootstrap](../../../config/includes.chroot/usr/local/src/ph4ntxm-browser-airlock/bootstrap.c)\
[Build hook](../../../config/hooks/normal/0037-build-ph4ntxm-browser-airlock.chroot)
