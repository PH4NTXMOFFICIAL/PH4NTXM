# [ CLIPBOARD GUARD ]

## [ OVERVIEW ]

Clipboard Guard optionally clears copied content after a chosen timeout without retrieving its contents or maintaining clipboard history. It operates on the host X11 display. Nested Airlock desktops have separate clipboards and are outside this control.

## [ STARTUP ]

Open PH4NTXM Clipboard Guard from PH4NTXM Apps. Protection starts disabled at each boot. The initial timeout is 60 seconds. While disabled, choose a timeout from 1 to 86400 seconds and whether to also cover selected text pasted through middle-click. Ordinary clipboard coverage is enabled by default. Enable starts protection without root privileges or session-password authentication.

## [ RUNTIME ]

Enable starts a countdown for each currently owned selection and observes later ownership renewals. Each new copy starts a fresh countdown for its selection. The clipboard and optional middle-click selection have independent timers. Event-driven XFixes notifications provide ownership metadata without requesting text, images, targets or other clipboard contents. Clipboard Guard itself creates no clipboard history or content files and makes no external network requests.

Timers use a monotonic clock rather than the session's wall clock. Expiry clears a selection using its X server timestamp so an older timer cannot clear a newer ownership generation. A fresh copy from the same application also renews the timer when the application renews selection ownership.

Clear Now explicitly clears the selected coverage. Disable cancels pending timers and leaves current contents available. Closing the controls keeps enabled protection running. Opening the application again returns to the same instance. Settings and timers are kept only in process memory. Stopping the process ends protection.

When a clipboard history manager owns the X11 `CLIPBOARD_MANAGER` selection, startup uses XRes metadata to identify its local process. When the process is the current user's verified xfsettingsd, it launches a replacement with XFSETTINGSD_NO_CLIPBOARD=1. The supported --replace mechanism keeps the other Xfce settings functions active while disabling clipboard persistence. This is a runtime change, without editing autostart or desktop settings. Cached clipboard content held by the old daemon may be lost. The choice remains until xfsettingsd restarts without that environment setting or the session ends. Startup can also stop the current user's verified standalone Clipman instance on this display. Clipman termination uses a process handle, SIGTERM and a bounded wait without elevated privileges. It does not stop a panel process or an unknown manager. If ownership cannot be verified, XRes is unavailable or the manager does not stop, close the manager manually before trying again.

Clipman is stopped only for the current session and is not restarted automatically. Clipboard Guard does not read or delete its existing history, change global settings or alter autostart entries. Clipman may save existing history during its normal termination. If a clipboard manager appears while protection is enabled, monitoring stops and the controls show an error.

## [ CHECKS ]

Choose a short timeout, enable protection and copy harmless text. Paste immediately, then confirm it is unavailable after the timeout. Copy different text before the first timeout and confirm the newer copy receives its own full interval. Repeat within the same application. If middle-click coverage is selected, test a text selection separately.

Confirm Disable leaves copied text available beyond the configured timeout. Close and reopen the controls while enabled, then repeat expiry. An unknown manager must prevent startup. Starting a clipboard manager that owns `CLIPBOARD_MANAGER` while protection is enabled must produce an error and disable protection rather than silently claiming to expire its history. With the native Xfce manager active, confirm Enable succeeds and xfsettingsd remains running with its other settings functions. With standalone Clipman active before startup, confirm only its instance on this display stops and that it is not restarted automatically.

This reduces accidental clipboard exposure. Applications and clipboard managers may already hold independent copies, which cannot be revoked. It is not a security boundary against malicious clients in the same X11 session. Root or host compromise and stopping the user process can defeat it. Unsupported display access is reported instead of silently claiming protection.

## [ SOURCE ]

[ph4ntxm-clipboard-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-clipboard-guard)\
[Timer and lifecycle policy](../../../config/includes.chroot/usr/lib/ph4ntxm/clipboard_guard.py)\
[X11 ownership backend](../../../config/includes.chroot/usr/lib/ph4ntxm/clipboard_guard_x11.py)\
[GTK controls](../../../config/includes.chroot/usr/lib/ph4ntxm/clipboard_guard_gui.py)\
[Verified Clipman termination](../../../config/includes.chroot/usr/lib/ph4ntxm/clipboard_guard_manager.py)\
[Build integration](../../../config/hooks/normal/0038-install-ph4ntxm-clipboard-guard.chroot)
