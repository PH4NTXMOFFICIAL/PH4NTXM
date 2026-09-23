# [ MEDIA VIEWERS ]

## [ OVERVIEW ]

Ristretto displays local images, including WebP, and Parole plays local video and audio. Both follow the selected desktop edition.

## [ STARTUP ]

The media launcher opens local images through Ristretto or audio/video through Parole inside disposable sandboxes. It requires the normal desktop account, private tmpfs runtime storage and a working user systemd manager.

Readiness tests the namespace and syscall-filter setup, including rejection of IPv4/IPv6 sockets. Failure stops launch instead of opening the file in an unisolated viewer.

## [ RUNTIME ]

Each request accepts one to 32 nonempty regular files. Online URLs are rejected. Local file URIs are supported. Image files are limited to 128 MiB, and special runtime/device paths are excluded. Selected files are opened and exposed read-only through file descriptors.

The viewer receives a private home, temporary directories, D-Bus session and nested Xephyr display. It does not get the ordinary desktop's home, GPU device or direct X socket. The separate display process bridges the nested window to the desktop, with GLX and XTEST disabled there.

Video audio uses a fixed raw PCM channel to a separate playback process. The decoder does not receive the host audio socket directly. Image sessions do not need that playback path.

A transient user service limits memory, swap, tasks and CPU. Memory is capped at 512 MiB for images or 768 MiB for video, reduced when available RAM requires it, while preserving a 192 MiB host reserve. Requests below the minimum budget are rejected. Swap allowance is zero, tasks are capped at 128 and CPU quota at 200 percent.

Closing the window stops child processes and the transient unit, then removes temporary state. Component failure or resource exhaustion closes the isolated view and reports an error. Source media remains read-only throughout the viewer session.

## [ CHECKS ]

Use `ph4ntxm-media --kind image --check` or the video equivalent to inspect prerequisites. This tests isolation/resource controls without decoding a chosen media file.

For playback failure, inspect the user-service journal and available memory. Use Document Airlock when a rendered PDF export is the intended result.

## [ SOURCE ]

[ph4ntxm-media](../../../config/includes.chroot/usr/local/bin/ph4ntxm-media)  
[media.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-media/media.py)  
[filter.c](../../../config/includes.chroot/usr/local/src/ph4ntxm-media/filter.c)
