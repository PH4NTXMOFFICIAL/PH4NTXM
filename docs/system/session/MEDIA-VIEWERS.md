# [ MEDIA VIEWERS ]

## [ OVERVIEW ]

Ristretto displays local images, including WebP, and Parole plays local video and audio. Both follow the selected desktop edition.

## [ STARTUP ]

Available through the PH4NTXM applications menu and default media associations. Select one or more local files.  
Document Airlock remains available through Open With for supported images; PDF and Office documents continue to use Airlock.

## [ RUNTIME ]

Each opening uses disposable namespaces, a private display and session bus, read-only selected files and a network-blocking syscall filter. Audio leaves through a fixed-format PCM pipe.  
Memory, CPU and process limits cover the whole session. Closing the window stops its processes and discards temporary state.  
Desktop thumbnails and the initial file-manager preview are disabled. The viewer opens only when the required isolation is available.

## [ SOURCE ]

[ph4ntxm-media](../../../config/includes.chroot/usr/local/bin/ph4ntxm-media)  
[media.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-media/media.py)  
[filter.c](../../../config/includes.chroot/usr/local/src/ph4ntxm-media/filter.c)
