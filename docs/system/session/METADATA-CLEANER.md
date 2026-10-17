# [ METADATA CLEANER ]

## [ OVERVIEW ]

PH4NTXM Metadata Cleaner inspects supported metadata and creates separate cleaned copies. It uses Debian mat2 inside an offline process sandbox. Original files stay unchanged. Cleaning does not remove identifying visible content, filenames, watermarks or steganography and does not establish anonymity.

## [ STARTUP ]

Open **PH4NTXM Metadata Cleaner** from PH4NTXM Apps or run `ph4ntxm-metadata-cleaner -- file`. The normal desktop account, private user runtime, RAM-backed `/tmp`, disabled swap and a working user service manager are required. KVM is needed only for previews that use Document Airlock.

## [ RUNTIME ]

Add up to 32 nonempty regular files, 64 MiB each and 128 MiB combined. Inspect reads the private snapshot. Clean Copy reports supported metadata Before and After, including remaining fields and report truncation. Supported formats include JPEG, PNG, GIF, single-page TIFF, SVG, HEIC, PDF, modern Office/OpenDocument, EPUB, ZIP/TAR, MP3, FLAC, Ogg/Opus, WAV/AIFF and MP4/AVI/WMV. Actual file features and installed codecs can limit support.

Private session files use a 0700 directory on verified `/tmp` tmpfs. The user runtime directory supplies the service-manager connection and isolated preview handoff. Processing has no external network access, home directory, display or audio connection. Private namespaces, a syscall filter, a 512 MiB memory limit, zero worker swap and a 180-second deadline bound the job. Admission checks count the worker memory bound once, separately from tmpfs capacity. Input is read-only and only a bounded report and verified output return to the application.

Unknown archive members and unsupported revision attribution stop cleaning. Animated PNG, multipage TIFF and PNG needing orientation normalization can be inspected but cannot be cleaned.

PDF cleaning rasterizes pages. Images may be rendered or re-encoded, and Office cleaning removes comments and supported change history. Review the result before sharing. Preview Original and Preview Cleaned use existing isolated viewers when the format supports them. A blank metadata report means no supported fields were reported, rather than proof that every identifying field is absent.

Export Copy saves only the selected cleaned result and refuses an existing destination. Each result is limited to 128 MiB, with a 128 MiB combined result limit. Clear and Close cancel workers, stop owned previews and remove session files. Failed cleanup remains visible for retry. Uncatchable termination can leave private RAM files until cleanup or reboot, with worker execution still bounded by its deadline.

## [ CHECKS ]

Run `ph4ntxm-metadata-cleaner --check`. Compare a metadata-bearing image, PDF and Office file before and after cleaning, then verify the originals are unchanged. Test malformed files, unknown archive members, encrypted inputs, existing export destinations, cancellation and cleanup. Supported inspection does not imply every feature can be cleaned or previewed.

## [ SOURCE ]

[ph4ntxm-metadata-cleaner](../../../config/includes.chroot/usr/local/bin/ph4ntxm-metadata-cleaner)\
[cleaner.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-metadata-cleaner/cleaner.py)\
[worker.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-metadata-cleaner/worker.py)\
[Build hook](../../../config/hooks/normal/0031-build-ph4ntxm-metadata-cleaner.chroot)\
[Document Airlock](DOCUMENT-AIRLOCK.md)\
[Media Viewers](MEDIA-VIEWERS.md)
