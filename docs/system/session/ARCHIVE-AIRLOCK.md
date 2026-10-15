# [ ARCHIVE AIRLOCK ]

## [ OVERVIEW ]

Inspects local archives offline and opens one selected file through its isolated viewer. Parsing uses the Document Airlock guest image, outside the host broker.

## [ STARTUP ]

Open from PH4NTXM Apps or an associated archive in Thunar. Supported formats are ZIP, RAR/RAR5, 7z and TAR, including gzip/bzip2/xz/zstd TAR. ZIP supports ZipCrypto and WinZip AES. Encrypted RAR/7z and multipart archives are unsupported.

Thunar extraction actions are disabled and Xarchiver is hidden from menus and Open With. The separate Create Archive action preserves compression without opening existing archives.

The desktop account needs KVM, private namespaces, trusted guest artifacts, disabled swap and private tmpfs storage. Checks use actual RAM and reject managed hardware views. Failed isolation never falls back to host extraction.

## [ RUNTIME ]

The source stays unchanged. A nonempty regular archive of at most 128 MiB is copied into private RAM. The offline guest has no shared home and returns at most 1000 entries, 1024 UTF-8 bytes per name and 2 MiB metadata.

Selection uses entry numbers, including duplicate names. Unsafe paths, links and special files are blocked. Unsupported types have no Open action. A fresh guest streams the chosen file into a fixed private filename, checking actual bytes against limits and any known listed size.

Files are capped at 128 MiB, documents at 64 MiB and UTF-8 text previews at 1 MiB. Each operation allows three minutes and uses 512 MiB guest RAM, plus 96 MiB process overhead, 192 MiB host reserve and output capacity. Admission accounts for the archive copy and tmpfs capacity. Low actual RAM stops the guest. A shared lock permits one Airlock guest operation at a time.

After the guest exits, documents use Document Airlock, images/video/audio use Media Viewers, and small `.txt`, `.csv`, `.log` and `.md` files use read-only previews. Viewers check their own budgets. Media handoff uses a sealed RAM snapshot. Unpacking does not sanitize file contents or execute them.

Cancel/Close stops the operation. Cleanup checks the viewer process group, including surviving children, before deleting temporary files. If bounded termination fails, the workspace is retained and shown for retry. Worker errors restore usable controls. An uncatchable kill cannot run cleanup.

## [ PASSWORDS ]

Opening an encrypted ZIP entry asks for a masked password. It travels through the private guest channel, never arguments, environment variables, files or logs. It is scoped to the current archive and cleared on replacement, cancellation, closure or failed authentication.

Authentication, CRC and reader warnings discard incomplete output before any viewer starts. Retries use fresh guests and retain all resource/path limits. An encrypted document inside the ZIP asks separately through Document Airlock. Archive passwords are not forwarded.

## [ CHECKS ]

Use `--check` for prerequisites. After a build, test normal and encrypted archives, viewer handoff, cancellation, cleanup and blocked entries. Separate missing isolation, insufficient RAM/tmpfs, unsupported formats and damaged data. Solid archives remain subject to guest memory and timeout limits even during listing.

## [ SOURCE ]

[ph4ntxm-archive-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-archive-airlock)\
[archives.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/archives.py)\
[archive_protocol.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/archive_protocol.py)\
[archive_guest.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/archive_guest.py)
