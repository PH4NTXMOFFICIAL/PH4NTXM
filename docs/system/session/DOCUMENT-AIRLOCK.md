# [ DOCUMENT AIRLOCK ]

## [ OVERVIEW ]

Converts supported PDF, Office documents and single-frame images into an image-only PDF using an offline disposable virtual machine.

## [ STARTUP ]

Run from the desktop account; root is rejected. Startup requires KVM, private namespaces, trusted guest hashes, disabled swap and private tmpfs storage. Actual `MemAvailable` is checked again before launch; managed hardware views are rejected. Failed isolation never falls back to a host office application.

## [ RUNTIME ]

Input must be a nonempty regular file of at most 64 MiB. Guest RAM is 384 MiB for images, 512 MiB for PDFs or 768 MiB for Office, plus a 192 MiB host reserve. A shared account lock permits one Document or Archive Airlock guest operation at a time.

The guest has no network adapter or shared home and uses a read-only root image. A bounded channel carries input and rendered RGB pages. The host rejects invalid framing, incomplete/trailing data and output exceeding 100 pages, 2400 pixels per dimension, 512 MiB RGB or 128 MiB compressed page data.

Conversion allows five minutes; cancellation stops the converter process group and low host RAM stops conversion. After it exits, review the pages and export to a new `.pdf` filename. Existing destinations are refused. The raster PDF replaces editable structure, macros, embedded objects and original metadata with page images; visible content remains.

Close cancels open dialogs, stops conversion and removes temporary pages. Startup/conversion errors restore controls; failed helper startup also terminates and reaps the converter. An uncatchable kill cannot run cleanup. CLI usage supports `--check` and `document --output new.pdf`.

## [ PASSWORDS ]

Masked prompts support encrypted PDFs, OpenDocument (`.odt/.ods/.odp/.odg`) and Office Open XML (`.docx/.xlsx/.pptx`). Encrypted legacy `.doc/.xls/.ppt` is unsupported. Guest pikepdf decrypts PDFs; LibreOffice uses a private UNO pipe with macros and document updates disabled. Office encryption support depends on the installed import filter.

Passwords travel through the private guest channel, never arguments, environment variables, password files or logs. Missing/rejected passwords are reported before output acceptance. Retrying discards incomplete results and starts a fresh guest. Cancel/Close stops the operation, and all resource limits still apply.

The source stays unchanged. Exported raster PDFs are unencrypted. CLI conversion prompts without echo in an interactive terminal; noninteractive calls fail with instructions to use GTK or an interactive terminal.

## [ CHECKS ]

Use `--check` for prerequisites. Test password retry/cancel and review layout, fonts and pagination before export, particularly for Office files. Distinguish isolation failures, actual-RAM limits, unsupported input and protocol/timeout errors.

## [ SOURCE ]

[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)\
[airlock.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/airlock.py)\
[guest.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/guest.py)
