# [ DOCUMENT AIRLOCK ]

## [ OVERVIEW ]

Converts supported PDF, Office documents and single-frame images into an image-only PDF using an offline disposable virtual machine.

## [ STARTUP ]

Airlock accepts a local PDF, supported Office document or single-frame image and converts it inside a disposable KVM guest. Run it from the desktop account. Root is rejected.

Startup checks KVM access, private namespaces, trusted image hashes, actual available RAM and a private tmpfs runtime directory. Memory checks read native `MemAvailable` and run again immediately before guest launch. A managed hardware-view environment is rejected. Active swap prevents conversion. There is no fallback to opening the original document in a host office application.

## [ RUNTIME ]

Input must be a nonempty regular file of at most 64 MiB. The converter uses 384 MiB guest RAM for images, 512 MiB for PDFs and 768 MiB for Office formats, with another 192 MiB required as host reserve. An account-level lock permits one Document or Archive Airlock guest operation at a time.

The guest has no network adapter or shared home directory. Its root image is read-only, and document bytes enter through a bounded channel. Host-side validation accepts rendered RGB pages rather than the original document structure.

Output is limited to 100 pages, 2400 pixels per dimension, 512 MiB total RGB and 128 MiB compressed page data. Invalid framing, incomplete data, trailing bytes or exceeded budgets fail the conversion. The host timeout is five minutes. Cancellation terminates the converter process group.

After conversion, the isolated process has closed. The UI lets you review pages before exporting a newly constructed raster PDF. The PDF contains rendered page images without the original macros, embedded objects or metadata. Raster output replaces editable text and document structure.

Export requires a new `.pdf` filename and refuses an existing destination. Closing cancels open password and export dialogs, stops an active conversion and removes temporary pages. Worker startup or conversion errors restore the operation controls and allow closing; failed helper startup also terminates and reaps the isolated converter. An uncatchable kill cannot run host cleanup. The command-line form supports `--check` for prerequisites and `document --output new.pdf` for direct conversion/export.

## [ PASSWORDS ]

Password-protected PDFs and supported encrypted OpenDocument (`.odt`, `.ods`, `.odp`, `.odg`) and Office Open XML (`.docx`, `.xlsx`, `.pptx`) documents can be opened through a masked GTK prompt. Encrypted legacy `.doc`, `.xls` and `.ppt` are outside this support; their existing unencrypted conversion remains available. PDF decryption uses pikepdf inside the disposable guest. Office documents use LibreOffice through a private UNO pipe with a password property, disabled macros and disabled document updates. Password support depends on the installed LibreOffice import filter; unsupported encryption fails the conversion.

The password is sent through the bounded private input channel, never command arguments or environment variables, with no password file or log. A missing or rejected password is reported before rendered output is accepted. Retrying starts a new guest and removes incomplete results. Cancel and Close stop the operation. Existing input, page, pixel, timeout and actual-RAM limits still apply; low host RAM stops conversion.

The source remains unchanged. Export produces a new unencrypted raster PDF; it does not inherit the source password. The command-line conversion prompts without echo in an interactive terminal. Noninteractive calls fail with instructions to use the GTK app or an interactive terminal.

## [ CHECKS ]

Review page layout, fonts and pagination in the preview before exporting, particularly for Office documents.

For failures, separate missing isolation prerequisites, memory limits, unsupported input and protocol/timeout errors. The source document is not overwritten.

## [ SOURCE ]

[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)  
[airlock.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/airlock.py)  
[guest.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/guest.py)
