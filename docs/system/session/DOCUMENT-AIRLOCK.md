# [ DOCUMENT AIRLOCK ]

## [ OVERVIEW ]

Converts supported PDF, Office documents and single-frame images into an image-only PDF using an offline disposable virtual machine.

## [ STARTUP ]

Airlock accepts a local PDF, supported Office document or single-frame image and converts it inside a disposable KVM guest. Run it from the desktop account. Root is rejected.

Startup checks KVM access, private namespaces, trusted image hashes, available RAM and a private tmpfs runtime directory. Active swap prevents conversion. There is no fallback to opening the original document in a host office application.

## [ RUNTIME ]

Input must be a nonempty regular file of at most 64 MiB. The converter uses 384 MiB guest RAM for images, 512 MiB for PDFs and 768 MiB for Office formats, with another 192 MiB required as host reserve. An account-level lock permits one conversion at a time.

The guest has no network adapter or shared home directory. Its root image is read-only, and document bytes enter through a bounded channel. Host-side validation accepts rendered RGB pages rather than the original document structure.

Output is limited to 100 pages, 2400 pixels per dimension, 512 MiB total RGB and 128 MiB compressed page data. Invalid framing, incomplete data, trailing bytes or exceeded budgets fail the conversion. The host timeout is five minutes. Cancellation terminates the converter process group.

After conversion, the isolated process has closed. The UI lets you review pages before exporting a newly constructed raster PDF. The PDF contains rendered page images without the original macros, embedded objects or metadata. Raster output replaces editable text and document structure.

Export requires a new `.pdf` filename and refuses an existing destination. Closing removes temporary pages. The command-line form supports `--check` for prerequisites and `document --output new.pdf` for direct conversion/export.

## [ CHECKS ]

Review page layout, fonts and pagination in the preview before exporting, particularly for Office documents.

For failures, separate missing isolation prerequisites, memory limits, unsupported input and protocol/timeout errors. The source document is not overwritten.

## [ SOURCE ]

[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)  
[airlock.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/airlock.py)  
[guest.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/guest.py)
