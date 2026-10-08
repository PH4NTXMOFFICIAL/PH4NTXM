# [ ARCHIVE AIRLOCK ]

## [ OVERVIEW ]

Lists local archives offline and opens one selected file through its supported isolated viewer. It uses the Document Airlock guest image without installing an archive parser in the host broker.

## [ STARTUP ]

Open Archive Airlock from PH4NTXM Apps or open an associated archive in the file manager. ZIP, RAR/RAR5, 7z and TAR are supported, including gzip, bzip2, xz and zstd compressed TAR. Encrypted and multipart archives are not supported.

Run from the desktop account. KVM access, private namespaces, trusted guest artifacts, disabled swap and a private tmpfs runtime directory are required. Checks read actual available RAM and reject managed hardware-view environments. Missing isolation does not fall back to host extraction.

## [ RUNTIME ]

The original archive remains unchanged. The broker copies a nonempty regular file of at most 128 MiB into its private RAM workspace. The guest receives those bytes through the existing offline VM channel and returns a bounded contents listing. There is no shared host home or network adapter.

Listings contain at most 1000 entries, names of at most 1024 UTF-8 bytes and at most 2 MiB metadata. Selection uses the entry number, including when names are duplicated. Unsafe paths, links, special files and encrypted entries are blocked. Unsupported file types stay visible without an Open action. Archive-created names and permissions are never used to create host filesystem paths.

Opening a supported file starts a fresh archive guest, streams that selected entry into a fixed private filename and closes the guest before launching its viewer. Actual streamed bytes are checked independently of the declared size. Files are limited to 128 MiB, documents to 64 MiB and UTF-8 text previews to 1 MiB. A known listed size is also enforced. There is no recursive extraction or automatic execution.

Archive guests use 512 MiB RAM. Admission also reserves 96 MiB for the virtual-machine process, 192 MiB for the host and the selected output budget after the archive copy has been charged to memory. RAM workspace capacity is checked separately. A low-memory check stops the guest if actual available RAM falls below the host reserve. The shared Airlock lock permits one guest operation at a time. Each archive operation has a three-minute timeout.

Documents open through Document Airlock, images through Image Viewer, and supported audio/video through Media Player. Small `.txt`, `.csv`, `.log` and `.md` files have a read-only UTF-8 preview. These viewers perform their own resource checks after the archive guest has exited. Unpacking preserves the original file bytes; it does not sanitize their document or media structure.

Close or Cancel stops the active operation. The selected temporary file remains available until its viewer exits, then is removed. Closing Archive Airlock removes the copied archive and its private workspace. `--check` verifies isolation prerequisites.

## [ CHECKS ]

After an ISO build, open a normal archive, search for an entry and view a document, image and text file. Verify cancellation during inspection and closing with a viewer open. Confirm that blocked links and paths remain unopenable and that unsupported types do not launch another application.

Distinguish missing KVM or namespaces, insufficient real RAM or workspace capacity, unsupported encryption/compression and damaged archives. Solid archives can require substantial decompression even while listing; the guest memory and time limits still apply.

## [ SOURCE ]

[ph4ntxm-archive-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-archive-airlock)\
[archives.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/archives.py)\
[archive_protocol.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/archive_protocol.py)\
[archive_guest.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/archive_guest.py)
