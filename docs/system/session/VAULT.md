# [ VAULT ]

## [ OVERVIEW ]

PH4NTXM Vault collects explicitly selected files in private RAM and exports an encrypted `.ph4vault` file. It is an optional application, with no boot service or persistence of operating system configuration or profiles. Vault performs no external network access.

## [ STARTUP ]

Open PH4NTXM Vault from PH4NTXM Apps or open a `.ph4vault` file in the file manager. The command is `ph4ntxm-vault`. Create a new vault or manually enter a vault passphrase to unlock an existing one.

The desktop account needs private tmpfs storage under `/run/user/UID`, disabled swap and sufficient actual available RAM. Creating and exporting selected files does not need KVM. Opening existing vaults and reviewing files require the Airlock KVM guest. Missing prerequisites stop the operation.

## [ RUNTIME ]

Add Files accepts up to 32 selected nonempty regular files, with a combined limit of 64 MiB. Source files stay unchanged. New, Add, Remove and unlock operations keep their working data in private RAM. Changes remain there until another explicit Export.

Export writes a standard binary age file containing a ZIP archive, using a scrypt work factor of 18. A separate vault passphrase of at least 12 characters is required. Password entries are masked and cleared immediately. The application does not cache the passphrase. The crypto helper receives it through a pipe, never command arguments, environment variables, files or logs. Losing the passphrase leaves no recovery path.

The Go crypto helper runs without external networking in a private bubblewrap sandbox and a transient user service with a 512 MiB memory limit, zero swap and a 90-second deadline. Admission checks use actual RAM and tmpfs capacity. These limits also apply during decryption.

Only ciphertext is written to the chosen export destination. Publication is atomic and refuses replacement of an existing path. Failed writes do not replace an existing vault. Exported copies on external storage intentionally persist until the user removes them.

Opening an existing vault decrypts into private RAM. Manual Review uses the existing Archive Airlock guest and Document Airlock or Media Viewers for supported files. Small supported UTF-8 text files have a read-only preview. Unsupported files can be carried and exported but cannot be reviewed. Review does not sanitize file contents.

Lock and Close stop owned viewers and clear the private RAM session. New, Open, Lock and Close ask before discarding unexported changes. Closing during an operation requests cancellation and waits for cleanup. A cleanup failure remains visible for retry. Uncatchable termination cannot run application cleanup, and cleanup is not a guarantee of physical memory erasure.

## [ CHECKS ]

Run `ph4ntxm-vault --check` for prerequisites. Test a new export and manual unlock, a wrong passphrase, filename collisions, unsupported review types, cancellation and cleanup. Check file-count and byte limits, low actual RAM or tmpfs capacity, enabled swap, unavailable KVM and damaged ciphertext. An existing export must remain unchanged after any failed write.

## [ SOURCE ]

[ph4ntxm-vault](../../../config/includes.chroot/usr/local/bin/ph4ntxm-vault)\
[vault.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-vault/vault.py)\
[Crypto helper](../../../config/includes.chroot/usr/local/src/ph4ntxm-vault/main.go)\
[Build hook](../../../config/hooks/normal/0028-build-ph4ntxm-vault.chroot)\
[Archive Airlock](ARCHIVE-AIRLOCK.md)\
[Document Airlock](DOCUMENT-AIRLOCK.md)\
[Media Viewers](MEDIA-VIEWERS.md)
