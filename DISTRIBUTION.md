# [ DISTRIBUTION ]

## [ MODEL ]

PH4NTXM is distributed as source through [PH4NTXMOFFICIAL/PH4NTXM](https://github.com/PH4NTXMOFFICIAL/PH4NTXM).  
We do not provide official pre-built binaries or signed ISO releases.  
Operators build their own images with Debian live-build.

Package archives and external downloads can change between builds.  
The same source revision does not guarantee a byte-identical ISO.

## [ BUILDING PH4NTXM ]

Verify the selected source revision below, then follow [INSTALLATION.md](INSTALLATION.md) to build and prepare live media.

## [ AUTHENTICITY & INTEGRITY ]

Our key is [ph4ntxm-public-key.asc](ph4ntxm-public-key.asc). From the repository root, display its fingerprint:

```bash
gpg --show-keys --with-fingerprint ph4ntxm-public-key.asc
```

Confirm the fingerprint through a trusted independent channel before importing it:

```bash
gpg --import ph4ntxm-public-key.asc
git tag --list
```

For example, select `v1.1.0` below. Replace it with the release you want.

Verify the tag and confirm the signer matches the trusted key:

```bash
git verify-tag v1.1.0
```

If verification succeeds, switch to that release and verify its commit. Run each command separately and stop if either fails:

```bash
git switch --detach v1.1.0
git verify-commit HEAD
```

Build only after both signatures match the trusted key.  
A good signature with an owner-trust warning still requires fingerprint confirmation.  
The signatures cover source revisions, not local changes or the built ISO.

Each exported build includes `SHA256SUMS`. Run this from its `output/` subdirectory alongside the ISO, and repeat after transfer:

```bash
sha256sum --check SHA256SUMS
```

Keep the source revision, local change record, edition and exported checksums together when recording a build. They identify what was built and which exported files were checked. A checksum verifies the file against that record. Source authenticity still comes from the trusted signing key.

## [ REDISTRIBUTION ]

PH4NTXM project code uses [GNU GPLv3](LICENSE).  
Bundled components retain their own licenses and notices.  
Modified distributions must identify their changes and follow [TRADEMARKS.md](TRADEMARKS.md).
