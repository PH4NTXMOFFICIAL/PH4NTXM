# [ DISTRIBUTION ]

## [ MODEL ]

PH4NTXM is distributed as source through [PH4NTXMOFFICIAL/PH4NTXM](https://github.com/PH4NTXMOFFICIAL/PH4NTXM).  
We do not provide official pre-built binaries or signed ISO releases.  
Operators build their own images with Debian live-build.

Package archives and external downloads can change between builds.  
The same source revision does not guarantee a byte-identical ISO.

## [ BUILDING PH4NTXM ]

Follow [INSTALLATION.md](INSTALLATION.md) to build and prepare live media.

## [ AUTHENTICITY & INTEGRITY ]

Our key is [ph4ntxm-public-key.asc](ph4ntxm-public-key.asc). From the repository root, display its fingerprint:

```bash
gpg --show-keys --with-fingerprint ph4ntxm-public-key.asc
```

Confirm the fingerprint through a trusted independent channel before importing it:

```bash
gpg --import ph4ntxm-public-key.asc
git verify-commit HEAD
```

Stop on a bad signature or unexpected signer.  
A good signature with an owner-trust warning still requires fingerprint confirmation.  
The signature covers the commit, not local changes or the built ISO.

From the ISO folder, record its SHA256 and compare it after transfer. Replace `ph4ntxm.iso` with your ISO filename:

```bash
sha256sum ph4ntxm.iso
```

## [ REDISTRIBUTION ]

PH4NTXM project code uses [GNU GPLv3](LICENSE).  
Bundled components retain their own licenses and notices.  
Modified distributions must identify their changes and follow [TRADEMARKS.md](TRADEMARKS.md).
