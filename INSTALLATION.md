# [ INSTALLATION ]

## [ BUILD HOST ]

Use Debian 13 `trixie` on amd64, with administrative access, internet connectivity, and enough space for the package cache, build chroot, and ISO.

## [ GETTING STARTED ]

Install the build tools:

```bash
sudo apt update
sudo apt install git live-build
```

Clone the repository:

```bash
git clone https://github.com/PH4NTXMOFFICIAL/PH4NTXM.git
cd PH4NTXM
```

Choose Abyss for the dark navy desktop or Ghost for the light pearl-white desktop with cyan and magenta accents. Both provide the same boot modes and system components.

Build the default Abyss edition from the repository root:

```bash
sudo ./build.sh --edition abyss
```

Build the Ghost edition:

```bash
sudo ./build.sh --edition ghost
```

To inspect the prepared configuration without downloading packages or building an ISO:

```bash
./build.sh --edition ghost --prepare-only
```

Run preparation with sudo if an earlier sudo build owns the edition directory.

The wrapper prepares each edition under `build/<edition>/`, runs `lb config` and `lb build`, and copies successful outputs into a new directory under `output/`, together with `SHA256SUMS`. Repeating the build command cleans the selected edition's previous live-build state while preserving its package cache and previously exported images. It does not clean builds in the repository root or the other edition.

The usual `sudo lb config` followed by `sudo lb build` from the repository root also builds Abyss through this wrapper. Choose Ghost explicitly with `--edition ghost`.

A lock prevents two builds of the same edition from running together. The wrapper refuses an unmanaged directory or mounted filesystems in its build workspace. Resolve the reported condition before retrying.

Do not run `lb` manually inside a managed edition directory while its wrapper is active. Stop on signature or checksum failures.

See [BUILD EDITIONS](docs/build/BUILD-EDITIONS.md) for source layout and appearance settings.

## [ CLEANUP AND OUTPUTS ]

The build script cleans the selected edition's previous build before rebuilding. The ISO inside `build/abyss/` or `build/ghost/` is a working output; successful builds also export a separate copy into a timestamped directory under `output/`.

Plain `lb clean` removes intermediate state and matching generated images in the working directory where it runs. At the repository root it cleans older root-level builds; it does not descend into `build/abyss/` or `build/ghost/`. When run inside an edition's build directory, it removes that directory's generated ISO. The exported copies under the repository's `output/` directory are retained by this workflow.

Cleanup preserves the source under `config/` and `editions/`. Switching the next build to the other edition uses the same clone. Package caches are kept by plain `lb clean`; `--purge` also removes the cache in the directory being cleaned.

## [ CREATE BOOTABLE USB ]

Use a USB device large enough for the generated ISO. All existing data on the selected device will be erased.

Find the USB by its size. If unsure, compare the output before and after plugging it in:

```bash
lsblk
```

Unmount the USB's mounted partitions first. Run from the folder containing your ISO.  
Replace `ph4ntxm.iso` with your ISO filename and `/dev/sdX` with the USB disk, not a partition such as `/dev/sdX1`. Confirm the target before running:

```bash
sudo dd if=ph4ntxm.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

Wait for completion before removing the USB.

## [ BOOTING ]

Boot the USB on supported amd64 hardware and select Linux, Windows, or Lone Wolf.  
Allow enough RAM for the live image, applications, and `crashkernel=256M` reservation.  
Firmware, drivers, and Nuke arming must work on the selected machine.

Boot Pilot opens after startup. Its Wi-Fi selector is available in every mode.  
Continue closes Pilot; the separate browser button launches Firefox ESR or Tor Browser.  
Both remain gated by the required protection checks. Lone Wolf needs internet access before Tor can bootstrap.

PH4NTXM is intended for bare-metal use. Virtualized environments compromise its security model.

Read the [session documentation](docs/system/session/) for session components and operation.
