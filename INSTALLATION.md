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

Build from the repository root:

```bash
sudo lb config
sudo lb build
```

For a rebuild, preserve any previous ISO you need, then run:

```bash
sudo lb clean
sudo lb config
sudo lb build
```

Do not run two builds in the same checkout.  
Run commands in order and stop if one fails.  
After a successful build, the ISO is in the repository root.  
Do not bypass signature or checksum failures.

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

Boot the USB on supported amd64 hardware and select Linux, Windows, or Lonewolf.  
Allow enough RAM for the live image, applications, and `crashkernel=256M` reservation.  
Firmware, drivers, and Nuke arming must work on the selected machine.

Boot Pilot opens after startup. Its Wi-Fi selector is available in every mode.  
Continue closes Pilot; the separate browser button launches Firefox ESR or Tor Browser.  
Both remain gated by the required protection checks. Lonewolf needs internet access before Tor can bootstrap.

PH4NTXM is intended for bare-metal use. Virtualized environments compromise its security model.

Read the [session documentation](docs/system/session/) for session components and operation.
