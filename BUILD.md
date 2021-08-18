This doc details all the steps to build and run the emulator.


# Prerequisites
You will need a macOS system for some of the preparation steps.

# Getting dependencies

## Getting support tools

```sh
git clone https://github.com/TrungNguyen1909/qemu-t8030-tools
pip3 install pyasn1
```


### macOS Homebrew

```sh
brew install libtasn1 meson ninja pixman lzfse jtool2 jq
```


### Linux
```sh
sudo apt update
sudo apt install -y git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libtasn1-dev ninja-build build-essential cmake

# install lzfse
git clone https://github.com/lzfse/lzfse
cd lzfse
mkdir build; cd build
cmake ..
make
sudo make install
cd ..
```

Get jtool2 from the [jtool2's official website](http://newosxbook.com/tools/jtool.html).

There is a `jtool2.ELF64` inside the package.


# Building QEMU

```sh
git clone https://github.com/TrungNguyen1909/qemu-t8030
cd qemu-tt8030
mkdir build; cd build
../configure --target-list=aarch64-softmmu,x86_64-softmmu --disable-capstone --disable-slirp
make -j$(nproc)
```


# Getting iOS firmware

Download and unzip [iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw](https://updates.cdn-apple.com/2020SummerSeed/fullrestores/001-35886/5FE9BE2E-17F8-41C8-96BB-B76E2B225888/iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw)

```sh
wget https://updates.cdn-apple.com/2020SummerSeed/fullrestores/001-35886/5FE9BE2E-17F8-41C8-96BB-B76E2B225888/iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw
mkdir iphone; cd iphone
unzip ../iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw
```

# Getting precompiled system binaries

```shell
export STRAP_URL=$(curl https://assets.checkra.in/loader/config.json | jq ".core_bootstrap_tar" | cut -d '"' -f 2)
wget $STRAP_URL
mkdir strap
tar xf strap.tar.lzma -C strap
```

# Preparing the ramdisk

These steps are only needed if you want to add your own binaries to the ramdisk.

Note that for all the below steps might need to be run on macOS.

## Unpacking the ramdisk

```sh
python3 qemu-t8030-tools/bootstrap_scripts/asn1rdskdecode.py 038-44087-125.dmg 038-44087-125.dmg.out
```

```sh
# resize
hdiutil resize -size 512M -imagekey diskimage-class=CRawDiskImage 038-44087-125.dmg.out

# mount
hdiutil attach -imagekey diskimage-class=CRawDiskImage 038-44087-125.dmg.out

# enable ownership
sudo diskutil enableownership /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk

# Copy system binaries
sudo rsync -av strap/ /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk

# LaunchDaemons
sudo rm /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk/System/Library/LaunchDaemons/*
sudo cp qemu-t8030/setup-ios/bash.plist /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk/System/Library/LaunchDaemons/

# unmount
hdiutil detach /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk
```

## Creating trustcache for the modified ramdisk

This step is no longer needed as we now patch AMFI

### Bundled trustcache

```shell
python3 qemu-t8030-tools/bootstrap_scripts/asn1trustcachedecode.py Firmware/038-44087-125.dmg.trustcache Firmware/038-44087-125.dmg.trustcache.out
python3 qemu-t8030-tools/bootstrap_scripts/dump_trustcache.py Firmware/038-44087-125.dmg.trustcache.out | grep cdhash | cut -d' ' -f2 > tchashes
```

### System Binaries

```shell
for filename in $(find strap/ -type f); do jtool2 --sig $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes
```

### Serialize trustcache

```shell
python3 qemu-t8030-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
```

# Preparing the RootFS

This step is temporary as this is not enough to create a usable system.
As such, some userspace daemons might fail to start.

To create a usable system, we need to do a restore;
However, we haven't found a way to modify the virtual disk after restore yet.

So if you want to run your own binaries, either use the ramdisk environment, or follow the steps below.

## Convert the disk image
```sh
hdiutil convert 038-44337-083.dmg -format UDRW -tgtimagekey diskimage-class=CRawDiskImage -o disk.1
mv disk.1.dmg disk.1
```


## Mount the disk image
```sh
hdiutil attach -imagekey diskimage-class=CRawDiskImage disk.1

# enable ownership
sudo diskutil enableownership /Volumes/AzulSeed18A5351d.N104N841DeveloperOS

# mount with RW
mount -urw /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```


## Create Preboot and Data Volumes (disk3 is the APFS Volume)
```sh
sudo newfs_apfs -v Preboot -o role=b -e -A disk3
sudo newfs_apfs -v Data -o role=d -e -A disk3
```


## Create needed folders
```sh
sudo mkdir -p /Volumes/AzulSeed18A5351d.N104N841DeveloperOS/private/preboot/000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000/usr/standalone/firmware
sudo mkdir -p /Volumes/AzulSeed18A5351d.N104N841DeveloperOS/private/var/hardware/FactoryData/System/Library/Caches/com.apple.factorydata
```


## Add precompiled system binaries
```sh
sudo rsync -av strap/ /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```


## Create trustcache

This step is no longer needed as we now patch AMFI

### Bundled trustcache
```sh
python3 qemu-t8030-tools/bootstrap_scripts/asn1trustcachedecode.py Firmware/038-44337-083.dmg.trustcache Firmware/038-44337-083.dmg.trustcache.out
python3 qemu-t8030-tools/bootstrap_scripts/dump_trustcache.py Firmware/038-44337-083.dmg.trustcache.out | grep cdhash | cut -d' ' -f2 > tchashes
```

### Create trustcache for system binaries
```sh
for filename in $(find strap/  -type f); do jtool2 --sig $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes
```

### Serialize trustcache
```sh
python3 qemu-t8030-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
```


## Configure LaunchDaemons

Either use `setup-ios/launchd.plist`, or customize it from iOS firmware as follows.

- Copy `/Volumes/AzulSeed18A5351d.N104N841DeveloperOS/System/Library/xpc/launchd.plist` to somewhere else to work with.
- Convert to xml1 format: `plutil -convert xml1 /path/to/launchd.plist`
- Use Xcode or your preferred xml editor
  - Remove all entries in `LaunchDaemons` (may be optional)
  - Add an entry for bash in `LaunchDaemons`
```xml
		<key>/System/Library/LaunchDaemons/bash.plist</key>
		<dict>
			<key>EnablePressuredExit</key>
			<false/>
			<key>Label</key>
			<string>com.apple.bash</string>
			<key>POSIXSpawnType</key>
			<string>Interactive</string>
			<key>ProgramArguments</key>
			<array>
				<string>/bin/bash</string>
			</array>
			<key>RunAtLoad</key>
			<true/>
			<key>StandardErrorPath</key>
			<string>/dev/console</string>
			<key>StandardInPath</key>
			<string>/dev/console</string>
			<key>StandardOutPath</key>
			<string>/dev/console</string>
			<key>Umask</key>
			<integer>0</integer>
			<key>UserName</key>
			<string>root</string>
		</dict>
```

- Copy back
```sh
sudo cp /path/to/launchd.plist /Volumes/AzulSeed18A5351d.N104N841DeveloperOS/System/Library/xpc/launchd.plist
```


## Unmount the disk image
```
hdiutil detach /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```


# Creating NVMe namespaces

```sh
./qemu-t8030/build/qemu-img create -f qcow2 nvme.1.qcow2 128G
./qemu-t8030/build/qemu-img create -f raw nvme.2 8M
./qemu-t8030/build/qemu-img create -f raw nvme.3 128K
./qemu-t8030/build/qemu-img create -f raw nvme.4 8K
./qemu-t8030/build/qemu-img create -f raw nvram  8K
./qemu-t8030/build/qemu-img create -f raw nvme.6 4K
./qemu-t8030/build/qemu-img create -f raw nvme.7 1M
```


# Run

Don't forget that `-snapshot` can be used to prevent filesystem corruptions on reset.

`-smp` can be set up to 6 CPUs.

## Auto boot

This will put the device into Restore mode on the first run and boot to NAND after restore completed

```sh
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,trustcache-filename=Firmware/038-44135-124.dmg.trustcache,ticket-filename=root_ticket.der \
-kernel kernelcache.research.iphone12b \
-dtb Firmware/all_flash/DeviceTree.n104ap.im4p \
-append "debug=0x14e kextlog=0xffff serial=3 -v" \
-initrd 038-44135-124.dmg \
-cpu max -smp 2 \
-m 4G -serial mon:stdio \
-drive file=nvme.1.qcow2,format=qcow2,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.2,format=raw,if=none,id=drive.2 \
-device nvme-ns,drive=drive.2,bus=nvme-bus.0,nsid=2,nstype=2,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.3,format=raw,if=none,id=drive.3 \
-device nvme-ns,drive=drive.3,bus=nvme-bus.0,nsid=3,nstype=3,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.4,format=raw,if=none,id=drive.4 \
-device nvme-ns,drive=drive.4,bus=nvme-bus.0,nsid=4,nstype=4,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvram,if=none,format=raw,id=nvram \
-device apple-nvram,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.6,format=raw,if=none,id=drive.6 \
-device nvme-ns,drive=drive.6,bus=nvme-bus.0,nsid=6,nstype=6,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.7,format=raw,if=none,id=drive.7 \
-device nvme-ns,drive=drive.7,bus=nvme-bus.0,nsid=7,nstype=8,logical_block_size=4096,physical_block_size=4096 \
-monitor telnet:127.0.0.1:1235,server,nowait
```


## Boot from modified Ramdisk/RootFS

Remove `rd=md0` boot args from the below commands if you want to boot from NAND instead of ramdisk.

```sh
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,trustcache-filename=static_tc,boot-mode=manual \
-kernel kernelcache.research.iphone12b \
-dtb Firmware/all_flash/DeviceTree.n104ap.im4p \
-append "debug=0x14e kextlog=0xffff serial=3 -v rd=md0 wdt=-1" \
-initrd 038-44087-125.dmg.out \
-cpu max -smp 1 \
-m 4G -serial mon:stdio \
-drive file=disk.1,format=raw,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvram,if=none,format=raw,id=nvram \
-device apple-nvram,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram,logical_block_size=4096,physical_block_size=4096
```

## Stop the emulator

Connect to the monitor at `localhost:1235` and use the `q` command, the `shutdown` command is not yet supported.

As such, to avoid filesystem corruptions on the NAND, run this command after the `wdog: reset system` (will appear when iOS reboots) and before the NAND mounts.

----
# Connect to iOS emulator over USB

This requires another Linux VM to connect to an iOS VM.

Note that the USB-over-TCP Protocol will run on unix socket at `/tmp/usbqemu` by default.

## Run a Linux VM as USB host

You can use any QEMU Linux VM. Example below uses Arch Linux installer ISO

```shell
./qemu-system-x86_64 -cdrom archlinux-2021.06.01-x86_64.iso -boot order=d -m 1024 -vga virtio -cpu qemu64 -device usb-ehci,id=ehci -device usb-tcp-remote,bus=ehci.0
```

## Start iOS VM

Start an iOS QEMU instance, which will automatically connect to unix socket `/tmp/usbqemu`.

## Connect to iOS VM

From inside the Linux VM, you can access to the iOS VM over USB like a real device.

## Restore iOS firmware

To restore iOS, you need a working Linux installation on QEMU. I use Arch Linux for this purpose.
The installation guide can be found on [their official guide](https://wiki.archlinux.org/title/Installation_guide)

Here is my QEMU command to run the Linux VM:

```sh
./qemu-t8030/build/qemu-system-x86_64 -boot order=c -m 1024 -vga none -device virtio-vga,xres=640,yres=480 -cpu qemu64 -usb -device usb-ehci,id=ehci -device usb-tcp-remote,bus=ehci.0 -drive file=arch.qcow2 -monitor telnet:127.0.0.1:1236,server,nowait
```

First boot the Linux VM, then install `usbmuxd` if it hasn't been installed.

**DO NOT** install `idevicerestore` from your package manager.

### Setting up SSH connection to the Linux VM

Because you will need scp/sftp to transfer the ipsw, and also for convenince, below is my way of setting up SSH.

Run this command on the Linux VM

```sh
ssh -fN -R 10222:localhost:22 <host-user-name>@<host-ip-address>
```
and enter your HOST user password.

And then run this command on your host machine to connect to it

```sh
ssh root@localhost -p 10222
```
now enter your VM user password.

If you have an SSH server (i.e openssh-server) installed on the Linux VM, you will now have a shell on it.

To copy any file from your host to the VM:

```sh
scp /path/to/file scp://root@localhost:10222/
```

### Building idevicerestore

For `idevicerestore` we need to clone and patch it

Run these commands on the Linux VM

```sh
git clone https://github.com/libimobiledevice/idevicerestore.git
cd idevicerestore
git apply /path/to/qemu-t8030-tools/libimobiledevice_patches/idevicerestore.patch
./autogen.sh
make
sudo make install
```

### Creating APTicket

If the iOS version you are trying to restore is still signed, it is okay to use [tsschecker](https://github.com/1Conan/tsschecker) to fetch the SHSH2 blobs. Then extract the data from the `APImg4Ticket` field of the blob (plist) and save it at `root_ticket.der`

Otherwise, you can use my script to do that.

```sh
python3 qemu-t8030-tools/bootstrap_scripts/create_apticket.py n104ap BuildManifest.plist ticket.shsh2 root_ticket.der
```

A sample ticket is also provided in the `bootstrap_scripts` folder for your ease.

**DO NOT** modify the `root_ticket.der` until you restore again. It is required even after the restore completed.

### Restore

With the `root_ticket.der` and the ipsw inside the Linux VM. Start up the iOS emulator using the command from [Auto boot](#auto-boot)

Then when you saw something like `could not receive message`, run the following command in the Linux VM to start the restore process.

```sh
idevicerestore -P -d --erase --restore-mode -i 0x1122334455667788 iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw -T root_ticket.der
```

After you type `YES` to the prompt, the restore will start.

**DO NOT** let your computer sleep during this process.

If the restore completed successfully, the iOS VM will automatically reboot to NAND, otherwise, it will reboot to the ramdisk and attempt to restore again.


----
# Add a new binary to firmware

## Build binary - require Xcode on macOS

```sh
xcrun -sdk iphoneos clang -arch arm64 -mcpu=apple-a13 -o hello hello.c
```

Then sign the binary

```
codesign -f -s - hello
```


## Copy binary to firmware

```sh
# attach image
hdiutil attach -imagekey diskimage-class=CRawDiskImage disk.1

# enable ownership
sudo diskutil enableownership /Volumes/AzulSeed18A5351d.N104N841DeveloperOS

# mount with RW
mount -urw /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```

Then copy the signed binary to image

```sh
sudo cp hello /Volumes/AzulSeed18A5351d.N104N841DeveloperOS/bin
```

Also copy the binary to the local `strap` directory

```sh
cp hello strap/bin
```

## Re-generate trustcache

This step is no longer needed as we now patch AMFI

```sh
# dump trustcache from firmware
python3 qemu-t8030-tools/bootstrap_scripts/dump_trustcache.py Firmware/038-44337-083.dmg.trustcache.out | grep cdhash | cut -d' ' -f2 > tchashes

# update trustcache with new binaries from strap
for filename in $(find strap/  -type f); do jtool2 --sig $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes

# re-serialize updated trustcache
python3 qemu-t8030-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
```

## Unmount the image
Finally, unmount the firmware image - now with new binary inserted

```sh
hdiutil detach /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```
