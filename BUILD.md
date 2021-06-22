This doc details all the steps to build and run the emulator.


# Prerequisites
You will need a macOS system for some of the preparation steps.

# Getting dependencies

### Getting support tools

```sh
git clone https://github.com/TrungNguyen1909/xnu-qemu-arm64-tools
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
python3 xnu-qemu-arm64-tools/bootstrap_scripts/asn1rdskdecode.py 038-44087-125.dmg 038-44087-125.dmg.out
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

### Bundled trustcache

```shell
python3 xnu-qemu-arm64-tools/bootstrap_scripts/asn1trustcachedecode.py Firmware/038-44087-125.dmg.trustcache Firmware/038-44087-125.dmg.trustcache.out
python3 xnu-qemu-arm64-tools/bootstrap_scripts/dump_trustcache.py Firmware/038-44087-125.dmg.trustcache.out | grep cdhash | cut -d' ' -f2 > tchashes
```

### System Binaries

```shell
for filename in $(find strap/ -type f); do jtool2 --sig $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes
```

### Serialize trustcache

```shell
python3 xnu-qemu-arm64-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
```

# Preparing the RootFS

This step is temporary as this is not enough to create a usable system.


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

### Bundled trustcache
```sh
python3 xnu-qemu-arm64-tools/bootstrap_scripts/asn1trustcachedecode.py Firmware/038-44337-083.dmg.trustcache Firmware/038-44337-083.dmg.trustcache.out
python3 xnu-qemu-arm64-tools/bootstrap_scripts/dump_trustcache.py Firmware/038-44337-083.dmg.trustcache.out | grep cdhash | cut -d' ' -f2 > tchashes
```

### Create trustcache for system binaries
```sh
for filename in $(find strap/  -type f); do jtool2 --sig $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes
```

### Serialize trustcache
```sh
python3 xnu-qemu-arm64-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
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


# Preparing NVRAM

Either use `setup-ios/nvram`, or create it yourself as follows.

```sh
echo "XQAAAAT//////////wAtIHxAA8l2M4RwLYP/nVI8/XJz1smfQHsB1bYBDcXGde9gDROioaQd5idJPDeyKi/XrDIVFDVxwhaUAvSvYtKbu9Hs/pS2MN3p09D/mcqXOKs2di3TWiuNQUYbsWMOACSAbmhlikZkXD2LfUNIuxvxJ4g7VtdQl+gefhX8xA+LOoNwO88uhrlSnNHTA85R9Lwj4PgM79i6f+mrzEgAuXZ2VyVkHig/Di57BeIpn0WrBqW9L/JR4/P6WlOnN32PgJvq/arUT/MM3ikXaOPamiXxFCPk/8deoBBt6VPU//+2HcAA" | base64 -d | unlzma -c > nvram
```


# Run

## Boot from stock Ramdisk
```sh
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,kernel-filename=kernelcache.research.iphone12b,dtb-filename=Firmware/all_flash/DeviceTree.n104ap.im4p,kern-cmd-args="debug=0x8 kextlog=0xffff serial=3 -v rd=md0",ramdisk-filename=038-44087-125.dmg,xnu-ramfb=on,trustcache-filename=Firmware/038-44087-125.dmg.trustcache \
-cpu max -smp 1 \
-m 4G -serial mon:stdio \
-drive file=disk.1,format=raw,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1 \
-drive file=nvram,if=none,format=raw,id=nvram \
-device nvme-ns,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram
```


## Boot from modified Ramdisk
```sh
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,kernel-filename=kernelcache.research.iphone12b,dtb-filename=Firmware/all_flash/DeviceTree.n104ap.im4p,kern-cmd-args="debug=0x8 kextlog=0xffff serial=3 -v rd=md0",ramdisk-filename=038-44087-125.dmg,xnu-ramfb=on,trustcache-filename=static_tc \
-cpu max -smp 1 \
-m 4G -serial mon:stdio \
-drive file=disk.1,format=raw,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1 \
-drive file=nvram,if=none,format=raw,id=nvram \
-device nvme-ns,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram
```


## Boot from NAND
```sh
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,kernel-filename=kernelcache.research.iphone12b,dtb-filename=Firmware/all_flash/DeviceTree.n104ap.im4p,kern-cmd-args="debug=0x8 kextlog=0xffff serial=3 -v rd=disk0s1 launchd_unsecure_cache=1",ramdisk-filename=038-44087-125.dmg.out,xnu-ramfb=on,trustcache-filename=static_tc \
-cpu max -smp 1 \
-m 4G -serial mon:stdio \
-drive file=disk.1,format=raw,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1 \
-drive file=nvram,if=none,format=raw,id=nvram \
-device nvme-ns,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram
```


----
## Connect to iOS emulator over USB

This requires another Linux VM to connect to an iOS VM.

Note that the USB-over-TCP Protocol will run on port `7632` by default.

### Run a Linux VM as USB host

You can use any QEMU Linux VM. Example below uses Arch Linux installer ISO

```shell
./qemu-system-x86_64 -cdrom archlinux-2021.06.01-x86_64.iso -boot order=d -m 1024 -vga virtio -cpu qemu64 -usb -device usb-tcp-remote,bus=usb-bus.0
```

### Start iOS VM

Start an iOS QEMU instance, which will automatically connect to port `7632`.

### Connect to iOS VM

From inside the Linux VM, you can access to the iOS VM over USB.

Currently, only `lsusb` is known to be able to detect the iOS device.

Other tools such as `libimobiledevice` are not yet supported.

----
## Add a new binary to firmware

### Build binary - require Xcode on macOS

```sh
xcrun -sdk iphoneos clang -arch arm64 -mcpu=apple-a13 -o hello hello.c
```

Then sign the binary

```
codesign -f -s - hello
```


### Copy binary to firmware

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

### Re-generate trustcache

```sh
# dump trustcache from firmware
python3 xnu-qemu-arm64-tools/bootstrap_scripts/dump_trustcache.py Firmware/038-44337-083.dmg.trustcache.out | grep cdhash | cut -d' ' -f2 > tchashes

# update trustcache with new binaries from strap
for filename in $(find strap/  -type f); do jtool2 --sig $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes

# re-serialize updated trustcache
python3 xnu-qemu-arm64-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
```

Finally, unmount the firmware image - now with new binary inserted

```sh
hdiutil detach /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```
