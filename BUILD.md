This doc details all the steps to build and run the emulator.


# Prerequisites
You will need a macOS system for some of the preparation steps.

# Getting dependencies

### Getting support tools

```sh
git clone https://github.com/TrungNguyen1909/xnu-qemu-arm64-tools
pip3 install pyasn1
```

### MacOS Homebrew

```sh
brew install libtasn1 meson ninja pixman lzfse
```

### Linux
```sh
sudo apt update
sudo apt install -y git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libtasn1-dev ninja-build build-essential cmake

#lzfse
git clone https://github.com/lzfse/lzfse
cd lzfse
mkdir build
cd build
cmake ..
make
make install
cd ..
```

# Building QEMU

```sh
git clone https://github.com/TrungNguyen1909/qemu-t8030
cd qemu-tt8030
mkdir build; cd build
../configure --target-list=aarch64-softmmu --disable-capstone --disable-slirp
make -j$(nproc)
```

# Getting iOS

Download and unzip [iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw](https://updates.cdn-apple.com/2020SummerSeed/fullrestores/001-35886/5FE9BE2E-17F8-41C8-96BB-B76E2B225888/iPhone11,8,iPhone12,1_14.0_18A5351d_Restore.ipsw)


# Unpacking the ramdisk

```sh
python3 xnu-qemu-arm64-tools/bootstrap_scripts/asn1rdskdecode.py 038-44087-125.dmg 038-44087-125.dmg.out
```


# Preparing the ramdisk

This step is needed until issue #1 is fixed.

```sh
#resize
hdiutil resize -size 512M -imagekey diskimage-class=CRawDiskImage 038-44087-125.dmg.out
#mount
hdiutil attach -imagekey diskimage-class=CRawDiskImage 038-44087-125.dmg.out
#enable ownership
sudo diskutil enableownership /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk
#decompress: you will need a macOS system for this step
sudo afscexpand /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk
#unmount
hdiutil detach /Volumes/AzulSeed18A5351d.arm64eUpdateRamDisk
```


# Preparing the RootFS

This step is temporary as this is not enough to create a usable system.


## Convert the disk image
```sh
hdiutil convert 038-44337-083.dmg -format UDRW -tgtimagekey diskimage-class=CRawDiskImage -o disk.1
mv disk.1.dmg disk.1
```


## Resize the disk image
```sh
hdiutil resize -size 12G -imagekey diskimage-class=CRawDiskImage disk.1
```


## Mount the disk image
```sh
hdiutil attach -imagekey diskimage-class=CRawDiskImage disk.1
#enable ownership
sudo diskutil enableownership /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```


## Decompress the disk image (might take a while)
```sh
sudo afscexpand /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
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


## Add binpack
```sh
curl -LO https://github.com/pwn20wndstuff/Undecimus/raw/master/Undecimus/resources/binpack64-256.tar.lzma
mkdir binpack64
tar xvf binpack64-256.tar.lzma -C binpack64
sudo cp -R binpack64 /Volumes/AzulSeed18A5351d.N104N841DeveloperOS
```


## Create trustcache


### Bundled trustcache
```sh
python3 xnu-qemu-arm64-tools/bootstrap_scripts/dump_trustcache.py Firmware/038-44337-083.dmg.trustcache.out | grep cdhash | cut -d' ' -f2 > tchashes
```


### binpack trustcache
```sh
for filename in $(find binpack64/  -type f); do jtool --sig --ent $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes
```


### Serialize
```sh
python3 xnu-qemu-arm64-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
```


## Configure LaunchDaemons

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
				<string>/binpack64/bin/bash</string>
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

```sh
echo "XQAAAAT//////////wAtIHxAA8l2M4RwLYP/nVI8/XJz1smfQHsB1bYBDcXGde9gDROioaQd5idJPDeyKi/XrDIVFDVxwhaUAvSvYtKbu9Hs/pS2MN3p09D/mcqXOKs2di3TWiuNQUYbsWMOACSAbmhlikZkXD2LfUNIuxvxJ4g7VtdQl+gefhX8xA+LOoNwO88uhrlSnNHTA85R9Lwj4PgM79i6f+mrzEgAuXZ2VyVkHig/Di57BeIpn0WrBqW9L/JR4/P6WlOnN32PgJvq/arUT/MM3ikXaOPamiXxFCPk/8deoBBt6VPU//+2HcAA" | base64 -d | unlzma -c > nvram
```


# Run


## Boot from NAND
```sh
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,kernel-filename=kernelcache.research.iphone12b,dtb-filename=Firmware/all_flash/DeviceTree.n104ap.im4p,kern-cmd-args="debug=0x8 kextlog=0xffff serial=2 -v nvme=0xffff rd=disk0s1 cpus=1 launchd_unsecure_cache=1",ramdisk-filename=038-44087-125.dmg.out,xnu-ramfb=on,trustcache-filename=static_tc \
-cpu max -smp 1 \
-m 4G -serial mon:stdio \
-drive file=disk.1,format=raw,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1 \
-drive file=nvram,if=none,format=raw,id=nvram \
-device nvme-ns,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram
```


## Boot from Ramdisk
```sh
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,kernel-filename=kernelcache.research.iphone12b,dtb-filename=Firmware/all_flash/DeviceTree.n104ap.im4p,kern-cmd-args="debug=0x8 kextlog=0xffff serial=2 -v nvme=0xffff rd=md0 cpus=1",ramdisk-filename=038-44087-125.dmg.out,xnu-ramfb=on,trustcache-filename=Firmware/038-44087-125.dmg.trustcache \
-cpu max -smp 1 \
-m 4G -serial mon:stdio \
-drive file=disk.1,format=raw,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1 \
-drive file=nvram,if=none,format=raw,id=nvram \
-device nvme-ns,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram
```


## Add binpack to PATH

Run on iOS shell:

```sh
export PATH=$PATH:/binpack64/usr/bin:/binpack64/bin:/binpack64/usr/sbin:/binpack64/sbin
```
