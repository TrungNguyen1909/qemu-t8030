#!/bin/sh

AFL/afl-showmap -m 16G -t 5000 $@ -- \
qemu-t8030/build/qemu-system-aarch64 -s -M t8030,trustcache-filename=Firmware/038-44135-124.dmg.trustcache,ticket-filename=rootticket.der,boot-mode=enter_recovery \
-kernel kernelcache.research.iphone12b \
-dtb Firmware/all_flash/DeviceTree.n104ap.im4p \
-append "debug=0x14e kextlog=0xffff serial=3 -v launchd_unsecure_cache=1 tlto_us=300000 wdt=-1 iomfb_system_type=2 iomfb_disable_rt_bw=1" \
-initrd fuzz.dmg \
-cpu max -smp 1 -nographic -d nochain \
-m 1G -icount shift=0,align=off -serial stdio -monitor none \
-drive file=nvme.1.qcow2,format=qcow2,if=none,id=drive.1 \
-device nvme-ns,drive=drive.1,bus=nvme-bus.0,nsid=1,nstype=1,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.2.qcow2,format=qcow2,if=none,id=drive.2 \
-device nvme-ns,drive=drive.2,bus=nvme-bus.0,nsid=2,nstype=2,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.3.qcow2,format=qcow2,if=none,id=drive.3 \
-device nvme-ns,drive=drive.3,bus=nvme-bus.0,nsid=3,nstype=3,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.4.qcow2,format=qcow2,if=none,id=drive.4 \
-device nvme-ns,drive=drive.4,bus=nvme-bus.0,nsid=4,nstype=4,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvram.qcow2,if=none,format=qcow2,id=nvram \
-device apple-nvram,drive=nvram,bus=nvme-bus.0,nsid=5,nstype=5,id=nvram,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.6.qcow2,format=qcow2,if=none,id=drive.6 \
-device nvme-ns,drive=drive.6,bus=nvme-bus.0,nsid=6,nstype=6,logical_block_size=4096,physical_block_size=4096 \
-drive file=nvme.7.qcow2,format=qcow2,if=none,id=drive.7 \
-device nvme-ns,drive=drive.7,bus=nvme-bus.0,nsid=7,nstype=8,logical_block_size=4096,physical_block_size=4096
