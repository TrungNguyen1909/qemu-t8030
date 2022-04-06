QEMU-T8030 Fuzzing
===

This branch is dedicated for iOS fuzzing. Currently it is supporting 2 modes of fuzzing:
- Syscall Fuzzing (`target/arm/helper-a64.c`)
- USB Fuzzing     (`hw/usb/hcd-fuzz.c`)

You can find the workflow diagram of both modes at [our wiki](https://github.com/TrungNguyen1909/qemu-t8030/wiki/Fuzzing)

We use the [original AFL](https://github.com/google/AFL) to run this, but feel free to port it to AFL++.

## Snapshot
Before any fuzzing can be done, you must have created a base snapshot.
Generally, the snapshot is created when the `./fuzz_create.sh`
stopped the emulator. You can use (`^A-C`) or telnet to access the QEMU monitor.
The commands used to create a snapshot is `savevm <snapshot name>`.

To set the base snapshot, goto `softmmu/main.c`.
You can see the snapshot name being hardcoded there.
Change it to the one you created.

## Fuzzing scripts
In the `setup-ios` you can find some scripts to help you get started.

### fuzz\_create.sh
This script starts the emulator to help you create a snapshot.
- For USB, this will stop the machine automatically when the USB stack is started.
- For syscall fuzzing, this will stop when `#hint 0x33` is run.

You can execute this script directly.

### fuzz.sh
This script is used to start AFL normally to fuzz.
The default timeout might be a bit strict so I generally set it to 5s.
```sh
./fuzz.sh -t 5000
```

### fuzz\_showmap.sh
This script runs afl-showmap.
The way you execute it is:

```sh
./fuzz_showmap.sh -o showmap_output < input
```

## Notes on USB fuzzing
iOS does not automatically initializes the USB stack.
The way I prefer to do this is running an vanilla update ramdisk.
`restored` can enable the USB stack for you.
When it does so, the emulator should stop for you to create a snapshot.

## Notes on syscall fuzzing
In `setup-ios`, we also included a stub (`sock_fuzz.c`),
this is supposed to be run inside the emulator.
When you run it after starting the emulator,
it will stop the emulator so that you can create a base snapshot.

## Disclaimer
- This branch is currently very raw and is a huge mess.
Please be an advised reader.
- This is committed at the last known good state of syscall fuzzing.
USB fuzzing might not work out of box.
