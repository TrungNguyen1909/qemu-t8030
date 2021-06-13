/*
 *
 * Copyright (c) 2019 Jonathan Afek <jonyafek@me.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "hw/arm/xnu.h"
#include "hw/loader.h"
#include "hw/arm/xnu_file_mmio_dev.h"

static uint64_t xnu_file_mmio_dev_read(void *opaque,
        hwaddr addr, unsigned size)
{
    FileMmioDev *file_dev = opaque;
    uint64_t ret = 0;

    if (addr + size > file_dev->size) {
        abort();
    }

    if (size > sizeof(ret)) {
        abort();
    }

    if (lseek(file_dev->fd, addr, SEEK_SET) != addr) {
        abort();
    }

    if (read(file_dev->fd, &ret, size) != size) {
        abort();
    }

    return ret;
}

static void xnu_file_mmio_dev_write(void *opaque, hwaddr addr,
        uint64_t val, unsigned size)
{
    FileMmioDev *file_dev = opaque;

    if (addr + size > file_dev->size) {
        abort();
    }

    if (lseek(file_dev->fd, addr, SEEK_SET) != addr) {
        abort();
    }

    if (write(file_dev->fd, &val, size) != size) {
        abort();
    }

}

const MemoryRegionOps xnu_file_mmio_dev_ops = {
    .read = xnu_file_mmio_dev_read,
    .write = xnu_file_mmio_dev_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

void xnu_file_mmio_dev_create(MemoryRegion *sysmem, FileMmioDev *file_dev,
                              const char *name, const char *filename)
{
    MemoryRegion *iomem = g_new(MemoryRegion, 1);
    struct stat st;

    if (lstat(filename, &st) == -1) {
        abort();
    }

    file_dev->size = st.st_size;

    memory_region_init_io(iomem, NULL, &xnu_file_mmio_dev_ops, file_dev,
                          name, file_dev->size);
    memory_region_add_subregion(sysmem, file_dev->pa, iomem);

    // TODO: think about using O_SYNC
    // or maybe use fsync() from time to time
    file_dev->fd = open(filename, O_RDWR);

    if (file_dev->fd == -1) {
        abort();
    }
}
