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
#include "hw/display/xnu_ramfb.h"
#include "include/hw/qdev-properties.h"

void xnu_define_ramfb_device(AddressSpace *as, hwaddr ramfb_pa)
{
    DeviceState *fb_dev;

    fb_dev = qdev_new(TYPE_XNU_RAMFB_DEVICE);
    qdev_prop_set_uint64(fb_dev, "as", (hwaddr)as);
    qdev_prop_set_uint64(fb_dev, "fb_pa", ramfb_pa);
    qdev_prop_set_uint32(fb_dev, "fb_size", RAMFB_SIZE);
    qdev_prop_set_uint32(fb_dev, "display_cfg.height", V_HEIGHT);
    qdev_prop_set_uint32(fb_dev, "display_cfg.width", V_WIDTH);
    qdev_prop_set_uint32(fb_dev, "display_cfg.linesize", V_LINESIZE);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(fb_dev), &error_fatal);
}

void xnu_get_video_bootargs(void *opaque, hwaddr ramfb_pa)
{
    video_boot_args *v_bootargs = (video_boot_args *)opaque;

    v_bootargs->v_baseAddr = ramfb_pa | 1;
    v_bootargs->v_depth = V_DEPTH;
    v_bootargs->v_display = V_DISPLAY;
    v_bootargs->v_height = V_HEIGHT;
    v_bootargs->v_width = V_WIDTH;
    v_bootargs->v_rowBytes = V_LINESIZE;
}
