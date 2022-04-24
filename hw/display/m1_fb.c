/*
 * Apple M1 SoC Framebuffer Emulation
 *
 * Copyright (c) 2021 Iris Johnson <iris@modwiz.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "qemu/osdep.h"
#include "hw/display/m1_fb.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"
#include "ui/pixel_ops.h"
#include "ui/console.h"
#include "qapi/error.h"
#include "framebuffer.h"

static void fb_draw_row(void *opaque, uint8_t *dest, const uint8_t *src,
                        int width, int dest_pitch)
{
    while (width--) {
        /* Load using endian-safe loads */
        uint32_t color = ldl_le_p(src);
        /* Increment source pointer */
        src += 4;

        /* Blit it to the display output now that it's converted */
        /* FIXME this might not be endian-safe but the rest should be */
        memcpy(dest, &color, sizeof(color));
        /*
         * NOTE: We always assume that pixels are packed end to end so we
         * ignore dest_pitch
         */
        dest += 4;
    }
}

static void fb_gfx_update(void *opaque)
{
    M1FBState *s = M1_FB(opaque);
    DisplaySurface *surface = qemu_console_surface(s->console);

    /* Used as both input to start converting fb memory and output of dirty */
    int first_row = 0;
    /* Output of last row of fb that was updated during conversion */
    int last_row;

    int width = s->width;
    int height = s->height;
    int src_stride = width*4; /* Bytes per line is 4*pixels */
    int dest_stride = src_stride; /* Same number of bytes per line */

    /*
     * This helper is used to reinitialize the dirty section.
     *
     * This is only done if the section hasn't been initialized since the memory
     * region itself is never changed.
     */
    /* TODO: this is the only way to tell if it's not initialized since
     * vram_section isn't a pointer. We should just handle invalidate properly
     */
    if (s->vram_section.mr == NULL) {
        framebuffer_update_memory_section(&s->vram_section, s->vram, 0,
                                          height, src_stride);
    }

    /*
     * Update the display memory that's changed using fb_draw_row to convert
     * between the source and destination pixel formats
     */
    framebuffer_update_display(surface, &s->vram_section,
                               width, height,
                               src_stride, dest_stride, 0, 0,
                               fb_draw_row, s, &first_row, &last_row);

    /* If anything changed update that region of the display */
    if (first_row >= 0) {
        /* # of rows that were updated, including row 1 (offset 0) */
        int updated_rows = last_row - first_row + 1;
        dpy_gfx_update(s->console, 0, first_row, width, updated_rows);
    }
}

static void fb_invalidate(void *opaque)
{
    /* FIXME: adding invalidate support for changing display parameters when
    * this is implemented
    */
    printf("FB invalidate called\n");
}

static const GraphicHwOps m1_fb_ops = {
        .invalidate = fb_invalidate,
        .gfx_update = fb_gfx_update,
};

static void m1_fb_realize(DeviceState *dev, Error **errp)
{
    printf("Qemu FB realize\n");
    M1FBState *s = M1_FB(dev);
    Object *obj;

    /*
     * FIXME: This probably should have an AddressSpace since I'm sure it's
     * passed through a DART, TODO for when DART support is added and more
     * is understood about where the framebuffer in the M1 comes from at all
     */
    obj = object_property_get_link(OBJECT(dev), "vram", &error_abort);
    s->vram = MEMORY_REGION(obj);

    s->console = graphic_console_init(dev, 0, &m1_fb_ops, s);
    qemu_console_resize(s->console, s->width, s->height);
}

static const VMStateDescription vmstate_m1_fb = {
        .name = TYPE_M1_FB,
        .version_id = 1,
        .minimum_version_id = 1,
        .fields = (VMStateField[]) {
                VMSTATE_UINT32(width, M1FBState),
                VMSTATE_UINT32(height, M1FBState),
                VMSTATE_END_OF_LIST()
        }
};

static Property m1_fb_props[] = {
        DEFINE_PROP_UINT32("width", M1FBState, width, 1280),
        DEFINE_PROP_UINT32("height", M1FBState, height, 800),
        DEFINE_PROP_END_OF_LIST()
};

static void m1_fb_class_init(ObjectClass *oc, void *data) {
    DeviceClass *dc = DEVICE_CLASS(oc);

    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    device_class_set_props(dc, m1_fb_props);
    dc->realize = m1_fb_realize;
    dc->vmsd = &vmstate_m1_fb;
}

static const TypeInfo m1_fb_type_info = {
        .name = TYPE_M1_FB,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(M1FBState),
        .class_init = m1_fb_class_init,
};

static void m1_fb_register_types(void)
{
    type_register_static(&m1_fb_type_info);
}

type_init(m1_fb_register_types);
