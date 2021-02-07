#include "qemu/osdep.h"
#include "hw/loader.h"
#include "hw/qdev-properties.h"
#include "hw/display/xnu_ramfb.h"
#include "ui/console.h"

#define XNU_RAMFB(obj) \
    OBJECT_CHECK(xnu_ramfb_state, (obj), TYPE_XNU_RAMFB_DEVICE)

typedef struct display_cfg{
    uint32_t format;
    uint32_t width;
    uint32_t height;
    uint32_t linesize;
} xnu_display_cfg;

typedef struct xnu_ramfb_state {
    SysBusDevice parent_obj;
    xnu_display_cfg display_cfg;
    QemuConsole* con;
    uint8_t* qemu_fb_ptr; //Pointer that will sent to display callbacks 
    hwaddr fb_pa;
    uint32_t fb_size;
    hwaddr as;
} xnu_ramfb_state;

void xnu_ramfb_display_update(void *opaque)
{
    DisplaySurface *ds = NULL;
    xnu_ramfb_state *xnu_ramfb = XNU_RAMFB(opaque);
    uint32_t format = xnu_ramfb->display_cfg.format;
    uint32_t width = xnu_ramfb->display_cfg.width;
    uint32_t height = xnu_ramfb->display_cfg.height;
    uint32_t linesize = xnu_ramfb->display_cfg.linesize;
    QemuConsole *con = xnu_ramfb->con;
    hwaddr as = xnu_ramfb->as;
    hwaddr fb_pa = xnu_ramfb->fb_pa;
    uint32_t fb_size = xnu_ramfb->fb_size;
    uint8_t*  qemu_fb_ptr = xnu_ramfb->qemu_fb_ptr;

    assert(qemu_fb_ptr != 0);
    assert(fb_pa != 0);

    address_space_rw((AddressSpace*) as, fb_pa, MEMTXATTRS_UNSPECIFIED,
                qemu_fb_ptr, fb_size, FALSE);
    ds = qemu_create_displaysurface_from(
        width, height, format, linesize, qemu_fb_ptr);
    if (ds) {
        dpy_gfx_replace_surface(con, ds);
    }
    dpy_gfx_update_full(con);
}

void xnu_display_prolog(xnu_ramfb_state* xnu_fb_state)
{
    //currently empty
    return;
}

void xnu_ramfb_setup(xnu_ramfb_state* xnu_fb_state)
{
    uint8_t* fb_ptr;
    xnu_fb_state->display_cfg.format = PIXMAN_LE_r8g8b8;

    if (xnu_fb_state->fb_size == 0){
        fprintf(stderr,
            "xnu_ram_fb: size for the framebuffer is zero, aborting...\n");
        abort();
    }
    fb_ptr = g_malloc0(xnu_fb_state->fb_size);
    if (fb_ptr == NULL){
        fprintf(stderr,
            "xnu_ram_fb: failed to allocate memory for the framebuffer.\n");
        abort();
    }
    xnu_fb_state->qemu_fb_ptr = fb_ptr;

    xnu_display_prolog(xnu_fb_state);
}

void xnu_ramfb_free(uint8_t* qemu_fb_ptr)
{
    g_free(qemu_fb_ptr);
}

static const GraphicHwOps wrapper_ops = {
    .gfx_update = xnu_ramfb_display_update,
};

static void xnu_ramfb_realizefn(DeviceState *dev, Error **errp)
{
    xnu_ramfb_state *xnu_ramfb = XNU_RAMFB(dev);
    xnu_ramfb->con = graphic_console_init(dev, 0, &wrapper_ops, dev);
    xnu_ramfb_setup(xnu_ramfb);
}

static void xnu_ramfb_unrealizefn(DeviceState *dev)
{
    xnu_ramfb_state *xnu_ramfb = XNU_RAMFB(dev);
    graphic_console_close(xnu_ramfb->con);
    xnu_ramfb_free(xnu_ramfb->qemu_fb_ptr);
}

static Property xnu_ramfb_properties[] = {
    DEFINE_PROP_UINT64("as", xnu_ramfb_state, as, 0),
    DEFINE_PROP_UINT64("fb_pa", xnu_ramfb_state, fb_pa, 0),
    DEFINE_PROP_UINT32("fb_size", xnu_ramfb_state, fb_size, 0),
    DEFINE_PROP_UINT32("display_cfg.width", xnu_ramfb_state, 
                display_cfg.width, 0),
    DEFINE_PROP_UINT32("display_cfg.height", xnu_ramfb_state, 
                display_cfg.height, 0),
    DEFINE_PROP_UINT32("display_cfg.linesize", xnu_ramfb_state, 
                display_cfg.linesize, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void xnu_ramfb_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    dc->realize = xnu_ramfb_realizefn;
    dc->unrealize = xnu_ramfb_unrealizefn;
    device_class_set_props(dc, xnu_ramfb_properties);
    dc->desc = "xnu ram framebuffer";
    dc->user_creatable = true;
}

static const TypeInfo xnu_ramfb_info = {
    .name          = TYPE_XNU_RAMFB_DEVICE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(xnu_ramfb_state),
    .class_init    = xnu_ramfb_class_initfn,
};

static void xnu_ramfb_register_types(void)
{
    type_register_static(&xnu_ramfb_info);
}

type_init(xnu_ramfb_register_types)
