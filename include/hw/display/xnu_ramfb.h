#ifndef XNU_RAMFB_H
#define XNU_RAMFB_H

typedef struct xnu_ramfb_state xnu_ramfb_state;
void xnu_ramfb_display_update(void *opaque);
void xnu_ramfb_setup(xnu_ramfb_state* xnu_fb_state);
void xnu_ramfb_free(uint8_t* qemu_fb_ptr);
void xnu_display_prolog(xnu_ramfb_state* xnu_fb_state);

#define TYPE_XNU_RAMFB_DEVICE "xnu_ramfb"

#endif /* XNU_RAMFB_H */
