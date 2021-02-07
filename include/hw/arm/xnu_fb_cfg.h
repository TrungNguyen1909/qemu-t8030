#ifndef HW_ARM_XNU_RAMFB_CFG_H
#define HW_ARM_XNU_RAMFB_CFG_H

#include "qemu/osdep.h"

#define V_DEPTH     (16|(1<<16))
#define V_HEIGHT    800
#define V_WIDTH     600
#define V_DISPLAY   1
#define V_LINESIZE  (V_WIDTH * 3)

#define RAMFB_SIZE (V_LINESIZE * V_HEIGHT)

void xnu_define_ramfb_device(AddressSpace* as, hwaddr ramfb_pa);
void xnu_get_video_bootargs(void *opaque, hwaddr ramfb_pa);

#endif