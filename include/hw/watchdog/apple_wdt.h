#ifndef HW_WATCHDOG_APPLE_WDT_H
#define HW_WATCHDOG_APPLE_WDT_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

SysBusDevice *apple_wdt_create(DTBNode *node);

#endif /* HW_WATCHDOG_APPLE_WDT_H */

