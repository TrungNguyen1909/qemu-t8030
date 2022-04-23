#ifndef APPLE_SMC_H
#define APPLE_SMC_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

SysBusDevice *apple_smc_create(DTBNode *node, uint32_t protocol_version);

#endif /* APPLE_SMC_H */
