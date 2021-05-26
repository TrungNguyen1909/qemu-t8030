#ifndef HW_ARM_T8030_GXF_H
#define HW_ARM_T8030_GXF_H

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "target/arm/cpu.h"

void t8030cpu_init_gxf(ARMCPU *cpu);

#endif /* HW_ARM_T8030_GXF_H */