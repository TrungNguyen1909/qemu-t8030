#ifndef HW_ARM_T8030_GXF_H
#define HW_ARM_T8030_GXF_H

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "target/arm/cpu.h"
#include "hw/arm/t8030_cpu.h"

void t8030cpu_init_gxf(T8030CPUState *cpu);

void t8030cpu_init_gxf_override(T8030CPUState *cpu);

#endif /* HW_ARM_T8030_GXF_H */
