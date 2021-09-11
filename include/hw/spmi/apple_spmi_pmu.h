#ifndef APPLE_SPMI_PMU_H
#define APPLE_SPMI_PMU_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/spmi/spmi.h"

DeviceState *apple_spmi_pmu_create(DTBNode *node);
#endif /* APPLE_SPMI_PMU_H */
