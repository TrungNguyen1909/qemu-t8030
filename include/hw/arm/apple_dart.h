#ifndef HW_ARM_APPLE_DART_H
#define HW_ARM_APPLE_DART_H

#include "qemu/osdep.h"
#include "qemu/queue.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

typedef struct AppleDARTState AppleDARTState;

#define TYPE_APPLE_DART "apple.dart"
OBJECT_DECLARE_SIMPLE_TYPE(AppleDARTState, APPLE_DART)

#define TYPE_APPLE_DART_IOMMU_MEMORY_REGION "apple.dart.iommu"
OBJECT_DECLARE_SIMPLE_TYPE(AppleDARTIOMMUMemoryRegion, APPLE_DART_IOMMU_MEMORY_REGION)

IOMMUMemoryRegion *apple_dart_iommu_mr(AppleDARTState *dart, uint32_t sid);
IOMMUMemoryRegion *apple_dart_instance_iommu_mr(AppleDARTState *s,
                                                uint32_t instance,
                                                uint32_t sid);
AppleDARTState *apple_dart_create(DTBNode *node);

#endif /* HW_ARM_APPLE_DART_H */
