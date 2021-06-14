#ifndef APPLE_ANS_H
#define APPLE_ANS_H

#include "qemu/queue.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/block/block.h"
#include "hw/pci/pci.h"
#include "hw/pci/pcie_host.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/dma.h"
#include "hw/block/nvme.h"

SysBusDevice *apple_ans_create(DTBNode* node, uint32_t build_version);

#endif /* APPLE_ANS_H */
