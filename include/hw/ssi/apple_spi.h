#ifndef APPLE_SPI_H
#define APPLE_SPI_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/ssi/ssi.h"

#define TYPE_APPLE_SPI "apple.spi"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSPIState, APPLE_SPI)

SysBusDevice *apple_spi_create(DTBNode *node);
#endif /* APPLE_SPI_H */
