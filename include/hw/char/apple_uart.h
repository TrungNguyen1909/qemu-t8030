#ifndef APPLE_UART_H
#define APPLE_UART_H
#include "hw/or-irq.h"
#include "hw/sysbus.h"
#include "target/arm/cpu-qom.h"
#include "qom/object.h"

DeviceState *apple_uart_create(hwaddr addr,
                               int fifo_size,
                               int channel,
                               Chardev *chr,
                               qemu_irq irq);
#endif /* APPLE_UART_H */
