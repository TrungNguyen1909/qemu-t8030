#ifndef APPLE_TRISTAR_H
#define APPLE_TRISTAR_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/i2c/i2c.h"

#define TYPE_APPLE_TRISTAR "apple.tristar"
OBJECT_DECLARE_SIMPLE_TYPE(AppleTristarState, APPLE_TRISTAR)

struct AppleTristarState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    qemu_irq irq;

    bool last_level;
    uint32_t address;
    uint32_t mode;

    union {
        uint8_t reg[0x63];
        struct QEMU_PACKED {
            uint8_t rsrv0;              /* 0x00 */
            uint8_t dxctrl;             /* 0x01 */
            uint8_t acc_ctrl;           /* 0x02 */
            uint8_t dcp_ctrl;           /* 0x03 */
            uint8_t rsrv4;              /* 0x04 */
            uint8_t misc_ctrl;          /* 0x05 */
            uint8_t dig_id;             /* 0x06 */
            uint8_t rsrv7[2];           /* 0x07 - 0x08 */
            uint8_t fault_enable;       /* 0x09 */
            uint8_t event1;             /* 0x0A */
            uint8_t status1;            /* 0x0B */
            uint8_t status0;            /* 0x0C */
            uint8_t event0;             /* 0x0D */
            uint8_t mask;               /* 0x0E */
            uint8_t rev;                /* 0x0F */
            uint8_t dp1_dp2_uart_ctl;   /* 0x10 */
            uint8_t auth_ctrl0;         /* 0x11 */
            uint8_t acc_fault_status;   /* 0x12 */
            uint8_t acc_fault_ctrl0;    /* 0x13 */
            uint8_t acc_fault_ctrl1;    /* 0x14 */
            uint8_t rsrv15[8];          /* 0x15 - 0x1C */
            uint8_t misc_io;            /* 0x1D */
            uint8_t con_det_smpl;       /* 0x1E */
            uint8_t rd_fifo;            /* 0x1F */
            uint8_t fifo[64];           /* 0x20 - 0x5f */
            uint8_t fifo_ctrl1;         /* 0x60 */
            uint8_t fifo_ctrl0;         /* 0x61 */
            uint8_t fifo_fill_status;   /* 0x62 */
        };
    };

};

DeviceState *apple_tristar_create(DTBNode *node);
#endif /* APPLE_I2C_H */
