#include "qemu/osdep.h"
#include "hw/usb/apple-tristar.h"
#include "hw/i2c/i2c.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"

enum {
    TRISTAR_REG_IDLE,
    TRISTAR_REG_READ,
    TRISTAR_REG_WRITE
};

enum {
	DXCTRL					= 0x01,
	    DXCTRL_DX2OVRD			= (1 << 7),
	    DXCTRL_DPDN2SW_mask			= (7 << 4),
	    DXCTRL_DPDN2SW_open			= (0 << 4),
	    DXCTRL_DPDN2SW_usb0			= (1 << 4),
	    DXCTRL_DPDN2SW_uart0		= (2 << 4),
	    DXCTRL_DPDN2SW_dig			= (3 << 4),
	    DXCTRL_DPDN2SW_brick_id_p		= (4 << 4),
	    DXCTRL_DPDN2SW_brick_id_n		= (5 << 4),
	    DXCTRL_DPDN2SW_uart2		= (6 << 4),
	    DXCTRL_DPDN2SW_uart1		= (7 << 4),
	    DXCTRL_DX1OVRD			= (1 << 3),
	    DXCTRL_DPDN1SW_mask			= (7 << 0),
	    DXCTRL_DPDN1SW_open			= (0 << 0),
	    DXCTRL_DPDN1SW_usb0			= (1 << 0),
	    DXCTRL_DPDN1SW_uart0		= (2 << 0),
	    DXCTRL_DPDN1SW_dig			= (3 << 0),
	    DXCTRL_DPDN1SW_brick_id_p		= (4 << 0),
	    DXCTRL_DPDN1SW_brick_id_n		= (5 << 0),
	    DXCTRL_DPDN1SW_usb1			= (6 << 0),
	    DXCTRL_DPDN1SW_jtag			= (7 << 0),

	ACC_CTRL				= 0x02,
	    ACC_CTRL_ACC2OVRD			= (1 << 7),
	    ACC_CTRL_ACC2SW_mask		= (7 << 4),
	    ACC_CTRL_ACC2SW_open		= (0 << 4),
	    ACC_CTRL_ACC2SW_uart1_tx		= (1 << 4),
	    ACC_CTRL_ACC2SW_jtag_clk		= (2 << 4),
	    ACC_CTRL_ACC2SW_acc_pwr		= (3 << 4),
	    ACC_CTRL_ACC2SW_brick_id		= (4 << 4),
	    ACC_CTRL_ACC1OVRD			= (1 << 3),
	    ACC_CTRL_ACC1SW_mask		= (7 << 0),
	    ACC_CTRL_ACC1SW_open		= (0 << 0),
	    ACC_CTRL_ACC1SW_uart1_rx		= (1 << 0),
	    ACC_CTRL_ACC1SW_jtag_dio		= (2 << 0),
	    ACC_CTRL_ACC1SW_acc_pwr		= (3 << 0),
	    ACC_CTRL_ACC1SW_brick_id		= (4 << 0),
	
	DCP_CTRL				= 0x03,
	    DCP_CTRL_IDXSINKEN			= (1 << 3),
	    DCP_CTRL_VDXSRCSW_mask		= (7 << 0),
	    DCP_CTRL_VDXSRCSW_off		= (0 << 0),
	    DCP_CTRL_VDXSRCSW_dp1		= (1 << 0),
	    DCP_CTRL_VDXSRCSW_dn1		= (2 << 0),
	    DCP_CTRL_VDXSRCSW_dp2		= (3 << 0),
	    DCP_CTRL_VDXSRCSW_dn2		= (4 << 0),

	MISC_CTRL				= 0x05,
	    MISC_CTRL_DPDN2_TERM		= (1 << 5),
	    MISC_CTRL_DPDN1_TERM		= (1 << 4),
	    MISC_CTRL_IDBUS_RESET		= (1 << 3),
	    MISC_CTRL_IDBUS_BREAK		= (1 << 2),
	    MISC_CTRL_IDBUS_REORIENT		= (1 << 1),
	    MISC_CTRL_IDBUS_P_INSINK_EN		= (1 << 0),

	DIG_ID					= 0x06,
	    DIG_ID_Dx1				= (1 << 3),
	    DIG_ID_Dx0				= (1 << 2),
	    DIG_ID_ACCx1			= (1 << 1),
	    DIG_ID_ACCx0			= (1 << 0),

	FAULT_ENABLE				= 0x09,
	    DYNAMIC_CHRG_PUMP			= (1 << 7),
	    CHECK_VICT				= (1 << 6),
	    CHECK_AGGR				= (1 << 5),
	    PROTECT_UNDER			= (1 << 4),
	    PROTECT_DIG				= (1 << 3),
	    PROTECT_UART			= (1 << 2),
	    PROTECT_USB				= (1 << 1),
	    PROTECT_ACC				= (1 << 0),

	EVENT1					= 0x0A,
	    EVENT1_Dx2_FAULT			= (1 << 2),
	    EVENT1_Dx1_FAULT			= (1 << 1),
	    EVENT1_ACCx_FAULT			= (1 << 0),
	
	STATUS1					= 0x0B,
	    STATUS1_CMD_PEND			= (1 << 0),
	
	STATUS0					= 0x0C,
	    STATUS0_IDBUS_CONNECTED		= (1 << 7),
	    STATUS0_IDBUS_ORIENT		= (1 << 6),
	    STATUS0_SWITCH_EN			= (1 << 5),
	    STATUS0_HOST_RESET			= (1 << 4),
	    STATUS0_POWER_GATE_EN		= (1 << 3),
	    STATUS0_CON_DET_L			= (1 << 2),
	    STATUS0_P_IN_STAT_mask		= (3 << 0),
	    STATUS0_P_IN_STAT_brownout		= (0 << 0),
	    STATUS0_P_IN_STAT_maintain		= (1 << 0),
	    STATUS0_P_IN_STAT_ovp		= (2 << 0),
	    STATUS0_P_IN_STAT_insdet		= (3 << 0),

	EVENT0					= 0x0D,
	    EVENT_IO_FAULT			= (1 << 7),
	    EVENT_IDBUS_TIMEOUT			= (1 << 6),
	    EVENT_FIFO_ERR			= (1 << 5),
	    EVENT_FIFO_RDY			= (1 << 4),
	    EVENT_CRC_ERR			= (1 << 5),
	    EVENT_RESP_VALID			= (1 << 4),
	    EVENT_DIGITAL_ID			= (1 << 3),
	    EVENT_CON_DET_L			= (1 << 2),
	    EVENT_IDBUS_WAKE			= (1 << 1),
	    EVENT_P_IN				= (1 << 0),

	MASK					= 0x0E,
	    MASK_IO_FAULT			= (1 << 7),
	    MASK_IDBUS_TIMEOUT			= (1 << 6),
	    MASK_CRC_ERR			= (1 << 5),
	    MASK_RESP_VALID			= (1 << 4),
	    MASK_DIGITAL_ID			= (1 << 3),
	    MASK_CON_DET_L			= (1 << 2),
	    MASK_IDBUS_WAKE			= (1 << 1),
	    MASK_P_IN				= (1 << 0),

	REV					= 0x0F,
	    REV_VENDOR_ID_shift			= (6),
	    REV_VENDOR_ID_mask			= (3 << REV_VENDOR_ID_shift),
	    REV_VENDOR_ID_nxp			= (2 << REV_VENDOR_ID_shift),
	    REV_BASE_VER_shift			= (3),
	    REV_BASE_VER_mask			= (7 << REV_BASE_VER_shift),
	    REV_METAL_VER_shift			= (0),
	    REV_METAL_VER_mask			= (7 << REV_METAL_VER_shift),

	DP1_DP2_UART_CTL			= 0x10,
	    DP1_DP2_UART_CTL_DP2_SLEW_mask	= (3 << 2),
	    DP1_DP2_UART_CTL_DP2_SLEW_10ns	= (0 << 2),
	    DP1_DP2_UART_CTL_DP2_SLEW_20ns	= (1 << 2),
	    DP1_DP2_UART_CTL_DP2_SLEW_40ns	= (2 << 2),
	    DP1_DP2_UART_CTL_DP2_SLEW_80ns	= (3 << 2),
	    DP1_DP2_UART_CTL_DP1_SLEW_mask	= (3 << 0),
	    DP1_DP2_UART_CTL_DP1_SLEW_10ns	= (0 << 0),
	    DP1_DP2_UART_CTL_DP1_SLEW_20ns	= (1 << 0),
	    DP1_DP2_UART_CTL_DP1_SLEW_40ns	= (2 << 0),
	    DP1_DP2_UART_CTL_DP1_SLEW_80ns	= (3 << 0),
	
	AUTH_CTRL0				= 0x11,
	    AUTH_CTRL0_LOCK_STAT_VALID		= (1 << 7),
	    AUTH_CTRL0_ESN_LOCK_STAT		= (1 << 6),
	    AUTH_CTRL0_KEYSET2_LOCK_STAT	= (1 << 5),
	    AUTH_CTRL0_KEYSET1_LOCK_STAT	= (1 << 4),
	    AUTH_CTRL0_SELECT_AUTH_DOMAIN_mask	= (1 << 3),
	    AUTH_CTRL0_SELECT_AUTH_DOMAIN_0	= (0 << 3),
	    AUTH_CTRL0_SELECT_AUTH_DOMAIN_1	= (1 << 3),
	    AUTH_CTRL0_I2C_AUTH_DONE		= (1 << 1),
	    AUTH_CTRL0_I2C_AUTH_START		= (1 << 0),
	
	ACC_FAULT_STATUS			= 0x12,
	    ACC_FAULT_STATUS_RVR_COMP_OUT	= (1 << 6),
	    ACC_FAULT_STATUS_ACC_FINGERS_5	= (1 << 5),
	    ACC_FAULT_STATUS_ACC_FINGERS_4	= (1 << 4),
	    ACC_FAULT_STATUS_ACC_FINGERS_3	= (1 << 3),
	    ACC_FAULT_STATUS_ACC_FINGERS_2	= (1 << 2),
	    ACC_FAULT_STATUS_ACC_FINGERS_1	= (1 << 1),
	    ACC_FAULT_STATUS_ACC_FINGERS_0	= (1 << 0),
	
	ACC_FAULT_CTRL0				= 0x13,
	    ACC_FAULT_CTRL0_EN_2X_OFFSET	= (1 << 7),
	    ACC_FAULT_CTRL0_BP_DISABLE_ACC_DISCONNECT	= (1 << 6),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_mask	= (15 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_no	= (0 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_12us	= (1 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_36us	= (2 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_60us	= (3 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_100us	= (4 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_200us	= (5 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_500us	= (6 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_1000us	= (7 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_2ms	= (8 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_5ms	= (9 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_10ms	= (10 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_20ms	= (11 << 0),
	    ACC_FAULT_CTRL0_BP_DEGLITCH_50ms	= (12 << 0),
	
	ACC_FAULT_CTRL1				= 0x14,
	    ACC_FAULT_CTRL1_BP_MODE_mask	= (3 << 6),
	    ACC_FAULT_CTRL1_BP_MODE_no		= (0 << 6),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_mask	= (63 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_800mohm	= (0 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_270mohm	= (32 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_170mohm	= (48 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_130mohm	= (56 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_100mohm	= (52 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_90mohm	= (60 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_600mohm	= (62 << 0),
	    ACC_FAULT_CTRL1_BP_SW_CTRL_40mohm	= (63 << 0),

	MISC_IO					= 0x1D,
	    MISC_IO_IDBUS_TIMEOUT_mask		= (3 << 3),
	    MISC_IO_IDBUS_TIMEOUT_disabled	= (0 << 3),
	    MISC_IO_IDBUS_TIMEOUT_5s		= (1 << 3),
	    MISC_IO_IDBUS_TIMEOUT_10s		= (2 << 3),
	    MISC_IO_IDBUS_TIMEOUT_30s		= (3 << 3),
	    MISC_IO_UART2_LOOP_BK		= (1 << 2),
	    MISC_IO_UART1_LOOP_BK		= (1 << 1),
	    MISC_IO_UART0_LOOP_BK		= (1 << 0),
	
	CON_DET_SMPL				= 0x1E,
	    CON_DET_SMPL_CON_DET_PULLUP_mask	= (3 << 5),
	    CON_DET_SMPL_CON_DET_PULLUP_20kohm	= (0 << 5),
	    CON_DET_SMPL_CON_DET_PULLUP_40kohm	= (1 << 5),
	    CON_DET_SMPL_CON_DET_PULLUP_60kohm	= (2 << 5),
	    CON_DET_SMPL_CON_DET_PULLUP_80kohm	= (3 << 5),
	    CON_DET_SMPL_SMPL_DUR_mask		= (3 << 3),
	    CON_DET_SMPL_SMPL_DUR_15us		= (0 << 3),
	    CON_DET_SMPL_SMPL_DUR_70us		= (1 << 3),
	    CON_DET_SMPL_SMPL_DUR_130us		= (2 << 3),
	    CON_DET_SMPL_SMPL_DUR_260us		= (3 << 3),
	    CON_DET_SMPL_SMPL_RATE_mask		= (3 << 1),
	    CON_DET_SMPL_SMPL_RATE_660Hz	= (0 << 1),
	    CON_DET_SMPL_SMPL_RATE_265Hz	= (1 << 1),
	    CON_DET_SMPL_SMPL_RATE_130Hz	= (2 << 1),
	    CON_DET_SMPL_SMPL_RATE_70Hz		= (3 << 1),
	    CON_DET_SMPL_SMPL_MODE_mask		= (1 << 0),
	    CON_DET_SMPL_SMPL_MODE_TriStar2	= (0 << 0),
	    CON_DET_SMPL_SMPL_MODE_TriStar1	= (1 << 0),
	
	RD_FIFO					= 0x1F,
	
	FIFO0					= 0x20,
	FIFO63					= 0x5F,
	FIFO_LEN				= (FIFO63 - FIFO0 + 1),
	
	FIFO_MTP2_TIMING			= 0x20,
	FIFO_KEY_CTRL				= 0x21,
	    FIFO_KEY_CTRL_LOCK_REQ		= (1 << 5),
	    FIFO_KEY_CTRL_ESN			= (1 << 4),
	    FIFO_KEY_CTRL_KEY2_2		= (1 << 3),
	    FIFO_KEY_CTRL_KEY2_1		= (1 << 2),
	    FIFO_KEY_CTRL_KEY1_2		= (1 << 1),
	    FIFO_KEY_CTRL_KEY1_1		= (1 << 0),
	FIFO_KEY_ESN_BYTE0			= 0x22,
	FIFO_KEY_ESN_BYTE1			= 0x23,
	FIFO_KEY_ESN_BYTE2			= 0x24,
	FIFO_KEY_ESN_BYTE3			= 0x25,
	FIFO_KEY_ESN_BYTE4			= 0x26,
	FIFO_KEY_ESN_BYTE5			= 0x27,
	FIFO_KEY_ESN_BYTE6			= 0x28,
	FIFO_KEY_ESN_BYTE7			= 0x29,
	FIFO_MTP2_PRG_CTRL			= 0x2E,
	FIFO_ENONCE_M_BYTE0			= 0x49,
	FIFO_ENONCE_M_BYTE1			= 0x50,
	FIFO_ENONCE_M_BYTE2			= 0x51,
	FIFO_ENONCE_M_BYTE3			= 0x52,
	FIFO_ENONCE_M_BYTE4			= 0x53,
	FIFO_ENONCE_M_BYTE5			= 0x54,
	FIFO_ENONCE_M_BYTE6			= 0x55,
	FIFO_ENONCE_M_BYTE7			= 0x56,
	FIFO_ESN_BYTE0				= 0x57,
	FIFO_ESN_BYTE1				= 0x58,
	FIFO_ESN_BYTE2				= 0x59,
	FIFO_ESN_BYTE3				= 0x5A,
	FIFO_ESN_BYTE4				= 0x5B,
	FIFO_ESN_BYTE5				= 0x5C,
	FIFO_ESN_BYTE6				= 0x5D,
	FIFO_ESN_BYTE7				= 0x5E,
	
	FIFO_CTRL1				= 0x60,
	    FIFO_CTRL1_ULIMITED_RX		= (1 << 7),
	    FIFO_CTRL1_RESP_LENGTH_shift	= (1),
	    FIFO_CTRL1_RESP_LENGTH_mask		= (63 << FIFO_CTRL1_RESP_LENGTH_shift),
	    FIFO_CTRL1_RD_TRIG_LVL_shift	= (1),
	    FIFO_CTRL1_RD_TRIG_LVL_mask		= (63 << FIFO_CTRL1_RD_TRIG_LVL_shift),
	    FIFO_CTRL1_CMD_KILL			= (1 << 0),
	
	FIFO_CTRL0				= 0x61,
	    FIFO_CTRL0_CMD_LENGTH_shift		= (1),
	    FIFO_CTRL0_CMD_LENGTH_mask		= (63 << FIFO_CTRL0_CMD_LENGTH_shift),
	    FIFO_CTRL0_AID_CMD_SEND		= (1 << 0),
	
	FIFO_FILL_STATUS			= 0x62,
	    FIFO_FILL_STATUS_FIFO_RD_LVL_shift	= (0),
	    FIFO_FILL_STATUS_FIFO_RD_LVL_mask	= (127 << FIFO_FILL_STATUS_FIFO_RD_LVL_shift),
};

static uint8_t apple_tristar_reg_read(AppleTristarState *t, hwaddr addr)
{
    qemu_log_mask(LOG_UNIMP, "%s: addr: 0x" TARGET_FMT_plx "\n", __func__, addr);
    switch (addr) {
        case MASK:
            return t->mask;
        case REV:
            return 0x8a;
        case FIFO_KEY_ESN_BYTE0 ... FIFO_KEY_ESN_BYTE7:
            return t->key_esn[addr - FIFO_KEY_ESN_BYTE0];
        case FIFO_ENONCE_M_BYTE0 ... FIFO_ENONCE_M_BYTE7:
            return t->enonce_m[addr - FIFO_ENONCE_M_BYTE0];
        case FIFO_ESN_BYTE0 ... FIFO_ESN_BYTE7:
            return t->esn[addr - FIFO_ESN_BYTE0];
        case 0x5f:
            return 0x74;
    }
    return 0;
}
static void apple_tristar_reg_write(AppleTristarState *t, hwaddr addr, uint8_t data)
{
    qemu_log_mask(LOG_UNIMP, "%s: addr: 0x" TARGET_FMT_plx " data: 0x%x\n", __func__, addr, data);
    switch (addr) {
        case MASK:
            t->mask = data;
            return;
        case FIFO_KEY_ESN_BYTE0 ... FIFO_KEY_ESN_BYTE7:
            t->key_esn[addr - FIFO_KEY_ESN_BYTE0] = data;
            return;
        case FIFO_ENONCE_M_BYTE0 ... FIFO_ENONCE_M_BYTE7:
            t->enonce_m[addr - FIFO_ENONCE_M_BYTE0] = data;
            return;
    }
    return;
}

static int tristar_reg_i2c_event(I2CSlave *s, enum i2c_event event)
{
    AppleTristarState *t = APPLE_TRISTAR(s);
    switch (event) {
        case I2C_START_RECV:
            // Slave to master
            if (t->mode != TRISTAR_REG_READ) {
                return 1;
            }
            break;
        case I2C_START_SEND:
            // Master to slave
            break;
        case I2C_FINISH:
            // recv or send ended
            switch (t->mode) {
                case TRISTAR_REG_WRITE:          
                    t->mode = TRISTAR_REG_IDLE;
                    break;
            }
            break;
        case I2C_NACK:
            t->mode = TRISTAR_REG_IDLE;
            break;
    }
    return 0;
}

static uint8_t tristar_reg_i2c_recv(I2CSlave *s)
{
    AppleTristarState *t = APPLE_TRISTAR(s);
    return apple_tristar_reg_read(t, t->address++);
}

static int tristar_reg_i2c_send(I2CSlave *s, uint8_t data)
{
    AppleTristarState *t = APPLE_TRISTAR(s);
    switch(t->mode) {
        case TRISTAR_REG_IDLE:
            t->address = data;
            t->mode = TRISTAR_REG_READ;
            return 0;
        case TRISTAR_REG_READ:
            t->mode = TRISTAR_REG_WRITE;
            /* fallthrough */
        case TRISTAR_REG_WRITE:
            apple_tristar_reg_write(t, t->address++, data);
            return 0;
    }
    return 1;
}

static void tristar_reg_reset(AppleTristarState *t) {
    t->address = -1;
    t->mask = 0xff;
}

DeviceState *apple_tristar_create(DTBNode *node)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_TRISTAR);
    I2CSlave *s = I2C_SLAVE(dev);
    AppleTristarState *t = APPLE_TRISTAR(dev);

    qdev_init_gpio_out(dev, t->irq, 1);

    DTBProp *prop = get_dtb_prop(node, "compatible");
    g_free(prop->value);
    prop->value = (uint8_t*)g_strdup("tristar,cbtl1610");
    prop->length = 17;
    
    prop = get_dtb_prop(node, "reg");
    s->address = *(uint32_t*)prop->value;

    tristar_reg_reset(t);
    return dev;
}

static void apple_tristar_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *sc = I2C_SLAVE_CLASS(klass);
    
    dc->desc = "Apple Tristar CBTL1610";

    sc->event = tristar_reg_i2c_event;
    sc->recv = tristar_reg_i2c_recv;
    sc->send = tristar_reg_i2c_send;
}

static const TypeInfo apple_tristar_type_info = {
    .name = TYPE_APPLE_TRISTAR,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(AppleTristarState),
    .class_init = apple_tristar_class_init,
};

static void apple_tristar_register_types(void)
{
    type_register_static(&apple_tristar_type_info);
}

type_init(apple_tristar_register_types)