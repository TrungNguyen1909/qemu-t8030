#include "qemu/osdep.h"
#include "hw/spmi/apple_spmi_pmu.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"
#include "sysemu/sysemu.h"

#define TYPE_APPLE_SPMI_PMU "apple.spmi.pmu"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSPMIPMUState, APPLE_SPMI_PMU)

#define LEG_SCRPAD_OFFSET_SECS_OFFSET   (4)
#define LEG_SCRPAD_OFFSET_TICKS_OFFSET  (21)
#define RTC_TICK_FREQ                   (32768)

struct AppleSPMIPMUState {
    /*< private >*/
    SPMISlave parent_obj;

    /*< public >*/
    qemu_irq irq;
    uint64_t rtc_offset;
    uint64_t tick_offset;
    uint32_t tick_period;
    uint32_t reg_rtc;
    uint32_t reg_leg_scrpad;
    uint8_t reg[0xffff];
    uint16_t addr;
};

static unsigned int frq_to_period_ns(unsigned int freq_hz)
{
    return NANOSECONDS_PER_SECOND > freq_hz ?
      NANOSECONDS_PER_SECOND / freq_hz : 1;
}
static uint64_t rtc_get_tick(AppleSPMIPMUState *p, uint64_t *out_ns)
{
    uint64_t now = qemu_clock_get_ns(rtc_clock);
    uint64_t offset = p->rtc_offset;
    if (out_ns) {
        *out_ns = now;
    }
    now -= offset;
    return ((now / NANOSECONDS_PER_SECOND) << 15)
           | ((now / p->tick_period) & 0x7fff);
}

static int apple_spmi_pmu_send(SPMISlave *s, uint8_t *data,
                               uint8_t len)
{
    AppleSPMIPMUState *p = APPLE_SPMI_PMU(s);
    uint16_t addr;
    for (addr = p->addr; addr < p->addr + len; addr++) {
        p->reg[addr] = data[addr - p->addr];
    }
    p->addr = addr;
    return len;
}

static int apple_spmi_pmu_recv(SPMISlave *s, uint8_t *data,
                               uint8_t len)
{
    AppleSPMIPMUState *p = APPLE_SPMI_PMU(s);
    uint16_t addr;

    for (addr = p->addr; addr < p->addr + len; addr++) {
        if (addr >= p->reg_rtc && addr < p->reg_rtc + 6) {
            uint64_t now = rtc_get_tick(p, NULL);
            p->reg[p->reg_rtc] = now << 1;
            p->reg[p->reg_rtc + 1] = now >> 7;
            p->reg[p->reg_rtc + 2] = now >> 15;
            p->reg[p->reg_rtc + 3] = now >> 23;
            p->reg[p->reg_rtc + 4] = now >> 31;
            p->reg[p->reg_rtc + 5] = now >> 39;
        }
        data[addr - p->addr] = p->reg[addr];
    }
    p->addr = addr;
    return len;
}

static int apple_spmi_pmu_command(SPMISlave *s, uint8_t opcode,
                           uint16_t addr)
{
    AppleSPMIPMUState *p = APPLE_SPMI_PMU(s);
    p->addr = addr;

    switch (opcode) {
    case SPMI_CMD_EXT_READ:
    case SPMI_CMD_EXT_READL:
    case SPMI_CMD_EXT_WRITE:
    case SPMI_CMD_EXT_WRITEL:
        return 0;
    default:
        return 1;
    }
}

DeviceState *apple_spmi_pmu_create(DTBNode *node)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_SPMI_PMU);
    AppleSPMIPMUState *p = APPLE_SPMI_PMU(dev);
    DTBProp *prop;

    prop = find_dtb_prop(node, "reg");
    assert(prop);
    spmi_set_slave_sid(SPMI_SLAVE(dev), *(uint32_t *)prop->value);

    prop = find_dtb_prop(node, "info-rtc");
    p->reg_rtc = *(uint32_t *)prop->value;

    prop = find_dtb_prop(node, "info-leg_scrpad");
    p->reg_leg_scrpad = *(uint32_t *)prop->value;

    p->tick_period = frq_to_period_ns(RTC_TICK_FREQ);
    p->tick_offset = rtc_get_tick(p, &p->rtc_offset);

    p->reg[p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET + 0] = p->tick_offset >> 15;
    p->reg[p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET + 1] = p->tick_offset >> (8 + 15);
    p->reg[p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET + 2] = p->tick_offset >> (16 + 15);
    p->reg[p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_SECS_OFFSET + 3] = p->tick_offset >> (24 + 15);;
    p->reg[p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_TICKS_OFFSET + 0] = p->tick_offset & 0xff;
    p->reg[p->reg_leg_scrpad + LEG_SCRPAD_OFFSET_TICKS_OFFSET + 1] = (p->tick_offset >> 8) & 0x7f;

    qdev_init_gpio_out(dev, &p->irq, 1);
    return dev;
}

static void apple_spmi_pmu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SPMISlaveClass *sc = SPMI_SLAVE_CLASS(klass);

    dc->desc = "Apple Dialog SPMI PMU";

    sc->send = apple_spmi_pmu_send;
    sc->recv = apple_spmi_pmu_recv;
    sc->command = apple_spmi_pmu_command;
}

static const TypeInfo apple_spmi_pmu_type_info = {
    .name = TYPE_APPLE_SPMI_PMU,
    .parent = TYPE_SPMI_SLAVE,
    .instance_size = sizeof(AppleSPMIPMUState),
    .class_init = apple_spmi_pmu_class_init,
};

static void apple_spmi_pmu_register_types(void)
{
    type_register_static(&apple_spmi_pmu_type_info);
}

type_init(apple_spmi_pmu_register_types)

