#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/queue.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "hw/or-irq.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/arm/apple_a9.h"
#include "arm-powerctl.h"
#include "sysemu/reset.h"

#define VMSTATE_A9_CPREG(name) \
        VMSTATE_UINT64(A9_CPREG_VAR_NAME(name), AppleA9State)

#define A9_CPREG_FUNCS(name)                                               \
    static uint64_t a9_cpreg_read_##name(CPUARMState *env,                 \
                                            const ARMCPRegInfo *ri)           \
    {                                                                         \
        AppleA9State *tcpu = APPLE_A9(env_archcpu(env));                    \
        return tcpu->A9_CPREG_VAR_NAME(name);                              \
    }                                                                         \
    static void a9_cpreg_write_##name(CPUARMState *env,                    \
                                         const ARMCPRegInfo *ri,              \
                                         uint64_t value)                      \
    {                                                                         \
        AppleA9State *tcpu = APPLE_A9(env_archcpu(env));                    \
        tcpu->A9_CPREG_VAR_NAME(name) = value;                             \
        /* if (value != 0) fprintf(stderr, "%s value = 0x%llx at PC 0x%llx\n",\
                                           value, env->pc); */                \
    }

#define A9_CPREG_DEF(p_name, p_op0, p_op1, p_crn, p_crm, p_op2, p_access) \
    {                                                                        \
        .cp = CP_REG_ARM64_SYSREG_CP,                                        \
        .name = #p_name, .opc0 = p_op0, .crn = p_crn, .crm = p_crm,          \
        .opc1 = p_op1, .opc2 = p_op2, .access = p_access, .type = ARM_CP_IO, \
        .state = ARM_CP_STATE_AA64, .readfn = a9_cpreg_read_##p_name,     \
        .writefn = a9_cpreg_write_##p_name,                               \
    }

#define MPIDR_AFF0_SHIFT 0
#define MPIDR_AFF0_WIDTH 8
#define MPIDR_AFF0_MASK  (((1 << MPIDR_AFF0_WIDTH) - 1) << MPIDR_AFF0_SHIFT)
#define MPIDR_AFF1_SHIFT 8
#define MPIDR_AFF1_WIDTH 8
#define MPIDR_AFF1_MASK  (((1 << MPIDR_AFF1_WIDTH) - 1) << MPIDR_AFF1_SHIFT)
#define MPIDR_AFF2_SHIFT 16
#define MPIDR_AFF2_WIDTH 8
#define MPIDR_AFF2_MASK  (((1 << MPIDR_AFF2_WIDTH) - 1) << MPIDR_AFF2_SHIFT)

#define MPIDR_CPU_ID(mpidr_el1_val)             (((mpidr_el1_val) & MPIDR_AFF0_MASK) >> MPIDR_AFF0_SHIFT)
#define MPIDR_CLUSTER_ID(mpidr_el1_val)         (((mpidr_el1_val) & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT)

#define NSEC_PER_USEC   1000ull         /* nanoseconds per microsecond */
#define USEC_PER_SEC    1000000ull      /* microseconds per second */
#define NSEC_PER_SEC    1000000000ull   /* nanoseconds per second */
#define NSEC_PER_MSEC   1000000ull      /* nanoseconds per millisecond */
#define RTCLOCK_SEC_DIVISOR     24000000ull

static void
absolutetime_to_nanoseconds(uint64_t abstime,
                            uint64_t *result)
{
	uint64_t t64;

	*result = (t64 = abstime / RTCLOCK_SEC_DIVISOR) * NSEC_PER_SEC;
	abstime -= (t64 * RTCLOCK_SEC_DIVISOR);
	*result += (abstime * NSEC_PER_SEC) / RTCLOCK_SEC_DIVISOR;
}

static void
nanoseconds_to_absolutetime(uint64_t nanosecs,
                            uint64_t *result)
{
	uint64_t t64;

	*result = (t64 = nanosecs / NSEC_PER_SEC) * RTCLOCK_SEC_DIVISOR;
	nanosecs -= (t64 * NSEC_PER_SEC);
	*result += (nanosecs * RTCLOCK_SEC_DIVISOR) / NSEC_PER_SEC;
}


A9_CPREG_FUNCS(ARM64_REG_EHID4)
A9_CPREG_FUNCS(ARM64_REG_EHID10)
A9_CPREG_FUNCS(ARM64_REG_HID0)
A9_CPREG_FUNCS(ARM64_REG_HID3)
A9_CPREG_FUNCS(ARM64_REG_HID4)
A9_CPREG_FUNCS(ARM64_REG_HID5)
A9_CPREG_FUNCS(ARM64_REG_HID7)
A9_CPREG_FUNCS(ARM64_REG_HID8)
A9_CPREG_FUNCS(ARM64_REG_HID9)
A9_CPREG_FUNCS(ARM64_REG_HID11)
A9_CPREG_FUNCS(ARM64_REG_HID13)
A9_CPREG_FUNCS(ARM64_REG_HID14)
A9_CPREG_FUNCS(ARM64_REG_HID16)
A9_CPREG_FUNCS(ARM64_REG_LSU_ERR_STS)
A9_CPREG_FUNCS(PMC0)
A9_CPREG_FUNCS(PMC1)
A9_CPREG_FUNCS(PMCR1)
A9_CPREG_FUNCS(PMSR)
A9_CPREG_FUNCS(ARM64_REG_APCTL_EL1)
A9_CPREG_FUNCS(S3_4_c15_c0_5)
A9_CPREG_FUNCS(ARM64_REG_CYC_OVRD)
A9_CPREG_FUNCS(ARM64_REG_ACC_CFG)
A9_CPREG_FUNCS(S3_5_c15_c10_1)
A9_CPREG_FUNCS(UPMPCM)
A9_CPREG_FUNCS(UPMCR0)
A9_CPREG_FUNCS(UPMSR)

inline bool apple_a9_is_sleep(AppleA9State *tcpu)
{
    return CPU(tcpu)->halted;
}

void apple_a9_wakeup(AppleA9State *tcpu)
{
    int ret = QEMU_ARM_POWERCTL_RET_SUCCESS;

    if (ARM_CPU(tcpu)->power_state != PSCI_ON) {
        ret = arm_set_cpu_on_and_reset(tcpu->mpidr);
    }

    if (ret != QEMU_ARM_POWERCTL_RET_SUCCESS) {
        error_report("%s: failed to bring up CPU %d: err %d",
                __func__, tcpu->cpu_id, ret);
    }
}

static const ARMCPRegInfo a9_cp_reginfo_tcg[] = {
    A9_CPREG_DEF(ARM64_REG_EHID4, 3, 0, 15, 4, 1, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_EHID10, 3, 0, 15, 10, 1, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID0, 3, 0, 15, 0, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID3, 3, 0, 15, 3, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID4, 3, 0, 15, 4, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID5, 3, 0, 15, 5, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID7, 3, 0, 15, 7, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID8, 3, 0, 15, 8, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID9, 3, 0, 15, 9, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID11, 3, 0, 15, 11, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID13, 3, 0, 15, 14, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID14, 3, 0, 15, 15, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_HID16, 3, 0, 15, 15, 2, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_LSU_ERR_STS, 3, 3, 15, 0, 0, PL1_RW),
    A9_CPREG_DEF(PMC0, 3, 2, 15, 0, 0, PL1_RW),
    A9_CPREG_DEF(PMC1, 3, 2, 15, 1, 0, PL1_RW),
    A9_CPREG_DEF(PMCR1, 3, 1, 15, 1, 0, PL1_RW),
    A9_CPREG_DEF(PMSR, 3, 1, 15, 13, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_APCTL_EL1, 3, 4, 15, 0, 4, PL1_RW),
    A9_CPREG_DEF(S3_4_c15_c0_5, 3, 4, 15, 0, 5, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_CYC_OVRD, 3, 5, 15, 5, 0, PL1_RW),
    A9_CPREG_DEF(ARM64_REG_ACC_CFG, 3, 5, 15, 4, 0, PL1_RW),
    A9_CPREG_DEF(S3_5_c15_c10_1, 3, 5, 15, 10, 1, PL0_RW),
    A9_CPREG_DEF(UPMPCM, 3, 7, 15, 5, 4, PL1_RW),
    A9_CPREG_DEF(UPMCR0, 3, 7, 15, 0, 4, PL1_RW),
    A9_CPREG_DEF(UPMSR, 3, 7, 15, 6, 4, PL1_RW),
    REGINFO_SENTINEL,
};

static void a9_add_cpregs(AppleA9State *tcpu)
{
    ARMCPU *cpu = ARM_CPU(tcpu);
    define_arm_cp_regs(cpu, a9_cp_reginfo_tcg);
}

static void apple_a9_realize(DeviceState *dev, Error **errp)
{
    AppleA9State *tcpu = APPLE_A9(dev);
    AppleA9Class *tclass = APPLE_A9_GET_CLASS(dev);
    DeviceState *fiq_or;
    Object *obj = OBJECT(dev);

    object_property_set_link(OBJECT(tcpu), "memory", OBJECT(&tcpu->memory),
                             errp);
    if (*errp) {
        return;
    }
    a9_add_cpregs(tcpu);
    tclass->parent_realize(dev, errp);
    if (*errp) {
        return;
    }
    fiq_or = qdev_new(TYPE_OR_IRQ);
    object_property_add_child(obj, "fiq-or", OBJECT(fiq_or));
    qdev_prop_set_uint16(fiq_or, "num-lines", 16);
    qdev_realize_and_unref(fiq_or, NULL, errp);
    if (*errp) {
        return;
    }
    qdev_connect_gpio_out(fiq_or, 0, qdev_get_gpio_in(dev, ARM_CPU_FIQ));

    qdev_connect_gpio_out(dev, GTIMER_PHYS, qdev_get_gpio_in(fiq_or, 0));
}

static void apple_a9_reset(DeviceState *dev)
{
    AppleA9State *tcpu = APPLE_A9(dev);
    AppleA9Class *tclass = APPLE_A9_GET_CLASS(dev);
    tclass->parent_reset(dev);

    tcpu->A9_CPREG_VAR_NAME(ARM64_REG_LSU_ERR_STS) = 0;
    tcpu->A9_CPREG_VAR_NAME(PMC0) = 0;
    tcpu->A9_CPREG_VAR_NAME(PMC1) = 0;
    tcpu->A9_CPREG_VAR_NAME(PMCR1) = 0;
    tcpu->A9_CPREG_VAR_NAME(PMSR) = 0;
    tcpu->A9_CPREG_VAR_NAME(ARM64_REG_APCTL_EL1) = 2;
}

static void apple_a9_instance_init(Object *obj)
{
    object_property_set_uint(obj, "cntfrq", 24000000, &error_fatal);
}

AppleA9State *apple_a9_create(DTBNode *node)
{
    DeviceState  *dev;
    AppleA9State *tcpu;
    ARMCPU *cpu;
    Object *obj;
    DTBProp *prop;
    uint64_t mpidr;
    uint64_t freq;
    uint64_t *reg;

    obj = object_new(TYPE_APPLE_A9);
    dev = DEVICE(obj);
    tcpu = APPLE_A9(dev);
    cpu = ARM_CPU(tcpu);

    prop = find_dtb_prop(node, "name");
    dev->id = g_strdup((char *)prop->value);

    prop = find_dtb_prop(node, "cpu-id");
    assert(prop->length == 4);
    tcpu->cpu_id = *(unsigned int*)prop->value;

    prop = find_dtb_prop(node, "reg");
    assert(prop->length == 4);
    tcpu->phys_id = *(unsigned int*)prop->value;

    mpidr = 0LL | tcpu->phys_id | (tcpu->phys_id << MPIDR_AFF2_SHIFT)
            | (1LL << 31);
    mpidr |= 1 << MPIDR_AFF2_SHIFT;

    tcpu->mpidr = mpidr;
    object_property_set_uint(obj, "mp-affinity", mpidr, &error_fatal);
    //cpu->midr = FIELD_DP64(cpu->midr, MIDR_EL1, PARTNUM, 0x12 + tcpu->cluster_id);
    //cpu->midr = FIELD_DP64(cpu->midr, MIDR_EL1, VARIANT, 0x1);

    /* remove debug regs from device tree */
    prop = find_dtb_prop(node, "reg-private");
    if (prop != NULL) {
        remove_dtb_prop(node, prop);
    }

    prop = find_dtb_prop(node, "cpu-uttdbg-reg");
    if (prop != NULL) {
        remove_dtb_prop(node, prop);
    }

    /* need to set the cpu freqs instead of iBoot */
    freq = 24000000;

    if (tcpu->cpu_id == 0) {
        prop = find_dtb_prop(node, "state");
        if (prop != NULL) {
            remove_dtb_prop(node, prop);
        }
        set_dtb_prop(node, "state", 8, (uint8_t *)"running");
    } else {
        object_property_set_bool(obj, "start-powered-off", true, NULL);
    }
    #if 0
    object_property_set_bool(obj, "start-powered-off", true, NULL);
    #endif

    prop = find_dtb_prop(node, "timebase-frequency");
    if (prop != NULL) {
        remove_dtb_prop(node, prop);
    }
    set_dtb_prop(node, "timebase-frequency", sizeof(uint64_t),
                                             (uint8_t *)&freq);

    prop = find_dtb_prop(node, "fixed-frequency");
    if (prop != NULL) {
        remove_dtb_prop(node, prop);
    }
    set_dtb_prop(node, "fixed-frequency", sizeof(uint64_t), (uint8_t *)&freq);

    memory_region_init(&tcpu->memory, obj, "cpu-memory", UINT64_MAX);
    memory_region_init_alias(&tcpu->sysmem, obj, "sysmem", get_system_memory(),
                             0, UINT64_MAX);
    memory_region_add_subregion_overlap(&tcpu->memory, 0, &tcpu->sysmem, -2);

    prop = find_dtb_prop(node, "cpu-impl-reg");
    assert(prop);
    assert(prop->length == 16);

    reg = (uint64_t*)prop->value;

    memory_region_init_ram_device_ptr(&tcpu->impl_reg, obj,
                                      TYPE_APPLE_A9 ".impl-reg",
                                      reg[1], g_malloc0(reg[1]));
    memory_region_add_subregion(get_system_memory(),
                                reg[0], &tcpu->impl_reg);

    prop = find_dtb_prop(node, "coresight-reg");
    assert(prop);
    assert(prop->length == 16);

    reg = (uint64_t*)prop->value;

    memory_region_init_ram_device_ptr(&tcpu->coresight_reg, obj,
                                      TYPE_APPLE_A9 ".coresight-reg",
                                      reg[1], g_malloc0(reg[1]));
    memory_region_add_subregion(get_system_memory(),
                                reg[0], &tcpu->coresight_reg);

    return tcpu;
}

static Property apple_a9_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription vmstate_apple_a9 = {
    .name = "apple_a9",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_A9_CPREG(ARM64_REG_EHID4),
        VMSTATE_A9_CPREG(ARM64_REG_EHID10),
        VMSTATE_A9_CPREG(ARM64_REG_HID0),
        VMSTATE_A9_CPREG(ARM64_REG_HID3),
        VMSTATE_A9_CPREG(ARM64_REG_HID4),
        VMSTATE_A9_CPREG(ARM64_REG_HID5),
        VMSTATE_A9_CPREG(ARM64_REG_HID7),
        VMSTATE_A9_CPREG(ARM64_REG_HID8),
        VMSTATE_A9_CPREG(ARM64_REG_HID9),
        VMSTATE_A9_CPREG(ARM64_REG_HID11),
        VMSTATE_A9_CPREG(ARM64_REG_HID13),
        VMSTATE_A9_CPREG(ARM64_REG_HID14),
        VMSTATE_A9_CPREG(ARM64_REG_HID16),
        VMSTATE_A9_CPREG(ARM64_REG_LSU_ERR_STS),
        VMSTATE_A9_CPREG(PMC0),
        VMSTATE_A9_CPREG(PMC1),
        VMSTATE_A9_CPREG(PMCR1),
        VMSTATE_A9_CPREG(PMSR),
        VMSTATE_A9_CPREG(ARM64_REG_APCTL_EL1),
        VMSTATE_A9_CPREG(S3_4_c15_c0_5),
        VMSTATE_A9_CPREG(ARM64_REG_CYC_OVRD),
        VMSTATE_A9_CPREG(ARM64_REG_ACC_CFG),
        VMSTATE_A9_CPREG(S3_5_c15_c10_1),
        VMSTATE_A9_CPREG(UPMPCM),
        VMSTATE_A9_CPREG(UPMCR0),
        VMSTATE_A9_CPREG(UPMSR),
        VMSTATE_END_OF_LIST()
    }
};

static void apple_a9_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    AppleA9Class *tc = APPLE_A9_CLASS(klass);

    device_class_set_parent_realize(dc, apple_a9_realize, &tc->parent_realize);
    device_class_set_parent_reset(dc, apple_a9_reset, &tc->parent_reset);
    dc->desc = "Apple A9 CPU";
    dc->vmsd = &vmstate_apple_a9;
    set_bit(DEVICE_CATEGORY_CPU, dc->categories);
    device_class_set_props(dc, apple_a9_properties);
}

static const TypeInfo apple_a9_info = {
    .name = TYPE_APPLE_A9,
    .parent = ARM_CPU_TYPE_NAME("max"),
    .instance_size = sizeof(AppleA9State),
    .instance_init = apple_a9_instance_init,
    .class_size = sizeof(AppleA9Class),
    .class_init = apple_a9_class_init,
};

static void apple_a9_register_types(void)
{
    type_register_static(&apple_a9_info);
}

type_init(apple_a9_register_types);
