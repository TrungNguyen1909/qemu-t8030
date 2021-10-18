#include "qemu/osdep.h"
#include "qemu/queue.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "hw/or-irq.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/arm/t8030_cpu.h"
#include "hw/arm/t8030_gxf.h"
#include "arm-powerctl.h"
#include "sysemu/reset.h"

#define VMSTATE_T8030_CPREG(name) \
        VMSTATE_UINT64(T8030_CPREG_VAR_NAME(name), T8030CPUState)

#define T8030_CPREG_FUNCS(name)                                               \
    static uint64_t t8030_cpreg_read_##name(CPUARMState *env,                 \
                                            const ARMCPRegInfo *ri)           \
    {                                                                         \
        T8030CPUState *tcpu = T8030_CPU(env_archcpu(env));                    \
        return tcpu->T8030_CPREG_VAR_NAME(name);                              \
    }                                                                         \
    static void t8030_cpreg_write_##name(CPUARMState *env,                    \
                                         const ARMCPRegInfo *ri,              \
                                         uint64_t value)                      \
    {                                                                         \
        T8030CPUState *tcpu = T8030_CPU(env_archcpu(env));                    \
        tcpu->T8030_CPREG_VAR_NAME(name) = value;                             \
        /* if (value != 0) fprintf(stderr, "%s value = 0x%llx at PC 0x%llx\n",\
                                           value, env->pc); */                \
    }

#define T8030_CPREG_DEF(p_name, p_op0, p_op1, p_crn, p_crm, p_op2, p_access) \
    {                                                                        \
        .cp = CP_REG_ARM64_SYSREG_CP,                                        \
        .name = #p_name, .opc0 = p_op0, .crn = p_crn, .crm = p_crm,          \
        .opc1 = p_op1, .opc2 = p_op2, .access = p_access, .type = ARM_CP_IO, \
        .state = ARM_CP_STATE_AA64, .readfn = t8030_cpreg_read_##p_name,     \
        .writefn = t8030_cpreg_write_##p_name,                               \
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

#define IPI_SR_SRC_CPU_SHIFT 8
#define IPI_SR_SRC_CPU_WIDTH 8
#define IPI_SR_SRC_CPU_MASK  (((1 << IPI_SR_SRC_CPU_WIDTH) - 1) << IPI_SR_SRC_CPU_SHIFT)
#define IPI_SR_SRC_CPU(ipi_sr_val)         (((ipi_sr_val) & IPI_SR_SRC_CPU_MASK) >> IPI_SR_SRC_CPU_SHIFT)

#define IPI_RR_TARGET_CLUSTER_SHIFT 16

#define IPI_RR_TYPE_IMMEDIATE (0 << 28)
#define IPI_RR_TYPE_RETRACT   (1 << 28)
#define IPI_RR_TYPE_DEFERRED  (2 << 28)
#define IPI_RR_TYPE_NOWAKE    (3 << 28)
#define IPI_RR_TYPE_MASK      (3 << 28)
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


static QTAILQ_HEAD(, T8030CPUCluster) clusters = QTAILQ_HEAD_INITIALIZER(clusters);

static uint64_t ipi_cr = kDeferredIPITimerDefault;
static QEMUTimer *ipicr_timer = NULL;

T8030_CPREG_FUNCS(ARM64_REG_EHID4)
T8030_CPREG_FUNCS(ARM64_REG_EHID10)
T8030_CPREG_FUNCS(ARM64_REG_HID0)
T8030_CPREG_FUNCS(ARM64_REG_HID3)
T8030_CPREG_FUNCS(ARM64_REG_HID4)
T8030_CPREG_FUNCS(ARM64_REG_HID5)
T8030_CPREG_FUNCS(ARM64_REG_HID7)
T8030_CPREG_FUNCS(ARM64_REG_HID8)
T8030_CPREG_FUNCS(ARM64_REG_HID9)
T8030_CPREG_FUNCS(ARM64_REG_HID11)
T8030_CPREG_FUNCS(ARM64_REG_HID13)
T8030_CPREG_FUNCS(ARM64_REG_HID14)
T8030_CPREG_FUNCS(ARM64_REG_HID16)
T8030_CPREG_FUNCS(ARM64_REG_LSU_ERR_STS)
T8030_CPREG_FUNCS(PMC0)
T8030_CPREG_FUNCS(PMC1)
T8030_CPREG_FUNCS(PMCR1)
T8030_CPREG_FUNCS(PMSR)
T8030_CPREG_FUNCS(ARM64_REG_APCTL_EL1)
T8030_CPREG_FUNCS(ARM64_REG_KERNELKEYLO_EL1)
T8030_CPREG_FUNCS(ARM64_REG_KERNELKEYHI_EL1)
T8030_CPREG_FUNCS(S3_4_c15_c0_5)
T8030_CPREG_FUNCS(AMX_STATUS_EL1)
T8030_CPREG_FUNCS(AMX_CTL_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CYC_OVRD)
T8030_CPREG_FUNCS(ARM64_REG_ACC_CFG)
T8030_CPREG_FUNCS(S3_5_c15_c10_1)
T8030_CPREG_FUNCS(UPMPCM)
T8030_CPREG_FUNCS(UPMCR0)
T8030_CPREG_FUNCS(UPMSR)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_A_LWR_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_A_UPR_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_CTL_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_LOCK_EL1)

inline bool t8030_cpu_is_sleep(T8030CPUState *tcpu)
{
    return CPU(tcpu)->halted;
}

void t8030_cpu_wakeup(T8030CPUState *tcpu)
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

static T8030CPUCluster *t8030_find_cluster(int cluster_id)
{
    T8030CPUCluster *cluster = NULL;
    QTAILQ_FOREACH(cluster, &clusters, next) {
        if (cluster->id == cluster_id)
            return cluster;
    }
    return NULL;
}

/* Deliver IPI */
static void t8030_cluster_deliver_ipi(T8030CPUCluster *c, uint64_t cpu_id,
                                      uint64_t src_cpu, uint64_t flag)
{
    t8030_cpu_wakeup(c->cpus[cpu_id]);

    if (c->cpus[cpu_id]->ipi_sr)
        return;

    c->cpus[cpu_id]->ipi_sr = 1LL | (src_cpu << IPI_SR_SRC_CPU_SHIFT) | flag;
    qemu_irq_raise(c->cpus[cpu_id]->fast_ipi);
}

static int t8030_cpu_cluster_pre_save(void *opaque) {
    T8030CPUCluster *cluster = T8030_CPU_CLUSTER(opaque);
    cluster->ipi_cr = ipi_cr;
    return 0;
}

static int t8030_cpu_cluster_post_load(void *opaque, int version_id) {
    T8030CPUCluster *cluster = T8030_CPU_CLUSTER(opaque);
    ipi_cr = cluster->ipi_cr;
    return 0;
}

static void t8030_cpu_cluster_reset(DeviceState *dev) {
    T8030CPUCluster *cluster = T8030_CPU_CLUSTER(dev);
    memset(cluster->deferredIPI, 0, sizeof(cluster->deferredIPI));
    memset(cluster->noWakeIPI, 0, sizeof(cluster->noWakeIPI));
}

static int add_cpu_to_cluster(Object *obj, void *opaque)
{
    T8030CPUCluster *cluster = T8030_CPU_CLUSTER(opaque);
    CPUState *cpu = (CPUState *)object_dynamic_cast(obj, TYPE_CPU);
    T8030CPUState *tcpu = (T8030CPUState *)object_dynamic_cast(obj,
                                                               TYPE_T8030_CPU);

    if (cpu) {
        cpu->cluster_index = cluster->id;
        if (tcpu) {
            cluster->base = tcpu->cluster_reg[0];
            cluster->size = tcpu->cluster_reg[1];
            cluster->cpus[tcpu->cpu_id] = tcpu;
        }
    }
    return 0;
}

static void t8030_cpu_cluster_realize(DeviceState *dev, Error **errp)
{
    T8030CPUCluster *cluster = T8030_CPU_CLUSTER(dev);
    object_child_foreach_recursive(OBJECT(cluster), add_cpu_to_cluster, dev);

    if (cluster->size) {
        memory_region_init_ram_device_ptr(&cluster->mr, OBJECT(cluster),
                                          TYPE_T8030_CPU_CLUSTER ".cpm-impl-reg",
                                          cluster->size, g_malloc0(cluster->size));
    }
}

static void t8030_cpu_cluster_tick(T8030CPUCluster *c)
{
    int i, j;

    for (i = 0; i < T8030_MAX_CPU; i++) { /* source */
        for (j = 0; j < T8030_MAX_CPU; j++) { /* target */
            if (c->cpus[j] != NULL && c->deferredIPI[i][j]) {
                t8030_cluster_deliver_ipi(c, j, i, IPI_RR_TYPE_DEFERRED);
                break;
            }
        }
    }

    for (i = 0; i < T8030_MAX_CPU; i++) { /* source */
        for (j = 0; j < T8030_MAX_CPU; j++) { /* target */
            if (c->cpus[j] != NULL && c->noWakeIPI[i][j]
                && !t8030_cpu_is_sleep(c->cpus[j])) {
                t8030_cluster_deliver_ipi(c, j, i, IPI_RR_TYPE_NOWAKE);
                break;
            }
        }
    }
}

static void t8030_cpu_cluster_ipicr_tick(void* opaque)
{
    T8030CPUCluster *cluster;
    QTAILQ_FOREACH(cluster, &clusters, next) {
        t8030_cpu_cluster_tick(cluster);
    }

    timer_mod_ns(ipicr_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + ipi_cr);
}


static void t8030_cpu_cluster_reset_handler(void *opaque)
{
    if (ipicr_timer) {
        timer_del(ipicr_timer);
        ipicr_timer = NULL;
    }
    ipicr_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                               t8030_cpu_cluster_ipicr_tick, NULL);
    timer_mod_ns(ipicr_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                              + kDeferredIPITimerDefault);
}

static void t8030_cpu_cluster_instance_init(Object *obj)
{
    T8030CPUCluster *cluster = T8030_CPU_CLUSTER(obj);
    QTAILQ_INSERT_TAIL(&clusters, cluster, next);

    if (ipicr_timer == NULL) {
        qemu_register_reset(t8030_cpu_cluster_reset_handler, NULL);
    }
}

/* Deliver local IPI */
static void t8030_ipi_rr_local(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    T8030CPUState *tcpu = T8030_CPU(env_archcpu(env));

    uint32_t phys_id = MPIDR_CPU_ID(value) | (tcpu->cluster_id << 8);
    T8030CPUCluster *c = t8030_find_cluster(tcpu->cluster_id);
    uint32_t cpu_id = -1;
    int i;

    for(i = 0; i < T8030_MAX_CPU; i++) {
        if (c->cpus[i]) {
            if (c->cpus[i]->phys_id == phys_id) {
                cpu_id = i;
                break;
            }
        }
    }

    if (cpu_id == -1 || c->cpus[cpu_id] == NULL) {
        qemu_log_mask(LOG_GUEST_ERROR, "CPU %x failed to send fast IPI "
                                       "to local CPU %x: "
                                       "value: 0x"TARGET_FMT_lx"\n",
                                       tcpu->phys_id, phys_id, value);
        return;
    }

    switch (value & IPI_RR_TYPE_MASK) {
    case IPI_RR_TYPE_NOWAKE:
        if (t8030_cpu_is_sleep(c->cpus[cpu_id])) {
            c->noWakeIPI[tcpu->cpu_id][cpu_id] = 1;
        } else {
            t8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id,
                                      IPI_RR_TYPE_IMMEDIATE);
        }
        break;
    case IPI_RR_TYPE_DEFERRED:
        c->deferredIPI[tcpu->cpu_id][cpu_id] = 1;
        break;
    case IPI_RR_TYPE_RETRACT:
        c->deferredIPI[tcpu->cpu_id][cpu_id] = 0;
        c->noWakeIPI[tcpu->cpu_id][cpu_id] = 0;
        break;
    case IPI_RR_TYPE_IMMEDIATE:
        t8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id,
                                  IPI_RR_TYPE_IMMEDIATE);
        break;
    default:
        g_assert_not_reached();
        break;
    }
}

/* Deliver global IPI */
static void t8030_ipi_rr_global(CPUARMState *env, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    T8030CPUState *tcpu = T8030_CPU(env_archcpu(env));
    uint32_t cluster_id = MPIDR_CLUSTER_ID(value >> IPI_RR_TARGET_CLUSTER_SHIFT);
    T8030CPUCluster *c = t8030_find_cluster(cluster_id);

    if (!c) {
        return;
    }

    uint32_t phys_id = MPIDR_CPU_ID(value) | cluster_id << 8;
    uint32_t cpu_id = -1;
    int i;

    for(i = 0; i < T8030_MAX_CPU; i++) {
        if (c->cpus[i] != NULL) {
            if (c->cpus[i]->phys_id == phys_id) {
                cpu_id = i;
                break;
            }
        }
    }

    if (cpu_id == -1 || c->cpus[cpu_id] == NULL) {
        qemu_log_mask(LOG_GUEST_ERROR, "CPU %x failed to send fast IPI "
                                       "to global CPU %x: "
                                       "value: 0x" TARGET_FMT_lx "\n",
                                       tcpu->phys_id, phys_id, value);
        return;
    }

    switch (value & IPI_RR_TYPE_MASK) {
    case IPI_RR_TYPE_NOWAKE:
        if (t8030_cpu_is_sleep(c->cpus[cpu_id])) {
            c->noWakeIPI[tcpu->cpu_id][cpu_id] = 1;
        } else {
            t8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id,
                                      IPI_RR_TYPE_IMMEDIATE);
        }
        break;
    case IPI_RR_TYPE_DEFERRED:
        c->deferredIPI[tcpu->cpu_id][cpu_id] = 1;
        break;
    case IPI_RR_TYPE_RETRACT:
        c->deferredIPI[tcpu->cpu_id][cpu_id] = 0;
        c->noWakeIPI[tcpu->cpu_id][cpu_id] = 0;
        break;
    case IPI_RR_TYPE_IMMEDIATE:
        t8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id,
                                  IPI_RR_TYPE_IMMEDIATE);
        break;
    default:
        g_assert_not_reached();
        break;
    }
}

/* Receiving IPI */
static uint64_t t8030_ipi_read_sr(CPUARMState *env, const ARMCPRegInfo *ri)
{
    T8030CPUState *tcpu = T8030_CPU(env_archcpu(env));

    assert(env_archcpu(env)->mp_affinity == tcpu->mpidr);
    return tcpu->ipi_sr;
}

/* Acknowledge received IPI */
static void t8030_ipi_write_sr(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    T8030CPUState *tcpu = T8030_CPU(env_archcpu(env));
    T8030CPUCluster *c = t8030_find_cluster(tcpu->cluster_id);
    uint64_t src_cpu = IPI_SR_SRC_CPU(value);

    tcpu->ipi_sr = 0;
    qemu_irq_lower(tcpu->fast_ipi);

    switch (value & IPI_RR_TYPE_MASK) {
    case IPI_RR_TYPE_NOWAKE:
        c->noWakeIPI[src_cpu][tcpu->cpu_id] = 0;
        break;
    case IPI_RR_TYPE_DEFERRED:
        c->deferredIPI[src_cpu][tcpu->cpu_id] = 0;
        break;
    default:
        break;
    }
}

/* Read deferred interrupt timeout (global) */
static uint64_t t8030_ipi_read_cr(CPUARMState *env, const ARMCPRegInfo *ri)
{
    uint64_t abstime;

    nanoseconds_to_absolutetime(ipi_cr, &abstime);
    return abstime;
}

/* Set deferred interrupt timeout (global) */
static void t8030_ipi_write_cr(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    uint64_t nanosec = 0;

    absolutetime_to_nanoseconds(value, &nanosec);

    uint64_t ct;

    if (value == 0)
        value = kDeferredIPITimerDefault;

    ct = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    timer_mod_ns(ipicr_timer, (ct / ipi_cr) * ipi_cr + nanosec);
    ipi_cr = nanosec;
}

static const ARMCPRegInfo t8030_cp_reginfo_tcg[] = {
    T8030_CPREG_DEF(ARM64_REG_EHID4, 3, 0, 15, 4, 1, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_EHID10, 3, 0, 15, 10, 1, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID0, 3, 0, 15, 0, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID3, 3, 0, 15, 3, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID4, 3, 0, 15, 4, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID5, 3, 0, 15, 5, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID7, 3, 0, 15, 7, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID8, 3, 0, 15, 8, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID9, 3, 0, 15, 9, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID11, 3, 0, 15, 11, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID13, 3, 0, 15, 14, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID14, 3, 0, 15, 15, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID16, 3, 0, 15, 15, 2, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_LSU_ERR_STS, 3, 3, 15, 0, 0, PL1_RW),
    T8030_CPREG_DEF(PMC0, 3, 2, 15, 0, 0, PL1_RW),
    T8030_CPREG_DEF(PMC1, 3, 2, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(PMCR1, 3, 1, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(PMSR, 3, 1, 15, 13, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_APCTL_EL1, 3, 4, 15, 0, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_KERNELKEYLO_EL1, 3, 4, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_KERNELKEYHI_EL1, 3, 4, 15, 1, 1, PL1_RW),
    T8030_CPREG_DEF(S3_4_c15_c0_5, 3, 4, 15, 0, 5, PL1_RW),
    T8030_CPREG_DEF(AMX_STATUS_EL1, 3, 4, 15, 1, 3, PL1_R),
    T8030_CPREG_DEF(AMX_CTL_EL1, 3, 4, 15, 1, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CYC_OVRD, 3, 5, 15, 5, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_ACC_CFG, 3, 5, 15, 4, 0, PL1_RW),
    T8030_CPREG_DEF(S3_5_c15_c10_1, 3, 5, 15, 10, 1, PL0_RW),
    T8030_CPREG_DEF(UPMPCM, 3, 7, 15, 5, 4, PL1_RW),
    T8030_CPREG_DEF(UPMCR0, 3, 7, 15, 0, 4, PL1_RW),
    T8030_CPREG_DEF(UPMSR, 3, 7, 15, 6, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_A_LWR_EL1, 3, 4, 15, 2, 3, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_A_UPR_EL1, 3, 4, 15, 2, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_CTL_EL1, 3, 4, 15, 2, 5, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_LOCK_EL1, 3, 4, 15, 2, 2, PL1_RW),

    {
        .cp = CP_REG_ARM64_SYSREG_CP,
        .name = "ARM64_REG_IPI_RR_LOCAL",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 0, .opc2 = 0,
        .access = PL1_W, .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .state = ARM_CP_STATE_AA64,
        .readfn = arm_cp_read_zero,
        .writefn = t8030_ipi_rr_local
    },
    {
        .cp = CP_REG_ARM64_SYSREG_CP,
        .name = "ARM64_REG_IPI_RR_GLOBAL",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 0, .opc2 = 1,
        .access = PL1_W, .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .state = ARM_CP_STATE_AA64,
        .readfn = arm_cp_read_zero,
        .writefn = t8030_ipi_rr_global
    },
    {
        .cp = CP_REG_ARM64_SYSREG_CP,
        .name = "ARM64_REG_IPI_SR",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 1, .opc2 = 1,
        .access = PL1_RW, .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .state = ARM_CP_STATE_AA64,
        .readfn = t8030_ipi_read_sr,
        .writefn = t8030_ipi_write_sr
    },
    {
        .cp = CP_REG_ARM64_SYSREG_CP,
        .name = "ARM64_REG_IPI_CR",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 3, .opc2 = 1,
        .access = PL1_RW, .type = ARM_CP_IO,
        .state = ARM_CP_STATE_AA64,
        .readfn = t8030_ipi_read_cr,
        .writefn = t8030_ipi_write_cr
    },
    REGINFO_SENTINEL,
};

static void t8030_add_cpregs(T8030CPUState *tcpu)
{
    ARMCPU *cpu = ARM_CPU(tcpu);
    define_arm_cp_regs(cpu, t8030_cp_reginfo_tcg);
    t8030cpu_init_gxf(tcpu);
}

static void t8030_cpu_realize(DeviceState *dev, Error **errp)
{
    T8030CPUState *tcpu = T8030_CPU(dev);
    T8030CPUClass *tclass = T8030_CPU_GET_CLASS(dev);
    DeviceState *fiq_or;
    Object *obj = OBJECT(dev);

    object_property_set_link(OBJECT(tcpu), "memory", OBJECT(&tcpu->memory),
                             &error_abort);
    t8030_add_cpregs(tcpu);
    tclass->parent_realize(dev, errp);
    if (*errp) {
        return;
    }
    t8030cpu_init_gxf_override(tcpu);
    fiq_or = qdev_new(TYPE_OR_IRQ);
    object_property_add_child(obj, "fiq-or", OBJECT(fiq_or));
    qdev_prop_set_uint16(fiq_or, "num-lines", 16);
    qdev_realize_and_unref(fiq_or, NULL, &error_fatal);
    qdev_connect_gpio_out(fiq_or, 0, qdev_get_gpio_in(dev, ARM_CPU_FIQ));

    qdev_connect_gpio_out(dev, GTIMER_VIRT, qdev_get_gpio_in(fiq_or, 0));
    tcpu->fast_ipi = qdev_get_gpio_in(fiq_or, 1);
}

static void t8030_cpu_reset(DeviceState *dev)
{
    T8030CPUState *tcpu = T8030_CPU(dev);
    T8030CPUClass *tclass = T8030_CPU_GET_CLASS(dev);
    tclass->parent_reset(dev);

    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_LSU_ERR_STS) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMC0) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMC1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMCR1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMSR) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_APCTL_EL1) = 2;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_KERNELKEYLO_EL1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_KERNELKEYHI_EL1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(AMX_STATUS_EL1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(AMX_CTL_EL1) = 0;
}

static void t8030_cpu_instance_init(Object *obj)
{
    object_property_set_uint(obj, "cntfrq", 24000000, &error_fatal);
}

T8030CPUState *t8030_cpu_create(DTBNode *node)
{
    DeviceState  *dev;
    T8030CPUState *tcpu;
    ARMCPU *cpu;
    Object *obj;
    DTBProp *prop;
    uint64_t mpidr;
    uint64_t freq;
    uint64_t *reg;

    obj = object_new(TYPE_T8030_CPU);
    dev = DEVICE(obj);
    tcpu = T8030_CPU(dev);
    cpu = ARM_CPU(tcpu);

    prop = find_dtb_prop(node, "name");
    dev->id = g_strdup((char *)prop->value);

    prop = find_dtb_prop(node, "cpu-id");
    assert(prop->length == 4);
    tcpu->cpu_id = *(unsigned int*)prop->value;

    prop = find_dtb_prop(node, "reg");
    assert(prop->length == 4);
    tcpu->phys_id = *(unsigned int*)prop->value;

    prop = find_dtb_prop(node, "cluster-id");
    assert(prop->length == 4);
    tcpu->cluster_id = *(unsigned int*)prop->value;

    mpidr = 0LL | tcpu->phys_id | (tcpu->phys_id << MPIDR_AFF2_SHIFT)
            | (1LL << 31);

    prop = find_dtb_prop(node, "cluster-type");
    switch (prop->value[0]) {
    case 'P':
        mpidr |= 1 << MPIDR_AFF2_SHIFT;
        break;
    default:
        break;
    }
    tcpu->mpidr = mpidr;
    object_property_set_uint(obj, "mp-affinity", mpidr, &error_fatal);
    cpu->midr = FIELD_DP64(cpu->midr, MIDR_EL1, PARTNUM, 0x12 + tcpu->cluster_id);
    cpu->midr = FIELD_DP64(cpu->midr, MIDR_EL1, VARIANT, 0x1);

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

    object_property_set_bool(obj, "has_el3", false, NULL);

    object_property_set_bool(obj, "has_el2", false, NULL);

    memory_region_init(&tcpu->memory, obj, "cpu-memory", UINT64_MAX);
    memory_region_init_alias(&tcpu->sysmem, obj, "sysmem", get_system_memory(),
                             0, UINT64_MAX);
    memory_region_add_subregion_overlap(&tcpu->memory, 0, &tcpu->sysmem, -2);

    prop = find_dtb_prop(node, "cpu-impl-reg");
    assert(prop);
    assert(prop->length == 16);

    reg = (uint64_t*)prop->value;

    memory_region_init_ram_device_ptr(&tcpu->impl_reg, obj,
                                      TYPE_T8030_CPU ".impl-reg",
                                      reg[1], g_malloc0(reg[1]));
    memory_region_add_subregion(get_system_memory(),
                                reg[0], &tcpu->impl_reg);

    prop = find_dtb_prop(node, "coresight-reg");
    assert(prop);
    assert(prop->length == 16);

    reg = (uint64_t*)prop->value;

    memory_region_init_ram_device_ptr(&tcpu->coresight_reg, obj,
                                      TYPE_T8030_CPU ".coresight-reg",
                                      reg[1], g_malloc0(reg[1]));
    memory_region_add_subregion(get_system_memory(),
                                reg[0], &tcpu->coresight_reg);

    prop = find_dtb_prop(node, "cpm-impl-reg");
    assert(prop->length == 16);
    memcpy(tcpu->cluster_reg, prop->value, 16);
    return tcpu;
}

static Property t8030_cpu_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static Property t8030_cpu_cluster_properties[] = {
    DEFINE_PROP_UINT8("cluster-id", T8030CPUCluster, id, 0),
    DEFINE_PROP_UINT8("cluster-type", T8030CPUCluster, type, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription vmstate_t8030_cpu = {
    .name = "t8030_cpu",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_T8030_CPREG(ARM64_REG_EHID4),
        VMSTATE_T8030_CPREG(ARM64_REG_EHID10),
        VMSTATE_T8030_CPREG(ARM64_REG_HID0),
        VMSTATE_T8030_CPREG(ARM64_REG_HID3),
        VMSTATE_T8030_CPREG(ARM64_REG_HID4),
        VMSTATE_T8030_CPREG(ARM64_REG_HID5),
        VMSTATE_T8030_CPREG(ARM64_REG_HID7),
        VMSTATE_T8030_CPREG(ARM64_REG_HID8),
        VMSTATE_T8030_CPREG(ARM64_REG_HID9),
        VMSTATE_T8030_CPREG(ARM64_REG_HID11),
        VMSTATE_T8030_CPREG(ARM64_REG_HID13),
        VMSTATE_T8030_CPREG(ARM64_REG_HID14),
        VMSTATE_T8030_CPREG(ARM64_REG_HID16),
        VMSTATE_T8030_CPREG(ARM64_REG_LSU_ERR_STS),
        VMSTATE_T8030_CPREG(PMC0),
        VMSTATE_T8030_CPREG(PMC1),
        VMSTATE_T8030_CPREG(PMCR1),
        VMSTATE_T8030_CPREG(PMSR),
        VMSTATE_T8030_CPREG(ARM64_REG_APCTL_EL1),
        VMSTATE_T8030_CPREG(ARM64_REG_KERNELKEYLO_EL1),
        VMSTATE_T8030_CPREG(ARM64_REG_KERNELKEYHI_EL1),
        VMSTATE_T8030_CPREG(S3_4_c15_c0_5),
        VMSTATE_T8030_CPREG(AMX_STATUS_EL1),
        VMSTATE_T8030_CPREG(AMX_CTL_EL1),
        VMSTATE_T8030_CPREG(ARM64_REG_CYC_OVRD),
        VMSTATE_T8030_CPREG(ARM64_REG_ACC_CFG),
        VMSTATE_T8030_CPREG(S3_5_c15_c10_1),
        VMSTATE_T8030_CPREG(UPMPCM),
        VMSTATE_T8030_CPREG(UPMCR0),
        VMSTATE_T8030_CPREG(UPMSR),
        VMSTATE_T8030_CPREG(ARM64_REG_CTRR_A_LWR_EL1),
        VMSTATE_T8030_CPREG(ARM64_REG_CTRR_A_UPR_EL1),
        VMSTATE_T8030_CPREG(ARM64_REG_CTRR_CTL_EL1),
        VMSTATE_T8030_CPREG(ARM64_REG_CTRR_LOCK_EL1),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_t8030_cpu_cluster = {
    .name = "t8030_cpu_cluster",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = t8030_cpu_cluster_pre_save,
    .post_load = t8030_cpu_cluster_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_2DARRAY(deferredIPI, T8030CPUCluster,
                               T8030_MAX_CPU, T8030_MAX_CPU),
        VMSTATE_UINT32_2DARRAY(noWakeIPI, T8030CPUCluster,
                               T8030_MAX_CPU, T8030_MAX_CPU),
        VMSTATE_UINT64(tick, T8030CPUCluster),
        VMSTATE_UINT64(ipi_cr, T8030CPUCluster),
        VMSTATE_END_OF_LIST()
    }
};

static void t8030_cpu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    T8030CPUClass *tc = T8030_CPU_CLASS(klass);

    device_class_set_parent_realize(dc, t8030_cpu_realize, &tc->parent_realize);
    device_class_set_parent_reset(dc, t8030_cpu_reset, &tc->parent_reset);
    dc->desc = "Apple T8030 CPU";
    dc->vmsd = &vmstate_t8030_cpu;
    set_bit(DEVICE_CATEGORY_CPU, dc->categories);
    device_class_set_props(dc, t8030_cpu_properties);
}

static void t8030_cpu_cluster_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = t8030_cpu_cluster_realize;
    dc->reset = t8030_cpu_cluster_reset;
    dc->desc = "Apple T8030 CPU Cluster";
    dc->user_creatable = false;
    dc->vmsd = &vmstate_t8030_cpu_cluster;
    device_class_set_props(dc, t8030_cpu_cluster_properties);
}

static const TypeInfo t8030_cpu_info = {
    .name = TYPE_T8030_CPU,
    .parent = ARM_CPU_TYPE_NAME("max"),
    .instance_size = sizeof(T8030CPUState),
    .instance_init = t8030_cpu_instance_init,
    .class_size = sizeof(T8030CPUClass),
    .class_init = t8030_cpu_class_init,
};

static const TypeInfo t8030_cpu_cluster_info = {
    .name = TYPE_T8030_CPU_CLUSTER,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(T8030CPUCluster),
    .instance_init = t8030_cpu_cluster_instance_init,
    .class_init = t8030_cpu_cluster_class_init,
};

static void t8030_cpu_register_types(void)
{
    type_register_static(&t8030_cpu_info);
    type_register_static(&t8030_cpu_cluster_info);
}

type_init(t8030_cpu_register_types);
