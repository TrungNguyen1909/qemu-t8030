#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "target/arm/cpu.h"
#include "target/arm/internals.h"
#include "t8030_gxf.h"
#include "exec/exec-all.h"

CPAccessResult access_tvm_trvm(CPUARMState *env, const ARMCPRegInfo *ri,
                               bool isread);

static uint64_t raw_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    assert(ri->fieldoffset);
    if (cpreg_field_is_64bit(ri)) {
        return CPREG_FIELD64(env, ri);
    } else {
        return CPREG_FIELD32(env, ri);
    }
}

static void raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                      uint64_t value)
{
    assert(ri->fieldoffset);
    if (cpreg_field_is_64bit(ri)) {
        CPREG_FIELD64(env, ri) = value;
    } else {
        CPREG_FIELD32(env, ri) = value;
    }
}

static CPAccessResult access_gxf(CPUARMState *env, const ARMCPRegInfo *ri,
                                 bool isread)
{
    if (arm_is_guarded(env)) {
        return CP_ACCESS_OK;
    }
    return CP_ACCESS_TRAP;
}

static uint64_t tpidr_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_is_guarded(env)) {
        return env->gxf.tpidr_gl[1];
    } else {
        return env->cp15.tpidr_el[1];
    }
}

static void tpidr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_is_guarded(env)) {
        env->gxf.tpidr_gl[1] = value;
    } else {
        env->cp15.tpidr_el[1] = value;
    }
}

static uint64_t vbar_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_is_guarded(env)) {
        return env->gxf.vbar_gl[1];
    } else {
        return raw_read(env, ri);
    }
}

static void vbar_el1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_is_guarded(env)) {
        env->gxf.vbar_gl[1] = value & ~0x1FULL;
    } else {
        if (!arm_is_guarded(env) && env->cp15.vmsa_lock_el1 & VMSA_LOCK_VBAR_EL1) {
            return;
        }

        raw_write(env, ri, value & ~0x1FULL);
    }
}

static uint64_t spsr_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_is_guarded(env)) {
        return env->gxf.spsr_gl[1];
    } else {
        return env->banked_spsr[BANK_SVC];
    }
}

static void spsr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_is_guarded(env)) {
        env->gxf.spsr_gl[1] = value;
    } else {
        env->banked_spsr[BANK_SVC] = value;
    }
}

static uint64_t elr_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_is_guarded(env)) {
        return env->gxf.elr_gl[1];
    } else {
        return env->elr_el[1];
    }
}

static void elr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_is_guarded(env)) {
        env->gxf.elr_gl[1] = value;
    } else {
        env->elr_el[1] = value;
    }
}

static uint64_t esr_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_is_guarded(env)) {
        return env->gxf.esr_gl[1];
    } else {
        return env->cp15.esr_el[1];
    }
}

static void esr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_is_guarded(env)) {
        env->gxf.esr_gl[1] = value;
    } else {
        env->cp15.esr_el[1] = value;
    }
}

static uint64_t far_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_is_guarded(env)) {
        return env->gxf.far_gl[1];
    } else {
        return env->cp15.far_el[1];
    }
}

static void far_el1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_is_guarded(env)) {
        env->gxf.far_gl[1] = value;
    } else {
        env->cp15.far_el[1] = value;
    }
}

static void sprr_perm_el0_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    uint64_t perm = raw_read(env, ri);
    uint32_t mask = env->sprr.sprr_umask;
    if (arm_current_el(env)) {
        raw_write(env, ri, value);
        return;
    }
    
    for (int i = 0; i < 16; i++) {
        uint32_t umask = SPRR_MASK_EXTRACT_IDX_ATTR(mask, i);
        uint64_t requested_perm = APRR_EXTRACT_IDX_ATTR(value, i); 
        uint64_t orig_perm = APRR_EXTRACT_IDX_ATTR(perm, i);
        uint64_t changed_perm = ((requested_perm ^ orig_perm) & umask);
        uint64_t result_perm = orig_perm;
        /* Only change bits that are set in mask */

        result_perm &= ~changed_perm;
        result_perm |= requested_perm & changed_perm;
        
        perm &= ~(APRR_ATTR_MASK << APRR_SHIFT_FOR_IDX(i));
        perm |= result_perm << APRR_SHIFT_FOR_IDX(i);
    }

    raw_write(env, ri, perm);

    tlb_flush(env_cpu(env));
}

static void sprr_write_flush(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    raw_write(env, ri, value);

    tlb_flush(env_cpu(env));
}

static const ARMCPRegInfo t8030gxf_cp_reginfo[] = {
    { .name = "TPIDR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .opc2 = 4, .crn = 13, .crm = 0,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = tpidr_el1_read, .writefn = tpidr_el1_write,
      .resetvalue = 0 },
    { .name = "VBAR", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .crn = 12, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = vbar_el1_read, .writefn = vbar_el1_write,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.vbar_s),
                             offsetof(CPUARMState, cp15.vbar_ns) },
      .resetvalue = 0 },
    { .name = "SPSR_EL1", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS | ARM_CP_OVERRIDE,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 0, .opc2 = 0,
      .access = PL1_RW,
      .readfn = spsr_el1_read, .writefn = spsr_el1_write },
    { .name = "ELR_EL1", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS | ARM_CP_OVERRIDE,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 0, .opc2 = 1,
      .access = PL1_RW,
      .readfn = elr_el1_read, .writefn = elr_el1_write },
    { .name = "ESR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .crn = 5, .crm = 2, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .accessfn = access_tvm_trvm,
      .readfn = esr_el1_read, .writefn = esr_el1_write,
      .resetvalue = 0, },
    { .name = "FAR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .crn = 6, .crm = 0, .opc1 = 0, .opc2 = 0,
      .type = ARM_CP_OVERRIDE,
      .access = PL1_RW, .accessfn = access_tvm_trvm,
      .readfn = far_el1_read, .writefn = far_el1_write,
      .resetvalue = 0, },
    { .name = "GXF_CONFIG_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 1, .opc2 = 2,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, gxf.gxf_config_el[1]) },
    { .name = "GXF_STATUS_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 8, .opc2 = 0,
      .access = PL1_R, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, gxf.gxf_status_el[1]) },
    { .name = "GXF_ENTER_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 8, .opc2 = 1,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, gxf.gxf_enter_el[1]) },
    { .name = "GXF_ABORT_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 8, .opc2 = 2,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, gxf.gxf_abort_el[1]) },
    { .name = "ASPSR_GL11",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 8, .opc2 = 3,
      .access = PL1_RW, .accessfn = access_gxf, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, gxf.aspsr_gl[1]) },
    { .name = "TPIDR_GL11",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 1,
      .access = PL1_RW, .accessfn = access_gxf,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.tpidr_el[1]) },
    { .name = "VBAR_GL11",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_gxf,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.vbar_el[1]) },
    { .name = "SPSR_GL11",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 3,
      .access = PL1_RW, .accessfn = access_gxf,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_SVC]) },
    { .name = "ESR_GL11",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 5,
      .access = PL1_RW, .accessfn = access_gxf,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.esr_el[1]) },
    { .name = "ELR_GL11",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 6,
      .access = PL1_RW, .accessfn = access_gxf,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, elr_el[1]) },
    { .name = "FAR_GL11",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 7,
      .access = PL1_RW, .accessfn = access_gxf,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.far_el[1]) },
      //TODO: Implement lockdown for these registers to prevent unexpected changes
    { .name = "SPRR_CONFIG_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 1, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0,
      .readfn = raw_read, .writefn = sprr_write_flush,
      .fieldoffset = offsetof(CPUARMState, sprr.sprr_config_el[1]) },
    { .name = "SPRR_CONFIG_EL0",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 1, .opc2 = 1,
      .access = PL1_RW, .resetvalue = 0,
      .readfn = raw_read, .writefn = sprr_write_flush,
      .fieldoffset = offsetof(CPUARMState, sprr.sprr_config_el[0]) },
    { .name = "SPRR_PERM_EL0",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 1, .opc2 = 5,
      .access = PL0_RW, .resetvalue = 0,
      .readfn = raw_read,
      .writefn = sprr_perm_el0_write,
      .fieldoffset = offsetof(CPUARMState, sprr.sprr_perm_el[0]) },
    { .name = "SPRR_UNK_EL0",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 1, .opc2 = 6,
      .access = PL1_RW | PL0_R, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, sprr.sprr_unk_el[0]) },
    { .name = "SPRR_UNK_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 1, .opc2 = 7,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, sprr.sprr_unk_el[1]) },
    { .name = "SPRR_PERM_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 3, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0,
      .readfn = raw_read, .writefn = sprr_write_flush,
      .fieldoffset = offsetof(CPUARMState, sprr.sprr_perm_el[1]) },
    { .name = "SPRR_UMASK_EL1",
      .cp = CP_REG_ARM64_SYSREG_CP, .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 3, .opc2 = 1,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, sprr.sprr_umask) },
      REGINFO_SENTINEL,
};

void t8030cpu_init_gxf(ARMCPU *cpu)
{
    define_arm_cp_regs(cpu, t8030gxf_cp_reginfo);
}
