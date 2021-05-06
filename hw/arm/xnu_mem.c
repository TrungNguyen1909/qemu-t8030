/*
 * Copyright (c) 2019 Jonathan Afek <jonyafek@me.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/misc/unimp.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "hw/platform-bus.h"
#include "exec/memory.h"
#include "qemu-common.h"
#include "exec/hwaddr.h"
#include "hw/boards.h"
#include "hw/arm/boot.h"
#include "cpu.h"
#include "hw/arm/xnu_mem.h"

hwaddr g_virt_base, g_phys_base;

hwaddr vtop_bases(hwaddr va, hwaddr phys_base, hwaddr virt_base)
{
    if ((!virt_base) || (!phys_base)) {
        abort();
    }

    return va - virt_base + phys_base;
}

hwaddr ptov_bases(hwaddr pa, hwaddr phys_base, hwaddr virt_base)
{
    if ((!virt_base) || (!phys_base)) {
        abort();
    }

    return pa - phys_base + virt_base;
}

hwaddr vtop_static(hwaddr va)
{
    return vtop_bases(va, g_phys_base, g_virt_base);
}

hwaddr ptov_static(hwaddr pa)
{
    return ptov_bases(pa, g_phys_base, g_virt_base);
}

hwaddr vtop_mmu(hwaddr va, CPUState *cs)
{
    hwaddr phys_addr;
    MemTxAttrs attrs = {};

    phys_addr = arm_cpu_get_phys_page_attrs_debug(cs, va, &attrs);
    if (phys_addr == -1) {
        abort();
    }

    return phys_addr;
}

uint8_t get_highest_different_bit_index(hwaddr addr1, hwaddr addr2)
{
    if ((addr1 == addr2) || (0 == addr1) || (0 == addr2)) {
        abort();
    }

    return 64 - __builtin_clzll(addr1 ^ addr2);
}

hwaddr align_64k_low(hwaddr addr)
{
    return addr & ~0xffffull;
}

hwaddr align_64k_high(hwaddr addr)
{
    return (addr + 0xffffull) & ~0xffffull;
}

uint8_t get_lowest_non_zero_bit_index(hwaddr addr)
{
    if (!addr) {
        abort();
    }

    return __builtin_ctzll(addr);
}

hwaddr get_low_bits_mask_for_bit_index(uint8_t bit_index)
{
    if (bit_index >= 64) {
        abort();
    }

    return (1 << bit_index) - 1;
}

void allocate_ram(MemoryRegion *top, const char *name, hwaddr addr,
                  hwaddr size)
{
    MemoryRegion *sec = g_new(MemoryRegion, 1);
    memory_region_init_ram(sec, NULL, name, size, &error_fatal);
    memory_region_add_subregion(top, addr, sec);
}
