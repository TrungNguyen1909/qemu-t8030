/*
 *
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

#ifndef HW_ARM_XNU_MEM_H
#define HW_ARM_XNU_MEM_H

#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "target/arm/cpu.h"

extern hwaddr g_virt_base;
extern hwaddr g_phys_base;
extern hwaddr g_phys_slide;
extern hwaddr g_virt_slide;

hwaddr vtop_static(hwaddr va);
hwaddr ptov_static(hwaddr pa);
hwaddr vtop_mmu(hwaddr va, CPUState *cs);

hwaddr align_64k_low(hwaddr addr);
hwaddr align_64k_high(hwaddr addr);

hwaddr vtop_bases(hwaddr va, hwaddr phys_base, hwaddr virt_base);
hwaddr ptov_bases(hwaddr pa, hwaddr phys_base, hwaddr virt_base);

uint8_t get_highest_different_bit_index(hwaddr addr1, hwaddr addr2);
uint8_t get_lowest_non_zero_bit_index(hwaddr addr);
hwaddr get_low_bits_mask_for_bit_index(uint8_t bit_index);

void allocate_ram(MemoryRegion *top, const char *name, hwaddr addr,
                  hwaddr size);
#endif
