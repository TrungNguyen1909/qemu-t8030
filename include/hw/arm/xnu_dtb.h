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

#ifndef HW_ARM_XNU_DTB_H
#define HW_ARM_XNU_DTB_H

#include "qemu-common.h"

#define DT_PROP_FLAG_PLACEHOLDER (1 << 31)
#define DT_PROP_FLAGS_MASK		(0xf0000000)
#define DT_PROP_SIZE_MASK		(~DT_PROP_FLAGS_MASK)

#define DTB_PROP_NAME_LEN (32)

typedef struct {
    uint8_t name[DTB_PROP_NAME_LEN];
    uint32_t length;
    uint32_t flags;
    uint8_t *value;
} DTBProp;

typedef struct {
    uint32_t prop_count;
    uint32_t child_node_count;
    GList *props;
    GList *child_nodes;
} DTBNode;

DTBNode *load_dtb(uint8_t *dtb_blob);
void delete_dtb_node(DTBNode *node);
void save_dtb(uint8_t *buf, DTBNode *root);
bool remove_dtb_node_by_name(DTBNode *parent, char *name);
void remove_dtb_node(DTBNode *node, DTBNode *child);
void remove_dtb_prop(DTBNode *node, DTBProp *prop);
DTBProp *set_dtb_prop(DTBNode *n, const char *name, uint32_t size, uint8_t *val);
DTBNode *find_dtb_node(DTBNode *n, const char *name);
DTBNode *get_dtb_node(DTBNode *n, const char *name);
uint64_t get_dtb_node_buffer_size(DTBNode *node);
DTBProp *find_dtb_prop(DTBNode *node, const char *name);
void overwrite_dtb_prop_val(DTBProp *prop, uint8_t chr);
void overwrite_dtb_prop_name(DTBProp *prop, uint8_t chr);

#endif
