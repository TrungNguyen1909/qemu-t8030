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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "hw/arm/xnu.h"
#include "hw/loader.h"
#include "hw/arm/xnu_dtb.h"

static uint64_t align_4_high_num(uint64_t num)
{
    return (num + (4 - 1)) & ~(4 - 1);
}

static void *align_4_high_ptr(void *ptr)
{
    uint64_t num = align_4_high_num((uint64_t)ptr);
    return (void *)num;
}


static DTBProp *read_dtb_prop(uint8_t **dtb_blob)
{
    assert(dtb_blob && *dtb_blob);
    *dtb_blob = align_4_high_ptr(*dtb_blob);
    DTBProp *prop = g_new0(DTBProp, 1);
    memcpy(&prop->name[0], *dtb_blob, DTB_PROP_NAME_LEN);
    *dtb_blob += DTB_PROP_NAME_LEN;
    //zero out this flag which sometimes appears in the DT
    //normally done by iboot
    prop->length = *(uint32_t *)*dtb_blob & ~DT_PROP_FLAG_PLACEHOLDER;
    *dtb_blob += sizeof(uint32_t);
    if (0 != prop->length) {
        prop->value = g_malloc0(prop->length);
        assert(prop->value);
        memcpy(&prop->value[0], *dtb_blob, prop->length);
        *dtb_blob += prop->length;
    }

    return prop;
}

static void delete_prop(DTBProp *prop)
{
    if (NULL == prop) {
        return;
    }

    if (NULL != prop->value) {
        g_free(prop->value);
    }

    g_free(prop);
}

static DTBNode *read_dtb_node(uint8_t **dtb_blob)
{
    assert(dtb_blob && *dtb_blob);

    uint32_t i = 0;

    *dtb_blob = align_4_high_ptr(*dtb_blob);
    DTBNode *node = g_new0(DTBNode, 1);
    node->prop_count = *(uint32_t *)*dtb_blob;
    *dtb_blob += sizeof(uint32_t);
    node->child_node_count = *(uint32_t *)*dtb_blob;
    *dtb_blob += sizeof(uint32_t);

    assert(node->prop_count > 0);
    for (i = 0; i < node->prop_count; i++) {
        DTBProp *prop = read_dtb_prop(dtb_blob);
        node->props = g_list_append(node->props, prop);
    }
    for (i = 0; i < node->child_node_count; i++) {
        DTBNode *child = read_dtb_node(dtb_blob);
        node->child_nodes = g_list_append(node->child_nodes, child);
    }
    return node;
}

void delete_dtb_node(DTBNode *node)
{
    if (NULL == node) {
        return;
    }
    if (NULL != node->props) {
        g_list_free_full(node->props, (GDestroyNotify)delete_prop);
    }
    if (NULL != node->child_nodes) {
        g_list_free_full(node->child_nodes, (GDestroyNotify)delete_dtb_node);
    }
    g_free(node);
}

DTBNode *load_dtb(uint8_t *dtb_blob)
{
    DTBNode *root = read_dtb_node(&dtb_blob);
    return root;
}

static void save_prop(DTBProp *prop, uint8_t **buf)
{
    assert(prop && buf && *buf);

    *buf = align_4_high_ptr(*buf);
    memcpy(*buf, &prop->name[0], DTB_PROP_NAME_LEN);
    *buf += DTB_PROP_NAME_LEN;
    memcpy(*buf, &prop->length, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
    memcpy(*buf, prop->value, prop->length);
    *buf += prop->length;
}

static void save_node(DTBNode *node, uint8_t **buf)
{
    assert(node && buf && *buf);

    *buf = align_4_high_ptr(*buf);

    memcpy(*buf, &node->prop_count, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
    memcpy(*buf, &node->child_node_count, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
    g_list_foreach(node->props, (GFunc)save_prop, buf);
    g_list_foreach(node->child_nodes, (GFunc)save_node, buf);
}

void remove_dtb_node(DTBNode *parent, DTBNode *node)
{
    assert(parent && node);
    GList *iter;
    bool found = false;
    for (iter = parent->child_nodes; iter != NULL; iter = iter->next) {
        if (node == iter->data) {
            found = true;
            break;
        }
    }
    assert(found);
    delete_dtb_node(node);
    parent->child_nodes = g_list_delete_link(parent->child_nodes, iter);

    //sanity
    assert(parent->child_node_count > 0);

    parent->child_node_count--;
}
void remove_dtb_prop(DTBNode *node, DTBProp *prop)
{
    assert(node && prop);
    GList *iter;
    bool found = false;
    for (iter = node->props; iter != NULL; iter = iter->next) {
        if (prop == iter->data) {
            found = true;
            break;
        }
    }
    assert(found);
    delete_prop(prop);
    node->props = g_list_delete_link(node->props, iter);

    //sanity
    assert(node->prop_count > 0);

    node->prop_count--;
}

DTBProp *add_dtb_prop(DTBNode *n, const char *name, uint32_t size, uint8_t *val)
{
    assert(n && name && val);
    DTBProp *prop = g_new0(DTBProp, 1);
    memcpy(&prop->name[0], name, DTB_PROP_NAME_LEN);
    prop->length = size;
    prop->value = g_malloc0(size);
    memcpy(&prop->value[0], val, size);
    n->props = g_list_append(n->props, prop);
    n->prop_count++;
    return prop;
}
DTBNode *add_dtb_node(DTBNode *n, const char *name)
{
    assert(n && name);
    DTBNode *node = g_new0(DTBNode, 1);
    add_dtb_prop(node, "name", strlen(name) + 1, (uint8_t*)name);
    n->child_nodes = g_list_append(n->child_nodes, node);
    n->child_node_count ++;
    return node;
}

void save_dtb(uint8_t *buf, DTBNode *root)
{
    assert(buf && root);

    //TODO: handle cases where the buffer is not 4 bytes aligned
    //though this is never expected to happen and the code is simpler this
    //way
    assert(align_4_high_ptr(buf) == buf);

    save_node(root, &buf);
}

static uint64_t get_dtb_prop_size(DTBProp *prop)
{
    uint64_t size = 0;

    assert(prop);

    size = align_4_high_num(sizeof(prop->name) + sizeof(prop->length) +
                            prop->length);
    return size;
}

uint64_t get_dtb_node_buffer_size(DTBNode *node)
{
    uint64_t size = 0;
    DTBProp *prop = NULL;
    DTBNode *child = NULL;
    GList *iter = NULL;

    assert(node);

    size += sizeof(node->prop_count) + sizeof(node->child_node_count);

    for (iter = node->props; iter != NULL; iter = iter->next) {
        prop = (DTBProp *)iter->data;
        assert(prop);
        size += get_dtb_prop_size(prop);
    }
    for (iter = node->child_nodes; iter != NULL; iter = iter->next) {
        child = (DTBNode *)iter->data;
        assert(child);
        size += get_dtb_node_buffer_size(child);
    }
    return size;
}

DTBProp *get_dtb_prop(DTBNode *node, const char *name)
{
    assert(node && name);
    GList *iter = NULL;
    DTBProp *prop = NULL;

    for (iter = node->props; iter != NULL; iter = iter->next) {
        prop = (DTBProp *)iter->data;

        assert(prop);

        if (0 == strncmp((const char *)&prop->name[0], name,
                         DTB_PROP_NAME_LEN)) {
            return prop;
        }
    }
    return NULL;
}

DTBNode *get_dtb_child_node_by_name(DTBNode *node, const char *name)
{
    assert(node && name);

    GList *iter = NULL;
    DTBProp *prop = NULL;
    DTBNode *child = NULL;

    for (iter = node->child_nodes; iter != NULL; iter = iter->next) {
        child = (DTBNode *)iter->data;

        assert(child);

        prop = get_dtb_prop(child, "name");

        assert(prop);

        if (0 == strncmp((const char *)prop->value, name, prop->length)) {
            return child;
        }
    }
    return NULL;
}

void overwrite_dtb_prop_val(DTBProp *prop, uint8_t chr)
{
    uint64_t i = 0;
    uint8_t *ptr = prop->value;
    for (i = 0; i < prop->length; i++) {
        ptr[i] = chr;
    }
}

void overwrite_dtb_prop_name(DTBProp *prop, uint8_t chr)
{
    uint64_t i = 0;
    uint8_t *ptr = &prop->name[0];
    for (i = 0; i < DTB_PROP_NAME_LEN; i++) {
        ptr[i] = chr;
    }
}

void overwrite_dtb_prop(DTBNode *n, const char *name, uint32_t size, uint8_t *val){
    DTBProp* prop = get_dtb_prop(n, name);
    if (prop!=NULL){
        remove_dtb_prop(n, prop);
    }
    add_dtb_prop(n, name, size, val);
}