/*
 * QEMU SPMI bus interface.
 *
 * Copyright (c) 2021 Trung Nguyen Hoang.
 * Based on hw/i2c/core.c
 *
 * This code is licensed under the LGPL.
 */

#include "qemu/osdep.h"
#include "hw/spmi/spmi.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "trace.h"

static Property spmi_props[] = {
    DEFINE_PROP_UINT8("sid", struct SPMISlave, sid, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static const TypeInfo spmi_bus_info = {
    .name = TYPE_SPMI_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(SPMIBus),
};

static int spmi_bus_pre_save(void *opaque)
{
    SPMIBus *bus = opaque;

    bus->saved_sid = -1;
    if (bus->current_dev) {
        bus->saved_sid = bus->current_dev->sid;
    }

    return 0;
}

static const VMStateDescription vmstate_spmi_bus = {
    .name = "spmi_bus",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = spmi_bus_pre_save,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8(saved_sid, SPMIBus),
        VMSTATE_END_OF_LIST()
    }
};

/* Create a new SPMI bus.  */
SPMIBus *spmi_init_bus(DeviceState *parent, const char *name)
{
    SPMIBus *bus;

    bus = SPMI_BUS(qbus_new(TYPE_SPMI_BUS, parent, name));
    vmstate_register(NULL, VMSTATE_INSTANCE_ID_ANY, &vmstate_spmi_bus, bus);
    return bus;
}

void spmi_set_slave_sid(SPMISlave *dev, uint8_t sid)
{
    dev->sid = sid;
}

/* Return nonzero if bus is busy.  */
int spmi_bus_busy(SPMIBus *bus)
{
    return bus->current_dev != NULL;
}

/* TODO: Make this handle multiple masters.  */
/*
 * Start or continue an spmi transaction.  When this is called for the
 * first time or after an spmi_end_transfer(), if it returns an error
 * the bus transaction is terminated (or really never started).  If
 * this is called after another spmi_start_transfer() without an
 * intervening spmi_end_transfer(), and it returns an error, the
 * transaction will not be terminated.  The caller must do it.
 */
int spmi_start_transfer(SPMIBus *bus, uint8_t sid, uint8_t opcode,
                        uint16_t address)
{
    BusChild *kid;
    SPMISlaveClass *sc;
    bool bus_scanned = false;

    /*
     * If there are already devices in the list, that means we are in
     * the middle of a transaction and we shouldn't rescan the bus.
     */
    if (!bus->current_dev) {
        QTAILQ_FOREACH(kid, &bus->qbus.children, sibling) {
            DeviceState *qdev = kid->child;
            SPMISlave *candidate = SPMI_SLAVE(qdev);
            if (candidate->sid == sid) {
                bus->current_dev = candidate;
            }
        }
        bus_scanned = true;
    }

    if (!bus->current_dev) {
        return 1;
    }

    SPMISlave *s = bus->current_dev;
    int rv;

    sc = SPMI_SLAVE_GET_CLASS(s);
    /*
     * If the bus is already busy, assume this is a repeated
     * start condition.
     */

    if (sc->command) {
        rv = sc->command(s, opcode, address);
        trace_spmi_command(s->sid, opcode, address);
        if (rv) {
            if (bus_scanned) {
                /* First call, terminate the transfer. */
                spmi_end_transfer(bus);
            }
            return rv;
        }
    }
    return 0;
}

void spmi_end_transfer(SPMIBus *bus)
{
    SPMISlaveClass *sc;
    if (bus->current_dev) {
        SPMISlave *s = bus->current_dev;
        sc = SPMI_SLAVE_GET_CLASS(s);
        if (sc->finish) {
            trace_spmi_finish(s->sid);
            sc->finish(s);
        }
    }
}

int spmi_send_recv(SPMIBus *bus, uint8_t *data, uint8_t len, bool send)
{
    SPMISlaveClass *sc;
    SPMISlave *s;
    int ret = 0;

    if (send) {
        if (bus->current_dev) {
            s = bus->current_dev;
            sc = SPMI_SLAVE_GET_CLASS(s);
            if (sc->send) {
                ret = sc->send(s, data, len);
                trace_spmi_send(s->sid, len);
            } else {
                ret = -1;
            }
        }
    } else {
        if (bus->current_dev) {
            s = bus->current_dev;
            sc = SPMI_SLAVE_GET_CLASS(s);
            if (sc->recv) {
                ret = sc->recv(s, data, len);
                trace_spmi_recv(s->sid, len);
            } else {
                ret = -1;
            }
        }
    }
    return ret;
}

int spmi_send(SPMIBus *bus, uint8_t *data, uint8_t len)
{
    return spmi_send_recv(bus, data, len, true);
}

int spmi_recv(SPMIBus *bus, uint8_t *data, uint8_t len)
{
    return spmi_send_recv(bus, data, len, false);
}

static int spmi_slave_post_load(void *opaque, int version_id)
{
    SPMISlave *dev = opaque;
    SPMIBus *bus;

    bus = SPMI_BUS(qdev_get_parent_bus(DEVICE(dev)));
    if (bus->saved_sid == dev->sid) {
        bus->current_dev = dev;
    }
    return 0;
}

const VMStateDescription vmstate_spmi_slave = {
    .name = "SPMISlave",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = spmi_slave_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8(sid, SPMISlave),
        VMSTATE_END_OF_LIST()
    }
};

SPMISlave *spmi_slave_new(const char *name, uint8_t sid)
{
    DeviceState *dev;

    dev = qdev_new(name);
    qdev_prop_set_uint8(dev, "sid", sid);
    return SPMI_SLAVE(dev);
}

bool spmi_slave_realize_and_unref(SPMISlave *dev, SPMIBus *bus, Error **errp)
{
    return qdev_realize_and_unref(&dev->qdev, &bus->qbus, errp);
}

SPMISlave *spmi_slave_create_simple(SPMIBus *bus, const char *name, uint8_t sid)
{
    SPMISlave *dev = spmi_slave_new(name, sid);

    spmi_slave_realize_and_unref(dev, bus, &error_abort);

    return dev;
}

static void spmi_slave_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *k = DEVICE_CLASS(klass);
    set_bit(DEVICE_CATEGORY_MISC, k->categories);
    k->bus_type = TYPE_SPMI_BUS;
    device_class_set_props(k, spmi_props);
}

static const TypeInfo spmi_slave_type_info = {
    .name = TYPE_SPMI_SLAVE,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(SPMISlave),
    .abstract = true,
    .class_size = sizeof(SPMISlaveClass),
    .class_init = spmi_slave_class_init,
};

static void spmi_slave_register_types(void)
{
    type_register_static(&spmi_bus_info);
    type_register_static(&spmi_slave_type_info);
}

type_init(spmi_slave_register_types)
