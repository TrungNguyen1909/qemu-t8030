#include "qemu/osdep.h"
#include "monitor/monitor.h"
#include "monitor/hmp-target.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-target.h"

void hmp_info_dart(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "DART is not available in this QEMU\n");
}
