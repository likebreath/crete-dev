/*
 * kernel_api_resource_monitor.h
 *
 *  Created on: Jun 4, 2018
 *      Author: chenbo
 */

#ifndef LIB_INCLUDE_CRETE_KERNEL_API_RESOURCE_MONITOR_H_
#define LIB_INCLUDE_CRETE_KERNEL_API_RESOURCE_MONITOR_H_

static const char *CRETE_RESOURCE_MONITOR_PROCFS = "crete-resource-monitor-procfs";

#define CRETE_RESOURCE_MONITOR_ARRAY_SIZE 1024
#define CRETE_RESOUCE_MONITOR_NAME_SIZE 64

struct CRETE_RM_INFO
{
    const char *m_target_func;

    size_t m_value;
    size_t m_ret;

    size_t m_call_site;
    const char *m_call_site_module;
};

#endif /* LIB_INCLUDE_CRETE_KERNEL_API_RESOURCE_MONITOR_H_ */
