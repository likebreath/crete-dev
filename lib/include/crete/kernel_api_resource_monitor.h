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

enum CRETE_RM_ALLOC_FAILURE_TYPE
{
    RM_FT_NORMAL = 1,   // Failure with non-zero int return, e.g. 'int pci_enable_device(alloc_ptr)'
    RM_FT_NULL_PTR = 2, // Failure with NULL (zero) ptr return, e.g. 'void *__request_region(alloc_ptr)'
    RM_FT_VOID = 3, // Never fail: return void, e.g. 'void add_timer()'
};

#endif /* LIB_INCLUDE_CRETE_KERNEL_API_RESOURCE_MONITOR_H_ */
