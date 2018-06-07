#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "crete/kernel_api_resource_monitor.h"

//#define CRETE_DEBUG_RM

#ifdef CRETE_DEBUG_RM
#define CRETE_DBG_RM(x) do { x } while(0)
#else
#define CRETE_DBG_RM(x) do { } while(0)
#endif

enum CRETE_RM_ERROR
{
    RM_REPORT_BUG = 1,
    RM_DISABLED = 2,
    RM_MIS_PID = 3,
    RM_OUT_MODULE = 4,
    RM_SKIPPED = 5,
    RM_MUTEX_LOCKED = 6,
    RM_FATAL = 1989,
};

struct CRETE_RM_KPROBE_INFO
{
    size_t info_value;
};

// =======================================
// No mutex protection for read
static int crete_resource_monitor_enable = 1;

static inline int crete_resource_monitor_entry(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info);
static inline int crete_resource_monitor_alloc_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info, const int failure_type);
static inline int crete_resource_monitor_free_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, const char *info);

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(alloc_func, alloc_arg_index, ft)          \
        static int entry_handler_cl_##alloc_func(struct kretprobe_instance *ri,                     \
                struct pt_regs *regs)                                                               \
        {                                                                                           \
            if(alloc_arg_index != -1)                                                               \
            {                                                                                       \
                if(crete_resource_monitor_entry(ri, regs, alloc_arg_index, #alloc_func))            \
                {                                                                                   \
                    return 1;                                                                       \
                }                                                                                   \
            }                                                                                       \
            return 0;                                                                               \
        }                                                                                           \
        static int ret_handler_cl_##alloc_func(struct kretprobe_instance *ri, struct pt_regs *regs) \
        {                                                                                           \
            crete_resource_monitor_alloc_return(ri, regs, alloc_arg_index, #alloc_func, ft);        \
            return 0;                                                                               \
        }                                                                                           \
        static struct kretprobe rm_kretp_##alloc_func= {                                            \
                .kp.symbol_name = #alloc_func,                                                      \
                .entry_handler = entry_handler_cl_##alloc_func,                                     \
                .handler = ret_handler_cl_##alloc_func,                                             \
                .data_size = sizeof(struct CRETE_RM_KPROBE_INFO),                                   \
                .maxactive = NR_CPUS,                                                               \
        };

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(alloc_func, alloc_arg_index)                      \
        __CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(alloc_func, alloc_arg_index, RM_FT_NORMAL)

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(free_func, free_arg_index)                         \
        static int entry_handler_cl_##free_func(struct kretprobe_instance *ri, struct pt_regs *regs)\
        {                                                                                           \
            if(crete_resource_monitor_entry(ri, regs, free_arg_index, #free_func)) {                \
                return 1;                                                                           \
            }                                                                                       \
            return 0;                                                                               \
        }                                                                                           \
        static int ret_handler_cl_##free_func(struct kretprobe_instance *ri, struct pt_regs *regs)  \
        {                                                                                           \
            crete_resource_monitor_free_return(ri, regs, #free_func);                               \
            return 0;                                                                               \
        }                                                                                           \
        static struct kretprobe rm_kretp_##free_func= {                                             \
                .kp.symbol_name = #free_func,                                                       \
                .entry_handler = entry_handler_cl_##free_func,                                      \
                .handler = ret_handler_cl_##free_func,                                              \
                .data_size = sizeof(struct CRETE_RM_KPROBE_INFO),                                   \
                .maxactive = NR_CPUS,                                                               \
        };

#define __CRETE_REG_KPROBE_RM(func_name)                                                            \
        if(kallsyms_lookup_name(#func_name))                                                        \
        {                                                                                           \
            if(register_kretprobe(&rm_kretp_##func_name))                                           \
            {                                                                                       \
                printk(KERN_INFO "[CRETE ERROR]kprobe register failed for "#func_name"\n");         \
                return -1;                                                                          \
            }                                                                                       \
        } else {                                                                                    \
            printk(KERN_INFO "[CRETE ERROR] Can't find "#func_name" for kprobe.\n");                \
        }

#define __CRETE_UNREG_KPROBE_RM(func_name)                                              \
        if(kallsyms_lookup_name(#func_name))                                            \
        {                                                                               \
            unregister_kretprobe(&rm_kretp_##func_name);                                \
            if(rm_kretp_##func_name.nmissed != 0)                                       \
                printk(KERN_INFO "[CRETE INFO] Missed probing %d instances of %s.\n",   \
                    rm_kretp_##func_name.nmissed, rm_kretp_##func_name.kp.symbol_name); \
        }

__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(alloc_etherdev_mqs, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__alloc_workqueue_key, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(device_create_file, 1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(dma_pool_alloc, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(dma_pool_create, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(ioremap_nocache, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__kmalloc, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(led_classdev_register, 1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_enable_device, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_enable_device_mem, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_enable_msi_block, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_enable_msix, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_iomap, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_ioremap_bar, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_request_regions, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_request_selected_regions, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_request_selected_regions_exclusive, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_set_mwi, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pm_qos_add_request, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(register_netdev, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(request_threaded_irq, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(scsi_add_host_with_dma, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(scsi_host_alloc, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(vzalloc, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__alloc_pages_nodemask, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(__request_region, 0, RM_FT_NULL_PTR);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(kmem_cache_alloc_trace, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__alloc_ei_netdev, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__kmalloc_node, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(kmalloc_order_trace, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(kmem_cache_alloc, -1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(snd_dma_alloc_pages, 3);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(snd_pcm_lib_malloc_pages, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__pci_register_driver, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(snd_ac97_pcm_open, 0);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(snd_device_new, 0);   // xxx: called multiple time, and freed only once by snd_device_free
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(snd_card_proc_new, 0); // xxx: freed by snd_device_free()

//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(netif_napi_add, 1, RM_FT_VOID);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(add_timer, 0, RM_FT_VOID);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(mod_timer, 0);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__netdev_alloc_skb, -1);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__alloc_skb, -1);

__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(destroy_workqueue, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(device_remove_file, 1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(dma_pool_destroy, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(dma_pool_free, 1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(free_irq, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(free_netdev, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(iounmap, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(kfree, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(led_classdev_unregister, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_clear_mwi, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_disable_device, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_disable_msi, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_disable_msix, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_iounmap, 1);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_release_regions, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_release_selected_regions, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pm_qos_remove_request, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(scsi_host_put, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(scsi_remove_host, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(unregister_netdev, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(vfree, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(put_page, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(__release_region, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(__free_pages, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(snd_dma_free_pages, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(snd_pcm_lib_free_pages, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_unregister_driver, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(snd_ac97_pcm_close, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(snd_card_free, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(snd_device_free, 0);

//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(del_timer, 0);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(del_timer_sync, 0);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(consume_skb, 0);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(dev_kfree_skb_any, 0);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(dev_kfree_skb_irq, 0);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(kfree_skb, 0);

static inline int register_probes_crete_rm(void)
{
    __CRETE_REG_KPROBE_RM(alloc_etherdev_mqs);
    __CRETE_REG_KPROBE_RM(__alloc_workqueue_key);
    __CRETE_REG_KPROBE_RM(device_create_file);
    __CRETE_REG_KPROBE_RM(dma_pool_alloc);
    __CRETE_REG_KPROBE_RM(dma_pool_create);
    __CRETE_REG_KPROBE_RM(ioremap_nocache);
    __CRETE_REG_KPROBE_RM(__kmalloc);
    __CRETE_REG_KPROBE_RM(led_classdev_register);
    __CRETE_REG_KPROBE_RM(pci_enable_device);
    __CRETE_REG_KPROBE_RM(pci_enable_device_mem);
    __CRETE_REG_KPROBE_RM(pci_enable_msi_block);
    __CRETE_REG_KPROBE_RM(pci_enable_msix);
    __CRETE_REG_KPROBE_RM(pci_iomap);
    __CRETE_REG_KPROBE_RM(pci_ioremap_bar);
    __CRETE_REG_KPROBE_RM(pci_request_regions);
    __CRETE_REG_KPROBE_RM(pci_request_selected_regions);
    __CRETE_REG_KPROBE_RM(pci_request_selected_regions_exclusive);
    __CRETE_REG_KPROBE_RM(pci_set_mwi);
    __CRETE_REG_KPROBE_RM(pm_qos_add_request);
    __CRETE_REG_KPROBE_RM(register_netdev);
    __CRETE_REG_KPROBE_RM(request_threaded_irq);
    __CRETE_REG_KPROBE_RM(scsi_add_host_with_dma);
    __CRETE_REG_KPROBE_RM(scsi_host_alloc);
    __CRETE_REG_KPROBE_RM(vzalloc);
    __CRETE_REG_KPROBE_RM(__alloc_pages_nodemask);
    __CRETE_REG_KPROBE_RM(__request_region);
    __CRETE_REG_KPROBE_RM(kmem_cache_alloc_trace);
    __CRETE_REG_KPROBE_RM(__alloc_ei_netdev);
    __CRETE_REG_KPROBE_RM(__kmalloc_node);
    __CRETE_REG_KPROBE_RM(kmalloc_order_trace);
    __CRETE_REG_KPROBE_RM(kmem_cache_alloc);
    __CRETE_REG_KPROBE_RM(snd_dma_alloc_pages);
    __CRETE_REG_KPROBE_RM(snd_pcm_lib_malloc_pages);
    __CRETE_REG_KPROBE_RM(__pci_register_driver);
    __CRETE_REG_KPROBE_RM(snd_ac97_pcm_open);

    __CRETE_REG_KPROBE_RM(destroy_workqueue);
    __CRETE_REG_KPROBE_RM(device_remove_file);
    __CRETE_REG_KPROBE_RM(dma_pool_destroy);
    __CRETE_REG_KPROBE_RM(dma_pool_free);
    __CRETE_REG_KPROBE_RM(free_irq);
    __CRETE_REG_KPROBE_RM(free_netdev);
    __CRETE_REG_KPROBE_RM(iounmap);
    __CRETE_REG_KPROBE_RM(kfree);
    __CRETE_REG_KPROBE_RM(led_classdev_unregister);
    __CRETE_REG_KPROBE_RM(pci_clear_mwi);
    __CRETE_REG_KPROBE_RM(pci_disable_device);
    __CRETE_REG_KPROBE_RM(pci_disable_msi);
    __CRETE_REG_KPROBE_RM(pci_disable_msix);
    __CRETE_REG_KPROBE_RM(pci_iounmap);
    __CRETE_REG_KPROBE_RM(pci_release_regions);
    __CRETE_REG_KPROBE_RM(pci_release_selected_regions);
    __CRETE_REG_KPROBE_RM(pm_qos_remove_request);
    __CRETE_REG_KPROBE_RM(scsi_host_put);
    __CRETE_REG_KPROBE_RM(scsi_remove_host);
    __CRETE_REG_KPROBE_RM(unregister_netdev);
    __CRETE_REG_KPROBE_RM(vfree);
    __CRETE_REG_KPROBE_RM(put_page);
    __CRETE_REG_KPROBE_RM(__release_region);
    __CRETE_REG_KPROBE_RM(__free_pages);
    __CRETE_REG_KPROBE_RM(snd_dma_free_pages);
    __CRETE_REG_KPROBE_RM(snd_pcm_lib_free_pages);
    __CRETE_REG_KPROBE_RM(pci_unregister_driver);
    __CRETE_REG_KPROBE_RM(snd_ac97_pcm_close);
    __CRETE_REG_KPROBE_RM(snd_card_free);
    __CRETE_REG_KPROBE_RM(snd_device_free);

    return 0;
}

static inline void unregister_probes_crete_rm(void)
{
    __CRETE_UNREG_KPROBE_RM(alloc_etherdev_mqs);
    __CRETE_UNREG_KPROBE_RM(__alloc_workqueue_key);
    __CRETE_UNREG_KPROBE_RM(device_create_file);
    __CRETE_UNREG_KPROBE_RM(dma_pool_alloc);
    __CRETE_UNREG_KPROBE_RM(dma_pool_create);
    __CRETE_UNREG_KPROBE_RM(ioremap_nocache);
    __CRETE_UNREG_KPROBE_RM(__kmalloc);
    __CRETE_UNREG_KPROBE_RM(led_classdev_register);
    __CRETE_UNREG_KPROBE_RM(pci_enable_device);
    __CRETE_UNREG_KPROBE_RM(pci_enable_device_mem);
    __CRETE_UNREG_KPROBE_RM(pci_enable_msi_block);
    __CRETE_UNREG_KPROBE_RM(pci_enable_msix);
    __CRETE_UNREG_KPROBE_RM(pci_iomap);
    __CRETE_UNREG_KPROBE_RM(pci_ioremap_bar);
    __CRETE_UNREG_KPROBE_RM(pci_request_regions);
    __CRETE_UNREG_KPROBE_RM(pci_request_selected_regions);
    __CRETE_UNREG_KPROBE_RM(pci_request_selected_regions_exclusive);
    __CRETE_UNREG_KPROBE_RM(pci_set_mwi);
    __CRETE_UNREG_KPROBE_RM(pm_qos_add_request);
    __CRETE_UNREG_KPROBE_RM(register_netdev);
    __CRETE_UNREG_KPROBE_RM(request_threaded_irq);
    __CRETE_UNREG_KPROBE_RM(scsi_add_host_with_dma);
    __CRETE_UNREG_KPROBE_RM(scsi_host_alloc);
    __CRETE_UNREG_KPROBE_RM(vzalloc);
    __CRETE_UNREG_KPROBE_RM(__alloc_pages_nodemask);
    __CRETE_UNREG_KPROBE_RM(__request_region);
    __CRETE_UNREG_KPROBE_RM(kmem_cache_alloc_trace);
    __CRETE_UNREG_KPROBE_RM(__alloc_ei_netdev);
    __CRETE_UNREG_KPROBE_RM(__kmalloc_node);
    __CRETE_UNREG_KPROBE_RM(kmalloc_order_trace);
    __CRETE_UNREG_KPROBE_RM(kmem_cache_alloc);
    __CRETE_UNREG_KPROBE_RM(snd_dma_alloc_pages);
    __CRETE_UNREG_KPROBE_RM(snd_pcm_lib_malloc_pages);
    __CRETE_UNREG_KPROBE_RM(__pci_register_driver);
    __CRETE_UNREG_KPROBE_RM(snd_ac97_pcm_open);

    __CRETE_UNREG_KPROBE_RM(destroy_workqueue);
    __CRETE_UNREG_KPROBE_RM(device_remove_file);
    __CRETE_UNREG_KPROBE_RM(dma_pool_destroy);
    __CRETE_UNREG_KPROBE_RM(dma_pool_free);
    __CRETE_UNREG_KPROBE_RM(free_irq);
    __CRETE_UNREG_KPROBE_RM(free_netdev);
    __CRETE_UNREG_KPROBE_RM(iounmap);
    __CRETE_UNREG_KPROBE_RM(kfree);
    __CRETE_UNREG_KPROBE_RM(led_classdev_unregister);
    __CRETE_UNREG_KPROBE_RM(pci_clear_mwi);
    __CRETE_UNREG_KPROBE_RM(pci_disable_device);
    __CRETE_UNREG_KPROBE_RM(pci_disable_msi);
    __CRETE_UNREG_KPROBE_RM(pci_disable_msix);
    __CRETE_UNREG_KPROBE_RM(pci_iounmap);
    __CRETE_UNREG_KPROBE_RM(pci_release_regions);
    __CRETE_UNREG_KPROBE_RM(pci_release_selected_regions);
    __CRETE_UNREG_KPROBE_RM(pm_qos_remove_request);
    __CRETE_UNREG_KPROBE_RM(scsi_host_put);
    __CRETE_UNREG_KPROBE_RM(scsi_remove_host);
    __CRETE_UNREG_KPROBE_RM(unregister_netdev);
    __CRETE_UNREG_KPROBE_RM(vfree);
    __CRETE_UNREG_KPROBE_RM(put_page);
    __CRETE_UNREG_KPROBE_RM(__release_region);
    __CRETE_UNREG_KPROBE_RM(__free_pages);
    __CRETE_UNREG_KPROBE_RM(snd_dma_free_pages);
    __CRETE_UNREG_KPROBE_RM(snd_pcm_lib_free_pages);
    __CRETE_UNREG_KPROBE_RM(pci_unregister_driver);
    __CRETE_UNREG_KPROBE_RM(snd_ac97_pcm_close);
    __CRETE_UNREG_KPROBE_RM(snd_card_free);
    __CRETE_UNREG_KPROBE_RM(snd_device_free);
}

static inline void crete_resource_monitor_panic(void)
{
    printk(KERN_INFO  "[CRETE Warning] 'crete_resource_monitor_panic()' indicating a crete-rc error.\n");

    panic("[CRETE] panic on CRETE-RC error\n");
}

static inline int crete_resource_monitor_prelogue(size_t ret_addr,
        const struct TargetModuleInfo **target_module)
{
    if(!crete_resource_monitor_enable)
        return -RM_DISABLED;

    if(!_crete_get_current_target_pid)
    {
        printk(KERN_INFO  "[CRETE ERROR] '_crete_get_current_target_pid()' is not initialized.\n");

        crete_resource_monitor_panic();
        return -RM_FATAL;
    }

//    if(_crete_get_current_target_pid() != current->pid)
//        return -RM_MIS_PID;

    *target_module = find_target_module_info(ret_addr);
    if(!(*target_module))
    {
        return -RM_OUT_MODULE;
    }

    return 0;
}

static inline int crete_resource_monitor_entry(struct kretprobe_instance *ri, struct pt_regs *regs,
        int target_arg_indx, const char *info)
{
    struct CRETE_RM_KPROBE_INFO *my_data;

    if(!crete_resource_monitor_enable)
        return -RM_DISABLED;

    my_data = (struct CRETE_RM_KPROBE_INFO *)ri->data;

    switch(target_arg_indx)
    {
    case 0: // arg[0]
        my_data->info_value = regs->ax;
        break;
    case 1: // arg[1]
        my_data->info_value = regs->dx;
        break;
    case 2: // arg[2]
        my_data->info_value = regs->cx;
        break;
    case 3: // arg[3]
        my_data->info_value = regs_get_kernel_stack_nth(regs, 1);
        break;
    case 4: // arg[4]
        my_data->info_value = regs_get_kernel_stack_nth(regs, 2);
        break;
    default:
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_monitor_entry(): "
                "invalid target_arg_indx = %d [%s]!\n", target_arg_indx, info);

        crete_resource_monitor_panic();
        return -RM_FATAL;
        break;
    }

    return 0;
}

static inline int add_crete_rm_info(const char *target_func, size_t value, size_t ret,
        size_t call_site, const char *call_site_module);

static inline int crete_resource_monitor_alloc_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *target_func_name, const int failure_type)
{
    size_t alloc_value;
    size_t ret_value;
    size_t alloc_site;

    const struct TargetModuleInfo *target_module;
    int ret_prelogue = crete_resource_monitor_prelogue((size_t)ri->ret_addr, &target_module);
    if(ret_prelogue) return ret_prelogue;

    if(target_arg_indx == -1)
    {
        alloc_value = regs_return_value(regs);
    } else {
        alloc_value = ((struct CRETE_RM_KPROBE_INFO *)ri->data)->info_value;
    }

    ret_value = regs_return_value(regs);

#if defined(__USED_OLD_MODULE_LAYOUT)
    alloc_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.module_core;
#else
    alloc_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.core_layout.base;
#endif

    return add_crete_rm_info(target_func_name, alloc_value, ret_value, alloc_site, target_module->m_name);
}

static inline int crete_resource_monitor_free_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, const char *target_func_name)
{
    size_t free_value;
    size_t ret_value;
    size_t free_site;

    const struct TargetModuleInfo *target_module;
    int ret_prelogue = crete_resource_monitor_prelogue((size_t)ri->ret_addr, &target_module);
    if(ret_prelogue) return ret_prelogue;

    free_value = ((struct CRETE_RM_KPROBE_INFO *)ri->data)->info_value;
    ret_value = regs_return_value(regs);

#if defined(__USED_OLD_MODULE_LAYOUT)
    free_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.module_core;
#else
    free_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.core_layout.base;
#endif

    CRETE_DBG_RM(
    printk(KERN_INFO "[CRETE INFO] crete_rm_free() entered: free_value = %p, free_site = %p [%s].\n",
            (void *)free_value, (void *)free_site, target_func_name);
    );

    if(free_value == 0)
    {
        printk(KERN_INFO  "[CRETE Warning] 'crete_resource_monitor_free()': free_value == 0, free_site = %p [%s]\n",
                (void *)free_site, target_func_name);

        return 0;
    }

    return add_crete_rm_info(target_func_name, free_value, ret_value, free_site, target_module->m_name);
}

// =======================================
static int crete_rm_mutex_failed_count = 0; // not protected by MUTEX

static DEFINE_MUTEX(crete_rm_mutex);
static struct CRETE_RM_INFO crete_rm_info_array[CRETE_RESOURCE_MONITOR_ARRAY_SIZE];
static uint32_t crete_rm_info_count = 0;

static inline int add_crete_rm_info(const char *target_func, size_t value, size_t ret,
        size_t call_site, const char *call_site_module) {
    if(mutex_is_locked(&crete_rm_mutex))
    {
        ++crete_rm_mutex_failed_count;
        printk(KERN_INFO  "[CRETE INFO] add_crete_rm_info(): mutex is locked %d ['%s' in '%s']\n",
                crete_rm_mutex_failed_count, target_func, call_site_module);
        return -RM_MUTEX_LOCKED;
    }

    mutex_lock(&crete_rm_mutex);

    if(crete_rm_info_count >= CRETE_RESOURCE_MONITOR_ARRAY_SIZE)
    {
        printk(KERN_INFO  "[CRETE ERROR] add_crete_rm_info(): current_index = %u ['%s' in '%s']\n",
                crete_rm_info_count, target_func, call_site_module);

        mutex_unlock(&crete_rm_mutex);
        crete_resource_monitor_panic();
        return -RM_FATAL;
    }

    crete_rm_info_array[crete_rm_info_count].m_target_func = target_func;
    crete_rm_info_array[crete_rm_info_count].m_value = value ;
    crete_rm_info_array[crete_rm_info_count].m_ret = ret ;
    crete_rm_info_array[crete_rm_info_count].m_call_site = call_site ;
    crete_rm_info_array[crete_rm_info_count].m_call_site_module = call_site_module ;

    crete_rm_info_count++;

    mutex_unlock(&crete_rm_mutex);

    return 0;
}

static inline void crete_resource_monitor_start(void)
{
    if(mutex_is_locked(&crete_rm_mutex))
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_monitor_start(): mutex is locked %d\n",
                crete_rm_mutex_failed_count);
        crete_resource_monitor_panic();
        return;
    }

    CRETE_DBG_RM(
    printk(KERN_INFO "[CRETE DEBUG] crete_resource_monitor_start()\n");
    );

    mutex_lock(&crete_rm_mutex);

    crete_resource_monitor_enable = 1;
    crete_rm_mutex_failed_count = 0;

    memset(crete_rm_info_array, 0, sizeof(crete_rm_info_array));
    crete_rm_info_count = 0;

    mutex_unlock(&crete_rm_mutex);
}

static inline void crete_resource_monitor_finish(void)
{
    uint16_t i;

    if(mutex_is_locked(&crete_rm_mutex))
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_monitor_finish(): mutex is locked %d\n",
                crete_rm_mutex_failed_count);
        crete_resource_monitor_panic();
        return;
    }

    CRETE_DBG_RM(
    printk(KERN_INFO "[CRETE DEBUG] crete_resource_monitor_finish()\n");
    );

    mutex_lock(&crete_rm_mutex);

    crete_resource_monitor_enable = 0;

    CRETE_DBG_RM(
    for(i = 0; i < crete_rm_info_count; ++i)
    {
        printk(KERN_INFO "[%d] %s, value = %zu, ret = %zu, call_site = %zu (%s)\n",
                i, crete_rm_info_array[i].m_target_func,
                crete_rm_info_array[i].m_value,
                crete_rm_info_array[i].m_ret,
                crete_rm_info_array[i].m_call_site,
                crete_rm_info_array[i].m_call_site_module);
    }
    );

    mutex_unlock(&crete_rm_mutex);
}

// ----------------------------
static ssize_t crete_rm_fops_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{
    int i;
    int name_size;
    char __user *tmp_buf;
    unsigned long err_ret;

    if(size != ((sizeof(struct CRETE_RM_INFO) + CRETE_RESOUCE_MONITOR_NAME_SIZE*2)*CRETE_RESOURCE_MONITOR_ARRAY_SIZE))
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_rm_fops_write(): incorrect array size: size = %zu\n"
                "sizeof(struct CRETE_RM_INFO) = %zu, CRETE_RESOUCE_MONITOR_NAME_SIZE = %d, "
                "CRETE_RESOURCE_MONITOR_ARRAY_SIZE = %d\n", size,
                sizeof(struct CRETE_RM_INFO), CRETE_RESOUCE_MONITOR_NAME_SIZE,
                CRETE_RESOURCE_MONITOR_ARRAY_SIZE);
        return 0;
    }

    err_ret = copy_to_user(buf, crete_rm_info_array, sizeof(struct CRETE_RM_INFO)*crete_rm_info_count);
    if(err_ret) {
        printk(KERN_INFO  "[CRETE ERROR] crete_rm_fops_read(): copy_to_user(1) failed\n");
        return 0;
    }

    tmp_buf = buf + sizeof(struct CRETE_RM_INFO)*CRETE_RESOURCE_MONITOR_ARRAY_SIZE;
    for(i = 0; i < crete_rm_info_count; ++i)
    {
        name_size = strlen(crete_rm_info_array[i].m_target_func);
        if(name_size > CRETE_RESOUCE_MONITOR_NAME_SIZE)
        {
            printk(KERN_INFO  "[CRETE ERROR] crete_rm_fops_read(): name_size = %d (bigger than limit %d)\n",
                    name_size, CRETE_RESOUCE_MONITOR_NAME_SIZE);
            return 0;
        }
        err_ret = copy_to_user(tmp_buf, crete_rm_info_array[i].m_target_func, name_size);
        if(err_ret) {
            printk(KERN_INFO  "[CRETE ERROR] crete_rm_fops_read(): copy_to_user(2) failed\n");
            return 0;
        }

        tmp_buf += CRETE_RESOUCE_MONITOR_NAME_SIZE;
    }

    tmp_buf = buf + (sizeof(struct CRETE_RM_INFO) + CRETE_RESOUCE_MONITOR_NAME_SIZE)*CRETE_RESOURCE_MONITOR_ARRAY_SIZE;
    for(i = 0; i < crete_rm_info_count; ++i)
    {
        name_size = strlen(crete_rm_info_array[i].m_call_site_module);
        if(name_size > CRETE_RESOUCE_MONITOR_NAME_SIZE)
        {
            printk(KERN_INFO  "[CRETE ERROR] crete_rm_fops_read(): name_size = %d (bigger than limit %d)\n",
                    name_size, CRETE_RESOUCE_MONITOR_NAME_SIZE);
            return 0;
        }
        err_ret = copy_to_user(tmp_buf, crete_rm_info_array[i].m_call_site_module, name_size);
        if(err_ret) {
            printk(KERN_INFO  "[CRETE ERROR] crete_rm_fops_read(): copy_to_user(3) failed\n");
            return 0;
        }
        tmp_buf += CRETE_RESOUCE_MONITOR_NAME_SIZE;
    }

    return crete_rm_info_count;
}

static struct file_operations crete_rm_fops = {
        .owner = THIS_MODULE,
        .read =  crete_rm_fops_read,
};
