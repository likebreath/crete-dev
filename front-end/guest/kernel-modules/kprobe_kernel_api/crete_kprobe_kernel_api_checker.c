#include <linux/mutex.h>

//#define CRETE_DEBUG_RC

#ifdef CRETE_DEBUG_RC
#define CRETE_DBG_RC(x) do { x } while(0)
#else
#define CRETE_DBG_RC(x) do { } while(0)
#endif

enum CRETE_RC_ERROR
{
    RC_REPORT_BUG = 1,
    RC_DISABLED = 2,
    RC_MIS_PID = 3,
    RC_OUT_MODULE = 4,
    RC_SKIPPED = 5,
    RC_MUTEX_LOCKED = 6,
    RC_FATAL = 1989,
};

enum CRETE_RC_ALLOC_FAILURE_TYPE
{
    RC_FT_NORMAL = 1,   // Failure with non-zero int return, e.g. 'int pci_enable_device(alloc_ptr)'
    RC_FT_NULL_PTR = 2, // Failure with NULL (zero) ptr return, e.g. 'void *__request_region(alloc_ptr)'
    RC_FT_VOID = 3, // Never fail: return void, e.g. 'void add_timer()'
};
struct CRETE_RC_ALLOC_INFO
{
    size_t alloc_value;
    size_t alloc_site;
};

struct CRETE_RC_INFO
{
    size_t info_value;
};

// =======================================
// No mutex protection for read
static int crete_resource_checker_enable = 1;

static inline int crete_resource_checker_alloc_entry(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info);
static inline int crete_resource_checker_free_entry(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info);
static inline int crete_resource_checker_alloc_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info, const int failure_type);
static inline int crete_resource_checker_free_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, const char *info);

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(alloc_func, alloc_arg_index, ft)          \
        static int entry_handler_cl_##alloc_func(struct kretprobe_instance *ri,                     \
                struct pt_regs *regs)                                                               \
        {                                                                                           \
            if(alloc_arg_index != -1)                                                               \
            {                                                                                       \
                if(crete_resource_checker_alloc_entry(ri, regs, alloc_arg_index, #alloc_func))      \
                {                                                                                   \
                    return 1;                                                                       \
                }                                                                                   \
            }                                                                                       \
            return 0;                                                                               \
        }                                                                                           \
        static int ret_handler_cl_##alloc_func(struct kretprobe_instance *ri, struct pt_regs *regs) \
        {                                                                                           \
            crete_resource_checker_alloc_return(ri, regs, alloc_arg_index, #alloc_func, ft);        \
            return 0;                                                                               \
        }                                                                                           \
        static struct kretprobe rc_kretp_##alloc_func= {                                            \
                .kp.symbol_name = #alloc_func,                                                      \
                .entry_handler = entry_handler_cl_##alloc_func,                                     \
                .handler = ret_handler_cl_##alloc_func,                                             \
                .data_size = sizeof(struct CRETE_RC_INFO),                                          \
                .maxactive = NR_CPUS,                                                               \
        };

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(alloc_func, alloc_arg_index)                      \
        __CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(alloc_func, alloc_arg_index, RC_FT_NORMAL)

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(free_func, free_arg_index)                         \
        static int entry_handler_cl_##free_func(struct kretprobe_instance *ri, struct pt_regs *regs)\
        {                                                                                           \
            if(crete_resource_checker_free_entry(ri, regs, free_arg_index, #free_func)) {           \
                return 1;                                                                           \
            }                                                                                       \
            return 0;                                                                               \
        }                                                                                           \
        static int ret_handler_cl_##free_func(struct kretprobe_instance *ri, struct pt_regs *regs)  \
        {                                                                                           \
            crete_resource_checker_free_return(ri, regs, #free_func);                               \
            return 0;                                                                               \
        }                                                                                           \
        static struct kretprobe rc_kretp_##free_func= {                                             \
                .kp.symbol_name = #free_func,                                                       \
                .entry_handler = entry_handler_cl_##free_func,                                      \
                .handler = ret_handler_cl_##free_func,                                              \
                .data_size = sizeof(struct CRETE_RC_INFO),                                          \
                .maxactive = NR_CPUS,                                                               \
        };

#define __CRETE_REG_KPROBE_RC(func_name)                                                            \
        if(kallsyms_lookup_name(#func_name))                                                        \
        {                                                                                           \
            if(register_kretprobe(&rc_kretp_##func_name))                                           \
            {                                                                                       \
                printk(KERN_INFO "[CRETE ERROR]kprobe register failed for "#func_name"\n");         \
                return -1;                                                                          \
            }                                                                                       \
        } else {                                                                                    \
            printk(KERN_INFO "[CRETE ERROR] Can't find "#func_name" for kprobe.\n");                \
        }

#define __CRETE_UNREG_KPROBE_RC(func_name)                                              \
        if(kallsyms_lookup_name(#func_name))                                            \
        {                                                                               \
            unregister_kretprobe(&rc_kretp_##func_name);                                \
            if(rc_kretp_##func_name.nmissed != 0)                                       \
                printk(KERN_INFO "[CRETE INFO] Missed probing %d instances of %s.\n",   \
                    rc_kretp_##func_name.nmissed, rc_kretp_##func_name.kp.symbol_name); \
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
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(__request_region, 0, RC_FT_NULL_PTR);
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

//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(netif_napi_add, 1, RC_FT_VOID);
//__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC_SPECIAL(add_timer, 0, RC_FT_VOID);
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

static inline int register_probes_crete_rc(void)
{
    __CRETE_REG_KPROBE_RC(alloc_etherdev_mqs);
    __CRETE_REG_KPROBE_RC(__alloc_workqueue_key);
    __CRETE_REG_KPROBE_RC(device_create_file);
    __CRETE_REG_KPROBE_RC(dma_pool_alloc);
    __CRETE_REG_KPROBE_RC(dma_pool_create);
    __CRETE_REG_KPROBE_RC(ioremap_nocache);
    __CRETE_REG_KPROBE_RC(__kmalloc);
    __CRETE_REG_KPROBE_RC(led_classdev_register);
    __CRETE_REG_KPROBE_RC(pci_enable_device);
    __CRETE_REG_KPROBE_RC(pci_enable_device_mem);
    __CRETE_REG_KPROBE_RC(pci_enable_msi_block);
    __CRETE_REG_KPROBE_RC(pci_enable_msix);
    __CRETE_REG_KPROBE_RC(pci_iomap);
    __CRETE_REG_KPROBE_RC(pci_ioremap_bar);
    __CRETE_REG_KPROBE_RC(pci_request_regions);
    __CRETE_REG_KPROBE_RC(pci_request_selected_regions);
    __CRETE_REG_KPROBE_RC(pci_request_selected_regions_exclusive);
    __CRETE_REG_KPROBE_RC(pci_set_mwi);
    __CRETE_REG_KPROBE_RC(pm_qos_add_request);
    __CRETE_REG_KPROBE_RC(register_netdev);
    __CRETE_REG_KPROBE_RC(request_threaded_irq);
    __CRETE_REG_KPROBE_RC(scsi_add_host_with_dma);
    __CRETE_REG_KPROBE_RC(scsi_host_alloc);
    __CRETE_REG_KPROBE_RC(vzalloc);
    __CRETE_REG_KPROBE_RC(__alloc_pages_nodemask);
    __CRETE_REG_KPROBE_RC(__request_region);
    __CRETE_REG_KPROBE_RC(kmem_cache_alloc_trace);
    __CRETE_REG_KPROBE_RC(__alloc_ei_netdev);
    __CRETE_REG_KPROBE_RC(__kmalloc_node);
    __CRETE_REG_KPROBE_RC(kmalloc_order_trace);
    __CRETE_REG_KPROBE_RC(kmem_cache_alloc);
    __CRETE_REG_KPROBE_RC(snd_dma_alloc_pages);
    __CRETE_REG_KPROBE_RC(snd_pcm_lib_malloc_pages);
    __CRETE_REG_KPROBE_RC(__pci_register_driver);
    __CRETE_REG_KPROBE_RC(snd_ac97_pcm_open);

    __CRETE_REG_KPROBE_RC(destroy_workqueue);
    __CRETE_REG_KPROBE_RC(device_remove_file);
    __CRETE_REG_KPROBE_RC(dma_pool_destroy);
    __CRETE_REG_KPROBE_RC(dma_pool_free);
    __CRETE_REG_KPROBE_RC(free_irq);
    __CRETE_REG_KPROBE_RC(free_netdev);
    __CRETE_REG_KPROBE_RC(iounmap);
    __CRETE_REG_KPROBE_RC(kfree);
    __CRETE_REG_KPROBE_RC(led_classdev_unregister);
    __CRETE_REG_KPROBE_RC(pci_clear_mwi);
    __CRETE_REG_KPROBE_RC(pci_disable_device);
    __CRETE_REG_KPROBE_RC(pci_disable_msi);
    __CRETE_REG_KPROBE_RC(pci_disable_msix);
    __CRETE_REG_KPROBE_RC(pci_iounmap);
    __CRETE_REG_KPROBE_RC(pci_release_regions);
    __CRETE_REG_KPROBE_RC(pci_release_selected_regions);
    __CRETE_REG_KPROBE_RC(pm_qos_remove_request);
    __CRETE_REG_KPROBE_RC(scsi_host_put);
    __CRETE_REG_KPROBE_RC(scsi_remove_host);
    __CRETE_REG_KPROBE_RC(unregister_netdev);
    __CRETE_REG_KPROBE_RC(vfree);
    __CRETE_REG_KPROBE_RC(put_page);
    __CRETE_REG_KPROBE_RC(__release_region);
    __CRETE_REG_KPROBE_RC(__free_pages);
    __CRETE_REG_KPROBE_RC(snd_dma_free_pages);
    __CRETE_REG_KPROBE_RC(snd_pcm_lib_free_pages);
    __CRETE_REG_KPROBE_RC(pci_unregister_driver);
    __CRETE_REG_KPROBE_RC(snd_ac97_pcm_close);
    __CRETE_REG_KPROBE_RC(snd_card_free);
    __CRETE_REG_KPROBE_RC(snd_device_free);

    return 0;
}

static inline void unregister_probes_crete_rc(void)
{
    __CRETE_UNREG_KPROBE_RC(alloc_etherdev_mqs);
    __CRETE_UNREG_KPROBE_RC(__alloc_workqueue_key);
    __CRETE_UNREG_KPROBE_RC(device_create_file);
    __CRETE_UNREG_KPROBE_RC(dma_pool_alloc);
    __CRETE_UNREG_KPROBE_RC(dma_pool_create);
    __CRETE_UNREG_KPROBE_RC(ioremap_nocache);
    __CRETE_UNREG_KPROBE_RC(__kmalloc);
    __CRETE_UNREG_KPROBE_RC(led_classdev_register);
    __CRETE_UNREG_KPROBE_RC(pci_enable_device);
    __CRETE_UNREG_KPROBE_RC(pci_enable_device_mem);
    __CRETE_UNREG_KPROBE_RC(pci_enable_msi_block);
    __CRETE_UNREG_KPROBE_RC(pci_enable_msix);
    __CRETE_UNREG_KPROBE_RC(pci_iomap);
    __CRETE_UNREG_KPROBE_RC(pci_ioremap_bar);
    __CRETE_UNREG_KPROBE_RC(pci_request_regions);
    __CRETE_UNREG_KPROBE_RC(pci_request_selected_regions);
    __CRETE_UNREG_KPROBE_RC(pci_request_selected_regions_exclusive);
    __CRETE_UNREG_KPROBE_RC(pci_set_mwi);
    __CRETE_UNREG_KPROBE_RC(pm_qos_add_request);
    __CRETE_UNREG_KPROBE_RC(register_netdev);
    __CRETE_UNREG_KPROBE_RC(request_threaded_irq);
    __CRETE_UNREG_KPROBE_RC(scsi_add_host_with_dma);
    __CRETE_UNREG_KPROBE_RC(scsi_host_alloc);
    __CRETE_UNREG_KPROBE_RC(vzalloc);
    __CRETE_UNREG_KPROBE_RC(__alloc_pages_nodemask);
    __CRETE_UNREG_KPROBE_RC(__request_region);
    __CRETE_UNREG_KPROBE_RC(kmem_cache_alloc_trace);
    __CRETE_UNREG_KPROBE_RC(__alloc_ei_netdev);
    __CRETE_UNREG_KPROBE_RC(__kmalloc_node);
    __CRETE_UNREG_KPROBE_RC(kmalloc_order_trace);
    __CRETE_UNREG_KPROBE_RC(kmem_cache_alloc);
    __CRETE_UNREG_KPROBE_RC(snd_dma_alloc_pages);
    __CRETE_UNREG_KPROBE_RC(snd_pcm_lib_malloc_pages);
    __CRETE_UNREG_KPROBE_RC(__pci_register_driver);
    __CRETE_UNREG_KPROBE_RC(snd_ac97_pcm_open);

    __CRETE_UNREG_KPROBE_RC(destroy_workqueue);
    __CRETE_UNREG_KPROBE_RC(device_remove_file);
    __CRETE_UNREG_KPROBE_RC(dma_pool_destroy);
    __CRETE_UNREG_KPROBE_RC(dma_pool_free);
    __CRETE_UNREG_KPROBE_RC(free_irq);
    __CRETE_UNREG_KPROBE_RC(free_netdev);
    __CRETE_UNREG_KPROBE_RC(iounmap);
    __CRETE_UNREG_KPROBE_RC(kfree);
    __CRETE_UNREG_KPROBE_RC(led_classdev_unregister);
    __CRETE_UNREG_KPROBE_RC(pci_clear_mwi);
    __CRETE_UNREG_KPROBE_RC(pci_disable_device);
    __CRETE_UNREG_KPROBE_RC(pci_disable_msi);
    __CRETE_UNREG_KPROBE_RC(pci_disable_msix);
    __CRETE_UNREG_KPROBE_RC(pci_iounmap);
    __CRETE_UNREG_KPROBE_RC(pci_release_regions);
    __CRETE_UNREG_KPROBE_RC(pci_release_selected_regions);
    __CRETE_UNREG_KPROBE_RC(pm_qos_remove_request);
    __CRETE_UNREG_KPROBE_RC(scsi_host_put);
    __CRETE_UNREG_KPROBE_RC(scsi_remove_host);
    __CRETE_UNREG_KPROBE_RC(unregister_netdev);
    __CRETE_UNREG_KPROBE_RC(vfree);
    __CRETE_UNREG_KPROBE_RC(put_page);
    __CRETE_UNREG_KPROBE_RC(__release_region);
    __CRETE_UNREG_KPROBE_RC(__free_pages);
    __CRETE_UNREG_KPROBE_RC(snd_dma_free_pages);
    __CRETE_UNREG_KPROBE_RC(snd_pcm_lib_free_pages);
    __CRETE_UNREG_KPROBE_RC(pci_unregister_driver);
    __CRETE_UNREG_KPROBE_RC(snd_ac97_pcm_close);
    __CRETE_UNREG_KPROBE_RC(snd_card_free);
    __CRETE_UNREG_KPROBE_RC(snd_device_free);
}

static inline void crete_resource_checker_panic(void)
{
    printk(KERN_INFO  "[CRETE Warning] 'crete_resource_checker_panic()' indicating a crete-rc error.\n");

    panic("[CRETE] panic on CRETE-RC error\n");
}

static inline int crete_resource_checker_prelogue(size_t ret_addr,
        const struct TargetModuleInfo **target_module)
{
    if(!crete_resource_checker_enable)
        return -RC_DISABLED;

    if(!_crete_get_current_target_pid)
    {
        printk(KERN_INFO  "[CRETE ERROR] '_crete_get_current_target_pid()' is not initialized.\n");

        crete_resource_checker_panic();
        return -RC_FATAL;
    }

//    if(_crete_get_current_target_pid() != current->pid)
//        return -RC_MIS_PID;

    *target_module = find_target_module_info(ret_addr);
    if(!(*target_module))
    {
        return -RC_OUT_MODULE;
    }

    return 0;
}

static inline int crete_resource_checker_alloc_entry(struct kretprobe_instance *ri, struct pt_regs *regs,
        int target_arg_indx, const char *info)
{
    struct CRETE_RC_INFO *my_data;

    if(!crete_resource_checker_enable)
        return -RC_DISABLED;

    if(target_arg_indx == -1)
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_alloc_entry(): "
                "target_arg_indx = %d (should not be -1)!\n", target_arg_indx);

        crete_resource_checker_panic();
        return -RC_FATAL;
    }

    my_data = (struct CRETE_RC_INFO *)ri->data;

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
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_alloc_entry(): "
                "invalid target_arg_indx = %d [%s]!\n", target_arg_indx, info);

        crete_resource_checker_panic();
        return -RC_FATAL;
        break;
    }

    return 0;
}

static inline int crete_resource_checker_free_entry(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info) {
    struct CRETE_RC_INFO *my_data;

    if(!crete_resource_checker_enable)
        return -RC_DISABLED;

    my_data = (struct CRETE_RC_INFO *)ri->data;

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
    default:
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_free_entry(): "
                "invalid target_arg_indx = %d [%s]!\n", target_arg_indx, info);

        crete_resource_checker_panic();
        return -RC_FATAL;
        break;
    }

    return 0;
}

static inline int crete_resource_checker_alloc_internal(size_t alloc_value, size_t alloc_site, const char *info);
static inline int crete_resource_checker_alloc_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info, const int failure_type)
{
    size_t alloc_value;
    size_t alloc_site;
    int ret_prelogue;
    const struct TargetModuleInfo *target_module;

    ret_prelogue = crete_resource_checker_prelogue((size_t)ri->ret_addr, &target_module);
    if(ret_prelogue) return ret_prelogue;

    if(target_arg_indx == -1)
    {
        alloc_value = regs_return_value(regs);
        if(alloc_value == 0)
        {
            printk(KERN_INFO  "[CRETE WARNING] crete_rc_alloc_return(): "
                    "skipping alloc_value = %p [%s] as its return value is 0 (indicating an alloc failure)]!\n",
                    (void *)alloc_value, info);
            return -RC_SKIPPED;
        }
    } else {
        alloc_value = ((struct CRETE_RC_INFO *)ri->data)->info_value;

        if( ((failure_type == RC_FT_NORMAL) && ((regs_return_value(regs) >> (sizeof(size_t)*8 - 1)) && 1)) ||
                ((failure_type == RC_FT_NULL_PTR) && (regs_return_value(regs) == 0)) )
        {
            printk(KERN_INFO  "[CRETE WARNING] crete_rc_alloc_return(): "
                    "alloc failure from '%s' with ret = %lu, skipping alloc_value = %p!\n",
                    info, regs_return_value(regs), (void *)alloc_value);
            return -RC_SKIPPED;
        } else if ((failure_type == RC_FT_NORMAL) && (regs_return_value(regs) != 0)) {
            printk(KERN_INFO  "[CRETE WARNING] crete_rc_alloc_return(): "
                    "alloc from '%s' with ret = %lu, alloc_value = %p!\n",
                    info, regs_return_value(regs), (void *)alloc_value);
        }
    }

#if defined(__USED_OLD_MODULE_LAYOUT)
    alloc_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.module_core;
#else
    alloc_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.core_layout.base;
#endif

    return crete_resource_checker_alloc_internal(alloc_value, alloc_site, info);
}

static inline int crete_resource_checker_free_internal(size_t free_value, size_t free_site, const char *info);
static inline int crete_resource_checker_free_return(struct kretprobe_instance *ri,
        struct pt_regs *regs, const char *info)
{
    size_t free_value;
    size_t free_site;
    const struct TargetModuleInfo *target_module;

    int ret_prelogue = crete_resource_checker_prelogue((size_t)ri->ret_addr, &target_module);
    if(ret_prelogue) return ret_prelogue;

    free_value = ((struct CRETE_RC_INFO *)ri->data)->info_value;

#if defined(__USED_OLD_MODULE_LAYOUT)
    free_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.module_core;
#else
    free_site = (unsigned long)ri->ret_addr - (unsigned long)target_module->m_mod.core_layout.base;
#endif

    CRETE_DBG_RC(
    printk(KERN_INFO "[CRETE INFO] crete_rc_free() entered: free_value = %p, free_site = %p [%s].\n",
            (void *)free_value, (void *)free_site, info);
    );

    if(free_value == 0)
    {
        printk(KERN_INFO  "[CRETE Warning] 'crete_resource_checker_free()': free_value == 0, free_site = %p [%s]\n",
                (void *)free_site, info);

        return 0;
    }

    return crete_resource_checker_free_internal(free_value, free_site, info);
}

// =======================================
#define CRETE_RESOURCE_CHECKER_ALLOC_LIST_SIZE 1024
static int cret_rc_mutex_failed_count = 0; // not protected by MUTEX

static DEFINE_MUTEX(crete_rc_mutex);
// TODO: XXX use a single array to hold alloc info
// 1. The good side is that this supports multiple free functions for multiple alloc functions, e.g. '__netdev_alloc_skb' related
// 2. The bad side is that this only matches free func with alloc func by values, which might be problematic, e.g.
//    pci_enable/disable_device() and pci_request/release_regions() takes same pointer input to alloc/free different memories

static struct CRETE_RC_ALLOC_INFO crete_rc_array[CRETE_RESOURCE_CHECKER_ALLOC_LIST_SIZE];
static uint16_t crete_rc_array_size = 0;
static int crete_rc_potential_bugs = 0;

static inline int crete_resource_checker_alloc_internal(size_t alloc_value, size_t alloc_site, const char *info)
{
    if(mutex_is_locked(&crete_rc_mutex))
    {
        ++cret_rc_mutex_failed_count;
        printk(KERN_INFO  "[CRETE INFO] crete_rc_alloc_inter(): mutex is locked %d [%s]\n",
                cret_rc_mutex_failed_count, info);
        return -RC_MUTEX_LOCKED;
    }

    mutex_lock(&crete_rc_mutex);

    CRETE_DBG_RC(
    printk(KERN_INFO  "[CRETE INFO] crete_rc_alloc(): current_index = %u, alloc_value = %p, alloc_site = %p [%s]\n",
            crete_rc_array_size, (void *)alloc_value, (void *)alloc_site, info);
    );

    if(crete_rc_array_size >= CRETE_RESOURCE_CHECKER_ALLOC_LIST_SIZE)
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_alloc_internal(): current_index = %u [%s]\n",
                crete_rc_array_size, info);

        crete_resource_checker_panic();
        mutex_unlock(&crete_rc_mutex);
        return -RC_FATAL;
    }

    crete_rc_array[crete_rc_array_size].alloc_value = alloc_value;
    crete_rc_array[crete_rc_array_size].alloc_site = alloc_site;
    ++crete_rc_array_size;

    mutex_unlock(&crete_rc_mutex);
    return 0;
}

static inline int crete_resource_checker_free_internal(size_t free_value, size_t free_site, const char *info)
{
    int i;

    if(mutex_is_locked(&crete_rc_mutex))
    {
        ++cret_rc_mutex_failed_count;
        printk(KERN_INFO  "[CRETE INFO] crete_rc_alloc_inter(): mutex is locked %d [%s]\n",
                cret_rc_mutex_failed_count, info);
        return -RC_MUTEX_LOCKED;
    }

    mutex_lock(&crete_rc_mutex);

    for(i = crete_rc_array_size; i > 0; --i)
    {
        if(crete_rc_array[i-1].alloc_value == free_value)
        {
            CRETE_DBG_RC(
            printk(KERN_INFO "[CRETE INFO] match found: ptr = %p, alloc_site = %p, free_site = %p [%s], current_index = %u.\n",
                    (void *)free_value, (void *)(crete_rc_array[i-1].alloc_site), (void *)free_site, info, crete_rc_array_size);
            );
            break;
        }
    }

    // No match found
    if(i == 0)
    {
        printk(KERN_INFO "[CRETE REPORT] Potential bug: double free, free_value = %p, free_site = %p [%s].\n",
                (void *)free_value, (void *)free_site, info);

//        ++crete_rc_potential_bugs;
        mutex_unlock(&crete_rc_mutex);
        return -RC_REPORT_BUG;
    }

    // Match found
    if(crete_rc_array[i -1].alloc_value != free_value)
    {
        printk(KERN_INFO  "[CRETE ERROR] inconsistent match with 'free_value'\n");

        crete_resource_checker_panic();
        mutex_unlock(&crete_rc_mutex);
        return -RC_FATAL;
    }

    // Remove matched from alloc_array
    for(;i < crete_rc_array_size; ++i)
    {
        crete_rc_array[i-1] = crete_rc_array[i];
    }
    crete_rc_array[i].alloc_site = 0;
    crete_rc_array[i].alloc_value = 0;

    --crete_rc_array_size;

    mutex_unlock(&crete_rc_mutex);
    return 0;
}

static inline void crete_resource_checker_start(void)
{
    if(mutex_is_locked(&crete_rc_mutex))
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_start(): mutex is locked %d\n",
                cret_rc_mutex_failed_count);
        crete_resource_checker_panic();
        return;
    }

    CRETE_DBG_RC(
    printk(KERN_INFO "[CRETE DEBUG] crete_resource_checker_start()\n");
    );

    mutex_lock(&crete_rc_mutex);

    crete_resource_checker_enable = 1;
    cret_rc_mutex_failed_count = 0;

    memset(crete_rc_array, 0, sizeof(crete_rc_array));
    crete_rc_array_size = 0;
    crete_rc_potential_bugs = 0;

    mutex_unlock(&crete_rc_mutex);
}

static inline void crete_resource_checker_finish(void)
{
    uint16_t i;

    if(mutex_is_locked(&crete_rc_mutex))
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_finish(): mutex is locked %d\n",
                cret_rc_mutex_failed_count);
        crete_resource_checker_panic();
        return;
    }

    CRETE_DBG_RC(
    printk(KERN_INFO "[CRETE DEBUG] crete_resource_checker_finish()\n");
    );

    mutex_lock(&crete_rc_mutex);

    for(i = 0; i < crete_rc_array_size; ++i)
    {
        printk(KERN_INFO "[CRETE REPORT] Potential bug: 'resource leak',"
                "alloc_site = %p, ptr = %p.\n",
                (void *)(crete_rc_array[i].alloc_site),
                (void *)(crete_rc_array[i].alloc_value));
        ++crete_rc_potential_bugs;
    }

    if(crete_rc_potential_bugs != 0)
    {
        panic("[CRETE RC] panic on potential bugs: %d, cret_rc_mutex_failed_count = %d\n",
                crete_rc_potential_bugs, cret_rc_mutex_failed_count);
    }

    crete_resource_checker_enable = 0;

    mutex_unlock(&crete_rc_mutex);
}