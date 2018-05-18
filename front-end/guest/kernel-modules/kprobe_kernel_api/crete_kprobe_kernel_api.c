#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bo Chen (chenbo@pdx.edu)");
MODULE_DESCRIPTION("CRETE probes for kernel API functions to inject concolic values");

//#define CRETE_ENABLE_DEBUG
#define CRETE_ENABLE_RESOURCE_CHECKER

#ifdef CRETE_ENABLE_DEBUG
#define CRETE_DBG(x) do { x } while(0)
#else
#define CRETE_DBG(x) do { } while(0)
#endif

#ifdef CRETE_ENABLE_RESOURCE_CHECKER
#define CRETE_RC(x) do { x } while(0)
#else
#define CRETE_RC(x) do { } while(0)
#endif

#if defined(CRETE_USED_OLD_MODULE_LAYOUT)
#define __USED_OLD_MODULE_LAYOUT
#endif
static char crete_ksym_symbol[KSYM_SYMBOL_LEN*2];

struct TargetModuleInfo
{
    size_t m_name_size;
    char *m_name;
    int   m_mod_loaded;
    struct module m_mod;
};

static struct TargetModuleInfo target_module = {
        .m_name_size = 0,
        .m_name = "",
        .m_mod_loaded = 0,
};

module_param_named(target_module, target_module.m_name, charp, 0);
MODULE_PARM_DESC(target_module, "The name of target module to enable probe on kernel APIs");

static void (*_crete_make_concolic)(void*, size_t, const char *);
static void (*_crete_kernel_oops)(void);

static bool target_module_probes = false;
static void (*_crete_register_probes_target_module)(void);
static void (*_crete_unregister_probes_target_module)(void);

static int entry_handler_default(struct kretprobe_instance *ri, struct pt_regs *regs);
static int ret_handler_make_concolic(struct kretprobe_instance *ri, struct pt_regs *regs);

#ifdef CRETE_ENABLE_RESOURCE_CHECKER
static uint32_t (*_crete_get_current_target_pid)(void);
#include "crete_kprobe_kernel_api_checker.c"
#endif

#define __CRETE_DEF_KPROBE(func_name)                                                              \
        static int entry_handler_##func_name(struct kretprobe_instance *ri, struct pt_regs *regs); \
        static int ret_handler_##func_name(struct kretprobe_instance *ri, struct pt_regs *regs);   \
        static struct kretprobe kretp_##func_name = {                                              \
                .kp.symbol_name = #func_name,                                                      \
                .entry_handler = entry_handler_##func_name,                                        \
                .handler = ret_handler_##func_name,                                                \
        };

#define __CRETE_DEF_KPROBE_RET_CONCOLIC(func_name)                                                 \
        static struct kretprobe kretp_##func_name = {                                              \
                .kp.symbol_name = #func_name,                                                      \
                .handler = ret_handler_make_concolic,                                              \
                .entry_handler = entry_handler_default,                                            \
        };

#define __CRETE_REG_KPROBE(func_name)                                          \
        if(kallsyms_lookup_name(#func_name))                                   \
        {                                                                      \
            if(register_kretprobe(&kretp_##func_name))                         \
            {                                                                  \
                printk(KERN_INFO "kprobe register failed for "#func_name"\n"); \
                return -1;                                                     \
            }                                                                  \
        }

#define __CRETE_UNREG_KPROBE(func_name)                 \
        if(kallsyms_lookup_name(#func_name))            \
        {                                               \
            unregister_kretprobe(&kretp_##func_name);   \
        }


/* ------------------------------- */
// Define interested functions to hook
__CRETE_DEF_KPROBE(oops_enter);

// -------------------------------------------
// 1. Pointer return with failure on NULL (28)
// -------------------------------------------
__CRETE_DEF_KPROBE_RET_CONCOLIC(__alloc_ei_netdev);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__alloc_pages_nodemask); // invoked from a loop in e1000
__CRETE_DEF_KPROBE_RET_CONCOLIC(__alloc_skb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__kmalloc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__napi_alloc_skb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__netdev_alloc_skb); // invoked from a loop in e100
__CRETE_DEF_KPROBE_RET_CONCOLIC(__pskb_pull_tail);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__request_region);
__CRETE_DEF_KPROBE_RET_CONCOLIC(alloc_etherdev_mqs);
__CRETE_DEF_KPROBE_RET_CONCOLIC(alloc_pages_current);
__CRETE_DEF_KPROBE_RET_CONCOLIC(build_skb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_get_drvdata);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dma_pool_alloc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dma_pool_create);
__CRETE_DEF_KPROBE_RET_CONCOLIC(ioremap_nocache);
__CRETE_DEF_KPROBE_RET_CONCOLIC(kmem_cache_alloc_trace);
__CRETE_DEF_KPROBE_RET_CONCOLIC(netdev_alloc_frag);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_get_device);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_get_domain_bus_and_slot);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_iomap);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_ioremap_bar);
__CRETE_DEF_KPROBE_RET_CONCOLIC(scsi_host_alloc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(sg_next);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ctl_new1);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_info_create_card_entry);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pci_quirk_lookup);
__CRETE_DEF_KPROBE_RET_CONCOLIC(trace_event_buffer_reserve);
__CRETE_DEF_KPROBE_RET_CONCOLIC(vzalloc);

// ------------------------------------------
// 2. Integer return with negative on failure
// ------------------------------------------

__CRETE_DEF_KPROBE_RET_CONCOLIC(__pci_enable_wake);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__pci_register_driver);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__pm_runtime_suspend);
__CRETE_DEF_KPROBE_RET_CONCOLIC(_dev_info);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_close);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_err);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_open);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_set_drvdata);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_warn);
__CRETE_DEF_KPROBE_RET_CONCOLIC(device_set_wakeup_enable);
//__CRETE_DEF_KPROBE_RET_CONCOLIC(dma_alloc_from_coherent); // 0/1
__CRETE_DEF_KPROBE_RET_CONCOLIC(dma_set_mask);
__CRETE_DEF_KPROBE_RET_CONCOLIC(dma_supported);
__CRETE_DEF_KPROBE_RET_CONCOLIC(down_timeout);
__CRETE_DEF_KPROBE_RET_CONCOLIC(eth_change_mtu);
__CRETE_DEF_KPROBE_RET_CONCOLIC(eth_mac_addr);
__CRETE_DEF_KPROBE_RET_CONCOLIC(eth_validate_addr);
__CRETE_DEF_KPROBE_RET_CONCOLIC(ethtool_op_get_ts_info);
__CRETE_DEF_KPROBE_RET_CONCOLIC(generic_mii_ioctl);
__CRETE_DEF_KPROBE_RET_CONCOLIC(mii_ethtool_gset);
__CRETE_DEF_KPROBE_RET_CONCOLIC(mii_ethtool_sset);
__CRETE_DEF_KPROBE_RET_CONCOLIC(mii_link_ok);
__CRETE_DEF_KPROBE_RET_CONCOLIC(mii_nway_restart);
__CRETE_DEF_KPROBE_RET_CONCOLIC(misc_deregister);
__CRETE_DEF_KPROBE_RET_CONCOLIC(misc_register);
__CRETE_DEF_KPROBE_RET_CONCOLIC(mod_timer);
__CRETE_DEF_KPROBE_RET_CONCOLIC(net_ratelimit);
__CRETE_DEF_KPROBE_RET_CONCOLIC(netdev_err);
__CRETE_DEF_KPROBE_RET_CONCOLIC(netdev_info);
__CRETE_DEF_KPROBE_RET_CONCOLIC(netdev_warn);
__CRETE_DEF_KPROBE_RET_CONCOLIC(nonseekable_open);
__CRETE_DEF_KPROBE_RET_CONCOLIC(param_get_int);
__CRETE_DEF_KPROBE_RET_CONCOLIC(param_set_int);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_bus_read_config_byte);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_bus_read_config_dword);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_bus_read_config_word);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_bus_write_config_byte);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_bus_write_config_dword);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_bus_write_config_word);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_enable_device);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_enable_device_mem);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_enable_msi_range);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_prepare_to_sleep);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_request_region);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_request_regions);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_request_selected_regions);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_save_state);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_select_bars);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_set_mwi);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_set_power_state);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_wake_from_d3);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pcix_get_mmrbc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pcix_set_mmrbc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(probe_irq_off);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pskb_expand_head);
//__CRETE_DEF_KPROBE_RET_CONCOLIC(register_netdev); // Cause false alarm of crashes, becuase of only flipping return
__CRETE_DEF_KPROBE_RET_CONCOLIC(request_firmware);
__CRETE_DEF_KPROBE_RET_CONCOLIC(request_firmware_nowait);
__CRETE_DEF_KPROBE_RET_CONCOLIC(request_threaded_irq);
__CRETE_DEF_KPROBE_RET_CONCOLIC(scsi_esp_register);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_memory_wb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_memory_wc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_pages_array_wb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_pages_array_wc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(skb_pad);

// -------
// 3. Others
// -------
//__CRETE_DEF_KPROBE_RET_CONCOLIC(arch_dma_alloc_attrs) // Bool
//__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_choose_state)

//__CRETE_DEF_KPROBE_RET_CONCOLIC()

static inline int register_probes(void)
{
    __CRETE_REG_KPROBE(oops_enter);

    // -------------------------------------------
    // 1. Pointer return with failure on NULL (28)
    // -------------------------------------------
    __CRETE_REG_KPROBE(__alloc_ei_netdev);
    __CRETE_REG_KPROBE(__alloc_pages_nodemask);
    __CRETE_REG_KPROBE(__alloc_skb);
    __CRETE_REG_KPROBE(__kmalloc);
    __CRETE_REG_KPROBE(__napi_alloc_skb);
    __CRETE_REG_KPROBE(__netdev_alloc_skb);
    __CRETE_REG_KPROBE(__pskb_pull_tail);
    __CRETE_REG_KPROBE(__request_region);
    __CRETE_REG_KPROBE(alloc_etherdev_mqs);
    __CRETE_REG_KPROBE(alloc_pages_current);
    __CRETE_REG_KPROBE(build_skb);
    __CRETE_REG_KPROBE(dev_get_drvdata);
    __CRETE_REG_KPROBE(dma_pool_alloc);
    __CRETE_REG_KPROBE(dma_pool_create);
    __CRETE_REG_KPROBE(ioremap_nocache);
    __CRETE_REG_KPROBE(kmem_cache_alloc_trace);
    __CRETE_REG_KPROBE(netdev_alloc_frag);
    __CRETE_REG_KPROBE(pci_get_device);
    __CRETE_REG_KPROBE(pci_get_domain_bus_and_slot);
    __CRETE_REG_KPROBE(pci_iomap);
    __CRETE_REG_KPROBE(pci_ioremap_bar);
    __CRETE_REG_KPROBE(scsi_host_alloc);
    __CRETE_REG_KPROBE(sg_next);
    __CRETE_REG_KPROBE(snd_ctl_new1);
    __CRETE_REG_KPROBE(snd_info_create_card_entry);
    __CRETE_REG_KPROBE(snd_pci_quirk_lookup);
    __CRETE_REG_KPROBE(trace_event_buffer_reserve);
    __CRETE_REG_KPROBE(vzalloc);

    // ------------------------------------------
    // 2. Integer return with negative on failure
    // ------------------------------------------
    __CRETE_REG_KPROBE(__pci_enable_wake);
    __CRETE_REG_KPROBE(__pci_register_driver);
    __CRETE_REG_KPROBE(__pm_runtime_suspend);
    __CRETE_REG_KPROBE(_dev_info);
    __CRETE_REG_KPROBE(dev_close);
    __CRETE_REG_KPROBE(dev_err);
    __CRETE_REG_KPROBE(dev_open);
    __CRETE_REG_KPROBE(dev_set_drvdata);
    __CRETE_REG_KPROBE(dev_warn);
    __CRETE_REG_KPROBE(device_set_wakeup_enable);
//    __CRETE_REG_KPROBE(dma_alloc_from_coherent);
    __CRETE_REG_KPROBE(dma_set_mask);
    __CRETE_REG_KPROBE(dma_supported);
    __CRETE_REG_KPROBE(down_timeout);
    __CRETE_REG_KPROBE(eth_change_mtu);
    __CRETE_REG_KPROBE(eth_mac_addr);
    __CRETE_REG_KPROBE(eth_validate_addr);
    __CRETE_REG_KPROBE(ethtool_op_get_ts_info);
    __CRETE_REG_KPROBE(generic_mii_ioctl);
    __CRETE_REG_KPROBE(mii_ethtool_gset);
    __CRETE_REG_KPROBE(mii_ethtool_sset);
    __CRETE_REG_KPROBE(mii_link_ok);
    __CRETE_REG_KPROBE(mii_nway_restart);
    __CRETE_REG_KPROBE(misc_deregister);
    __CRETE_REG_KPROBE(misc_register);
    __CRETE_REG_KPROBE(mod_timer);
    __CRETE_REG_KPROBE(net_ratelimit);
    __CRETE_REG_KPROBE(netdev_err);
    __CRETE_REG_KPROBE(netdev_info);
    __CRETE_REG_KPROBE(netdev_warn);
    __CRETE_REG_KPROBE(nonseekable_open);
    __CRETE_REG_KPROBE(param_get_int);
    __CRETE_REG_KPROBE(param_set_int);
    __CRETE_REG_KPROBE(pci_bus_read_config_byte);
    __CRETE_REG_KPROBE(pci_bus_read_config_dword);
    __CRETE_REG_KPROBE(pci_bus_read_config_word);
    __CRETE_REG_KPROBE(pci_bus_write_config_byte);
    __CRETE_REG_KPROBE(pci_bus_write_config_dword);
    __CRETE_REG_KPROBE(pci_bus_write_config_word);
    __CRETE_REG_KPROBE(pci_enable_device);
    __CRETE_REG_KPROBE(pci_enable_device_mem);
    __CRETE_REG_KPROBE(pci_enable_msi_range);
    __CRETE_REG_KPROBE(pci_prepare_to_sleep);
    __CRETE_REG_KPROBE(pci_request_region);
    __CRETE_REG_KPROBE(pci_request_regions);
    __CRETE_REG_KPROBE(pci_request_selected_regions);
    __CRETE_REG_KPROBE(pci_save_state);
    __CRETE_REG_KPROBE(pci_select_bars);
    __CRETE_REG_KPROBE(pci_set_mwi);
    __CRETE_REG_KPROBE(pci_set_power_state);
    __CRETE_REG_KPROBE(pci_wake_from_d3);
    __CRETE_REG_KPROBE(pcix_get_mmrbc);
    __CRETE_REG_KPROBE(pcix_set_mmrbc);
    __CRETE_REG_KPROBE(probe_irq_off);
    __CRETE_REG_KPROBE(pskb_expand_head);
//    __CRETE_REG_KPROBE(register_netdev);
    __CRETE_REG_KPROBE(request_firmware);
    __CRETE_REG_KPROBE(request_firmware_nowait);
    __CRETE_REG_KPROBE(request_threaded_irq);
    __CRETE_REG_KPROBE(scsi_esp_register);
    __CRETE_REG_KPROBE(set_memory_wb);
    __CRETE_REG_KPROBE(set_memory_wc);
    __CRETE_REG_KPROBE(set_pages_array_wb);
    __CRETE_REG_KPROBE(set_pages_array_wc);
    __CRETE_REG_KPROBE(skb_pad);

//    __CRETE_REG_KPROBE();

    return 0;
}

static inline void unregister_probes(void)
{
    __CRETE_UNREG_KPROBE(oops_enter);

    // -------------------------------------------
    // 1. Pointer return with failure on NULL (28)
    // -------------------------------------------
    __CRETE_UNREG_KPROBE(__alloc_ei_netdev);
    __CRETE_UNREG_KPROBE(__alloc_pages_nodemask);
    __CRETE_UNREG_KPROBE(__alloc_skb);
    __CRETE_UNREG_KPROBE(__kmalloc);
    __CRETE_UNREG_KPROBE(__napi_alloc_skb);
    __CRETE_UNREG_KPROBE(__netdev_alloc_skb);
    __CRETE_UNREG_KPROBE(__pskb_pull_tail);
    __CRETE_UNREG_KPROBE(__request_region);
    __CRETE_UNREG_KPROBE(alloc_etherdev_mqs);
    __CRETE_UNREG_KPROBE(alloc_pages_current);
    __CRETE_UNREG_KPROBE(build_skb);
    __CRETE_UNREG_KPROBE(dev_get_drvdata);
    __CRETE_UNREG_KPROBE(dma_pool_alloc);
    __CRETE_UNREG_KPROBE(dma_pool_create);
    __CRETE_UNREG_KPROBE(ioremap_nocache);
    __CRETE_UNREG_KPROBE(kmem_cache_alloc_trace);
    __CRETE_UNREG_KPROBE(netdev_alloc_frag);
    __CRETE_UNREG_KPROBE(pci_get_device);
    __CRETE_UNREG_KPROBE(pci_get_domain_bus_and_slot);
    __CRETE_UNREG_KPROBE(pci_iomap);
    __CRETE_UNREG_KPROBE(pci_ioremap_bar);
    __CRETE_UNREG_KPROBE(scsi_host_alloc);
    __CRETE_UNREG_KPROBE(sg_next);
    __CRETE_UNREG_KPROBE(snd_ctl_new1);
    __CRETE_UNREG_KPROBE(snd_info_create_card_entry);
    __CRETE_UNREG_KPROBE(snd_pci_quirk_lookup);
    __CRETE_UNREG_KPROBE(trace_event_buffer_reserve);
    __CRETE_UNREG_KPROBE(vzalloc);

    // ------------------------------------------
    // 2. Integer return with negative on failure
    // ------------------------------------------
    __CRETE_UNREG_KPROBE(__pci_enable_wake);
    __CRETE_UNREG_KPROBE(__pci_register_driver);
    __CRETE_UNREG_KPROBE(__pm_runtime_suspend);
    __CRETE_UNREG_KPROBE(_dev_info);
    __CRETE_UNREG_KPROBE(dev_close);
    __CRETE_UNREG_KPROBE(dev_err);
    __CRETE_UNREG_KPROBE(dev_open);
    __CRETE_UNREG_KPROBE(dev_set_drvdata);
    __CRETE_UNREG_KPROBE(dev_warn);
    __CRETE_UNREG_KPROBE(device_set_wakeup_enable);
//    __CRETE_UNREG_KPROBE(dma_alloc_from_coherent);
    __CRETE_UNREG_KPROBE(dma_set_mask);
    __CRETE_UNREG_KPROBE(dma_supported);
    __CRETE_UNREG_KPROBE(down_timeout);
    __CRETE_UNREG_KPROBE(eth_change_mtu);
    __CRETE_UNREG_KPROBE(eth_mac_addr);
    __CRETE_UNREG_KPROBE(eth_validate_addr);
    __CRETE_UNREG_KPROBE(ethtool_op_get_ts_info);
    __CRETE_UNREG_KPROBE(generic_mii_ioctl);
    __CRETE_UNREG_KPROBE(mii_ethtool_gset);
    __CRETE_UNREG_KPROBE(mii_ethtool_sset);
    __CRETE_UNREG_KPROBE(mii_link_ok);
    __CRETE_UNREG_KPROBE(mii_nway_restart);
    __CRETE_UNREG_KPROBE(misc_deregister);
    __CRETE_UNREG_KPROBE(misc_register);
    __CRETE_UNREG_KPROBE(mod_timer);
    __CRETE_UNREG_KPROBE(net_ratelimit);
    __CRETE_UNREG_KPROBE(netdev_err);
    __CRETE_UNREG_KPROBE(netdev_info);
    __CRETE_UNREG_KPROBE(netdev_warn);
    __CRETE_UNREG_KPROBE(nonseekable_open);
    __CRETE_UNREG_KPROBE(param_get_int);
    __CRETE_UNREG_KPROBE(param_set_int);
    __CRETE_UNREG_KPROBE(pci_bus_read_config_byte);
    __CRETE_UNREG_KPROBE(pci_bus_read_config_dword);
    __CRETE_UNREG_KPROBE(pci_bus_read_config_word);
    __CRETE_UNREG_KPROBE(pci_bus_write_config_byte);
    __CRETE_UNREG_KPROBE(pci_bus_write_config_dword);
    __CRETE_UNREG_KPROBE(pci_bus_write_config_word);
    __CRETE_UNREG_KPROBE(pci_enable_device);
    __CRETE_UNREG_KPROBE(pci_enable_device_mem);
    __CRETE_UNREG_KPROBE(pci_enable_msi_range);
    __CRETE_UNREG_KPROBE(pci_prepare_to_sleep);
    __CRETE_UNREG_KPROBE(pci_request_region);
    __CRETE_UNREG_KPROBE(pci_request_regions);
    __CRETE_UNREG_KPROBE(pci_request_selected_regions);
    __CRETE_UNREG_KPROBE(pci_save_state);
    __CRETE_UNREG_KPROBE(pci_select_bars);
    __CRETE_UNREG_KPROBE(pci_set_mwi);
    __CRETE_UNREG_KPROBE(pci_set_power_state);
    __CRETE_UNREG_KPROBE(pci_wake_from_d3);
    __CRETE_UNREG_KPROBE(pcix_get_mmrbc);
    __CRETE_UNREG_KPROBE(pcix_set_mmrbc);
    __CRETE_UNREG_KPROBE(probe_irq_off);
    __CRETE_UNREG_KPROBE(pskb_expand_head);
//    __CRETE_UNREG_KPROBE(register_netdev);
    __CRETE_UNREG_KPROBE(request_firmware);
    __CRETE_UNREG_KPROBE(request_firmware_nowait);
    __CRETE_UNREG_KPROBE(request_threaded_irq);
    __CRETE_UNREG_KPROBE(scsi_esp_register);
    __CRETE_UNREG_KPROBE(set_memory_wb);
    __CRETE_UNREG_KPROBE(set_memory_wc);
    __CRETE_UNREG_KPROBE(set_pages_array_wb);
    __CRETE_UNREG_KPROBE(set_pages_array_wc);
    __CRETE_UNREG_KPROBE(skb_pad);

//    __CRETE_UNREG_KPROBE();
}

/* ------------------------------- */
// Define entry handlers for each interested function

//static int entry_handler___kmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
//{
//    char *sp_regs = (char *)kernel_stack_pointer(regs);
//    printk(KERN_INFO "entry_handler_kmalloc() entered.\n");
//    _crete_make_concolic(&regs->cx, sizeof(int), "e1000_ioctl_arg3");
//    return 0;
//}

static int entry_handler_default(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if(!current->mm)
        return 1;  // Skip kernel threads
    else
        return 0;
}

// Only inject concolic values if:
// 1. its caller is within target_module AND
// 2. the convention on return value holds
static int ret_handler_make_concolic(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // NOTE: xxx inject concolics only for module_core (not for module_init)
    if(!(target_module.m_mod_loaded &&
         (within_module_core((unsigned long)ri->ret_addr, &target_module.m_mod))))
    {
        return 0;
    }

    if(regs->ax != regs_return_value(regs))
    {
        printk(KERN_INFO  "[CRETE ERROR] Wrong assumption on return value convention about \'%s\'\n",
                ri->rp->kp.symbol_name);
        return 0;
    }

    if(!_crete_make_concolic)
    {
        CRETE_DBG(printk(KERN_INFO  "[CRETE ERROR] \'_crete_make_concolic() is not initialized\'\n"););
        return 0;
    }

    {
        unsigned long offset;

#if defined(__USED_OLD_MODULE_LAYOUT)
        offset = (unsigned long)ri->ret_addr - (unsigned long)target_module.m_mod.module_core;
#else
        offset = (unsigned long)ri->ret_addr - (unsigned long)target_module.m_mod.core_layout.base;
#endif

        // Naming convention: func_name[mod_name.module_core+offset]
        // 'offset' is normally offset from .text section of a .ko file,
        // and can be used with addr2line to find the line number in source
        // code, e.g.: 'eu-addr2line -f -e $(modinfo -n mod_name) -j .text offset'
        sprintf(crete_ksym_symbol, "%s[%s.module_core+%#lx]",
                ri->rp->kp.symbol_name, target_module.m_name, offset);

        CRETE_DBG(
        printk(KERN_INFO "ret_handler \'%s\': ret = %p (offset = %p)\n"
                "crete_ksym_symbol = %s\n",
                ri->rp->kp.symbol_name, (void *)regs->ax, (void *)offset,
                crete_ksym_symbol);
        );

        _crete_make_concolic(&regs->ax, sizeof(regs->ax), crete_ksym_symbol);
    }

    return 0;
}

static int entry_handler_oops_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    _crete_kernel_oops();

    return 1;
}

static int ret_handler_oops_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

/* ------------------------------- */

static int crete_kapi_module_event(struct notifier_block *self, unsigned long event, void *data)
{
    struct module *m = data;

    if(strlen(m->name) != target_module.m_name_size)
        return NOTIFY_DONE;

    if(strncmp(m->name, target_module.m_name, target_module.m_name_size) != 0)
        return NOTIFY_DONE;

    switch (event) {
    case MODULE_STATE_COMING:
        printk(KERN_INFO "MODULE_STATE_COMING: %s\n", m->name);
        target_module.m_mod_loaded = 1;
#if defined(__USED_OLD_MODULE_LAYOUT)
        target_module.m_mod.module_core = m->module_core;
        target_module.m_mod.core_size = m->core_size;
        target_module.m_mod.module_init = m->module_init;
        target_module.m_mod.init_size = m->init_size;

        CRETE_DBG(
        printk(KERN_INFO "[CRETE INFO] target_module:  m->module_core = %p,  m->module_size = %p\n",
                (void *)m->module_core, (void *) m->core_size);
        );
#else
        target_module.m_mod.core_layout = m->core_layout;
        target_module.m_mod.init_layout = m->init_layout;

        CRETE_DBG(
        printk(KERN_INFO "[CRETE INFO] target_module:  m->module_core = %p,  m->module_size = %p\n",
                (void *)m->core_layout.base, (void *) m->core_layout.size);
        );
#endif

        CRETE_RC(
        reset_crete_rc();
        );

        if(target_module_probes)
            _crete_register_probes_target_module();
        break;

    case MODULE_STATE_GOING:
        printk(KERN_INFO "MODULE_STATE_GOING: %s\n", m->name);
        target_module.m_mod_loaded = 0;
        CRETE_RC(
        check_crete_rc_array();
        );
        if(target_module_probes)
            _crete_unregister_probes_target_module();
        break;

    case MODULE_STATE_LIVE:
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block crete_kapi_module_probe= {
        .notifier_call = crete_kapi_module_event,
        .priority = 1,
};

static inline int init_crete_intrinsics(void)
{
    _crete_make_concolic = (void *)kallsyms_lookup_name("crete_make_concolic");
    _crete_kernel_oops = (void *)kallsyms_lookup_name("crete_kernel_oops");

    if (!(_crete_make_concolic && _crete_kernel_oops)) {
        printk(KERN_INFO "[crete] not all function found, please check crete-intrinsics.ko\n");
        return -1;
    }

    CRETE_RC(
    _crete_get_current_target_pid = (void *)kallsyms_lookup_name("crete_get_current_target_pid");

    if(!_crete_get_current_target_pid) {
        printk(KERN_INFO "[crete] not all function found, please check crete-intrinsics-replay.ko\n");
        return -1;
    }
    );

    _crete_register_probes_target_module = (void *)kallsyms_lookup_name("crete_register_probes_e1000");
    _crete_unregister_probes_target_module = (void *)kallsyms_lookup_name("crete_unregister_probes_e1000");

    if(_crete_register_probes_target_module &&
            _crete_unregister_probes_target_module)
    {
        printk(KERN_INFO "target_module_probes found!\n");
        target_module_probes = true;
    }

    return 0;
}

static int __init crete_kprobe_init(void)
{
    if(init_crete_intrinsics())
        return -1;

    if(register_probes())
        return -1;

    // XXX Assumption: probes on the same address will
    // be executed in the order as they are registered.
    CRETE_RC(
    if(register_probes_crete_rc())
        return -1;
    );

    target_module.m_name_size = strlen(target_module.m_name);
    register_module_notifier(&crete_kapi_module_probe);

    CRETE_DBG(printk(KERN_INFO "size = %zu, name = %s\n", target_module.m_name_size, target_module.m_name););

    return 0;
}

static void __exit crete_kprobe_exit(void)
{
    unregister_module_notifier(&crete_kapi_module_probe);
    unregister_probes();

    CRETE_RC(
    unregister_probes_crete_rc();
    );
}

module_init(crete_kprobe_init)
module_exit(crete_kprobe_exit)
