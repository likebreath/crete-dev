#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bo Chen (chenbo@pdx.edu)");
MODULE_DESCRIPTION("CRETE probes for kernel API functions to inject concolic values");

//#define CRETE_ENABLE_DEBUG
#define CRETE_ENABLE_RESOURCE_MONITOR

#ifdef CRETE_ENABLE_DEBUG
#define CRETE_DBG(x) do { x } while(0)
#else
#define CRETE_DBG(x) do { } while(0)
#endif

#ifdef CRETE_ENABLE_RESOURCE_MONITOR
#define CRETE_RM(x) do { x } while(0)
#else
#define CRETE_RM(x) do { } while(0)
#endif

#if defined(CRETE_USED_OLD_MODULE_LAYOUT)
#define __USED_OLD_MODULE_LAYOUT
#endif
static char crete_ksym_symbol[KSYM_SYMBOL_LEN*2];

#define MAX_TARGET_MODULE_COUNT 8

struct TargetModuleInfo
{
    size_t m_name_size;
    char *m_name;
    int   m_mod_loaded;
    struct module m_mod;
};

static struct TargetModuleInfo target_modules[MAX_TARGET_MODULE_COUNT] = {{0}};

static char *target_module_names[MAX_TARGET_MODULE_COUNT] = {NULL};
static int argc_target_modules = 0;
module_param_array(target_module_names, charp, &argc_target_modules, 0);
MODULE_PARM_DESC(target_module_names, "The name of target modulse to enable probe on kernel APIs");

static void (*_crete_make_concolic)(void*, size_t, const char *);
static void (*_crete_kernel_oops)(void);

static bool target_module_probes = false;
static void (*_crete_register_probes_target_module)(void);
static void (*_crete_unregister_probes_target_module)(void);

static int entry_handler_default(struct kretprobe_instance *ri, struct pt_regs *regs);
static int ret_handler_make_concolic(struct kretprobe_instance *ri, struct pt_regs *regs);

#ifdef CRETE_ENABLE_RESOURCE_MONITOR
static int target_module_count = 0;

static const struct TargetModuleInfo *find_target_module_info(unsigned long addr);
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
__CRETE_DEF_KPROBE(warn_slowpath_null);

// -------------------------------------------
// 1. Pointer return with failure on NULL (35)
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
__CRETE_DEF_KPROBE_RET_CONCOLIC(__alloc_workqueue_key);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__kmalloc_node);
__CRETE_DEF_KPROBE_RET_CONCOLIC(kmalloc_order_trace);
__CRETE_DEF_KPROBE_RET_CONCOLIC(kmem_cache_alloc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_spdif_out_of_nid);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_lib_default_mmap);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__symbol_get);

//__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_get_drvdata); // False alarm: seems always return non-NULL value, based on e1000 maintainer

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
__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_warn);
__CRETE_DEF_KPROBE_RET_CONCOLIC(device_set_wakeup_enable);
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
__CRETE_DEF_KPROBE_RET_CONCOLIC(request_firmware);
__CRETE_DEF_KPROBE_RET_CONCOLIC(request_firmware_nowait);
__CRETE_DEF_KPROBE_RET_CONCOLIC(scsi_esp_register);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_memory_wb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_memory_wc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_pages_array_wb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_pages_array_wc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(skb_pad);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_enable_msi_block);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_enable_msix);
__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_request_selected_regions_exclusive);
__CRETE_DEF_KPROBE_RET_CONCOLIC(scsi_add_host_with_dma);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__pm_runtime_idle);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__pm_runtime_resume);
__CRETE_DEF_KPROBE_RET_CONCOLIC(__request_module);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_pages_uc);
__CRETE_DEF_KPROBE_RET_CONCOLIC(set_pages_wb);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_bus);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_mixer);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_pcm_assign);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_pcm_close);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_pcm_double_rate_rules);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_pcm_open);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_set_rate);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_tune_hardware);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_update_bits);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ac97_update_power);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_card_create);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_card_disconnect);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_card_free);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_card_proc_new);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_card_register);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_component_add);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ctl_add);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_ctl_boolean_mono_info);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_dma_alloc_pages);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_build_controls);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_build_pcms);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_bus_new);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hdac_bus_alloc_stream_pages);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_codec_configure);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_codec_new);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_codec_prepare);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_lock_devices);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_hda_queue_unsol_event);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_add_chmap_ctls);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_format_width);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_hw_constraint_integer);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_hw_constraint_list);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_hw_constraint_minmax);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_hw_constraint_msbits);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_hw_constraint_ratnums);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_hw_constraint_step);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_lib_free_pages);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_lib_ioctl);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_lib_malloc_pages);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_lib_preallocate_pages_for_all);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_limit_hw_rates);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_new);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_pcm_suspend_all);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_rawmidi_new);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_rawmidi_receive);
__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_rawmidi_transmit);

//__CRETE_DEF_KPROBE_RET_CONCOLIC(dma_alloc_from_coherent); // 0/1
//__CRETE_DEF_KPROBE_RET_CONCOLIC(register_netdev); // xxx False alarm: crashes, because of only flipping return
//__CRETE_DEF_KPROBE_RET_CONCOLIC(request_threaded_irq); // xxx False alarm: crashes, because of only flipping return
//__CRETE_DEF_KPROBE_RET_CONCOLIC(snd_device_new); // xxx False Alarm: crashes, because of only flipping return
//__CRETE_DEF_KPROBE_RET_CONCOLIC(dev_set_drvdata); // Never fail

// -------
// 3. Others
// -------
//__CRETE_DEF_KPROBE_RET_CONCOLIC(arch_dma_alloc_attrs) // Bool
//__CRETE_DEF_KPROBE_RET_CONCOLIC(pci_choose_state)

//__CRETE_DEF_KPROBE_RET_CONCOLIC()

static inline int register_probes(void)
{
    __CRETE_REG_KPROBE(oops_enter);
    __CRETE_REG_KPROBE(warn_slowpath_null);

    // -------------------------------------------
    // 1. Pointer return with failure on NULL (35)
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
    __CRETE_REG_KPROBE(__alloc_workqueue_key);
    __CRETE_REG_KPROBE(__kmalloc_node);
    __CRETE_REG_KPROBE(kmalloc_order_trace);
    __CRETE_REG_KPROBE(kmem_cache_alloc);
    __CRETE_REG_KPROBE(snd_hda_spdif_out_of_nid);
    __CRETE_REG_KPROBE(snd_pcm_lib_default_mmap);
    __CRETE_REG_KPROBE(__symbol_get);

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
    __CRETE_REG_KPROBE(dev_warn);
    __CRETE_REG_KPROBE(device_set_wakeup_enable);
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
    __CRETE_REG_KPROBE(request_firmware);
    __CRETE_REG_KPROBE(request_firmware_nowait);
    __CRETE_REG_KPROBE(scsi_esp_register);
    __CRETE_REG_KPROBE(set_memory_wb);
    __CRETE_REG_KPROBE(set_memory_wc);
    __CRETE_REG_KPROBE(set_pages_array_wb);
    __CRETE_REG_KPROBE(set_pages_array_wc);
    __CRETE_REG_KPROBE(skb_pad);
    __CRETE_REG_KPROBE(pci_enable_msi_block);
    __CRETE_REG_KPROBE(pci_enable_msix);
    __CRETE_REG_KPROBE(pci_request_selected_regions_exclusive);
    __CRETE_REG_KPROBE(scsi_add_host_with_dma);
    __CRETE_REG_KPROBE(__pm_runtime_idle);
    __CRETE_REG_KPROBE(__pm_runtime_resume);
    __CRETE_REG_KPROBE(__request_module);
    __CRETE_REG_KPROBE(set_pages_uc);
    __CRETE_REG_KPROBE(set_pages_wb);
    __CRETE_REG_KPROBE(snd_ac97_bus);
    __CRETE_REG_KPROBE(snd_ac97_mixer);
    __CRETE_REG_KPROBE(snd_ac97_pcm_assign);
    __CRETE_REG_KPROBE(snd_ac97_pcm_close);
    __CRETE_REG_KPROBE(snd_ac97_pcm_double_rate_rules);
    __CRETE_REG_KPROBE(snd_ac97_pcm_open);
    __CRETE_REG_KPROBE(snd_ac97_set_rate);
    __CRETE_REG_KPROBE(snd_ac97_tune_hardware);
    __CRETE_REG_KPROBE(snd_ac97_update_bits);
    __CRETE_REG_KPROBE(snd_ac97_update_power);
    __CRETE_REG_KPROBE(snd_card_create);
    __CRETE_REG_KPROBE(snd_card_disconnect);
    __CRETE_REG_KPROBE(snd_card_free);
    __CRETE_REG_KPROBE(snd_card_proc_new);
    __CRETE_REG_KPROBE(snd_card_register);
    __CRETE_REG_KPROBE(snd_component_add);
    __CRETE_REG_KPROBE(snd_ctl_add);
    __CRETE_REG_KPROBE(snd_ctl_boolean_mono_info);
    __CRETE_REG_KPROBE(snd_dma_alloc_pages);
    __CRETE_REG_KPROBE(snd_hda_build_controls);
    __CRETE_REG_KPROBE(snd_hda_build_pcms);
    __CRETE_REG_KPROBE(snd_hda_bus_new);
    __CRETE_REG_KPROBE(snd_hdac_bus_alloc_stream_pages);
    __CRETE_REG_KPROBE(snd_hda_codec_configure);
    __CRETE_REG_KPROBE(snd_hda_codec_new);
    __CRETE_REG_KPROBE(snd_hda_codec_prepare);
    __CRETE_REG_KPROBE(snd_hda_lock_devices);
    __CRETE_REG_KPROBE(snd_hda_queue_unsol_event);
    __CRETE_REG_KPROBE(snd_pcm_add_chmap_ctls);
    __CRETE_REG_KPROBE(snd_pcm_format_width);
    __CRETE_REG_KPROBE(snd_pcm_hw_constraint_integer);
    __CRETE_REG_KPROBE(snd_pcm_hw_constraint_list);
    __CRETE_REG_KPROBE(snd_pcm_hw_constraint_minmax);
    __CRETE_REG_KPROBE(snd_pcm_hw_constraint_msbits);
    __CRETE_REG_KPROBE(snd_pcm_hw_constraint_ratnums);
    __CRETE_REG_KPROBE(snd_pcm_hw_constraint_step);
    __CRETE_REG_KPROBE(snd_pcm_lib_free_pages);
    __CRETE_REG_KPROBE(snd_pcm_lib_ioctl);
    __CRETE_REG_KPROBE(snd_pcm_lib_malloc_pages);
    __CRETE_REG_KPROBE(snd_pcm_lib_preallocate_pages_for_all);
    __CRETE_REG_KPROBE(snd_pcm_limit_hw_rates);
    __CRETE_REG_KPROBE(snd_pcm_new);
    __CRETE_REG_KPROBE(snd_pcm_suspend_all);
    __CRETE_REG_KPROBE(snd_rawmidi_new);
    __CRETE_REG_KPROBE(snd_rawmidi_receive);
    __CRETE_REG_KPROBE(snd_rawmidi_transmit);

//    __CRETE_REG_KPROBE();

    return 0;
}

static inline void unregister_probes(void)
{
    __CRETE_UNREG_KPROBE(oops_enter);
    __CRETE_UNREG_KPROBE(warn_slowpath_null);

    // -------------------------------------------
    // 1. Pointer return with failure on NULL (35)
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
    __CRETE_UNREG_KPROBE(__alloc_workqueue_key);
    __CRETE_UNREG_KPROBE(__kmalloc_node);
    __CRETE_UNREG_KPROBE(kmalloc_order_trace);
    __CRETE_UNREG_KPROBE(kmem_cache_alloc);
    __CRETE_UNREG_KPROBE(snd_hda_spdif_out_of_nid);
    __CRETE_UNREG_KPROBE(snd_pcm_lib_default_mmap);
    __CRETE_UNREG_KPROBE(__symbol_get);

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
    __CRETE_UNREG_KPROBE(dev_warn);
    __CRETE_UNREG_KPROBE(device_set_wakeup_enable);
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
    __CRETE_UNREG_KPROBE(request_firmware);
    __CRETE_UNREG_KPROBE(request_firmware_nowait);
    __CRETE_UNREG_KPROBE(scsi_esp_register);
    __CRETE_UNREG_KPROBE(set_memory_wb);
    __CRETE_UNREG_KPROBE(set_memory_wc);
    __CRETE_UNREG_KPROBE(set_pages_array_wb);
    __CRETE_UNREG_KPROBE(set_pages_array_wc);
    __CRETE_UNREG_KPROBE(skb_pad);
    __CRETE_UNREG_KPROBE(pci_enable_msi_block);
    __CRETE_UNREG_KPROBE(pci_enable_msix);
    __CRETE_UNREG_KPROBE(pci_request_selected_regions_exclusive);
    __CRETE_UNREG_KPROBE(scsi_add_host_with_dma);
    __CRETE_UNREG_KPROBE(__pm_runtime_idle);
    __CRETE_UNREG_KPROBE(__pm_runtime_resume);
    __CRETE_UNREG_KPROBE(__request_module);
    __CRETE_UNREG_KPROBE(set_pages_uc);
    __CRETE_UNREG_KPROBE(set_pages_wb);
    __CRETE_UNREG_KPROBE(snd_ac97_bus);
    __CRETE_UNREG_KPROBE(snd_ac97_mixer);
    __CRETE_UNREG_KPROBE(snd_ac97_pcm_assign);
    __CRETE_UNREG_KPROBE(snd_ac97_pcm_close);
    __CRETE_UNREG_KPROBE(snd_ac97_pcm_double_rate_rules);
    __CRETE_UNREG_KPROBE(snd_ac97_pcm_open);
    __CRETE_UNREG_KPROBE(snd_ac97_set_rate);
    __CRETE_UNREG_KPROBE(snd_ac97_tune_hardware);
    __CRETE_UNREG_KPROBE(snd_ac97_update_bits);
    __CRETE_UNREG_KPROBE(snd_ac97_update_power);
    __CRETE_UNREG_KPROBE(snd_card_create);
    __CRETE_UNREG_KPROBE(snd_card_disconnect);
    __CRETE_UNREG_KPROBE(snd_card_free);
    __CRETE_UNREG_KPROBE(snd_card_proc_new);
    __CRETE_UNREG_KPROBE(snd_card_register);
    __CRETE_UNREG_KPROBE(snd_component_add);
    __CRETE_UNREG_KPROBE(snd_ctl_add);
    __CRETE_UNREG_KPROBE(snd_ctl_boolean_mono_info);
    __CRETE_UNREG_KPROBE(snd_dma_alloc_pages);
    __CRETE_UNREG_KPROBE(snd_hda_build_controls);
    __CRETE_UNREG_KPROBE(snd_hda_build_pcms);
    __CRETE_UNREG_KPROBE(snd_hda_bus_new);
    __CRETE_UNREG_KPROBE(snd_hdac_bus_alloc_stream_pages);
    __CRETE_UNREG_KPROBE(snd_hda_codec_configure);
    __CRETE_UNREG_KPROBE(snd_hda_codec_new);
    __CRETE_UNREG_KPROBE(snd_hda_codec_prepare);
    __CRETE_UNREG_KPROBE(snd_hda_lock_devices);
    __CRETE_UNREG_KPROBE(snd_hda_queue_unsol_event);
    __CRETE_UNREG_KPROBE(snd_pcm_add_chmap_ctls);
    __CRETE_UNREG_KPROBE(snd_pcm_format_width);
    __CRETE_UNREG_KPROBE(snd_pcm_hw_constraint_integer);
    __CRETE_UNREG_KPROBE(snd_pcm_hw_constraint_list);
    __CRETE_UNREG_KPROBE(snd_pcm_hw_constraint_minmax);
    __CRETE_UNREG_KPROBE(snd_pcm_hw_constraint_msbits);
    __CRETE_UNREG_KPROBE(snd_pcm_hw_constraint_ratnums);
    __CRETE_UNREG_KPROBE(snd_pcm_hw_constraint_step);
    __CRETE_UNREG_KPROBE(snd_pcm_lib_free_pages);
    __CRETE_UNREG_KPROBE(snd_pcm_lib_ioctl);
    __CRETE_UNREG_KPROBE(snd_pcm_lib_malloc_pages);
    __CRETE_UNREG_KPROBE(snd_pcm_lib_preallocate_pages_for_all);
    __CRETE_UNREG_KPROBE(snd_pcm_limit_hw_rates);
    __CRETE_UNREG_KPROBE(snd_pcm_new);
    __CRETE_UNREG_KPROBE(snd_pcm_suspend_all);
    __CRETE_UNREG_KPROBE(snd_rawmidi_new);
    __CRETE_UNREG_KPROBE(snd_rawmidi_receive);
    __CRETE_UNREG_KPROBE(snd_rawmidi_transmit);

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

static const struct TargetModuleInfo *find_target_module_info(unsigned long addr)
{
    int i = 0;
    for(; i < argc_target_modules; ++i)
    {
        if(target_modules[i].m_mod_loaded &&
             (within_module_core(addr, &target_modules[i].m_mod)))
        {
            return &target_modules[i];
        }
    }
    return NULL;
}

// Only inject concolic values if:
// 1. its caller is within target_module AND
// 2. the convention on return value holds
static int ret_handler_make_concolic(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // NOTE: xxx inject concolics only for module_core (not for module_init)
    const struct TargetModuleInfo *target_module_info = find_target_module_info((unsigned long)ri->ret_addr);
    if(!target_module_info)
        return 0;

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
        offset = (unsigned long)ri->ret_addr - (unsigned long)target_module_info->m_mod.module_core;
#else
        offset = (unsigned long)ri->ret_addr - (unsigned long)target_module_info->m_mod.core_layout.base;
#endif

        // Naming convention: func_name[mod_name.module_core+offset]
        // 'offset' is normally offset from .text section of a .ko file,
        // and can be used with addr2line to find the line number in source
        // code, e.g.: 'eu-addr2line -f -e $(modinfo -n mod_name) -j .text offset'
        sprintf(crete_ksym_symbol, "%s[%s.module_core+%#lx]",
                ri->rp->kp.symbol_name, target_module_info->m_name, offset);

        CRETE_DBG(
        printk(KERN_INFO "[CRETE DBG] ret_handler \'%s\': ret = %p (offset = %p)\n"
                "crete_ksym_symbol = %s\n",
                ri->rp->kp.symbol_name, (void *)regs->ax, (void *)offset,
                crete_ksym_symbol);
        );

        _crete_make_concolic(&regs->ax, sizeof(regs->ax), crete_ksym_symbol);

        CRETE_DBG(
        printk(KERN_INFO "[CRETE DBG] after _make_concolic: ret = %lu\n", regs->ax);
        );
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

static int entry_handler_warn_slowpath_null(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

static int ret_handler_warn_slowpath_null(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    panic("[CRETE REPORT] potential warning!\n");

    return 0;
}

/* ------------------------------- */

static int crete_kapi_module_event(struct notifier_block *self, unsigned long event, void *data)
{
    struct module *m = data;
    struct TargetModuleInfo *target_module_info = NULL;

    int i = 0;
    for(; i < argc_target_modules; ++i)
    {
        if(strlen(m->name) != target_modules[i].m_name_size)
            continue;

        if(strncmp(m->name, target_modules[i].m_name, target_modules[i].m_name_size) != 0)
            continue;

        target_module_info = &target_modules[i];

        CRETE_DBG(
        printk(KERN_INFO "[%d] target_modules: name = %s, loaded = %d, size = %zu\n",
                i, target_module_info->m_name, target_module_info->m_mod_loaded,
                target_module_info->m_name_size);
        );
        break;
    }

    if(target_module_info == NULL)
        return NOTIFY_DONE;

    switch (event) {
    case MODULE_STATE_COMING:
        printk(KERN_INFO "MODULE_STATE_COMING: %s\n", m->name);
        target_module_info->m_mod_loaded = 1;
#if defined(__USED_OLD_MODULE_LAYOUT)
        target_module_info->m_mod.module_core = m->module_core;
        target_module_info->m_mod.core_size = m->core_size;
        target_module_info->m_mod.module_init = m->module_init;
        target_module_info->m_mod.init_size = m->init_size;

        CRETE_DBG(
        printk(KERN_INFO "[CRETE INFO] target_module:  m->module_core = %p,  m->module_size = %p\n",
                (void *)target_module_info->m_mod.module_core, (void *) target_module_info->m_mod.core_size);
        );
#else
        target_module_info->m_mod.core_layout = m->core_layout;
        target_module_info->m_mod.init_layout = m->init_layout;

        CRETE_DBG(
        printk(KERN_INFO "[CRETE INFO] target_module:  m->module_core = %p,  m->module_size = %p\n",
                (void *)target_module_info->m_mod.core_layout.base,
                (void *) target_module_info->m_mod.core_layout.size);
        );
#endif

        CRETE_RM(
        if(target_module_count == 0)
            crete_resource_monitor_start();
        target_module_count++;
        );

        if(target_module_probes)
            _crete_register_probes_target_module();
        break;

    case MODULE_STATE_GOING:
        printk(KERN_INFO "MODULE_STATE_GOING: %s\n", m->name);
        target_module_info->m_mod_loaded = 0;
        CRETE_RM(
        if(target_module_count != 0)
            target_module_count--;
        if(target_module_count == 0)
            crete_resource_monitor_finish();
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

    CRETE_RM(
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

static inline void init_crete_target_modules(void)
{
    int i = 0;
    for(; i < argc_target_modules; ++i)
    {
        target_modules[i].m_name = target_module_names[i];
        target_modules[i].m_name_size = strlen(target_modules[i].m_name);

        CRETE_DBG(
        printk(KERN_INFO "[%d] target_modules: name = %s, loaded = %d, size = %lu\n",
                i, target_modules[i].m_name, target_modules[i].m_mod_loaded,
                target_modules[i].m_name_size);
        );
    }
}

static int __init crete_kprobe_init(void)
{
    if(init_crete_intrinsics())
        return -1;

    if(register_probes())
        return -1;

    // XXX Assumption: probes on the same address will
    // be executed in the order as they are registered.
    CRETE_RM(
    if(register_probes_crete_rm())
        return -1;
    );

    init_crete_target_modules();

    register_module_notifier(&crete_kapi_module_probe);

    CRETE_DBG(printk(KERN_INFO "size = %zu, name = %s\n", target_module.m_name_size, target_module.m_name););

    return 0;
}

static void __exit crete_kprobe_exit(void)
{
    unregister_module_notifier(&crete_kapi_module_probe);
    unregister_probes();

    CRETE_RM(
    unregister_probes_crete_rm();
    );
}

module_init(crete_kprobe_init)
module_exit(crete_kprobe_exit)
