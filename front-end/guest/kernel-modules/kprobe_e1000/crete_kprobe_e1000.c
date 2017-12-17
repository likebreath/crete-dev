#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bo Chen (chenbo@pdx.edu)");
MODULE_DESCRIPTION("CRETE probes for e1000 entry functions");

static void (*_crete_make_concolic)(void*, size_t, const char *);

static const char *CRETE_LDK_WL_PROCFS = "crete-ldk-wk-procfs";
static void *e1000_adapter_ptr = NULL;
static void *e1000_hw_ptr = NULL;

#define __CRETE_DEF_KPROBE_ENTRY(func_name)                                                         \
        static int entry_handler_##func_name(struct kretprobe_instance *ri, struct pt_regs *regs);  \
        static const struct kretprobe const_kretp_##func_name = {                                   \
                .kp.symbol_name = #func_name,                                                       \
                .entry_handler = entry_handler_##func_name,                                         \
        };                                                                                          \
        static struct kretprobe kretp_##func_name;

#define __CRETE_REG_KPROBE(func_name)                                           \
        {                                                                       \
            kretp_##func_name = const_kretp_##func_name;                        \
            if(register_kretprobe(&kretp_##func_name))                          \
            {                                                                   \
                printk(KERN_INFO "kprobe register failed for "#func_name"\n");  \
                return -1;                                                      \
            }                                                                   \
        }

#define __CRETE_UNREG_KPROBE(func_name)  unregister_kretprobe(&kretp_##func_name);

/* ------------------------------- */
// Define interested functions to hook
__CRETE_DEF_KPROBE_ENTRY(e1000_ioctl)
__CRETE_DEF_KPROBE_ENTRY(e1000_reset)
__CRETE_DEF_KPROBE_ENTRY(e1000_reset_hw)
//__CRETE_DEF_KPROBE();

static inline int crete_register_probes_e1000(void)
{
    printk(KERN_INFO "crete_register_probes_e1000()\n");
    __CRETE_REG_KPROBE(e1000_ioctl);
    __CRETE_REG_KPROBE(e1000_reset);
    __CRETE_REG_KPROBE(e1000_reset_hw);

//    __CRETE_REG_KPROBE();
    return 0;
}
EXPORT_SYMBOL(crete_register_probes_e1000);

static inline void crete_unregister_probes_e1000(void)
{
    printk(KERN_INFO "crete_unregister_probes_e1000()\n");
    __CRETE_UNREG_KPROBE(e1000_ioctl);
    __CRETE_UNREG_KPROBE(e1000_reset);
    __CRETE_UNREG_KPROBE(e1000_reset_hw);

//    __CRETE_UNREG_KPROBE();
}
EXPORT_SYMBOL(crete_unregister_probes_e1000);

/* ------------------------------- */
// Define entry handlers for each interested function

//@func signature:
//  static int e1000_ioctl(struct net_device *netdev,
//                         struct ifreq *ifr, int cmd);
static int entry_handler_e1000_ioctl(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // check whether this function is called with call_ioctl
    /* char *sp_regs = (char *)kernel_stack_pointer(regs); */
    /* printk(KERN_INFO "e1000_ioctl() entered: cmd = %x\n", (int)regs->cx); */
    _crete_make_concolic(&regs->cx, sizeof(int), "e1000_ioctl_arg3");
    return 0;
}

// @func signature: void e1000_reset(struct e1000_adapter *adapter)
static int entry_handler_e1000_reset(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    e1000_adapter_ptr = (void *)regs->ax;

    /* printk(KERN_INFO "e1000_adapter_ptr = %p\n", e1000_adapter_ptr); */

    return 0;
}

// @func signature: s32 e1000_reset_hw(struct e1000_hw *hw)
// @probe: get input pointer value for future re-use
static int entry_handler_e1000_reset_hw(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    e1000_hw_ptr = (void *)regs->ax;

//    printk(KERN_INFO "e1000_hw_ptr = %p\n", e1000_hw_ptr);
    return 0;
}

/* ------------------------------- */
#define __CRETE_E1000_WORKLOAD_HW_PTR(case_num, ret, name)  \
    case case_num:                                          \
    {                                                       \
        ret (*__##name)(void *);                            \
        __##name = (void *) kallsyms_lookup_name(#name);    \
        if(__##name)                                        \
        {                                                   \
            __##name(e1000_hw_ptr);                         \
        }                                                   \
        break;                                              \
   }

#define __CRETE_E1000_WORKLOAD_ADAP_PTR(case_num, ret, name)    \
    case case_num:                                              \
    {                                                           \
        ret (*__##name)(void *);                                \
        __##name = (void *) kallsyms_lookup_name(#name);        \
        if(__##name)                                            \
        {                                                       \
            __##name(e1000_adapter_ptr);                        \
        }                                                       \
        break;                                                  \
   }

static void crete_e1000_workload(int index)
{
    if(!(e1000_hw_ptr && e1000_adapter_ptr))
    {
        printk(KERN_INFO "[CRETE WARNING] crete_e1000_workload not executed: "
                "e1000_hw_ptr = %p, e1000_adapter_ptr = %p\n",
                e1000_hw_ptr, e1000_adapter_ptr);
        return;
    }
    printk(KERN_INFO "crete_e1000_workload(): %d\n", index);

    switch (index) {
    __CRETE_E1000_WORKLOAD_HW_PTR  (1,  s32,  e1000_check_for_link )
    __CRETE_E1000_WORKLOAD_ADAP_PTR(2,  void, e1000_check_options)
    __CRETE_E1000_WORKLOAD_HW_PTR  (3,  s32,  e1000_cleanup_led)
    __CRETE_E1000_WORKLOAD_HW_PTR  (4,  void, e1000_config_collision_dist)
//    __CRETE_E1000_WORKLOAD_ADAP_PTR(5,  void, e1000_down) // hanged
    __CRETE_E1000_WORKLOAD_HW_PTR  (6,  u32,  e1000_enable_mng_pass_thru)
    __CRETE_E1000_WORKLOAD_HW_PTR  (7,  s32,  e1000_force_mac_fc)
//    __CRETE_E1000_WORKLOAD_ADAP_PTR(8,  void, e1000_free_all_rx_resources) // crashed
//    __CRETE_E1000_WORKLOAD_ADAP_PTR(9,  void, e1000_free_all_tx_resources) // crashed
    __CRETE_E1000_WORKLOAD_HW_PTR  (10, void, e1000_get_bus_info)
    __CRETE_E1000_WORKLOAD_HW_PTR  (11, void*,e1000_get_hw_dev)
    case 12:
    {
        //    s32 e1000_get_speed_and_duplex(struct e1000_hw *hw, u16 *speed, u16 *duplex)
        s32 (*__e1000_get_speed_and_duplex)(void *, u16 *, u16 *);

        __e1000_get_speed_and_duplex = (void *) kallsyms_lookup_name("e1000_get_speed_and_duplex");
        if(__e1000_get_speed_and_duplex)
        {
            u16 speed, duplex;
            s32 ret_val;

            ret_val = __e1000_get_speed_and_duplex(e1000_hw_ptr, &speed, &duplex);

            printk(KERN_INFO "__e1000_get_speed_and_duplex(): ret = %d, speed = %d, duplex = %d\n",
                    ret_val, speed, duplex);
        }
        break;
    }
    case 13:
    {
        //    u32 e1000_hash_mc_addr(struct e1000_hw *hw, u8 *mc_addr)
        u32 (*__e1000_hash_mc_addr)(void *, u8 *);
        __e1000_hash_mc_addr = (void *) kallsyms_lookup_name("e1000_hash_mc_addr");
        if(__e1000_hash_mc_addr)
        {
//            u8 mc_addr; // Array ptr

//            __e1000_hash_mc_addr(e1000_hw_ptr, NULL);
            printk(KERN_INFO "__e1000_hash_mc_addr(): empty\n");
        }
        break;
    }
    __CRETE_E1000_WORKLOAD_ADAP_PTR(14, bool, e1000_has_link)
    __CRETE_E1000_WORKLOAD_HW_PTR  (15, s32, e1000_init_eeprom_params)
    __CRETE_E1000_WORKLOAD_HW_PTR  (16, s32, e1000_init_hw)
    case 17:
        {
            //    void e1000_io_write(struct e1000_hw *hw, unsigned long port, u32 value)
            void (*__e1000_io_write)(void *, unsigned long, u32);
            __e1000_io_write = (void *) kallsyms_lookup_name("e1000_io_write");
            if(__e1000_io_write)
            {
                unsigned long port;
                u32 value;
                port = 0;
                value = 0;
                __e1000_io_write(e1000_hw_ptr, port, value);

                printk(KERN_INFO "__e1000_io_write(): port = %lu, value = %u\n",
                        port, value);
            }
            break;
        }

    __CRETE_E1000_WORKLOAD_HW_PTR  (18, s32, e1000_led_off)
    __CRETE_E1000_WORKLOAD_HW_PTR  (19, s32, e1000_led_on)
    __CRETE_E1000_WORKLOAD_HW_PTR  (20, void, e1000_pci_clear_mwi)
    __CRETE_E1000_WORKLOAD_HW_PTR  (21, void, e1000_pci_set_mwi)
    __CRETE_E1000_WORKLOAD_HW_PTR  (22, int, e1000_pcix_get_mmrbc)
    case 23:
    {
        //    void e1000_pcix_set_mmrbc(struct e1000_hw *hw, int mmrbc)
        void (*__e1000_pcix_set_mmrbc)(void *, int);
        __e1000_pcix_set_mmrbc = (void *) kallsyms_lookup_name("e1000_pcix_set_mmrbc");
        if(__e1000_pcix_set_mmrbc)
        {
            int mmrbc;
            mmrbc = 2048;
            __e1000_pcix_set_mmrbc(e1000_hw_ptr, 2048);

            printk(KERN_INFO "__e1000_pcix_set_mmrbc(): %d\n", mmrbc);
        }
        break;
    }
    case 24:
    {
        //    s32 e1000_phy_get_info(struct e1000_hw *hw, struct e1000_phy_info *phy_info)
        s32 (*__e1000_phy_get_info)(void *, void *);
        __e1000_phy_get_info = (void *) kallsyms_lookup_name("e1000_phy_get_info");
        if(__e1000_phy_get_info)
        {

            //            struct e1000_phy_info *phy_info;
//            __e1000_phy_get_info(e1000_hw_ptr, NULL);

            printk(KERN_INFO "__e1000_phy_get_info(): empty\n");

        }
        break;
    }
    __CRETE_E1000_WORKLOAD_HW_PTR  (25, s32, e1000_phy_hw_reset)
    __CRETE_E1000_WORKLOAD_HW_PTR  (26, s32, e1000_phy_reset)
    __CRETE_E1000_WORKLOAD_HW_PTR  (27, s32, e1000_phy_setup_autoneg)
    __CRETE_E1000_WORKLOAD_ADAP_PTR(28, void, e1000_power_up_phy)
    case 29:
    {
        //    void e1000_rar_set(struct e1000_hw *hw, u8 *addr, u32 index)
        void (*__e1000_rar_set)(void *, u8 *, u32);
        __e1000_rar_set = (void *) kallsyms_lookup_name("e1000_rar_set");
        if(__e1000_rar_set)
        {
//            u8 *addr; // mc_addr array
//            u32 index;
//            index = 0;
//            __e1000_rar_set(e1000_hw_ptr, NULL, 0);

            printk(KERN_INFO "__e1000_rar_set(): empty\n");
        }
        break;
    }
    case 30:
    {
        //    s32 e1000_read_eeprom(struct e1000_hw *hw, u16 offset, u16 words, u16 *data)
        s32 (*__e1000_read_eeprom)(void *, u16, u16, u16 *);
        __e1000_read_eeprom = (void *) kallsyms_lookup_name("e1000_read_eeprom");
        if(__e1000_read_eeprom)
        {
            s32 ret_val;
            u16 offset;
            u16 words;
            u16 data[2];

            offset = 0;
            words = 2;

            ret_val = __e1000_read_eeprom(e1000_hw_ptr, offset, words, data);

            printk(KERN_INFO "__e1000_read_eeprom(): offset = %u, words = %u, data = %p, ret = %d\n",
                    offset, words, data, ret_val);
        }
        break;
    }
    __CRETE_E1000_WORKLOAD_HW_PTR  (31, s32, e1000_read_mac_addr)
    case 32:
    {
        //    s32 e1000_read_phy_reg(struct e1000_hw *hw, u32 reg_addr, u16 *phy_data)
        s32 (*__e1000_read_phy_reg)(void *, u32, u16 *);
        __e1000_read_phy_reg = (void *) kallsyms_lookup_name("e1000_read_phy_reg");
        if(__e1000_read_phy_reg)
        {
            s32 ret_val;
            u32 reg_addr;
            u16 phy_data;
            reg_addr = 1;
            __e1000_read_phy_reg(e1000_hw_ptr, reg_addr, &phy_data);

            printk(KERN_INFO "__e1000_read_phy_reg(): reg_addr = %u, phy_data = %u, ret = %d\n",
                    reg_addr, phy_data, ret_val);
        }
        break;
    }
//    __CRETE_E1000_WORKLOAD_ADAP_PTR(33, void, e1000_reinit_locked) // hanged
    __CRETE_E1000_WORKLOAD_ADAP_PTR(34, void, e1000_reset)
    __CRETE_E1000_WORKLOAD_HW_PTR  (35, void, e1000_reset_adaptive)
    __CRETE_E1000_WORKLOAD_HW_PTR  (36, s32, e1000_reset_hw)
    //    void    e1000_set_ethtool_ops(struct net_device *netdev)
    __CRETE_E1000_WORKLOAD_HW_PTR  (38, s32, e1000_set_mac_type)
    __CRETE_E1000_WORKLOAD_HW_PTR  (39, void, e1000_set_media_type)
    case 40:
    {
        //    int e1000_set_spd_dplx(struct e1000_adapter *adapter, u32 spd, u8 dplx)
        int (*__e1000_set_spd_dplx)(void *, u32, u8);
        __e1000_set_spd_dplx = (void *) kallsyms_lookup_name("e1000_set_spd_dplx");
        if(__e1000_set_spd_dplx)
        {
            int ret_val;
            u32 spd;
            u8 dplx;
            spd = 200;
            dplx = 0;
            ret_val = __e1000_set_spd_dplx(e1000_adapter_ptr, spd, dplx);

            printk(KERN_INFO "__e1000_set_spd_dplx(): spd = %u, dplx = %u, ret = %d\n",
                    spd, dplx, ret_val);
        }
        break;
    }
    __CRETE_E1000_WORKLOAD_ADAP_PTR(41, int, e1000_setup_all_rx_resources)
    __CRETE_E1000_WORKLOAD_ADAP_PTR(42, int, e1000_setup_all_tx_resources)
    __CRETE_E1000_WORKLOAD_HW_PTR  (43, s32, e1000_setup_led)
    __CRETE_E1000_WORKLOAD_HW_PTR  (44, s32, e1000_setup_link)
    __CRETE_E1000_WORKLOAD_ADAP_PTR(45, int, e1000_up) // lots of crete_make_concolic call
    __CRETE_E1000_WORKLOAD_HW_PTR  (46, void, e1000_update_adaptive)
    __CRETE_E1000_WORKLOAD_HW_PTR  (47, s32, e1000_update_eeprom_checksum)
    __CRETE_E1000_WORKLOAD_ADAP_PTR(48, void, e1000_update_stats)
    __CRETE_E1000_WORKLOAD_HW_PTR  (49, s32, e1000_validate_eeprom_checksum)
    __CRETE_E1000_WORKLOAD_HW_PTR  (50, s32, e1000_validate_mdi_setting)
    case 51:
    {
        //    s32 e1000_write_eeprom(struct e1000_hw *hw, u16 offset, u16 words, u16 *data)
        s32 (*__e1000_write_eeprom)(void *, u16, u16, u16 *);
        __e1000_write_eeprom = (void *) kallsyms_lookup_name("e1000_write_eeprom");
        if(__e1000_write_eeprom)
        {

            s32 ret_val;
            u16 offset;
            u16 words;
            u16 data[2];
            offset = 0;
            words = 2;
            ret_val = __e1000_write_eeprom(e1000_hw_ptr, offset, words, data);

            printk(KERN_INFO "__e1000_write_eeprom(): offset = %u, words = %u, data = %p, ret = %d\n",
                    offset, words, data, ret_val);
        }
        break;
    }
    case 52:
    {
        //    s32 e1000_write_phy_reg(struct e1000_hw *hw, u32 reg_addr, u16 phy_data)
        s32 (*__e1000_write_phy_reg)(void *, u32, u16);
        __e1000_write_phy_reg = (void *) kallsyms_lookup_name("e1000_write_phy_reg");
        if(__e1000_write_phy_reg)
        {
            s32 ret_val;
            u32 reg_addr;
            u16 phy_data;
            reg_addr = 1;
            ret_val = __e1000_write_phy_reg(e1000_hw_ptr, reg_addr, phy_data);

            printk(KERN_INFO "__e1000_read_phy_reg(): reg_addr = %u, phy_data = %u, ret = %d\n",
                    reg_addr, phy_data, ret_val);
        }

        break;
    }
    case 53:
    {
        //    void e1000_write_vfta(struct e1000_hw *hw, u32 offset, u32 value)
        void (*__e1000_write_vfta)(void *, u32, u32);
        __e1000_write_vfta = (void *) kallsyms_lookup_name("e1000_write_vfta");
        if(__e1000_write_vfta)
        {
            u32 offset;
            u32 value;
            offset = 0;
            value = 1989;
            __e1000_write_vfta(e1000_hw_ptr, offset, value);

            printk(KERN_INFO "__e1000_write_vfta(): offset = %u, value = %u\n",
                    offset, value);
        }
        break;
    }

    default :
        printk(KERN_INFO "crete_e1000_workload() invalid index: %d\n", index);
        break;
    }
}
/* ------------------------------- */

static ssize_t crete_ldk_wk_fops_read(struct file *sp_file,char __user *buf, size_t size, loff_t *offset)
{
    return 0;
}

static ssize_t crete_ldk_wk_fops_write(struct file *sp_file, const char __user *buf, size_t size, loff_t *offset)
{
    static int index = 0;

    crete_e1000_workload(++index);

    return size;
}

static struct file_operations crete_ldk_wk_fops = {
        .owner = THIS_MODULE,
        .read =  crete_ldk_wk_fops_read,
        .write = crete_ldk_wk_fops_write,
};
/* ------------------------------- */
static inline int init_crete_intrinsics(void)
{
    _crete_make_concolic = (void *) kallsyms_lookup_name("crete_make_concolic");

    if (!(_crete_make_concolic)) {
        printk(KERN_INFO "[crete] not all function found, please check crete-intrinsics.ko\n");
        return -1;
    }

    return 0;
}

static int __init kprobe_init(void)
{
    if(init_crete_intrinsics())
        return -1;

    if (!proc_create(CRETE_LDK_WL_PROCFS, 0666, NULL, &crete_ldk_wk_fops)) {
        printk(KERN_INFO "[CRETE ERROR] can't create profs: %s\n", CRETE_LDK_WL_PROCFS);
        remove_proc_entry(CRETE_LDK_WL_PROCFS, NULL);

        return -1;
    }

    return 0;
}

static void __exit kprobe_exit(void)
{
    crete_unregister_probes_e1000();
    remove_proc_entry(CRETE_LDK_WL_PROCFS, NULL);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
