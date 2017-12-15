#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bo Chen (chenbo@pdx.edu)");
MODULE_DESCRIPTION("CRETE probes for e1000 entry functions");

static void (*_crete_make_concolic)(void*, size_t, const char *);

#define __CRETE_DEF_KPROBE(func_name)                                                              \
        static int entry_handler_##func_name(struct kretprobe_instance *ri, struct pt_regs *regs); \
        static struct kretprobe kretp_##func_name = {                                              \
                .kp.symbol_name = #func_name,                                                      \
                .entry_handler = entry_handler_##func_name,                                        \
        };

#define __CRETE_REG_KPROBE(func_name)                                          \
        {                                                                      \
            if(register_kretprobe(&kretp_##func_name))                         \
            {                                                                  \
                printk(KERN_INFO "kprobe register failed for "#func_name"\n"); \
                return -1;                                                     \
            }                                                                  \
        }

#define __CRETE_UNREG_KPROBE(func_name)  unregister_kretprobe(&kretp_##func_name);

/* ------------------------------- */
// Define interested functions to hook
__CRETE_DEF_KPROBE(e1000_ioctl);

static inline int crete_register_probes_e1000(void)
{
    printk(KERN_INFO "crete_register_probes_e1000()\n");
    __CRETE_REG_KPROBE(e1000_ioctl);

    return 0;
}
EXPORT_SYMBOL(crete_register_probes_e1000);

static inline void crete_unregister_probes_e1000(void)
{
    printk(KERN_INFO "crete_unregister_probes_e1000()\n");
    __CRETE_UNREG_KPROBE(e1000_ioctl);
}
EXPORT_SYMBOL(crete_unregister_probes_e1000);

/* ------------------------------- */
// Define entry handlers for each interested function

//static int e1000_ioctl(
//    struct net_device *netdev,
//    struct ifreq *ifr,
//    int cmd                       [symbolic]
//);
static int entry_handler_e1000_ioctl(struct kretprobe_instance *ri, struct pt_regs *regs)
{
//    char *sp_regs = (char *)kernel_stack_pointer(regs);
//    printk(KERN_INFO "e1000_ioctl() entered: cmd = %x\n", (int)regs->cx);
    _crete_make_concolic(&regs->cx, sizeof(int), "e1000_ioctl_arg3");
    return 0;
}
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

    return 0;
}

static void __exit kprobe_exit(void)
{
}

module_init(kprobe_init)
module_exit(kprobe_exit)
