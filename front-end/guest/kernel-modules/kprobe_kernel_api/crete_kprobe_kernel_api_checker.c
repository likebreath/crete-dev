#define CRETE_RESOURCE_CHECKER_ALLOC_LIST_SIZE 128
static int crete_resource_checker_enable = 1;
static int crete_rc_potential_bugs = 0;

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
    RC_FATAL = 1989,
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

static inline int crete_resource_checker_alloc_entry(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info);
static inline int crete_resource_checker_alloc_return(struct kretprobe_instance *ri, struct pt_regs *regs,
        int target_arg_indx, struct CRETE_RC_ALLOC_INFO *array, uint16_t *array_size, const char *info);
static inline int crete_resource_checker_free_entry(struct kretprobe_instance *ri,
        struct pt_regs *regs, int target_arg_indx, const char *info);
static inline int crete_resource_checker_free_return(struct kretprobe_instance *ri, struct pt_regs *regs,
        struct CRETE_RC_ALLOC_INFO *alloc_array, uint16_t *array_size, const char *info);

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(alloc_func, alloc_arg_index, free_func)           \
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
            crete_resource_checker_alloc_return(ri, regs, alloc_arg_index,                          \
                    cl_##free_func, &cl_size_##free_func, #alloc_func);                             \
            return 0;                                                                               \
        }                                                                                           \
        static struct kretprobe rc_kretp_##alloc_func= {                                            \
                .kp.symbol_name = #alloc_func,                                                      \
                .entry_handler = entry_handler_cl_##alloc_func,                                     \
                .handler = ret_handler_cl_##alloc_func,                                             \
                .data_size = sizeof(struct CRETE_RC_INFO),                                          \
                .maxactive = NR_CPUS,                                                               \
        };

#define __CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(free_func, free_arg_index)                         \
        static struct CRETE_RC_ALLOC_INFO cl_##free_func[CRETE_RESOURCE_CHECKER_ALLOC_LIST_SIZE];   \
        static uint16_t cl_size_##free_func = 0;                                                    \
        static int entry_handler_cl_##free_func(struct kretprobe_instance *ri, struct pt_regs *regs)\
        {                                                                                           \
            if(crete_resource_checker_free_entry(ri, regs, free_arg_index, #free_func)) {           \
                return 1;                                                                           \
            }                                                                                       \
            return 0;                                                                               \
        }                                                                                           \
        static int ret_handler_cl_##free_func(struct kretprobe_instance *ri, struct pt_regs *regs)  \
        {                                                                                           \
            crete_resource_checker_free_return(ri, regs, cl_##free_func,                            \
                    &cl_size_##free_func, #free_func);                                              \
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
            printk(KERN_INFO "[CRETE INFO] Missed probing %d instances of %s.\n",       \
                    rc_kretp_##func_name.nmissed, rc_kretp_##func_name.kp.symbol_name); \
        }

#define __CRETE_RESET_RC(free_func)                                                     \
        memset(cl_##free_func, 0, sizeof(cl_##free_func));                              \
        cl_size_##free_func = 0;

#define __CRETE_CHECK_RC_ARRAY(free_func)                                               \
        for(i = 0; i < cl_size_##free_func; ++i)                                        \
        {                                                                               \
            printk(KERN_INFO "[CRETE REPORT] Potential bug: 'resource leak',"           \
                    "missing call to "#free_func" (alloc_site = %p, ptr = %p).\n",      \
                    (void *)(cl_##free_func[i].alloc_site),                             \
                    (void *)(cl_##free_func[i].alloc_value));                           \
            ++crete_rc_potential_bugs;                                                  \
        }

__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(kfree, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__kmalloc, -1, kfree);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(kmem_cache_alloc_trace, -1, kfree);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(__kmalloc_node, -1, kfree);

__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(vfree, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(vzalloc, -1, vfree);

__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_disable_device, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_enable_device, 0, pci_disable_device);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_enable_device_mem, 0, pci_disable_device);

__CRETE_DEF_KPROBE_RESOURCE_MONITOR_FREE(pci_release_regions, 0);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_request_regions, 0, pci_release_regions);
__CRETE_DEF_KPROBE_RESOURCE_MONITOR_ALLOC(pci_request_selected_regions_exclusive, 0, pci_release_regions);

static inline int register_probes_crete_rc(void)
{
    __CRETE_REG_KPROBE_RC(kfree);
    __CRETE_REG_KPROBE_RC(__kmalloc);
    __CRETE_REG_KPROBE_RC(kmem_cache_alloc_trace);
    __CRETE_REG_KPROBE_RC(__kmalloc_node);

    __CRETE_REG_KPROBE_RC(vfree);
    __CRETE_REG_KPROBE_RC(vzalloc);

    __CRETE_REG_KPROBE_RC(pci_disable_device);
    __CRETE_REG_KPROBE_RC(pci_enable_device);
    __CRETE_REG_KPROBE_RC(pci_enable_device_mem);

    __CRETE_REG_KPROBE_RC(pci_release_regions);
    __CRETE_REG_KPROBE_RC(pci_request_regions);
    __CRETE_REG_KPROBE_RC(pci_request_selected_regions_exclusive);

    return 0;
}

static inline void unregister_probes_crete_rc(void)
{
    __CRETE_UNREG_KPROBE_RC(kfree);
    __CRETE_UNREG_KPROBE_RC(__kmalloc);
    __CRETE_UNREG_KPROBE_RC(kmem_cache_alloc_trace);
    __CRETE_UNREG_KPROBE_RC(__kmalloc_node);

    __CRETE_UNREG_KPROBE_RC(vfree);
    __CRETE_UNREG_KPROBE_RC(vzalloc);

    __CRETE_UNREG_KPROBE_RC(pci_disable_device);
    __CRETE_UNREG_KPROBE_RC(pci_enable_device);
    __CRETE_UNREG_KPROBE_RC(pci_enable_device_mem);

    __CRETE_UNREG_KPROBE_RC(pci_release_regions);
    __CRETE_UNREG_KPROBE_RC(pci_request_regions);
    __CRETE_UNREG_KPROBE_RC(pci_request_selected_regions_exclusive);
}

static inline void clear_crete_rc_array(void)
{
    __CRETE_RESET_RC(kfree);
    __CRETE_RESET_RC(vfree);
    __CRETE_RESET_RC(pci_disable_device);
    __CRETE_RESET_RC(pci_release_regions);
}
static inline void reset_crete_rc(void)
{
    clear_crete_rc_array();

    crete_resource_checker_enable = 1;
    crete_rc_potential_bugs = 0;
}

static inline void check_crete_rc_array(void)
{
    uint16_t i;

    __CRETE_CHECK_RC_ARRAY(kfree);
    __CRETE_CHECK_RC_ARRAY(vfree);
    __CRETE_CHECK_RC_ARRAY(pci_disable_device);
    __CRETE_CHECK_RC_ARRAY(pci_release_regions);

    if(crete_rc_potential_bugs != 0)
    {
        panic("[CRETE RC] panic on potential bugs: %d\n", crete_rc_potential_bugs);
    }

    crete_resource_checker_enable = 0;
    crete_rc_potential_bugs = 0;
}

/* ------------------------------- */
// Define entry handlers for each interested function

static inline void disable_crete_resource_checker(void)
{
    printk(KERN_INFO  "[CRETE Warning] 'disable_crete_resource_checker()' indicating a crete-rc error.\n");

    crete_resource_checker_enable = 0;
    clear_crete_rc_array();

    panic("[CRETE] panic on CRETE-RC error\n");
}

static inline int crete_resource_checker_prelogue(size_t ret_addr)
{
    if(!crete_resource_checker_enable)
        return -RC_DISABLED;

    if(!_crete_get_current_target_pid)
    {
        printk(KERN_INFO  "[CRETE ERROR] '_crete_get_current_target_pid()' is not initialized.\n");

        disable_crete_resource_checker();
        return -RC_FATAL;
    }

//    if(_crete_get_current_target_pid() != current->pid)
//        return -RC_MIS_PID;

    if(!(target_module.m_mod_loaded &&
         (within_module_core(ret_addr, &target_module.m_mod))))
    {
        return -RC_OUT_MODULE;
    }

    return 0;
}

static inline int crete_resource_checker_alloc_internal(struct CRETE_RC_ALLOC_INFO *array, uint16_t *array_size,
        size_t alloc_value, size_t alloc_site, const char *info)
{
    uint16_t current_index = *array_size;

    CRETE_DBG_RC(
    printk(KERN_INFO  "[CRETE INFO] crete_rc_alloc(): current_index = %u, alloc_value = %p, alloc_site = %p [%s]\n",
            current_index, (void *)alloc_value, (void *)alloc_site, info);
    );

    if(alloc_value == 0)
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_alloc_internal(): alloc_value = 0, alloc_site = %p [%s].\n",
                (void *)alloc_site, info);

        disable_crete_resource_checker();
        return -RC_FATAL;
    }

    if(current_index >= CRETE_RESOURCE_CHECKER_ALLOC_LIST_SIZE)
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_alloc_internal(): current_index = %u [%s]\n", current_index, info);

        disable_crete_resource_checker();
        return -RC_FATAL;
    }

    array[current_index].alloc_value = alloc_value;
    array[current_index].alloc_site = alloc_site;
    *array_size = current_index + 1;

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

        disable_crete_resource_checker();
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
    case 2: // arg[3]
        my_data->info_value = regs->cx;
        break;
    default:
        my_data->info_value = 0;

        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_alloc_entry(): "
                "invalid target_arg_indx = %d [%s]!\n", target_arg_indx, info);
        disable_crete_resource_checker();
        return -RC_FATAL;
        break;
    }

    return 0;
}

static inline int crete_resource_checker_alloc_return(struct kretprobe_instance *ri, struct pt_regs *regs,
        int target_arg_indx, struct CRETE_RC_ALLOC_INFO *array, uint16_t *array_size, const char *info)
{
    size_t alloc_value;
    size_t alloc_site;
    int ret_prelogue;

    ret_prelogue = crete_resource_checker_prelogue((size_t)ri->ret_addr);
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
        if(regs_return_value(regs) != 0)
        {
            printk(KERN_INFO  "[CRETE WARNING] crete_rc_alloc_return(): "
                    "skipping alloc_value = %p [%s] as its return value is not 0 (indicating an alloc failure)]!\n",
                    (void *)alloc_value, info);
            return -RC_SKIPPED;
        }
    }

#if defined(__USED_OLD_MODULE_LAYOUT)
    alloc_site = (unsigned long)ri->ret_addr - (unsigned long)target_module.m_mod.module_core;
#else
    alloc_site = (unsigned long)ri->ret_addr - (unsigned long)target_module.m_mod.core_layout.base;
#endif

    return crete_resource_checker_alloc_internal(array, array_size, alloc_value, alloc_site, info);
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
    case 2: // arg[3]
        my_data->info_value = regs->cx;
        break;
    default:
        my_data->info_value = 0;

        printk(KERN_INFO  "[CRETE ERROR] crete_resource_checker_free_entry(): "
                "invalid target_arg_indx = %d [%s]!\n", target_arg_indx, info);
        disable_crete_resource_checker();
        return -RC_FATAL;
        break;
    }

    return 0;
}

static inline int crete_resource_checker_free_return(struct kretprobe_instance *ri, struct pt_regs *regs,
        struct CRETE_RC_ALLOC_INFO *alloc_array, uint16_t *array_size, const char *info)
{
    uint16_t current_index;
    size_t free_value;
    size_t free_site;
    uint16_t i;

    int ret_prelogue = crete_resource_checker_prelogue((size_t)ri->ret_addr);
    if(ret_prelogue) return ret_prelogue;

    current_index = *array_size;
    free_value = ((struct CRETE_RC_INFO *)ri->data)->info_value;

#if defined(__USED_OLD_MODULE_LAYOUT)
    free_site = (unsigned long)ri->ret_addr - (unsigned long)target_module.m_mod.module_core;
#else
    free_site = (unsigned long)ri->ret_addr - (unsigned long)target_module.m_mod.core_layout.base;
#endif

    CRETE_DBG_RC(
    printk(KERN_INFO "[CRETE INFO] crete_rc_free() entered: free_value = %p, free_site = %p [%s].\n",
            (void *)free_value, (void *)free_site, info);
    );

    if(free_value == 0)
    {
        printk(KERN_INFO  "[CRETE ERROR] 'crete_resource_checker_free()': free_value == 0, free_site = %p [%s]\n",
                (void *)free_site, info);

        disable_crete_resource_checker();
        return -RC_FATAL;
    }

    for(i = current_index; i > 0; --i)
    {
        if(alloc_array[i-1].alloc_value == free_value)
        {
            CRETE_DBG_RC(
            printk(KERN_INFO "[CRETE INFO] match found: ptr = %p, alloc_site = %p, free_site = %p [%s].\n",
                    (void *)free_value, (void *)(alloc_array[i-1].alloc_site), (void *)free_site, info);
            );
            break;
        }
    }

    // No match found
    if(i == 0)
    {
        printk(KERN_INFO "[CRETE REPORT] Potential bug: double free, free_value = %p, free_site = %p [%s].\n",
                (void *)free_value, (void *)free_site, info);

        ++crete_rc_potential_bugs;
        return -RC_REPORT_BUG;
    }

    // Match found
    if(alloc_array[i -1].alloc_value != free_value)
    {
        printk(KERN_INFO  "[CRETE ERROR] inconsistent match with 'free_value'\n");

        disable_crete_resource_checker();
        return -RC_FATAL;
    }

    // Remove matched from alloc_array
    for(;i < current_index; ++i)
    {
        alloc_array[i-1] = alloc_array[i];
    }
    alloc_array[i].alloc_site = 0;
    alloc_array[i].alloc_value = 0;

    *array_size = current_index - 1;

    return 0;
}
