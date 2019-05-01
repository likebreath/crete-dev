#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define CRETE_TC_REPLAYABLE_ARRAY_SIZE 1024
#define CRETE_TC_ELEM_NAME_SIZE 128
// =======================================
static int crete_tcr_mutex_failed_count = 0; // not protected by MUTEX

static DEFINE_MUTEX(crete_tcr_mutex);
static char crete_tcr_info_array[CRETE_TC_REPLAYABLE_ARRAY_SIZE][CRETE_TC_ELEM_NAME_SIZE];
static uint32_t crete_tcr_info_count = 0;

static inline int add_crete_tcr_info(const char *concolic_name) {
    if(mutex_is_locked(&crete_tcr_mutex))
    {
        ++crete_tcr_mutex_failed_count;
        printk(KERN_INFO  "[CRETE INFO] add_crete_tcr_info(): mutex is locked %d ['%s']\n",
                crete_tcr_mutex_failed_count, concolic_name);
        return -1;
    }

    mutex_lock(&crete_tcr_mutex);

    if((crete_tcr_info_count >= CRETE_TC_REPLAYABLE_ARRAY_SIZE) ||
            ((strlen(concolic_name) > CRETE_TC_ELEM_NAME_SIZE)))
    {
        printk(KERN_INFO  "[CRETE ERROR] add_crete_tcr_info(): current_index = %u ['%s']\n",
                crete_tcr_info_count, concolic_name);

        mutex_unlock(&crete_tcr_mutex);
//        crete_resource_monitor_panic();
        return -1;
    }

    strcpy(crete_tcr_info_array[crete_tcr_info_count], concolic_name);

    crete_tcr_info_count++;

    mutex_unlock(&crete_tcr_mutex);

    return 0;
}

static inline void crete_check_tc_replayable_reset(void)
{
    if(mutex_is_locked(&crete_tcr_mutex))
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_check_tc_replayable_start(): mutex is locked %d\n",
                crete_tcr_mutex_failed_count);
//        crete_resource_monitor_panic();
        return;
    }


    mutex_lock(&crete_tcr_mutex);

    crete_tcr_mutex_failed_count = 0;
    memset(crete_tcr_info_array, 0, CRETE_TC_REPLAYABLE_ARRAY_SIZE * CRETE_TC_ELEM_NAME_SIZE);
    crete_tcr_info_count = 0;

    mutex_unlock(&crete_tcr_mutex);
}

// ----------------------------
static ssize_t crete_tcr_fops_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{
    unsigned long err_ret;

    if(size != (CRETE_TC_REPLAYABLE_ARRAY_SIZE * CRETE_TC_ELEM_NAME_SIZE))
    {
        printk(KERN_INFO  "[CRETE ERROR] crete_tcr_fops_read(): incorrect array size: size = %zu\n"
                "CRETE_TC_REPLAYABLE_ARRAY_SIZE = %d, CRETE_TC_ELEM_NAME_SIZE = %d\n",
                size, CRETE_TC_REPLAYABLE_ARRAY_SIZE,  CRETE_TC_ELEM_NAME_SIZE);
        return 0;
    }

    err_ret = copy_to_user(buf, crete_tcr_info_array, size);

    if(err_ret) {
        printk(KERN_INFO  "[CRETE ERROR] crete_tcr_fops_read(): copy_to_user() failed\n");
        return 0;
    }

    return crete_tcr_info_count;
}

static struct file_operations crete_tcr_fops = {
        .owner = THIS_MODULE,
        .read =  crete_tcr_fops_read,
};
