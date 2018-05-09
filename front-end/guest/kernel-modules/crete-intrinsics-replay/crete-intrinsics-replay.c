#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include "crete/common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bo Chen (chenbo@pdx.edu)");
MODULE_DESCRIPTION("CRETE intrinsics for tc replay");

struct TestCases
{
    struct list_head list;
    char *name;
    char *value;
    uint32_t size;
};

static struct TestCases *tc_list;

static void clear_tc_list(void)
{
    if(tc_list)
    {
        struct TestCases *tmp;
        struct list_head *pos, *q;

        list_for_each_safe(pos, q, &tc_list->list)
        {
             tmp = list_entry(pos, struct TestCases, list);
             list_del(pos);
             kfree(tmp->name);
             kfree(tmp->value);
             kfree(tmp);
        }
    }
}

static void reset_tc_list(void)
{
    clear_tc_list();

    tc_list = (struct TestCases *)kmalloc(sizeof(struct TestCases), GFP_KERNEL);
    INIT_LIST_HEAD(&tc_list->list);
}

static void add_tc_list(char *name, char *value, uint32_t size)
{
    struct TestCases *tmp;

    tmp = (struct TestCases *)kmalloc(sizeof(struct TestCases), GFP_KERNEL);
    tmp->name = name;
    tmp->size = size;
    tmp->value = value;

    list_add(&(tmp->list), &(tc_list->list));
}

static void print_tc_list(void)
{
    struct TestCases *tmp;
    struct list_head *pos;
    int count;

    count = 0;
    if(tc_list)
    {
        list_for_each(pos, &tc_list->list)
        {
             tmp = list_entry(pos, struct TestCases, list);
             printk(KERN_INFO "tc_list[%d] (%s, %u)\n",
                     ++count, tmp->name, tmp->size);
        }
    }
}

#define CONCOLIC_NAME_SIZE 128

struct UniqueNames
{
    struct list_head list;
    char name[CONCOLIC_NAME_SIZE];
};

static struct UniqueNames *unique_names; // clear after replay of a tc

static void clear_name_list(void)
{
    if(unique_names)
    {
        struct UniqueNames *tmp;
        struct list_head *pos, *q;

        list_for_each_safe(pos, q, &unique_names->list)
        {
             tmp = list_entry(pos, struct UniqueNames, list);
             list_del(pos);
             kfree(tmp);
        }
    }
}

static void reset_name_list(void)
{
    clear_name_list();

    unique_names = (struct UniqueNames *)kmalloc(sizeof(struct UniqueNames), GFP_KERNEL);
    INIT_LIST_HEAD(&unique_names->list);
}

static bool add_to_name_list(const char *name)
{
    struct UniqueNames *tmp;

    if(!(sizeof(name) < CONCOLIC_NAME_SIZE))
        return false;

    tmp = (struct UniqueNames *)kmalloc(sizeof(struct UniqueNames), GFP_KERNEL);
    strcpy(tmp->name, name);
    list_add(&(tmp->list), &(unique_names->list));

    return true;
}

static void print_name_list(void)
{
    struct UniqueNames *tmp;
    struct list_head *pos;
    int count;
    count = 0;

    list_for_each(pos, &unique_names->list)
    {
         tmp = list_entry(pos, struct UniqueNames, list);
         printk(KERN_INFO "name_list[%d] = %s\n",
                 ++count, tmp->name);
    }
}

#define MSG_SIZE 255
static char msg_from_user[MSG_SIZE+1];
#define SUFFIX_SIZE 7
static char process_suffix[SUFFIX_SIZE + 1];

static uint32_t target_pid = 0;

static void reset_module(void)
{
    reset_name_list();
    reset_tc_list();
    target_pid = 0;
    process_suffix[0] = '\0';
}

static void clear_module(void)
{
    clear_name_list();
    clear_tc_list();
}

enum WriteMode
{
    Empty,
    TargetPid,
    Suffix,
    TestCase,
    Reset
};

static enum WriteMode mode = Empty;

static ssize_t crete_replay_fops_read(struct file *sp_file,char __user *buf, size_t size, loff_t *offset)
{
    printk(KERN_INFO "---------------------------------------------\n");
    printk(KERN_INFO "crete_replay_fops_read(): mode = %d, target_pid = %u, suffix = \'%s\'\n",
            mode, target_pid, process_suffix);
    print_name_list();
    print_tc_list();
    printk(KERN_INFO "---------------------------------------------\n");

    return 0;
}

// msg format: name_size (4 bytes), name (name_size bytes),
//             value_size (4 bytes), value (value_size bytes)
static void parse_msg_for_tc(const char *msg, size_t size)
{
    uint32_t name_size;
    uint32_t name_offset;
    char *name;

    uint32_t value_size;
    uint32_t value_offset;
    char *value;

    name_offset = sizeof(uint32_t);
    if(name_offset > size)
        goto ERR;

    name_size = *(uint32_t *)msg;

    value_offset = name_offset + name_size + sizeof(uint32_t);
    if(value_offset > size)
        goto ERR;

    value_size = *(uint32_t *)(msg + name_offset + name_size);

    //sanity check
    if((value_offset + value_size) != size )
        goto ERR;

    name = (char *)kmalloc(name_size + 1, GFP_KERNEL);
    memcpy(name, msg + name_offset, name_size);
    name[name_size] = '\0';

    value = (char *)kmalloc(value_size, GFP_KERNEL);
    memcpy(value, msg + value_offset, value_size);

    add_tc_list(name, value, value_size);

    return;

ERR:
    printk(KERN_INFO "[CRETE ERROR] add_tc_list: inconsistent msg "
            "(size = %zu, name_size = %u, name_offset = %u, value_size = %u, value_offset = %u)\n",
            size, name_size, name_offset, value_size, value_offset);
}

static ssize_t crete_replay_fops_write(struct file *sp_file, const char __user *buf, size_t size, loff_t *offset)
{
    if(mode == Empty)
    {
        if(size > MSG_SIZE)
        {
            printk(KERN_INFO "[CRETE ERROR] crete_replay_fops_write: size (%zu) > MSG_SIZE(%d)\n",
                    size, MSG_SIZE);
        } else {
            copy_from_user(msg_from_user, buf, size);
            msg_from_user[size] = '\0';

//            printk(KERN_INFO "msg_from_user = \'%s\'\n", msg_from_user);

            if (strcmp(msg_from_user, "TargetPid") == 0) {
                mode = TargetPid;
            } else if (strcmp(msg_from_user, "Suffix") == 0) {
                mode = Suffix;
            } else if(strcmp(msg_from_user, "TestCase") == 0) {
                mode = TestCase;
            } else if (strcmp(msg_from_user, "Reset") == 0) {
                reset_module();
            }
        }

        return size;
    }

    switch(mode) {
    case TargetPid:
        if(size == sizeof(target_pid))
        {
            copy_from_user(&target_pid, buf, size);
        } else {
            printk(KERN_INFO "[CRETE ERROR] crete_replay_fops_write: size (%zu) != sizeof(target_pid)(%zu)\n",
                    size, sizeof(target_pid));
        }
        break;

    case Suffix:
        if(size > SUFFIX_SIZE)
        {
            printk(KERN_INFO "[CRETE ERROR] crete_replay_fops_write: size (%zu) > SUFFIX_SIZE(%d)\n",
                    size, SUFFIX_SIZE);
        } else {
            copy_from_user(process_suffix, buf, size);
            process_suffix[size] = '\0';
        }
        break;

    case TestCase:
        if(size > MSG_SIZE)
        {
            printk(KERN_INFO "[CRETE ERROR] crete_replay_fops_write: size (%zu) > MSG_SIZE(%d)\n",
                    size, MSG_SIZE);
        } else {
            copy_from_user(msg_from_user, buf, size);

            parse_msg_for_tc(msg_from_user, size);
        }
        break;

    default:
        break;
    }

    mode = Empty;
    return size;
}

static struct file_operations crete_replay_fops = {
        .owner = THIS_MODULE,
        .read =  crete_replay_fops_read,
        .write = crete_replay_fops_write,
};

// @ret: 1, unique_name changed
//       0, unchanged
//      -1, error happened
static int get_unique_name(char *unique_name)
{
    struct UniqueNames *tmp;
    struct list_head *pos;

    size_t len_un;
    const char *current_name;
    size_t len_current;

    char suffix[8] = {0};

    int ret;

    len_un = strlen(unique_name);
    ret = 0;

    // check for each existed names, and get the biggest suffix if prefix matches
    list_for_each(pos, &unique_names->list)
    {
         tmp = list_entry(pos, struct UniqueNames, list);
         current_name = tmp->name;
         len_current = strlen(current_name);

         // check for prefix
         if((len_un <= len_current) && (strncmp(current_name, unique_name, len_un) == 0))
         {
             if(len_un == len_current)
             {
                 strcpy(suffix, "_0"); // to be added by 1

             } else {
                 // Naming convention should be "name_pN_N"
                 if(current_name[len_un] != '_')
                 {
                     printk(KERN_INFO "[CRETE ERROR] unexpected name: %s (should be \'name_pN_N\')\n", current_name);
                     return -1;
                 }

                 // current suffix is longer, then its bigger
                 if(strlen(suffix) < (len_current - len_un))
                 {
                     strcpy(suffix, current_name + len_un);
                 } else if (strlen(suffix) == (len_current - len_un)) {
                     if(strcmp(suffix, current_name + len_un) < 0)
                     {
                         strcpy(suffix, current_name + len_un);
                     }
                 }
             }
         }
    }

    // If suffix is not empty, adjust it by adding 1 and append it to unique_name
    if(strlen(suffix) != 0)
    {
        size_t suffix_len;
        suffix_len = strlen(suffix);

        if( suffix_len < 2 && suffix[0] != '_')
        {
            printk(KERN_INFO "[CRETE ERROR] unexpected name suffix: %s (should be \'_N\')\n", suffix);
            return -1;
        }

        // add suffix by 1, now only supports suffix smaller than '99'
        if(suffix_len == 2)
        {
            if(!(strcmp(suffix, "_0") >= 0 &&
                    (strcmp(suffix, "_9") <= 0)))
            {
                printk(KERN_INFO "[CRETE ERROR] unexpected name suffix: %s (should be \'_N\')\n", suffix);
                return -1;
            }

            if(strcmp(suffix, "_9") == 0)
            {
                strcpy(suffix, "_10");
            } else {
                suffix[1] += 1;
            }
        } else if (suffix_len == 3) {
            if(!(strcmp(suffix, "_00") >= 0 &&
                    (strcmp(suffix, "_99") <= 0)))
            {
                printk(KERN_INFO "[CRETE ERROR] unexpected name suffix: %s (should be \'_N\')\n", suffix);
                return -1;
            }

            if(strcmp(suffix, "_99") == 0)
            {
                strcpy(suffix, "_100");
            } else if (suffix[2] == '9') {
                suffix[1] += 1;
                suffix[2] = '0';
            } else {
                suffix[2] += 1;
            }
        } else {
            printk(KERN_INFO "[CRETE ERROR] too large suffix: %s (now only supports suffix smaller than \'99\'\n", suffix);
            return -1;
        }

        strcat(unique_name, suffix);

        ret = 1;
    }

    if(!add_to_name_list(unique_name))
    {
        printk(KERN_INFO "[CRETE ERROR] can't add_to_list() failed: %s\n", unique_name);
        return -1;
    }

    return ret;
}

static int crete_make_conoclic_internal(void* addr, size_t size, const char* name)
{
    struct TestCases *tmp;
    struct list_head *pos;

    list_for_each(pos, &tc_list->list)
    {
         tmp = list_entry(pos, struct TestCases, list);
         if(strcmp(tmp->name, name) == 0)
         {
             if(tmp->size != size)
             {
                 printk(KERN_INFO "[CRETE ERROR] crete_make_conoclic_internal(): \'%s\', size = %zu "
                         "and tc_list_size = %u mismatch!\n",
                         name, size, tmp->size);
                 return -1;
             } else {
                 memcpy(addr, tmp->value, size);
                 return 1;
             }
         }
    }

//    printk(KERN_INFO "[CRETE Warning] crete_make_conoclic_internal: no match found in tc_list, skip \'%s\'\n",
//            name);

    return 0;
}

void crete_make_concolic(void* addr, size_t size, const char* name)
{
    static char tmp_name[CONCOLIC_NAME_SIZE];
    int err;

    if(current->pid != target_pid)
    {
//        printk(KERN_INFO "[CRETE Warning] crete_make_concolic: not from target_pid: (addr = %p, size = %zu, name = %s)\n",
//                addr, size, name);
        return;
    }

    // check and get unique_name, by adding process_suffix and maybe name suffix
    strcpy(tmp_name, name);
    strcat(tmp_name, process_suffix);

    err = get_unique_name(tmp_name);
    if(err == -1)
    {
        printk(KERN_INFO "[CRETE ERROR] get_unique_name() failed in crete_make_concolic() (addr = %p, size = %zu, name = %s)!\n",
                addr, size, name);
        return;
    }

    crete_make_conoclic_internal(addr, size, tmp_name);
}

void crete_kernel_oops(void)
{
    ;
}

static int __init crete_intrinsics_replay_init(void)
{
    printk(KERN_INFO "[crete] crete_intrinsics_replay_init()!\n");

    reset_module();

    if (!proc_create(CRETE_REPLAY_PROCFS, 0666, NULL, &crete_replay_fops)) {
        printk(KERN_INFO "[CRETE ERROR] can't create profs: %s\n", CRETE_REPLAY_PROCFS);

        clear_module();
        remove_proc_entry(CRETE_REPLAY_PROCFS, NULL);

        return -1;
    }


    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit crete_intrinsics_replay_exit(void)
{
    clear_module();
    remove_proc_entry(CRETE_REPLAY_PROCFS, NULL);
}

EXPORT_SYMBOL(crete_make_concolic);
EXPORT_SYMBOL(crete_kernel_oops);

module_init(crete_intrinsics_replay_init);
module_exit(crete_intrinsics_replay_exit);
