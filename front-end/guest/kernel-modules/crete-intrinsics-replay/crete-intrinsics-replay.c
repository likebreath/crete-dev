#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include<linux/slab.h>
#include <linux/string.h>

#include "crete/custom_opcode.h"
#include "crete/common.h"

//MODULE_LICENSE("GPL");
//MODULE_AUTHOR("Bo Chen (chenbo@pdx.edu)");
//MODULE_DESCRIPTION("CRETE intrinsics for replay");

struct file *file_open(const char *path, int flags, int rights)
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

static void file_close(struct file *file)
{
    filp_close(file, NULL);
}

static int file_read(struct file *file, unsigned long long offset,
        unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

static int get_file_size(const char* file_path)
{
    struct path p;
    struct kstat ks;

    kern_path(file_path, 0, &p);
    vfs_getattr(&p, &ks);

    return ks.size;
}

void crete_capture_begin(void)
{
    ;
}

void crete_capture_end(void)
{
    ;
}

void crete_make_concolic(void* addr, size_t size, const char* name)
{
    char file_path[128];
    if((strlen(CRETE_REPLAY_CURRENT_TC) + strlen(name) + 2) >= 128)
    {
        printk(KERN_INFO "[CRETE ERROR] tc_element_path is longer than 128 bytes!\n");
        return;
    }
    strcpy(file_path, CRETE_REPLAY_CURRENT_TC);
    strcat(file_path, "/");
    strcat(file_path, name);
    printk(KERN_INFO "[crete] crete_make_concolic(), input file: %s", file_path);

    int file_size = get_file_size(file_path);
    if(file_size != size)
    {
        printk(KERN_INFO "[CRETE ERROR] crete_make_concolic() size = %d "
                "and file_size = %d mismatch!\n",
                size, file_size);
        return;
    }

    struct file * tc_file = file_open(file_path, O_RDONLY, 0);
    int bytes_read = file_read(tc_file, 0, addr, size);
    if(bytes_read != file_size)
    {
        printk(KERN_INFO "[CRETE ERROR] Only get %d bytes from reading file "
                "while expecting to read %d bytes\n",
                bytes_read, size);
    }

    file_close(tc_file);
}

static int __init crete_intrinsics_replay_init(void)
{
    printk(KERN_INFO "[crete] crete_intrinsics_replay_init()!\n");

//    char test[13];
//    test[12] = 0;
//    printk(KERN_INFO "[crete] before crete_make_concolic(), test = %s\n", test);
//    crete_make_concolic(test, 12, "test");
//    printk(KERN_INFO "[crete] after crete_make_concolic(), test = %s\n", test);

    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit crete_intrinsics_replay_exit(void)
{
}

EXPORT_SYMBOL(crete_capture_begin);
EXPORT_SYMBOL(crete_capture_end);
EXPORT_SYMBOL(crete_make_concolic);

// for Debuging
static void crete_test(int a)
{
    printk(KERN_INFO "crete_test() is called: a = %d\n", a);
}
EXPORT_SYMBOL(crete_test);

module_init(crete_intrinsics_replay_init);
module_exit(crete_intrinsics_replay_exit);
