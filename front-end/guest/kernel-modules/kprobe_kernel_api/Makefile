obj-m += crete_kprobe_kernel_api.o
my_dir = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
# EXTRA_CFLAGS=-DCRETE_USED_OLD_MODULE_LAYOUT
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(my_dir) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(my_dir) clean
