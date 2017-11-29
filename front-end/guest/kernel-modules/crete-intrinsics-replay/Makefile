obj-m += crete-intrinsics-replay.o
EXTRA_CFLAGS=-I$(PWD)/include -Wno-unused-variable

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
