CONFIG_MODULE_SIG=n

ccflags-y := -std=gnu99 -Wno-declaration-after-statement \
             -DHOOK1_HEX=$(HOOK1_HEX) \
             -DHOOK2_HEX=$(HOOK2_HEX)

obj-m += yolo_ebpf.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -rf *.ko *.o *.o.ur-safe *.order *.symvers .cache.mk .tmp_versions/ .*.cmd *.mod.c

install: yolo_ebpf.ko
	rmmod yolo_ebpf
	insmod yolo_ebpf.ko
