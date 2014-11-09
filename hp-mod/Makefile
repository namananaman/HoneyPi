CS5413 := hp_mod
CS5413_MODNAME := hp
DIST_FILE=sniffer.tar.gz

EXTRA_CFLAGS = -O3

ifneq ($(KERNELRELEASE),)
# in Kernel
obj-m := $(CS5413_MODNAME).o
$(CS5413_MODNAME)-objs := $(CS5413).o

else
KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
KSRC := /lib/modules/$(KVER)/source
PWD := $(shell pwd)

all: default

default:
	#KCPPFLAGS passes these flags to the kernel module makefiles
	KCPPFLAGS="-I$(PWD)/../include" $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm -f sniffer_control sniffer_read *.tar.gz *.dev

endif

