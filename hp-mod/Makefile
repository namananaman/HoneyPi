CS5413 := honeypi_mod
CS5413_MODNAME := honeypi
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

CC = gcc -Wall

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

endif
