CS5413 := hp_mod
CS5413_MODNAME := raspberry_honey
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

all: default sniffer_control sniffer_read
#all: default tester 

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm -f sniffer_control sniffer_read *.tar.gz *.dev

dist: clean
	tar -czf $(DIST_FILE) ../sniffer --exclude=$(DIST_FILE) --exclude=".svn"

endif

CC = gcc -Wall

sniffer_control: sniffer_control.c 
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) $^ 

sniffer_read: sniffer_read.c 
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) $^ 
