PWD=$(shell pwd)
CC=gcc
CFLAGS=-I$(PWD)/../include

hp-user: sniffer_read.c
	$(CC) $(CFLAGS) -o hp-user sniffer_read.c
