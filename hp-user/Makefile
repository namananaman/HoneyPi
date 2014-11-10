PWD=$(shell pwd)
CC=gcc
EXEC=hp-user
CFLAGS=-I$(PWD)/../include

default: ip-tree $(EXEC)

$(EXEC): sniffer_read.c ip-tree.o
	$(CC) $(CFLAGS) -o hp-user sniffer_read.c ip-tree.o

ip-tree:
	$(CC) -o ip-tree.o -c ip-tree.c

clean:
	rm $(EXEC)
