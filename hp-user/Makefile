PWD=$(shell pwd)
CC=gcc
EXEC=honeypi_read
CFLAGS=-I$(PWD)/../include -g -Wall
LDFLAGS=

default: ip-tree $(EXEC)

$(EXEC): honeypi_read.c ip-tree.o hashtable.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(EXEC) honeypi_read.c ip-tree.o hashtable.o

ip-tree:
	$(CC) $(CFLAGS) -o ip-tree.o -c ip-tree.c

hashtable:
	$(CC) $(CFLAGS) -o hashtable.o -c hashtable.c

hashtest: hashtable.o hashtest.c
	$(CC) $(CFLAGS) -o hashtest hashtest.c hashtable.o
clean:
	rm $(EXEC) ip-tree.o hashtable.o
