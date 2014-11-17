PWD=$(shell pwd)
CC=gcc
EXEC=honeypi_read
CFLAGS=-I$(PWD)/../include -g

default: ip-tree $(EXEC)

$(EXEC): honeypi_read.c ip-tree.o
	$(CC) $(CFLAGS) -o $(EXEC) honeypi_read.c ip-tree.o

ip-tree:
	$(CC) $(CFLAGS) -o ip-tree.o -c ip-tree.c

clean:
	rm $(EXEC) ip-tree.o
