PWD=$(shell pwd)
CC=gcc
CFLAGS=-I$(PWD)/../include
EXEC=hp-user

default: $(EXEC)

$(EXEC): sniffer_read.c
	$(CC) $(CFLAGS) -o hp-user sniffer_read.c

clean:
	rm $(EXEC)
