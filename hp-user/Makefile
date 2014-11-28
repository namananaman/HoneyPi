PWD=$(shell pwd)
CC=gcc
EXEC=honeypi_read
CFLAGS=-I$(PWD)/../include -g -Wall
LDFLAGS=

_SOURCES=honeypi_read.c hashtable.c ip-tree.c net.c

SOURCES=$(addprefix src/,$(_SOURCES))

OBJECTS=$(addprefix obj/,$(notdir $(SOURCES:.c=.o)))

default: $(EXEC)

$(EXEC): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(EXEC) $(OBJECTS)

obj/%.o: src/%.c
	$(CC) $(FLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm $(EXEC) $(OBJECTS)
