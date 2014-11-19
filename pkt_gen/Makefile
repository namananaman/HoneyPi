CC = gcc

CFLAGS = -std=gnu99

LIBS = -lcrypto -lm

TARGET = pkt_gen

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c $(LIBS)

clean:
	$(RM) $(TARGET)
