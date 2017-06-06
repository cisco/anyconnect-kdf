CC = gcc
CFLAGS = -I../../lkm/src/ -Wall -g
TARGET = kdf_listener

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -rf $(TARGET)
