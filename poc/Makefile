# Author: al4n4n (Dadb0d)
CC      = gcc
CFLAGS  = -Wall -Wextra -O2
TARGET  = opsflip

all: $(TARGET)

$(TARGET): opsflip.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
