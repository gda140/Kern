CC ?= cc
CFLAGS = -Wall -Wextra -g -I../src -I../../../main/core
SRCS = test_frame.c ../src/sec1210_frame.c ../../../main/core/seedkeeper.c \
       ../../../main/core/seedkeeper_sc.c
TARGET = test_frame

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
