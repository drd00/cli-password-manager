CC = gcc

INCLUDES = -I/usr/local/include
LIBS = -L/usr/local/lib -lsodium -lbsd -lncurses -lm

CFLAGS = -std=gnu99 -g -Og -Wall $(INCLUDES)
LDFLAGS = $(LIBS)

SRCS = main.c
OBJS = $(SRCS:.c=.o)
TARGET = passwordmanager

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
