CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -lssl -lcrypto

SRCS = main.c crypto.c network.c
OBJS = $(SRCS:.c=.o)
TARGET = e2ee

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

