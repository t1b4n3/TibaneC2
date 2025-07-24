# Name of output binary
TARGET = server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./includes

# Required libraries
LIBS = -lcjson -lssl -lcrypto -lpthread -lmysqlclient

# Source files (including those in ./includes/)
SRC = main.c ./includes/db.c ./includes/tcp/beacon_tcp.c ./includes/tcp/tcp_listener.c ./includes/logs.c \
	./includes/operator.c ./includes/agent.c ./includes/tcp_ssl/tcp_ssl.c \
	./includes/tcp_ssl/beacon_tcp_ssl.c

# Build target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS)

# Clean target
clean:
	rm -f $(TARGET)