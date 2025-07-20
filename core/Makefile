# Name of output binary
TARGET = server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./includes

# Required libraries
LIBS = -lcjson -lssl -lcrypto -lpthread -lmysqlclient

# Source files (including those in ./includes/)
SRC = main.c ./includes/register.c ./includes/db.c ./includes/beacon_tcp.c ./includes/logs.c ./includes/operator.c

# Build target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS)

# Clean target
clean:
	rm -f $(TARGET)