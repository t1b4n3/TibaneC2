# Name of output binary
TARGET = server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Required libraries
LIBS = -lcjson -lssl -lcrypto -lpthread -lmysqlclient 

# Source files
SRC = main.c

# Build target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Clean target
clean:
	rm -f $(TARGET)
