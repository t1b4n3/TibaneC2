# Name of output binary
TARGET = tibane-server

# Compiler and flags - use gcc for C code
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./includes -g  -s #-std=c99
LDFLAGS = #-static

# Source files
SRC = main.c ./includes/db.c ./includes/implant_handler.c ./includes/listener.c \
      ./includes/logs.c ./includes/operator.c ./includes/common.c

# Libraries
LIBS = -lcjson -lssl -lcrypto -lmysqlclient -lz -lcrypt -ldl -lpthread -lstdc++

# Build target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LIBS) $(shell mysql_config --cflags --libs)

clean:
	rm -f $(TARGET)