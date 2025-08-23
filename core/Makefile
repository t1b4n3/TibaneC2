# Name of output binary
TARGET = tibane-server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./includes 

# Required libraries
LIBS = -lcjson -lssl -lcrypto -lpthread -lmysqlclient -lcrypt

# Source files (including those in ./includes/)
SRC = main.c ./includes/db.c ./includes/implant_handler.c ./includes/listener.c \
		./includes/logs.c ./includes/operator.c ./includes/common.c

# Build target
all: $(TARGET)
#add static
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS) -g 

# Clean target
clean:
	rm -f $(TARGET)