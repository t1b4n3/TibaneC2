# Makefile -- builds tibane-client with Go static library

SRC = main.cpp
TARGET = ../build/tibane-client ./includes/cJSON/cJSON.c
CC = g++

# Compiler flags
CFLAGS = -Wall -Wextra -Wformat -Wformat-security -Werror=format-security \
         -O2 -pipe -g \
         -fstack-protector-strong \
         -fstack-clash-protection \
         -fcf-protection=full \
         -fvisibility=hidden

# Linker flags
LDFLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--as-needed

# Libraries for static linking
LIBS = -L./libs \
       -l:libreadline.a -l:libtinfo.a \
       -static -lstdc++ -lm -lc -lgcc -lssl -lcrypto -lhistory -s

# Go library
GO_SRC = display.go
GO_LIB = libs/libdisplay.a
GO_HEADER = libs/libdisplay.h

# Default target
all: $(TARGET)

# Ensure libs directory exists
libs:
	@mkdir -p libs

# Build Go static library and header
$(GO_LIB) $(GO_HEADER): $(GO_SRC) | libs
	go build -buildmode=c-archive -o $(GO_LIB) $(GO_SRC)

# Build C++ target - link Go library directly without -ldisplay flag
$(TARGET): $(SRC) $(GO_LIB) $(GO_HEADER)
	$(CC) $(CFLAGS) $(SRC) $(GO_LIB) $(LDFLAGS) $(LIBS) -o $(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(GO_LIB) $(GO_HEADER)
	rmdir libs 2>/dev/null || true

.PHONY: all clean