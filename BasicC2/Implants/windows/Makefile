# Cross-compilation settings
TARGET_ARCH := i686
CROSS_PREFIX := $(TARGET_ARCH)-w64-mingw32
CC := $(CROSS_PREFIX)-gcc

# Source file
SRC := main.c # Replace with your actual source file name

# Output executable
OUT := implant.exe

# Compiler flags
CFLAGS := -Wall -O2 -ffunction-sections -fdata-sections -fmerge-all-constants

# Linker flags
LDFLAGS := -lws2_32 -lsecur32 -static-libstdc++ -static-libgcc

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(OUT) *.o
