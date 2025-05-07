# Compiler
CC := gcc

# Source file
SRC := main.c  # Replace with your actual source file name

# Output executable
OUT := server

# Compiler flags (add necessary warnings and optimizations)
CFLAGS := -Wall -Wextra -O2 -Wno-unused-variable -Wno-return-type \
          -Wno-stringop-truncation

# Linker flags (link with libcrypto and libssl)
LDFLAGS := -lcrypto -lssl

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(OUT) *.o
