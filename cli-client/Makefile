# Makefile.static -- builds a static binary. Some mitigations are limited with -static.
SRC = main.cpp
TARGET = tibane-client
CC = g++

# Note: static linking reduces effectiveness of a few mitigations (PIE, full RELRO behavior),
# and can make binaries brittle across distros. Use only if you must deliver a single-file static binary.
CFLAGS = -Wall -Wextra -Wformat -Wformat-security -Werror=format-security \
         -O2 -pipe -g \
         -D_FORTIFY_SOURCE=2 \
         -fstack-protector-strong \
         -fstack-clash-protection \
         -fcf-protection=full \
         -fvisibility=hidden

# For static linking we cannot reliably use -fPIE/-pie (in many toolchains), so omitted.
# Linker flags: try to keep RELRO and noexecstack flags, but note some libc static builds ignore them.
LDFLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--as-needed

# Static link everything. This is aggressive and increases chance of linker errors.
LIBS = -L./libs -Wl,--whole-archive -ldisplay -Wl,--no-whole-archive \
       -l:libreadline.a -l:libtinfo.a -l:libcjson.a \
       -static -lstdc++ -lm -lc -lgcc -lssl -lcrypto -lhistory -s

GO_SRC = display.go
GO_LIB = libs/libdisplay.a
GO_HEADER = libs/libdisplay.h

all: libdir $(GO_LIB) $(TARGET)

libdir:
	@mkdir -p libs

$(GO_LIB): $(GO_SRC) | libdir
	go build -buildmode=c-archive -o $(GO_LIB) $(GO_SRC)

$(TARGET): $(SRC) $(GO_LIB)
	$(CC) $(CFLAGS) $(SRC) $(GO_LIB) $(LDFLAGS) $(LIBS) -o $(TARGET)

clean:
	rm -f $(TARGET) $(GO_LIB) $(GO_HEADER)
	rmdir libs 2>/dev/null || true
