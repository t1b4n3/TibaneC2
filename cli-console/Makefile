SRC = main.cpp
TARGET = tibane-console
CC = g++
CFLAGS = -g -O0            # debug mode
LDFLAGS = -L./libs -Wl,--whole-archive -ldisplay -Wl,--no-whole-archive \
          -l:libreadline.a -l:libtinfo.a -l:libcjson.a \
          -static -lstdc++ -lm -lc -lgcc -lssl -lcrypto -lhistory

GO_SRC = display.go
GO_LIB = libs/libdisplay.a
GO_HEADER = libs/libdisplay.h

all: libdir $(GO_LIB) $(TARGET)

libdir:
	@mkdir -p libs

$(GO_LIB): $(GO_SRC) | libdir
	go build -buildmode=c-archive -o $(GO_LIB) $(GO_SRC)

$(TARGET): $(SRC) $(GO_LIB)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET) $(GO_LIB) $(GO_HEADER)
	rmdir libs 2>/dev/null || true
