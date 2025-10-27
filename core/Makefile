TARGET = ../build/tibane-server

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./includes -g \
         -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
         -Wformat -Wformat-security -Werror=format-security \
         -fstack-clash-protection -fcf-protection=full \
         -Wl,-z,relro,-z,now,-z,noexecstack -s

MYSQL_CFLAGS = $(shell mysql_config --cflags)
MYSQL_LIBS = $(shell mysql_config --libs)

LDFLAGS = -L/usr/lib/x86-64-linux-gnu -lmysqlclient -lz -lzstd -lssl -lcrypto \
	-lresolv -lm -lcjson -ldl -lpthread -lstdc++ -lcrypt

SRC = main.c \
	./includes/db.c ./includes/implant_handler.c \
	./includes/listener.c \
      	./includes/logs.c ./includes/operator.c \
	./includes/common.c #./includes/cJSON/cJSON.c

INCLUDES = -I/usr/include/mysql

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRC) $(MYSQL_CFLAGS) $(MYSQL_LIBS) $(LDFLAGS)
clean:
	rm -f $(TARGET)
