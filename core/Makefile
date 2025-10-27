TARGET = ../build/tibane-server

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./includes -g \
         -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
         -Wformat -Wformat-security -Werror=format-security \
         -fstack-clash-protection -fcf-protection=full \
         -Wl,-z,relro,-z,now,-z,noexecstack -s

LDFLAGS = $(shell mysql_config --cflags --libs)
SRC = main.c ./includes/db.c ./includes/implant_handler.c ./includes/listener.c \
      ./includes/logs.c ./includes/operator.c ./includes/common.c #./includes/cJSON/cJSON.c

LIBS = -lssl -lcrypto -lmysqlclient -lz -lcrypt -ldl -lpthread -lstdc++

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
