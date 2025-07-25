SRC = main.cpp
TARGET = tibane-console
CC = g++
LIBS = -lcjson

all: $(TARGET)
$(TARGET): $(SRC)
	$(CC) $(SRC) $(LIBS) -o $(TARGET)

clean:
	rm $(TARGET)