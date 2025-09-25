name = hello

SRC = $(name).asm
OBJ = $(name).o
OUT = $(name)

all: $(OUT)

$(OUT): $(OBJ)
	ld -m elf_i386 $(OBJ) -o $(OUT)

$(OBJ): $(SRC)
	nasm -f elf32 $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ) $(OUT)