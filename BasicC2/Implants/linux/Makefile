name = rev

SRC = $(name).asm
OBJ = $(name).o
OUT = $(name)

all: $(OUT)

$(OUT): $(OBJ)
	ld -m elf_x86_64 $(OBJ) -o $(OUT)

$(OBJ): $(SRC)
	nasm -f elf64 $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ) $(OUT)
