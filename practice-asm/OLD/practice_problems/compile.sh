#!/bin/bash

nasm -f elf64 new.asm -o p.o
gcc -c call.c -o c.o
gcc c.o p.o -o vuln

rm p.o c.o