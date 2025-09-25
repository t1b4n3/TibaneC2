#!/bin/bash

nasm -f elf64 sum.asm -o p.o
gcc -c main.c -o c.o
gcc c.o p.o -o vuln

rm p.o c.o
