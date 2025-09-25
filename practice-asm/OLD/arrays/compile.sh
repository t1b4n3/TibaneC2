#!/bin/bash

nasm -f elf64 array.asm -o p.o
gcc -c main.c -o c.o 
gcc c.o p.o -o vuln -no-pie

rm p.o c.o