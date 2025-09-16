#!/bin/bash

# Stop on error
set -e

TARGET=tibane-server

echo "[*] Cleaning old build..."
make clean

echo "[*] Building with debug info..."
# Force debug symbols (-g) and disable optimizations (-O0) for Valgrind
make CFLAGS="-Wall -Wextra -O0 -g -I./includes"

echo "[*] Running $TARGET under Valgrind..."
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --log-file=valgrind-server.log \
         ./$TARGET "$@"

echo
echo "[*] Valgrind run complete. Report saved to valgrind-server.log"
grep "ERROR SUMMARY" valgrind-server.log

