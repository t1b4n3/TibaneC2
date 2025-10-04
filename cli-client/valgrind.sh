#!/bin/bash

# Stop on first error
set -e

# Variables
MAKEFILE=Makefile
TARGET=tibane-console

# Step 1: Clean old build
echo "[*] Cleaning old build..."
make -f $MAKEFILE clean

# Step 2: Rebuild with debug flags
echo "[*] Building with debug info..."
make -f $MAKEFILE CFLAGS="-g -O0"

# Step 3: Run with Valgrind
echo "[*] Running under Valgrind..."
valgrind --leak-check=full --show-leak-kinds=all \
         --track-origins=yes --log-file=valgrind.log \
         ./$TARGET "$@"

# Step 4: Show summary
echo
echo "[*] Valgrind finished. Report saved to valgrind.log"
grep "ERROR SUMMARY" valgrind.log

