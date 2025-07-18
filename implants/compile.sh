#!/bin/bash


src="main.cpp"

# for linux
linux_out="agent"
gcc $src -o $linux_out -lcjson
echo "[+] LINUX IMPLANT DONE\n"
# windows

win_out="implant"
i686-w64-mingw32-g++ -Wall -O2 -ffunction-sections -fdata-sections -fmerge-all-constants \
                    -static-libstdc++ -static-libgcc ./cJSON/cJSON.c \
                    $src -o $win_out -lws2_32
echo "[+] WINDOWS IMPLANT DONE\n"
