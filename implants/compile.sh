#!/bin/bash


src="main.cpp"

# for linux
linux_out="agent_linux"
#gcc $src -o $linux_out -lcjson --static -lcrypto -lssl
gcc $src -o $linux_out -static -lcjson -lssl -lcrypto -ldl -lpthread
echo "[+] LINUX IMPLANT DONE\n" 


# windows
win_out="implant_windows"
i686-w64-mingw32-g++ -Wall -O2 -ffunction-sections -fdata-sections -fmerge-all-constants \
                    -static-libstdc++ -static-libgcc ./includes/cJSON/cJSON.c \
                    $src -o $win_out -lws2_32 -lsecur32
echo "[+] WINDOWS IMPLANT DONE\n"
