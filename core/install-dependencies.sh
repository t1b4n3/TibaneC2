#!/bin/bash

set -e

echo "[*] Updating package lists..."
sudo apt update -y

echo "[*] Installing required libraries..."
sudo apt install -y \
    libcjson1 \
    libssl3 \
    libmysqlclient21 \
    libcrypt1 \
    libc6 \
    zlib1g \
    libstdc++6 \
    libgcc-s1 \
    build-essential

echo "[*] Cleaning up..."
sudo apt autoremove -y
sudo apt clean

echo "[*] Done."
