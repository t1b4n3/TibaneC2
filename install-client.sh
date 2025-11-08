#!/usr/bin/env bash
set -e

echo "[*] Updating package list..."
sudo apt update

echo "[*] Installing essential build tools..."
sudo apt install -y build-essential g++ gcc make pkg-config

echo "[*] Installing libraries..."
sudo apt install -y \
    libssl-dev \
    libreadline-dev \
    libtinfo-dev \
    libcjson-dev \
    zlib1g-dev \
    nlohmann-json3-dev \
    curl wget git

echo "[*] Installing Go (if not installed)..."
if ! command -v go >/dev/null 2>&1; then
    apt install golang
fi

echo "[*] Checking Go version..."
go version

echo "[*] Installing additional tools..."
sudo apt install -y jq 

echo "[*] All required libraries and compilers installed successfully!"


# Build if Makefile exists
if [ -f "./cli-client/Makefile" ]; then
    mkdir -p ./build
    cd ./cli-client/includes/
    git clone https://github.com/DaveGamble/cJSON.git
    cd ../../
    make -C ./cli-client || { echo "[-] Build failed"; exit 1; }
        chown $TARGET_USER:$TARGET_USER ./build/tibane-client
    sudo rm -r ./cli-client/includes/cJSON
else
    echo "[-] No Makefile found in ./cli-client, skipping build"
fi