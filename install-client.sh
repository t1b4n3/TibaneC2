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
    GO_VERSION="1.21.2"
    OS=$(uname | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi

    wget "https://go.dev/dl/go${GO_VERSION}.${OS}-${ARCH}.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    echo "export PATH=\$PATH:/usr/local/go/bin" >> "$HOME/.bashrc"
    export PATH=$PATH:/usr/local/go/bin
fi

echo "[*] Checking Go version..."
go version

echo "[*] Installing additional tools..."
sudo apt install -y jq

echo "[*] All required libraries and compilers installed successfully!"


# Build if Makefile exists
if [ -f "./cli-client/Makefile" ]; then
    mkdir -p ./build
    make -C ./cli-client || { echo "[-] Build failed"; exit 1; }
        chown $TARGET_USER:$TARGET_USER ./build/tibane-client
else
    echo "[-] No Makefile found in ./cli-client, skipping build"
fi