#!/usr/bin/env bash
# install-libs.sh
# Install development packages required to link:
# -lcjson -lssl -lcrypto -lmysqlclient -lz -lcrypt -ldl -lpthread -lstdc++
# Additionally: fetch cJSON from GitHub and copy headers to ./includes/
#
# Supports: Debian/Ubuntu (apt), Fedora/RHEL/CentOS (dnf/yum), Arch (pacman),
# Alpine (apk), macOS (brew). If libcjson dev package is missing, this script
# will clone and build cJSON and copy its headers into ./includes/.
set -euo pipefail

# --- package lists (per-distro) ---
PKGS_DEBIAN=(build-essential libssl-dev default-libmysqlclient-dev zlib1g-dev libcrypt-dev g++ cmake git)
PKGS_FEDORA=(@development-tools openssl-devel mariadb-devel zlib-devel libxcrypt-devel cmake git)
PKGS_CENTOS=(gcc gcc-c++ make glibc-headers glibc-devel openssl-devel mariadb-devel zlib-devel libxcrypt-devel cmake git)
PKGS_ARCH=(base-devel openssl mariadb zlib libxcrypt cmake git)
PKGS_ALPINE=(build-base libc-dev openssl-dev mariadb-dev zlib-dev libxcrypt-dev cmake git)
PKGS_BREW=(openssl@3 mysql cmake git)  # macOS: user may need to add brew to PATH

CJSON_REPO="https://github.com/DaveGamble/cJSON.git"
CJSON_LOCAL_DIR="./third_party/cjson"
INCLUDES_DIR="./includes"

command_exists() { command -v "$1" >/dev/null 2>&1; }

echo "Running installer: will attempt to install dev packages for required libs..."
echo "Local includes dir: ${INCLUDES_DIR}"

if command_exists apt-get; then
  echo "Detected apt (Debian/Ubuntu). Updating package index..."
  sudo apt-get update
  echo "Installing: ${PKGS_DEBIAN[*]}"
  sudo apt-get install -y "${PKGS_DEBIAN[@]}"
  PKG_MANAGER="apt"
  echo "Done (apt)."

elif command_exists dnf; then
  echo "Detected dnf (Fedora/RHEL)."
  echo "Installing: ${PKGS_FEDORA[*]}"
  sudo dnf install -y "${PKGS_FEDORA[@]}"
  PKG_MANAGER="dnf"
  echo "Done (dnf)."

elif command_exists yum; then
  echo "Detected yum (older RHEL/CentOS)."
  echo "Installing: ${PKGS_CENTOS[*]}"
  sudo yum install -y "${PKGS_CENTOS[@]}" || {
    echo "yum install failed — you may need EPEL or additional repos enabled."
  }
  PKG_MANAGER="yum"
  echo "Done (yum)."

elif command_exists pacman; then
  echo "Detected pacman (Arch)."
  echo "Installing: ${PKGS_ARCH[*]}"
  sudo pacman -Syu --noconfirm "${PKGS_ARCH[@]}"
  PKG_MANAGER="pacman"
  echo "Done (pacman)."

elif command_exists apk; then
  echo "Detected apk (Alpine)."
  echo "Installing: ${PKGS_ALPINE[*]}"
  sudo apk update
  sudo apk add "${PKGS_ALPINE[@]}"
  PKG_MANAGER="apk"
  echo "Done (apk)."

elif command_exists brew; then
  echo "Detected Homebrew (macOS)."
  echo "Installing: ${PKGS_BREW[*]}"
  brew update
  brew install "${PKGS_BREW[@]}"
  PKG_MANAGER="brew"
  echo "Note: you may need to set PKG_CONFIG_PATH and LDFLAGS/CPPFLAGS for OpenSSL."
  echo "  export LDFLAGS=\"-L$(brew --prefix openssl@3)/lib\""
  echo "  export CPPFLAGS=\"-I$(brew --prefix openssl@3)/include\""
  echo "Done (brew)."

else
  echo "Unsupported distro / package manager not detected."
  echo "The script will still attempt to fetch and build cJSON locally, but you must install build tools manually."
  PKG_MANAGER="none"
fi

echo
echo "Preparation: ensure we have git and cmake for building cJSON if needed..."
if ! command_exists git || ! command_exists cmake || ! command_exists make || ! command_exists gcc; then
  echo "Warning: git/cmake/make/gcc may not be available. The script attempted to install them above, but verify manually if needed."
fi

# Ensure includes dir exists
mkdir -p "${INCLUDES_DIR}"

# Helper to check if cJSON header is available system-wide (gcc compile check)
has_cjson_header() {
  printf '#include <cJSON.h>\nint main(void) { return 0; }\n' | gcc -x c - -o /dev/null - >/dev/null 2>&1
}

# If header exists, skip cloning; otherwise fetch & copy headers
if has_cjson_header; then
  echo "System cJSON header found (no local fetch required)."
else
  echo "System cJSON header not found — fetching cJSON from GitHub and copying headers to ${INCLUDES_DIR}/"
  # Clone or update repository
  if [ -d "${CJSON_LOCAL_DIR}" ]; then
    echo "Updating existing ${CJSON_LOCAL_DIR}..."
    git -C "${CJSON_LOCAL_DIR}" fetch --depth=1 origin
    git -C "${CJSON_LOCAL_DIR}" reset --hard origin/master
  else
    echo "Cloning cJSON into ${CJSON_LOCAL_DIR}..."
    git clone --depth 1 "${CJSON_REPO}" "${CJSON_LOCAL_DIR}"
  fi

  # Build cJSON (out-of-source)
  pushd "${CJSON_LOCAL_DIR}" >/dev/null
  mkdir -p build
  pushd build >/dev/null
  echo "Configuring cJSON (cmake)..."
  cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null
  echo "Building cJSON..."
  cmake --build . --config Release >/dev/null
  popd >/dev/null

  # Copy headers to includes dir
  if [ -d "include" ]; then
    echo "Copying include/ -> ${INCLUDES_DIR}/cjson"
    mkdir -p "${INCLUDES_DIR}/cjson"
    cp -v include/* "${INCLUDES_DIR}/cjson/" || true
  else
    # Some cJSON forks may put headers at project root
    if [ -f "cJSON.h" ]; then
      cp -v cJSON.h "${INCLUDES_DIR}/" || true
    else
      echo "Warning: couldn't find cJSON headers in the repo. Check ${CJSON_LOCAL_DIR}"
    fi
  fi

  # Optional: copy built static lib (libcjson.a) into third_party location for linking
  if [ -f "build/libcjson.a" ]; then
    mkdir -p "${CJSON_LOCAL_DIR}/artifacts"
    cp -v build/libcjson.a "${CJSON_LOCAL_DIR}/artifacts/" || true
    echo "Built libcjson.a copied to ${CJSON_LOCAL_DIR}/artifacts/libcjson.a"
  fi

  popd >/dev/null
  echo "cJSON fetched and headers copied."
fi

# Quick validation: check for header files / pkg-config entries where possible
echo
echo "Validation (best-effort):"

check_header() {
  local hdr="$1"
  if echo "#include <$hdr>" | gcc -x c - -o /dev/null - >/dev/null 2>&1; then
    echo "  [OK] header <$hdr> usable (system)"
  else
    # also check local includes dir
    if gcc -I"${INCLUDES_DIR}" -x c - -o /dev/null - 2>/dev/null <<'EOF'
#include <cJSON.h>
int main(void){return 0;}
EOF
    then
      echo "  [OK] header <$hdr> usable (from ${INCLUDES_DIR})"
    else
      echo "  [WARN] header <$hdr> NOT found or not usable"
    fi
  fi
}

check_header "cJSON.h"
check_header "openssl/ssl.h"
check_header "mysql/mysql.h"
check_header "zlib.h"
check_header "crypt.h"

echo
echo "If any WARNs appear above, you may need to install the corresponding -dev/-devel package or adjust include/library paths."
echo "Common manual fixes:"
echo " - Debian/Ubuntu: sudo apt-get install libcjson-dev libssl-dev default-libmysqlclient-dev zlib1g-dev libcrypt-dev g++ cmake git"
echo " - Fedora: sudo dnf install libcjson-devel openssl-devel mariadb-devel zlib-devel libxcrypt-devel cmake git"
echo " - If libcjson packages are unavailable in your distro, this script cloned and built cJSON and copied headers to ${INCLUDES_DIR}/cjson"
echo
echo "Installer finished."
