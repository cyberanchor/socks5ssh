#!/bin/bash
# ==============================================================================
# build.sh — Download, build dependencies, compile socks5ssh
# ==============================================================================
#
# Target OS: Ubuntu 22.04 / 24.04 / 25.10
#
# This script:
#   1. Installs required system packages via apt
#   2. Downloads libssh 0.12.0 and nlohmann/json (if not present)
#   3. Builds libssh 0.12.0 as a static library with legacy ciphers
#   4. Installs nlohmann/json headers
#
# Usage:
#   chmod +x build.sh
#   sudo ./build.sh              # full: apt + download + build deps
#   sudo ./build.sh --no-apt     # skip apt (packages already installed)
#
# After this script completes:
#   make release    # static optimized binary
#   make debug      # debug build with sanitizers
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS_DIR="$SCRIPT_DIR/deps"
INSTALL_DIR="$DEPS_DIR/install"
BUILD_DIR="$DEPS_DIR/build"

LIBSSH_VERSION="0.12.0"
LIBSSH_ARCHIVE="libssh-${LIBSSH_VERSION}.tar.xz"
LIBSSH_URL="https://www.libssh.org/files/0.12/${LIBSSH_ARCHIVE}"

JSON_ARCHIVE="json-develop.zip"
JSON_URL="https://github.com/nlohmann/json/archive/refs/heads/develop.zip"

echo "=============================================="
echo "  socks5ssh dependency builder"
echo "=============================================="
echo "  Install prefix: $INSTALL_DIR"
echo ""

# --------------------------------------------------------------------------
#  Step 1: System packages
# --------------------------------------------------------------------------

if [[ "$1" != "--no-apt" ]]; then
    echo "[1/4] Installing system packages..."
    apt-get update -qq

    apt-get install -y --no-install-recommends \
        build-essential \
        g++ \
        cmake \
        pkg-config \
        unzip \
        xz-utils \
        wget \
        libboost-system-dev \
        libboost-thread-dev \
        libssl-dev \
        zlib1g-dev \
        libzstd-dev

    echo "  Done."
    echo ""
else
    echo "[1/4] Skipping apt (--no-apt)."
    echo ""
fi

# --------------------------------------------------------------------------
#  Step 2: Download archives (if not present)
# --------------------------------------------------------------------------

echo "[2/4] Checking source archives..."

cd "$SCRIPT_DIR"

if [ ! -f "$LIBSSH_ARCHIVE" ]; then
    echo "  Downloading $LIBSSH_ARCHIVE..."
    wget -q --show-progress "$LIBSSH_URL" -O "$LIBSSH_ARCHIVE"
else
    echo "  $LIBSSH_ARCHIVE — already present."
fi

if [ ! -f "$JSON_ARCHIVE" ]; then
    echo "  Downloading $JSON_ARCHIVE..."
    wget -q --show-progress "$JSON_URL" -O "$JSON_ARCHIVE"
else
    echo "  $JSON_ARCHIVE — already present."
fi

echo "  Done."
echo ""

# --------------------------------------------------------------------------
#  Step 3: Build libssh (static, with legacy ciphers)
# --------------------------------------------------------------------------

echo "[3/4] Building libssh ${LIBSSH_VERSION} (static + legacy ciphers)..."

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

LIBSSH_SRC="$BUILD_DIR/libssh-${LIBSSH_VERSION}"
if [ ! -d "$LIBSSH_SRC" ]; then
    echo "  Extracting $LIBSSH_ARCHIVE..."
    tar xf "$SCRIPT_DIR/$LIBSSH_ARCHIVE" -C "$BUILD_DIR"
fi

LIBSSH_BUILD="$BUILD_DIR/libssh-build"
rm -rf "$LIBSSH_BUILD"
mkdir -p "$LIBSSH_BUILD"
cd "$LIBSSH_BUILD"

cmake "$LIBSSH_SRC" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DBUILD_SHARED_LIBS=OFF \
    -DWITH_SERVER=OFF \
    -DWITH_EXAMPLES=OFF \
    -DWITH_BLOWFISH_CIPHER=ON \
    -DWITH_GEX=ON \
    -DWITH_ZLIB=ON \
    -DWITH_SFTP=OFF \
    -DWITH_PCAP=OFF \
    -DWITH_SYMBOL_VERSIONING=OFF \
    -DUNIT_TESTING=OFF \
    -DCLIENT_TESTING=OFF

make -j"$(nproc)"
make install

echo "  libssh installed: $(ls "$INSTALL_DIR/lib/libssh.a" 2>/dev/null || echo 'NOT FOUND')"
echo ""

# --------------------------------------------------------------------------
#  Step 4: Install nlohmann/json headers
# --------------------------------------------------------------------------

echo "[4/4] Installing nlohmann/json headers..."

JSON_SRC="$BUILD_DIR/json-develop"
if [ ! -d "$JSON_SRC" ]; then
    echo "  Extracting $JSON_ARCHIVE..."
    unzip -q "$SCRIPT_DIR/$JSON_ARCHIVE" -d "$BUILD_DIR"
fi

mkdir -p "$INSTALL_DIR/include/nlohmann"
cp -r "$JSON_SRC/include/nlohmann/"* "$INSTALL_DIR/include/nlohmann/"

echo "  Headers installed: $INSTALL_DIR/include/nlohmann/"
echo ""

# --------------------------------------------------------------------------
#  Done
# --------------------------------------------------------------------------

echo "=============================================="
echo "  Dependencies ready!"
echo ""
echo "  Build:"
echo "    make release    # static binary (~7MB)"
echo "    make debug      # debug with sanitizers"
echo ""
echo "  Run:"
echo "    ./socks5proxy config.json"
echo "=============================================="
