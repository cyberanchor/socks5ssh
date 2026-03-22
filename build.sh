#!/bin/bash
# ==============================================================================
# build.sh — Install system packages and build static dependencies
# ==============================================================================
#
# Target OS: Ubuntu 25.10
#
# This script:
#   1. Installs required system packages via apt
#   2. Builds libssh 0.12.0 as a static library WITH legacy ciphers
#   3. Installs nlohmann/json headers (header-only library)
#
#
# Usage:
#   chmod +x build_deps.sh
#   sudo ./build_deps.sh        
#
# Or if deps archives are already present locally:
#   ./build_deps.sh --local     # skip apt, just build from local archives
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS_DIR="$SCRIPT_DIR/deps"
INSTALL_DIR="$DEPS_DIR/install"
BUILD_DIR="$DEPS_DIR/build"

# Expected source archives (place in same directory as this script)
LIBSSH_ARCHIVE="$SCRIPT_DIR/libssh-0.12.0.tar.xz"
JSON_ARCHIVE="$SCRIPT_DIR/json-develop.zip"

echo "=============================================="
echo "  socks5ssh dependency builder"
echo "=============================================="
echo "  Install prefix: $INSTALL_DIR"
echo ""

# --------------------------------------------------------------------------
#  Step 1: System packages
# --------------------------------------------------------------------------

if [[ "$1" != "--local" ]]; then
    echo "[1/3] Installing system packages..."
    apt-get update -qq

    apt-get install -y --no-install-recommends \
        build-essential \
        g++ \
        cmake \
        pkg-config \
        unzip \
        xz-utils \
        libboost-system-dev \
        libboost-thread-dev \
        libssl-dev \
        zlib1g-dev \
        libzstd-dev

    echo "  System packages installed."
    echo ""
else
    echo "[1/3] Skipping apt (--local mode)."
    echo ""
fi

# --------------------------------------------------------------------------
#  Step 2: Build libssh 0.12.0 (static, with legacy ciphers)
# --------------------------------------------------------------------------

echo "[2/3] Building libssh 0.12.0 (static + legacy ciphers)..."

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

# Extract
LIBSSH_SRC="$BUILD_DIR/libssh-0.12.0"
if [ ! -d "$LIBSSH_SRC" ]; then
    if [ -f "$LIBSSH_ARCHIVE" ]; then
        echo "  Extracting $LIBSSH_ARCHIVE..."
        tar xf "$LIBSSH_ARCHIVE" -C "$BUILD_DIR"
    else
        echo "  ERROR: $LIBSSH_ARCHIVE not found!"
        echo "  Download from: https://www.libssh.org/files/0.12/libssh-0.12.0.tar.xz"
        echo "  Place it in: $SCRIPT_DIR/"
        exit 1
    fi
fi

# Build
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

echo "  libssh installed to $INSTALL_DIR"
echo "  Static library: $(ls $INSTALL_DIR/lib/libssh.a 2>/dev/null || echo 'NOT FOUND')"
echo ""

# --------------------------------------------------------------------------
#  Step 3: Install nlohmann/json headers
# --------------------------------------------------------------------------

echo "[3/3] Installing nlohmann/json headers..."

JSON_SRC="$BUILD_DIR/json-develop"
if [ ! -d "$JSON_SRC" ]; then
    if [ -f "$JSON_ARCHIVE" ]; then
        echo "  Extracting $JSON_ARCHIVE..."
        unzip -q "$JSON_ARCHIVE" -d "$BUILD_DIR"
    else
        echo "  ERROR: $JSON_ARCHIVE not found!"
        echo "  Download from: https://github.com/nlohmann/json"
        echo "  Place json-develop.zip in: $SCRIPT_DIR/"
        exit 1
    fi
fi

# nlohmann/json is header-only: just copy the include dir
mkdir -p "$INSTALL_DIR/include/nlohmann"
cp -r "$JSON_SRC/include/nlohmann/"* "$INSTALL_DIR/include/nlohmann/"

echo "  nlohmann/json headers installed to $INSTALL_DIR/include/nlohmann/"
echo ""

# --------------------------------------------------------------------------
#  Done
# --------------------------------------------------------------------------

echo "=============================================="
echo "  Dependencies ready!"
echo ""
echo "  To build:"
echo "    make release    # static optimized binary"
echo "    make debug      # debug build with sanitizers"
echo ""
echo "  To run:"
echo "    ./socks5proxy config.json"
echo "=============================================="
