# ==============================================================================
# Makefile for socks5ssh — SOCKS5 Proxy over SSH Tunnel
# ==============================================================================
#
# Targets:
#   make release   — Static build: -O3, stripped, no build-id, minimal size
#   make debug     — Debug build: -O0 -g3, AddressSanitizer + UBSan
#   make clean     — Remove build artifacts
# ==============================================================================

CXX      := g++
CXXSTD   := -std=c++20

SRC      := socks5ssh.cpp
BIN_REL  := socks5proxy
BIN_DBG  := socks5proxy_debug

DEPS_DIR    := deps/install
LIBSSH_INC  := $(DEPS_DIR)/include
LIBSSH_LIB  := $(DEPS_DIR)/lib
JSON_INC    := $(DEPS_DIR)/include

INCLUDES := -I$(LIBSSH_INC) -I$(JSON_INC)
WARNINGS := -Wall -Wextra -Wpedantic -Wno-unused-parameter

# ==============================================================================
#  Release: static, optimized, maximum strip, no metadata
# ==============================================================================

RELEASE_CXXFLAGS := $(CXXSTD) -O3 -DNDEBUG -DLIBSSH_STATIC=1 \
    $(WARNINGS) $(INCLUDES) \
    -ffunction-sections \
    -fdata-sections \
    -fno-ident \
    -fno-asynchronous-unwind-tables

RELEASE_LDFLAGS := -static \
    -L$(LIBSSH_LIB) \
    -Wl,--build-id=none \
    -Wl,--gc-sections \
    -Wl,-s \
    -lssh \
    -lssl -lcrypto \
    -lzstd \
    -lz \
    -lpthread \
    -ldl

.PHONY: release
release: $(BIN_REL)

$(BIN_REL): $(SRC)
	$(CXX) $(RELEASE_CXXFLAGS) -o $@ $< $(RELEASE_LDFLAGS)
	@strip --strip-all \
	       --remove-section=.comment \
	       --remove-section=.note \
	       --remove-section=.note.gnu.build-id \
	       --remove-section=.note.ABI-tag \
	       --remove-section=.gnu.hash \
	       $@ 2>/dev/null || true
	@echo ""
	@echo "=== Release ==="
	@file $@
	@ls -lh $@
	@echo ""

# ==============================================================================
#  Debug: dynamic, sanitizers, full symbols
# ==============================================================================

DEBUG_CXXFLAGS := $(CXXSTD) -O0 -g3 -DDEBUG $(WARNINGS) $(INCLUDES) \
    -fsanitize=address,undefined -fno-omit-frame-pointer

DEBUG_LDFLAGS := \
    -L$(LIBSSH_LIB) \
    -lssh \
    -lboost_system \
    -lssl -lcrypto \
    -lzstd \
    -lz \
    -lpthread \
    -fsanitize=address,undefined

.PHONY: debug
debug: $(BIN_DBG)

$(BIN_DBG): $(SRC)
	$(CXX) $(DEBUG_CXXFLAGS) -o $@ $< $(DEBUG_LDFLAGS)
	@echo ""
	@echo "=== Debug ==="
	@file $@
	@ls -lh $@
	@echo ""

# ==============================================================================
#  Clean
# ==============================================================================

.PHONY: clean
clean:
	rm -f $(BIN_REL) $(BIN_DBG)
	@echo "Cleaned."
