# socks5ssh

socks5ssh forwards socks5 proxy traffic through SSH tunnels. 
Single static binary, event-driven architecture, supports multiple simultaneous tunnels.

## Features

- **Multiple tunnels** — each tunnel gets its own SSH connection and local SOCKS5 port
- **Event-driven I/O** — `ssh_get_fd()` + epoll integration, near-zero idle CPU
- **Static binary** — single ~7MB executable, no runtime dependencies
- **Auto-reconnect** — configurable retry count per tunnel
- **Legacy SSH support** — connects to OpenSSH 5.x+ (3des-cbc, blowfish-cbc, diffie-hellman-group1-sha1, ssh-dss)
- **Backpressure** — SSH read pauses while client write is pending
- **Diagnostics** — 5 log levels, SSH negotiation details, per-session transfer stats

## Quick Start

```bash
# 1. Download dependencies
wget https://www.libssh.org/files/0.12/libssh-0.12.0.tar.xz
wget -O json-develop.zip https://github.com/nlohmann/json/archive/refs/heads/develop.zip

# 2. Build dependencies
chmod +x build.sh
sudo ./build.sh

# 3. Build
make release

# 4. Run
./socks5proxy config.json
```

## Build

### Prerequisites

Ubuntu 25.10:

```bash
sudo apt install build-essential g++ cmake pkg-config unzip xz-utils \
    libboost-system-dev libboost-thread-dev libssl-dev zlib1g-dev libzstd-dev
```

### Build Targets

```bash
make release    # Static binary, -O3, stripped (~7MB)
make debug      # Dynamic, ASan+UBSan, -g3, debug/trace logging
make clean
```

## Usage

```
./socks5proxy [OPTIONS] <config.json>
```

### Options

| Flag | Description |
|------|-------------|
| `-h, --help` | Show help |
| `-v, --version` | Show version (libssh, OpenSSL, Boost) |
| `-t, --threads N` | Worker threads (default: CPU cores) |
| `-q, --quiet` | Errors only |
| `-d, --debug` | SSH negotiation, channel lifecycle |
| `-T, --trace` | Every packet, byte counts, fd events |
| `-L, --log-file PATH` | Log to file (append) |

Note: `-d` and `-T` require debug build.

### Examples

```bash
./socks5proxy config.json
./socks5proxy -d config.json
./socks5proxy -t 8 -q config.json
./socks5proxy -T -L proxy.log config.json
```

## Config

JSON array. Each object is one SSH tunnel with its own SOCKS5 port.

```json
[
  {
    "name": "proxy-us",
    "host": "203.0.113.10",
    "port": 22,
    "username": "tunnel",
    "password": "your_password",
    "local_port": 1080,
    "max_reconnects": 5,
    "ssh_timeout": 10
  }
]
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Tunnel ID (shown in logs) |
| `host` | string | yes | — | SSH server address |
| `port` | int | yes | — | SSH port |
| `username` | string | yes | — | SSH user |
| `password` | string | yes | — | SSH password |
| `local_port` | int | yes | — | Local SOCKS5 port |
| `max_reconnects` | int | no | 5 | Reconnect attempts |
| `ssh_timeout` | int | no | 10 | Connect timeout (sec) |


## Architecture

```
┌─────────┐                  ┌──────────────┐
│ Client  │ ←── async TCP ──→│ Socks5Session │←── notify_data_ready()
└─────────┘    boost::asio   └──────┬───────┘
                                    │
                             ┌──────┴────────┐
                             │  SSHManager    │
                             │  ssh_session   │
                             │  stream_desc   │←── epoll (single watcher)
                             │  ssh_strand_   │
                             │  pump_ssh()    │──→ notify registered sessions
                             └───────────────┘
```

- Single fd watcher per tunnel (no thundering herd)
- All libssh calls serialized through strand (no mutex)
- Backpressure: drain pauses during client write

## SSH Algorithms

Supports modern and legacy servers (OpenSSH 5.x+):

| Type | Algorithms |
|------|-----------|
| KEX | curve25519-sha256, ecdh-sha2-nistp*, dh-group-exchange-sha256, dh-group14/16/18, dh-group1-sha1, dh-gex-sha1 |
| Cipher | chacha20-poly1305, aes*-gcm, aes*-ctr, aes*-cbc, 3des-cbc, blowfish-cbc |
| MAC | hmac-sha2-*-etm, umac-*-etm, hmac-sha2-*, hmac-sha1, hmac-md5 |
| HostKey | ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa, ssh-dss |

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| [libssh](https://www.libssh.org) | 0.12.0 | SSH protocol |
| [Boost.Asio](https://www.boost.org) | 1.74+ | Async I/O |
| [OpenSSL](https://www.openssl.org) | 3.x | Crypto backend |
| [nlohmann/json](https://github.com/nlohmann/json) | 3.x | Config parsing |
| zlib | — | SSH compression |
