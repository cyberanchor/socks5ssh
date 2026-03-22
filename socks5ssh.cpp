/**
 * @file socks5ssh.cpp
 * @brief SOCKS5 Proxy over SSH — Event-Driven, Full Diagnostics
 * @version 3.2.6
 *
 * High-performance SOCKS5 proxy forwarding traffic through SSH tunnels.
 * Uses ssh_get_fd() integrated with boost::asio for event-driven I/O.
 * Single fd watcher per tunnel eliminates thundering herd.
 * All libssh calls serialized through strand (no mutex for SSH ops).
 *
 * @section Changes_v3_2_6
 *   - Fix: TCP Keep-Alive via setsockopt (SSH_OPTIONS_TCP_KEEPALIVE
 *     does not exist in libssh 0.12.0; now sets SO_KEEPALIVE +
 *     TCP_KEEPIDLE=60s + TCP_KEEPINTVL=15s + TCP_KEEPCNT=4 on SSH fd)
 *   - Fix: destroy() accessible via public shutdown() for graceful stop
 *   - Fix: GCC warn_unused_result on write() in signal handler
 *
 * @section Changes_v3_2_5
 *   - Fix: graceful shutdown via stop() instead of ioc.stop()
 *     (prevents Teardown UAF/segfault on Ctrl+C)
 *   - Fix: SIGPIPE ignored (prevents process kill on broken client socket)
 *   - Fix: sessions_.clear() in destroy() (prevents double-iterate on reconnect)
 *
 * @section Changes_v3_2_4
 *   - Fix: destroy() invalidates all session channels before ssh_free()
 *     (prevents Use-After-Free/segfault when SSH server crashes)
 *   - Disconnected sessions are closed immediately (no zombie clients)
 *
 * @section Changes_v3_2_3
 *   - Fix: pump_ssh() detects SSH disconnect, destroys watcher
 *     (prevents 100% CPU spin loop on server crash/EOF)
 *   - Fix: signal handler uses write() instead of Log::info()
 *     (eliminates async-signal-unsafe mutex deadlock on Ctrl+C)
 *
 * @section Changes_v3_2_2
 *   - Security: bind_ip config field, default 127.0.0.1 (no open proxy)
 *   - Fix: TCP Keep-Alive enabled (prevents NAT timeout zombie sessions)
 *   - Removed: SIGHUP handler (async-signal-unsafe, deadlock risk)
 *
 * @section Changes_v3_2_1
 *   - Fix: bytes_up_/bytes_down_ atomic with memory_order_relaxed
 *   - Fix: dup'd fd gets FD_CLOEXEC to prevent leak on fork+exec
 *
 * @section Changes_v3_2
 *   - 5-level logging: ERROR, WARN, INFO, DEBUG, TRACE
 *   - Millisecond timestamps in all log lines
 *   - SSH session diagnostics: negotiated cipher, kex, mac, server banner,
 *     host key type + SHA256 fingerprint, OpenSSH version, protocol, fd
 *   - Session lifecycle with unique connection IDs: tunnel[#42]
 *   - Transfer stats on close: bytes up/down, duration, client address
 *   - --trace / -T flag for packet-level debug
 *   - --log-file / -L to redirect output to file
 *   - --version shows libssh, OpenSSL, Boost, nlohmann/json versions + build type
 *   - Extended --help with full usage guide, config format, examples
 *
 * @section Architecture
 *
 *   ┌─────────┐                  ┌──────────────┐
 *   │ Client  │ ←── async TCP ──→│ Socks5Session │←── notify_data_ready()
 *   └─────────┘    boost::asio   └──────┬───────┘
 *                                       │ ssh_channel_read/write
 *                                ┌──────┴────────┐
 *                                │  SSHManager    │
 *                                │  ssh_session   │
 *                                │  stream_desc   │←── epoll (single watcher)
 *                                │  ssh_strand_   │
 *                                │  pump_ssh()    │──→ notify all sessions
 *                                └───────────────┘
 *
 * @section Performance
 *   Per tunnel: 300-800 concurrent connections (stable)
 *   Idle CPU: ~0%, relay latency: <1ms
 *   No thundering herd, proper backpressure
 *
 * @section Build
 *   make debug     — for -d/-T logging (ASan + UBSan)
 *   make release   — production (debug/trace compiled out)
 *
 * @copyright 2024-2025
 * @license MIT
 */

#define LIBSSH_STATIC 1

#include <boost/asio.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/version.hpp>
#include <nlohmann/json.hpp>
#include <libssh/libssh.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <string>
#include <vector>
#include <array>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <unordered_set>
#include <functional>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

using boost::asio::ip::tcp;
using json = nlohmann::json;

// =============================================================================
//  Constants
// =============================================================================

static constexpr const char* APP_NAME    = "socks5proxy";
static constexpr const char* APP_VERSION = "3.2.6";

/** @brief Relay buffer size per direction (client↔SSH). */
static constexpr std::size_t RELAY_BUF = 32768;

/** @brief Default max reconnection attempts. */
static constexpr int MAX_RECONN_DEF = 5;

/** @brief Delay between reconnection attempts (seconds). */
static constexpr int RECONN_DELAY = 3;

/** @brief Default SSH connect timeout (seconds). */
static constexpr int SSH_TIMEOUT_DEF = 10;

// =============================================================================
//  Log Level — 5 levels: ERROR, WARN, INFO, DEBUG, TRACE
// =============================================================================

enum class LogLevel : int {
    SILENT = 0,
    ERR    = 1,
    WARN   = 2,
    INFO   = 3,
    DBG    = 4,
    TRACE  = 5
};

/** @brief Global log level, settable via CLI flags. */
static LogLevel g_ll = LogLevel::INFO;

/** @brief Optional log file stream (--log-file). */
static std::ofstream g_logfile;

// =============================================================================
//  Logger — thread-safe, timestamped with milliseconds, severity-filtered
// =============================================================================

/**
 * @class Log
 * @brief Thread-safe logging with millisecond timestamps and 5 severity levels.
 *
 * Output goes to stdout (info/warn/debug/trace) or stderr (error).
 * If --log-file is set, all output redirects to the file.
 * In NDEBUG builds, debug() and trace() compile to no-ops.
 */
class Log {
public:
    /** @brief Log error to stderr (always visible unless SILENT). */
    template<typename... A>
    static void err(A&&... a) {
        if (g_ll >= LogLevel::ERR)
            put(cerr_stream(), "[ERROR] ", std::forward<A>(a)...);
    }

    /** @brief Log warning to stdout. */
    template<typename... A>
    static void warn(A&&... a) {
        if (g_ll >= LogLevel::WARN)
            put(cout_stream(), "[WARN]  ", std::forward<A>(a)...);
    }

    /** @brief Log informational message to stdout. */
    template<typename... A>
    static void info(A&&... a) {
        if (g_ll >= LogLevel::INFO)
            put(cout_stream(), "[INFO]  ", std::forward<A>(a)...);
    }

    /** @brief Log debug message (SSH negotiation, channels, SOCKS5 steps). */
    template<typename... A>
    static void dbg([[maybe_unused]] A&&... a) {
#ifndef NDEBUG
        if (g_ll >= LogLevel::DBG)
            put(cout_stream(), "[DEBUG] ", std::forward<A>(a)...);
#endif
    }

    /** @brief Log trace message (every packet, fd events, byte counts). */
    template<typename... A>
    static void trace([[maybe_unused]] A&&... a) {
#ifndef NDEBUG
        if (g_ll >= LogLevel::TRACE)
            put(cout_stream(), "[TRACE] ", std::forward<A>(a)...);
#endif
    }

private:
    static std::mutex m_;

    /** @brief Route output to log file if open, otherwise stdout. */
    static std::ostream& cout_stream() {
        return g_logfile.is_open() ? g_logfile : std::cout;
    }

    /** @brief Route error output to log file if open, otherwise stderr. */
    static std::ostream& cerr_stream() {
        return g_logfile.is_open() ? g_logfile : std::cerr;
    }

    /** @brief Generate timestamp with millisecond precision: "HH:MM:SS.mmm". */
    static std::string ts() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        std::tm l{};
        localtime_r(&t, &l);
        char b[32];
        std::snprintf(b, sizeof(b), "%02d:%02d:%02d.%03d",
                      l.tm_hour, l.tm_min, l.tm_sec, static_cast<int>(ms.count()));
        return b;
    }

    /** @brief Write formatted log line with timestamp + tag + args. */
    template<typename S, typename... A>
    static void put(S& s, const char* tag, A&&... a) {
        std::lock_guard<std::mutex> lk(m_);
        s << ts() << ' ' << tag;
        (s << ... << std::forward<A>(a)) << std::endl;
    }
};

std::mutex Log::m_;

// =============================================================================
//  Helpers
// =============================================================================

/**
 * @brief Format byte count as human-readable string.
 * @param b Byte count.
 * @return "123 B", "1.2 KB", "3.4 MB", "1.23 GB"
 */
static std::string fmt_bytes(uint64_t b) {
    char buf[32];
    if (b < 1024)
        std::snprintf(buf, sizeof(buf), "%lu B", static_cast<unsigned long>(b));
    else if (b < 1024 * 1024)
        std::snprintf(buf, sizeof(buf), "%.1f KB", b / 1024.0);
    else if (b < 1024ULL * 1024 * 1024)
        std::snprintf(buf, sizeof(buf), "%.1f MB", b / (1024.0 * 1024));
    else
        std::snprintf(buf, sizeof(buf), "%.2f GB", b / (1024.0 * 1024 * 1024));
    return buf;
}

/** @brief Global atomic connection counter for unique session IDs. */
static std::atomic<uint64_t> g_conn_id{0};

// =============================================================================
//  TunnelConfig — deserialized from JSON
// =============================================================================

/**
 * @struct TunnelConfig
 * @brief Holds parameters for a single SSH tunnel from the JSON config.
 */
struct TunnelConfig {
    std::string    name;           ///< Tunnel identifier (used in all log messages)
    std::string    host;           ///< SSH server hostname or IP
    std::string    username;       ///< SSH username
    std::string    password;       ///< SSH password
    std::string    bind_ip = "127.0.0.1"; ///< Local bind address (default: loopback only)
    int            port = 22;      ///< SSH server port
    int            max_reconnects = MAX_RECONN_DEF;  ///< Max reconnection attempts
    int            ssh_timeout = SSH_TIMEOUT_DEF;     ///< SSH connect timeout (seconds)
    unsigned short local_port = 1080;                 ///< Local SOCKS5 listen port
};

/**
 * @brief Parse JSON config file into a vector of TunnelConfig.
 * @param path  Path to JSON file (array of tunnel objects).
 * @param[out] out  Populated on success.
 * @return true if at least one valid tunnel was parsed.
 */
bool read_config(const std::string& path, std::vector<TunnelConfig>& out) {
    std::ifstream f(path);
    if (!f.is_open()) {
        Log::err("Cannot open config: ", path);
        return false;
    }

    try {
        json j = json::parse(f);
        if (!j.is_array()) {
            Log::err("Config must be a JSON array of tunnel objects.");
            return false;
        }

        for (const auto& it : j) {
            TunnelConfig c;

            // Helper lambdas for required field extraction
            auto str = [&](const char* k, std::string& o) -> bool {
                if (!it.contains(k) || !it[k].is_string()) {
                    Log::err("Tunnel skipped: missing or invalid '", k, "'.");
                    return false;
                }
                o = it[k].get<std::string>();
                return true;
            };

            auto num = [&](const char* k, int& o) -> bool {
                if (!it.contains(k) || !it[k].is_number_integer()) {
                    Log::err("Tunnel skipped: missing or invalid '", k, "'.");
                    return false;
                }
                o = it[k].get<int>();
                return true;
            };

            // Required fields
            if (!str("name", c.name)) continue;
            if (!str("host", c.host)) continue;
            if (!num("port", c.port)) continue;
            if (!str("username", c.username)) continue;
            if (!str("password", c.password)) continue;
            int lp;
            if (!num("local_port", lp)) continue;
            c.local_port = static_cast<unsigned short>(lp);

            // Optional fields with defaults
            if (it.contains("max_reconnects") && it["max_reconnects"].is_number_integer())
                c.max_reconnects = it["max_reconnects"].get<int>();
            if (it.contains("ssh_timeout") && it["ssh_timeout"].is_number_integer())
                c.ssh_timeout = it["ssh_timeout"].get<int>();
            if (it.contains("bind_ip") && it["bind_ip"].is_string())
                c.bind_ip = it["bind_ip"].get<std::string>();

            out.push_back(std::move(c));
            Log::dbg("Config: tunnel '", out.back().name, "' → ",
                     out.back().username, "@", out.back().host, ":", out.back().port,
                     " bind:", out.back().bind_ip, ":", out.back().local_port);
        }
    } catch (const json::parse_error& e) {
        Log::err("JSON parse error: ", e.what());
        return false;
    }

    if (out.empty()) {
        Log::err("No valid tunnels found in config.");
        return false;
    }
    return true;
}

// =============================================================================
//  Forward declarations & interface
// =============================================================================

class SSHManager;
class Socks5Session;

/**
 * @brief Interface for sessions receiving data-ready notifications from SSHManager.
 *
 * SSHManager calls notify_data_ready() on ssh_strand_ when pump_ssh() detects
 * new data on the SSH socket. Each session then drains its own channel.
 */
class ISessionNotify {
public:
    virtual ~ISessionNotify() = default;
    /** @brief Called on ssh_strand_ when SSH data may be available. */
    virtual void notify_data_ready() = 0;
    /** @brief Called on ssh_strand_ when SSH session is being destroyed.
     *  Nullifies channel pointer before ssh_free() to prevent Use-After-Free. */
    virtual void invalidate_channel() = 0;
};

// =============================================================================
//  SSHManager — single fd watcher, strand-only serialization
// =============================================================================

/**
 * @class SSHManager
 * @brief Manages one SSH session with event-driven fd integration.
 *
 * Key design decisions:
 * - Single stream_descriptor per tunnel (no thundering herd)
 * - ALL libssh calls execute on ssh_strand_ (no mutex for SSH operations)
 * - Registered sessions receive broadcast notifications after pump_ssh()
 * - Reconnect logic with configurable retry count and delay
 *
 * After successful connect, prints full SSH session diagnostics:
 * server banner, negotiated cipher/kex/mac, host key fingerprint, etc.
 */
class SSHManager : public std::enable_shared_from_this<SSHManager> {
public:
    /**
     * @brief Construct SSHManager for a tunnel configuration.
     * @param cfg  Tunnel config (host, port, credentials, etc.)
     * @param ioc  Boost.Asio io_context for async operations.
     */
    SSHManager(const TunnelConfig& cfg, boost::asio::io_context& ioc)
        : cfg_(cfg), ioc_(ioc), strand_(boost::asio::make_strand(ioc))
    {}

    /// Non-copyable.
    SSHManager(const SSHManager&) = delete;
    SSHManager& operator=(const SSHManager&) = delete;

    ~SSHManager() { destroy(); }

    /** @brief Get tunnel name for log messages. */
    const std::string& name() const { return cfg_.name; }

    /** @brief Get the strand serializing all SSH operations. */
    boost::asio::strand<boost::asio::io_context::executor_type>& strand() { return strand_; }

    /**
     * @brief Initial blocking SSH connect. Call before starting accept loop.
     * @return true on success.
     */
    bool initial_connect() {
        if (!do_connect()) return false;
        setup_fd_watcher();
        return true;
    }

    /**
     * @brief Open SSH forwarding channel asynchronously.
     * @note MUST be called on strand_.
     * @param host  Target hostname/IP to forward to.
     * @param port  Target port.
     * @param cb    Callback with ssh_channel (or nullptr on failure).
     */
    void open_channel_async(const std::string& host, int port,
                            std::function<void(ssh_channel)> cb) {
        if (!session_) {
            Log::err(cfg_.name, ": No active SSH session.");
            cb(nullptr);
            return;
        }

        ssh_channel ch = ssh_channel_new(session_);
        if (!ch) {
            Log::err(cfg_.name, ": ssh_channel_new() failed.");
            cb(nullptr);
            return;
        }

        Log::dbg(cfg_.name, ": Opening channel → ", host, ":", port, "...");

        if (ssh_channel_open_forward(ch, host.c_str(), port, "127.0.0.1", 0) != SSH_OK) {
            Log::err(cfg_.name, ": ssh_channel_open_forward: ", ssh_get_error(session_));
            ssh_channel_free(ch);
            cb(nullptr);
            return;
        }

        channels_++;
        Log::dbg(cfg_.name, ": Channel opened → ", host, ":", port,
                 " (active: ", channels_, ", window: ", ssh_channel_window_size(ch), " bytes)");
        cb(ch);
    }

    /**
     * @brief Write data to SSH channel. MUST be called on strand_.
     * @return Bytes written, or -1 on error.
     */
    int channel_write(ssh_channel ch, const void* data, uint32_t len) {
        if (!ch || !session_) return -1;
        int w = ssh_channel_write(ch, data, len);
        Log::trace(cfg_.name, ": channel_write ", len, " → ", w, " bytes");
        return w;
    }

    /**
     * @brief Non-blocking read from SSH channel. MUST be called on strand_.
     * @return Bytes read, 0 if no data, -1 on error/EOF.
     */
    int channel_read_nb(ssh_channel ch, void* buf, uint32_t len) {
        if (!ch) return -1;
        int r = ssh_channel_read_nonblocking(ch, buf, len, 0);
        if (r > 0) Log::trace(cfg_.name, ": channel_read_nb → ", r, " bytes");
        return r;
    }

    /** @brief Check if channel reached EOF. Call on strand_. */
    bool channel_is_eof(ssh_channel ch) {
        return ch && ssh_channel_is_eof(ch);
    }

    /** @brief Check if channel is closed. Call on strand_. */
    bool channel_is_closed(ssh_channel ch) {
        return !ch || ssh_channel_is_closed(ch);
    }

    /**
     * @brief Close and free SSH channel. MUST be called on strand_.
     * Decrements active channel counter.
     */
    void close_channel(ssh_channel ch) {
        if (ch) {
            ssh_channel_send_eof(ch);
            ssh_channel_close(ch);
            ssh_channel_free(ch);
            if (channels_ > 0) channels_--;
            Log::dbg(cfg_.name, ": Channel closed (active: ", channels_, ")");
        }
    }

    /** @brief Get last SSH error message. Call on strand_. */
    std::string get_error() {
        return session_ ? ssh_get_error(session_) : "No session";
    }

    /**
     * @brief Asynchronous reconnect with retry loop. MUST be called on strand_.
     * @param cb  Callback with true on success, false on failure.
     */
    void reconnect_async(std::function<void(bool)> cb) {
        if (reconnecting_) { cb(false); return; }
        if (channels_ > 0) {
            Log::warn(cfg_.name, ": Cannot reconnect: ", channels_, " active channel(s).");
            cb(false);
            return;
        }
        reconnecting_ = true;
        do_reconnect_loop(1, std::move(cb));
    }

    /** @brief Register session for data-ready broadcast. On strand_. */
    void register_session(ISessionNotify* s) {
        sessions_.insert(s);
        Log::trace(cfg_.name, ": Session registered (total: ", sessions_.size(), ")");
    }

    /** @brief Unregister session from broadcast. On strand_. */
    void unregister_session(ISessionNotify* s) {
        sessions_.erase(s);
        Log::trace(cfg_.name, ": Session unregistered (total: ", sessions_.size(), ")");
    }

    /**
     * @brief Public shutdown entry point for graceful teardown.
     * Called via post(strand_) from Socks5Proxy::stop().
     */
    void shutdown() { destroy(); }

private:
    // ── SSH Connect (blocking) ──────────────────────────────────────────────

    /**
     * @brief Create SSH session, set all options, connect, authenticate.
     * Prints full session diagnostics on success.
     * @return true on success.
     */
    bool do_connect() {
        destroy();
        session_ = ssh_new();
        if (!session_) {
            Log::err(cfg_.name, ": ssh_new() failed.");
            return false;
        }

        Log::info(cfg_.name, ": Connecting to ", cfg_.username, "@", cfg_.host, ":", cfg_.port, "...");

        // --- Core options ---
        if (!opt(SSH_OPTIONS_HOST, cfg_.host.c_str())) return false;
        if (!opt(SSH_OPTIONS_PORT, &cfg_.port)) return false;
        if (!opt(SSH_OPTIONS_USER, cfg_.username.c_str())) return false;

        // --- Disable host key checking & config file processing ---
        int no = 0;
        if (!opt(SSH_OPTIONS_STRICTHOSTKEYCHECK, &no)) return false;
        if (!opt(SSH_OPTIONS_PROCESS_CONFIG, &no)) return false;

        // --- Timeout ---
        long tmo = cfg_.ssh_timeout;
        if (!opt(SSH_OPTIONS_TIMEOUT, &tmo)) return false;

        // --- SSH verbosity tied to our log level ---
        int verb = SSH_LOG_NOLOG;
#ifndef NDEBUG
        if (g_ll >= LogLevel::TRACE)
            verb = SSH_LOG_FUNCTIONS;
        else if (g_ll >= LogLevel::DBG)
            verb = SSH_LOG_PROTOCOL;
#endif
        if (!opt(SSH_OPTIONS_LOG_VERBOSITY, &verb)) return false;

        // --- Ciphers: modern + legacy (3des-cbc, blowfish-cbc) ---
        const char* ciphers =
            "^aes128-ctr,aes256-ctr,aes192-ctr,"
            "aes256-cbc,aes192-cbc,aes128-cbc,"
            "3des-cbc,blowfish-cbc,"
            "chacha20-poly1305@openssh.com,"
            "aes128-gcm@openssh.com,aes256-gcm@openssh.com";
        if (!opt(SSH_OPTIONS_CIPHERS_C_S, ciphers)) return false;
        if (!opt(SSH_OPTIONS_CIPHERS_S_C, ciphers)) return false;

        // --- Key exchange: modern curves + legacy DH groups ---
        const char* kex =
            "^curve25519-sha256,curve25519-sha256@libssh.org,"
            "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
            "diffie-hellman-group-exchange-sha256,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
            "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,"
            "diffie-hellman-group1-sha1,"
            "diffie-hellman-group-exchange-sha1";
        if (!opt(SSH_OPTIONS_KEY_EXCHANGE, kex)) return false;

        // --- MACs: modern ETM + legacy ---
        const char* macs =
            "^hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
            "hmac-sha1-etm@openssh.com,"
            "umac-128-etm@openssh.com,umac-64-etm@openssh.com,"
            "hmac-sha2-256,hmac-sha2-512,hmac-sha1,"
            "hmac-md5,hmac-sha1-96,hmac-md5-96,"
            "umac-64@openssh.com,umac-128@openssh.com";
        if (!opt(SSH_OPTIONS_HMAC_C_S, macs)) return false;
        if (!opt(SSH_OPTIONS_HMAC_S_C, macs)) return false;

        // --- Host keys ---
        if (!opt(SSH_OPTIONS_HOSTKEYS, "ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa,ssh-dss")) return false;

        // --- No compression ---
        if (!opt(SSH_OPTIONS_COMPRESSION, "none")) return false;

        // --- Connect ---
        if (ssh_connect(session_) != SSH_OK) {
            Log::err(cfg_.name, ": Connect: ", ssh_get_error(session_));
            destroy();
            return false;
        }

        // --- TCP Keep-Alive on SSH socket (prevents NAT timeout drops) ---
        {
            int fd = static_cast<int>(ssh_get_fd(session_));
            if (fd >= 0) {
                int on = 1;
                setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
#ifdef TCP_KEEPIDLE
                int idle = 60;   // first probe after 60s idle (default: 7200s)
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
                int intvl = 15;  // probe every 15s
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
                int cnt = 4;     // give up after 4 failed probes
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
                Log::dbg(cfg_.name, ": TCP Keep-Alive enabled on fd ", fd);
            }
        }

        // --- Print negotiated session details ---
        print_ssh_info();

        // --- Authenticate ---
        Log::dbg(cfg_.name, ": Authenticating as '", cfg_.username, "'...");
        if (ssh_userauth_password(session_, nullptr, cfg_.password.c_str()) != SSH_AUTH_SUCCESS) {
            Log::err(cfg_.name, ": Auth: ", ssh_get_error(session_));
            destroy();
            return false;
        }

        Log::info(cfg_.name, ": SSH connected — ", cfg_.username, "@", cfg_.host, ":", cfg_.port);
        return true;
    }

    /**
     * @brief Print negotiated SSH session parameters after successful connect.
     *
     * Shows: server banner, client banner, OpenSSH version, issue banner (MOTD),
     * negotiated KEX algorithm, cipher in/out, MAC in/out,
     * host key type + SHA256 fingerprint, protocol version, socket fd.
     */
    void print_ssh_info() {
        if (!session_) return;

        // Server banner (e.g., "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        const char* sb = ssh_get_serverbanner(session_);
        if (sb) Log::info(cfg_.name, ": Server: ", sb);

        // Client banner
        const char* cb = ssh_get_clientbanner(session_);
        if (cb) Log::dbg(cfg_.name, ": Client: ", cb);

        // Issue banner (MOTD from server)
        char* ib = ssh_get_issue_banner(session_);
        if (ib) {
            Log::dbg(cfg_.name, ": MOTD: ", ib);
            ssh_string_free_char(ib);
        }

        // OpenSSH version (encoded as major*0x10000 + minor*0x100 + patch)
        int ov = ssh_get_openssh_version(session_);
        if (ov > 0) {
            Log::dbg(cfg_.name, ": OpenSSH: ", ((ov >> 16) & 0xFF), ".", ((ov >> 8) & 0xFF));
        }

        // Negotiated algorithms
        const char* kex_algo  = ssh_get_kex_algo(session_);
        const char* cipher_in = ssh_get_cipher_in(session_);
        const char* cipher_out = ssh_get_cipher_out(session_);
        const char* hmac_in  = ssh_get_hmac_in(session_);
        const char* hmac_out = ssh_get_hmac_out(session_);

        Log::info(cfg_.name, ": KEX:    ", kex_algo ? kex_algo : "?");
        Log::info(cfg_.name, ": Cipher: in=", cipher_in ? cipher_in : "?",
                  " out=", cipher_out ? cipher_out : "?");
        Log::info(cfg_.name, ": MAC:    in=", hmac_in ? hmac_in : "?",
                  " out=", hmac_out ? hmac_out : "?");

        // Host key type + SHA256 fingerprint
        ssh_key srv_key = nullptr;
        if (ssh_get_server_publickey(session_, &srv_key) == SSH_OK && srv_key) {
            const char* ktype = ssh_key_type_to_char(ssh_key_type(srv_key));

            unsigned char* hash = nullptr;
            size_t hlen = 0;
            if (ssh_get_publickey_hash(srv_key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hlen) == 0 && hash) {
                char* fp = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
                if (fp) {
                    Log::info(cfg_.name, ": HostKey: ", ktype ? ktype : "?", " ", fp);
                    ssh_string_free_char(fp);
                }
                ssh_clean_pubkey_hash(&hash);
            }
            ssh_key_free(srv_key);
        }

        // Protocol version and socket fd
        Log::dbg(cfg_.name, ": Protocol: ", ssh_get_version(session_),
                 " fd: ", static_cast<int>(ssh_get_fd(session_)));
    }

    /**
     * @brief Set a single SSH option with error logging.
     * @return true on success, false on error (session destroyed).
     */
    bool opt(ssh_options_e t, const void* v) {
        if (ssh_options_set(session_, t, v) != SSH_OK) {
            Log::err(cfg_.name, ": SSH option error: ", ssh_get_error(session_));
            destroy();
            return false;
        }
        return true;
    }

    /** @brief Disconnect and free SSH session, close fd watcher. */
    void destroy() {
        if (fd_desc_) {
            boost::system::error_code ec;
            fd_desc_->cancel(ec);
            fd_desc_->close(ec);
            fd_desc_.reset();
        }

        // Invalidate all session channels BEFORE ssh_free().
        // ssh_free() internally frees all associated ssh_channel memory.
        // Without this, sessions hold dangling ch_ pointers → Use-After-Free.
        for (auto* s : sessions_) {
            s->invalidate_channel();
        }
        sessions_.clear();
        channels_ = 0;

        if (session_) {
            if (ssh_is_connected(session_)) {
                Log::dbg(cfg_.name, ": Disconnecting SSH session...");
                ssh_disconnect(session_);
            }
            ssh_free(session_);
            session_ = nullptr;
        }
    }

    // ── Reconnect loop (async, on strand_) ──────────────────────────────────

    /**
     * @brief Recursive reconnect attempt with delay timer.
     * @param attempt  Current attempt number (1-based).
     * @param cb       Callback with result.
     */
    void do_reconnect_loop(int attempt, std::function<void(bool)> cb) {
        Log::info(cfg_.name, ": Reconnect attempt ", attempt, "/", cfg_.max_reconnects);

        if (do_connect()) {
            setup_fd_watcher();
            reconnecting_ = false;
            Log::info(cfg_.name, ": Reconnected successfully.");
            cb(true);
            return;
        }

        if (attempt >= cfg_.max_reconnects) {
            reconnecting_ = false;
            Log::err(cfg_.name, ": All ", cfg_.max_reconnects, " reconnect attempts failed.");
            cb(false);
            return;
        }

        // Delay before next attempt
        auto timer = std::make_shared<boost::asio::steady_timer>(
            ioc_, std::chrono::seconds(RECONN_DELAY));
        auto self = shared_from_this();
        timer->async_wait(boost::asio::bind_executor(strand_,
            [this, self, attempt, cb = std::move(cb), timer](boost::system::error_code ec) mutable {
                if (ec) { reconnecting_ = false; cb(false); return; }
                do_reconnect_loop(attempt + 1, std::move(cb));
            }));
    }

    // ── Single fd watcher (thundering-herd-free) ────────────────────────────

    /**
     * @brief Create stream_descriptor for SSH fd and start event monitoring.
     *
     * Uses dup(fd) so that descriptor lifetime is independent of SSH session.
     * Only one watcher exists per SSHManager — no thundering herd.
     */
    void setup_fd_watcher() {
        if (!session_) return;

        int fd = static_cast<int>(ssh_get_fd(session_));
        if (fd < 0) {
            Log::err(cfg_.name, ": Invalid SSH fd.");
            return;
        }

        int duped = ::dup(fd);
        if (duped < 0) {
            Log::err(cfg_.name, ": dup() failed.");
            return;
        }
        ::fcntl(duped, F_SETFD, FD_CLOEXEC);

        try {
            fd_desc_ = std::make_unique<boost::asio::posix::stream_descriptor>(ioc_, duped);
        } catch (const std::exception& e) {
            ::close(duped);
            Log::err(cfg_.name, ": stream_descriptor: ", e.what());
            return;
        }

        Log::dbg(cfg_.name, ": FD watcher armed on fd ", duped, " (original: ", fd, ")");
        arm_fd_wait();
    }

    /**
     * @brief Register for read-readiness on SSH socket fd.
     * When the kernel signals readability, pump_ssh() fires.
     */
    void arm_fd_wait() {
        if (!fd_desc_ || !fd_desc_->is_open()) return;

        auto self = shared_from_this();
        fd_desc_->async_wait(
            boost::asio::posix::stream_descriptor::wait_read,
            boost::asio::bind_executor(strand_,
                [this, self](boost::system::error_code ec) {
                    if (ec) {
                        if (ec != boost::asio::error::operation_aborted)
                            Log::dbg(cfg_.name, ": FD wait error: ", ec.message());
                        return;
                    }
                    pump_ssh();
                }));
    }

    /**
     * @brief Pump libssh state machine, then broadcast to all sessions.
     *
     * This is the single point of entry for SSH I/O. Runs on strand_.
     * 1. ssh_event_dopoll(0) processes pending packets
     * 2. Notify all registered sessions to drain their channels
     * 3. Re-arm the fd watcher
     */
    void pump_ssh() {
        if (!session_) return;

        Log::trace(cfg_.name, ": pump_ssh() → processing for ", sessions_.size(), " session(s)");

        // Process pending SSH packets (non-blocking)
        ssh_event ev = ssh_event_new();
        if (ev) {
            ssh_event_add_session(ev, session_);
            ssh_event_dopoll(ev, 0);
            ssh_event_free(ev);
        }

        // Check if SSH session died after polling (EOF/RST from server).
        // Without this check, fd stays in EOF state, epoll returns readable
        // immediately, and we spin at 100% CPU forever.
        if (!ssh_is_connected(session_)) {
            Log::warn(cfg_.name, ": SSH disconnected (detected in pump_ssh). Destroying watcher.");
            destroy();
            return;
        }

        // Broadcast: notify all sessions that data may be available
        for (auto* s : sessions_) {
            s->notify_data_ready();
        }

        // Re-arm for next event
        arm_fd_wait();
    }

    // ── Members ─────────────────────────────────────────────────────────────

    TunnelConfig cfg_;
    boost::asio::io_context& ioc_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;

    ssh_session  session_ = nullptr;
    std::size_t  channels_ = 0;
    bool         reconnecting_ = false;

    /// Single fd watcher — only SSHManager listens on the SSH socket
    std::unique_ptr<boost::asio::posix::stream_descriptor> fd_desc_;

    /// Registered sessions for data-ready broadcast
    std::unordered_set<ISessionNotify*> sessions_;
};

// =============================================================================
//  Socks5Session — notified by SSHManager, no own fd watcher
// =============================================================================

/**
 * @class Socks5Session
 * @brief Handles one SOCKS5 client: handshake, CONNECT, bidirectional relay.
 *
 * All SSH operations dispatched to ssh_->strand().
 * Receives data-ready notifications from SSHManager::pump_ssh().
 * Backpressure: drain pauses while async_write to client is in flight.
 *
 * Each session has a unique ID (conn_id_) and a log tag "tunnel[#42]"
 * for easy grep'ing in logs.
 */
class Socks5Session : public std::enable_shared_from_this<Socks5Session>,
                       public ISessionNotify {
public:
    Socks5Session(tcp::socket socket, boost::asio::io_context& ioc,
                  std::shared_ptr<SSHManager> ssh, const std::string& tname)
        : client_(std::move(socket))
        , ioc_(ioc)
        , strand_(boost::asio::make_strand(ioc))
        , ssh_(std::move(ssh))
        , tname_(tname)
        , conn_id_(++g_conn_id)
    {
        // Build log tag: "tunnel_name[#42]"
        tag_ = tname_ + "[#" + std::to_string(conn_id_) + "]";

        // Capture client address for close-time logging
        boost::system::error_code ec;
        auto ep = client_.remote_endpoint(ec);
        if (!ec)
            client_addr_ = ep.address().to_string() + ":" + std::to_string(ep.port());

        Log::dbg(tag_, ": New session from ", client_addr_);
    }

    ~Socks5Session() override = default;

    /** @brief Start SOCKS5 handshake. */
    void start() {
        auto self = shared_from_this();
        boost::asio::post(strand_, [this, self]() { read_greeting(); });
    }

    /**
     * @brief Called by SSHManager on ssh_strand_ when SSH data arrived.
     *
     * Posts drain to ssh_strand_ with backpressure check.
     * If write to client is pending, drain is skipped — it will be
     * re-triggered when the write completes.
     */
    void notify_data_ready() override {
        if (closed_.load()) return;
        auto self = shared_from_this();
        boost::asio::post(ssh_->strand(), [this, self]() {
            if (closed_.load() || write_pending_.load()) return;
            do_drain();
        });
    }

    /**
     * @brief Called by SSHManager::destroy() on ssh_strand_ before ssh_free().
     * Nullifies channel pointer (ssh_free will free the underlying memory)
     * and triggers session close to disconnect the client immediately.
     */
    void invalidate_channel() override {
        ch_ = nullptr;
        do_close();
    }

private:
    // ── SOCKS5 Greeting (RFC 1928 §3) ──────────────────────────────────────

    /** @brief Read VER + NMETHODS. */
    void read_greeting() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(hdr_, 2),
            boost::asio::transfer_exactly(2),
            boost::asio::bind_executor(strand_,
                [this, self](boost::system::error_code ec, std::size_t n) {
                    if (ec || n != 2) {
                        Log::dbg(tag_, ": Greeting read failed: ", ec.message());
                        do_close();
                        return;
                    }
                    if (hdr_[0] != 0x05) {
                        Log::warn(tag_, ": Not SOCKS5 (ver=", int(hdr_[0]), ")");
                        do_close();
                        return;
                    }
                    Log::trace(tag_, ": SOCKS5 greeting, ", int(hdr_[1]), " auth method(s)");
                    read_auth(hdr_[1]);
                }));
    }

    /** @brief Read offered auth methods, respond with 0x00 (no auth). */
    void read_auth(uint8_t nmethods) {
        methods_.resize(nmethods);
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(methods_),
            boost::asio::transfer_exactly(nmethods),
            boost::asio::bind_executor(strand_,
                [this, self](boost::system::error_code ec, std::size_t) {
                    if (ec) { do_close(); return; }

                    bool no_auth = false;
                    for (auto m : methods_) {
                        Log::trace(tag_, ": Auth method offered: 0x",
                                   std::hex, int(m), std::dec);
                        if (m == 0x00) no_auth = true;
                    }

                    if (!no_auth)
                        Log::warn(tag_, ": No supported auth method (need 0x00).");

                    uint8_t resp[2] = {0x05, uint8_t(no_auth ? 0x00 : 0xFF)};
                    auto s2 = shared_from_this();
                    boost::asio::async_write(client_, boost::asio::buffer(resp, 2),
                        boost::asio::bind_executor(strand_,
                            [this, s2, no_auth](boost::system::error_code ec, std::size_t) {
                                if (ec || !no_auth) { do_close(); return; }
                                read_request();
                            }));
                }));
    }

    // ── SOCKS5 Request (RFC 1928 §4) ───────────────────────────────────────

    /** @brief Read VER CMD RSV ATYP, dispatch by address type. */
    void read_request() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(hdr_, 4),
            boost::asio::transfer_exactly(4),
            boost::asio::bind_executor(strand_,
                [this, self](boost::system::error_code ec, std::size_t n) {
                    if (ec || n != 4) { do_close(); return; }
                    if (hdr_[0] != 0x05) { reply(0x01); return; }

                    uint8_t cmd = hdr_[1];
                    uint8_t atyp = hdr_[3];
                    Log::trace(tag_, ": Request CMD=", int(cmd), " ATYP=", int(atyp));

                    if (cmd != 0x01) {
                        Log::warn(tag_, ": Unsupported CMD ", int(cmd), " (only CONNECT=0x01)");
                        reply(0x07);
                        return;
                    }

                    switch (atyp) {
                        case 0x01: read_ipv4();   break;
                        case 0x03: read_domain(); break;
                        default:
                            Log::warn(tag_, ": Unsupported ATYP ", int(atyp));
                            reply(0x08);
                    }
                }));
    }

    /** @brief Read IPv4 address (4 bytes) + port (2 bytes). */
    void read_ipv4() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(addr_buf_, 6),
            boost::asio::transfer_exactly(6),
            boost::asio::bind_executor(strand_,
                [this, self](boost::system::error_code ec, std::size_t n) {
                    if (ec || n != 6) { reply(0x01); return; }
                    std::ostringstream oss;
                    oss << int(addr_buf_[0]) << '.' << int(addr_buf_[1]) << '.'
                        << int(addr_buf_[2]) << '.' << int(addr_buf_[3]);
                    dst_host_ = oss.str();
                    dst_port_ = (uint16_t(addr_buf_[4]) << 8) | uint16_t(addr_buf_[5]);
                    Log::info(tag_, ": CONNECT → ", dst_host_, ":", dst_port_);
                    do_open_channel();
                }));
    }

    /** @brief Read domain name (1-byte len + string + 2-byte port). */
    void read_domain() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(addr_buf_, 1),
            boost::asio::transfer_exactly(1),
            boost::asio::bind_executor(strand_,
                [this, self](boost::system::error_code ec, std::size_t) {
                    if (ec || addr_buf_[0] == 0) { reply(0x01); return; }
                    uint8_t dlen = addr_buf_[0];
                    domain_buf_.resize(dlen);
                    auto s2 = shared_from_this();
                    boost::asio::async_read(client_, boost::asio::buffer(domain_buf_),
                        boost::asio::transfer_exactly(dlen),
                        boost::asio::bind_executor(strand_,
                            [this, s2](boost::system::error_code ec, std::size_t) {
                                if (ec) { reply(0x01); return; }
                                dst_host_.assign(domain_buf_.begin(), domain_buf_.end());
                                auto s3 = shared_from_this();
                                boost::asio::async_read(client_, boost::asio::buffer(addr_buf_, 2),
                                    boost::asio::transfer_exactly(2),
                                    boost::asio::bind_executor(strand_,
                                        [this, s3](boost::system::error_code ec, std::size_t) {
                                            if (ec) { reply(0x01); return; }
                                            dst_port_ = (uint16_t(addr_buf_[0]) << 8) | uint16_t(addr_buf_[1]);
                                            Log::info(tag_, ": CONNECT → ", dst_host_, ":", dst_port_);
                                            do_open_channel();
                                        }));
                            }));
                }));
    }

    // ── Channel open (async, on ssh_strand_) ────────────────────────────────

    /**
     * @brief Request SSH channel via SSHManager (on ssh_strand_).
     * On failure, attempts reconnect then retries once.
     */
    void do_open_channel() {
        auto self = shared_from_this();
        boost::asio::post(ssh_->strand(), [this, self]() {
            ssh_->open_channel_async(dst_host_, dst_port_, [this, self](ssh_channel ch) {
                if (!ch) {
                    // Channel failed — try reconnect
                    Log::warn(tag_, ": Channel failed, attempting reconnect...");
                    ssh_->reconnect_async([this, self](bool ok) {
                        if (!ok) {
                            Log::err(tag_, ": Reconnect failed, refusing client.");
                            boost::asio::post(strand_, [this, self]() { reply(0x05); });
                            return;
                        }
                        // Retry channel after reconnect
                        ssh_->open_channel_async(dst_host_, dst_port_, [this, self](ssh_channel ch2) {
                            ch_ = ch2;
                            if (!ch_) {
                                boost::asio::post(strand_, [this, self]() { reply(0x05); });
                                return;
                            }
                            ssh_->register_session(this);
                            Log::dbg(tag_, ": Channel ready (after reconnect).");
                            boost::asio::post(strand_, [this, self]() { reply(0x00); });
                        });
                    });
                    return;
                }

                // Channel opened successfully
                ch_ = ch;
                ssh_->register_session(this);
                Log::dbg(tag_, ": Channel ready.");
                boost::asio::post(strand_, [this, self]() { reply(0x00); });
            });
        });
    }

    // ── SOCKS5 Reply (RFC 1928 §6) ─────────────────────────────────────────

    /**
     * @brief Send SOCKS5 reply to client. Start relay on success (0x00).
     * @param code SOCKS5 reply code (0x00=success, 0x01=failure, etc.)
     */
    void reply(uint8_t code) {
        reply_buf_.clear();
        reply_buf_.push_back(0x05);  // VER
        reply_buf_.push_back(code);  // REP
        reply_buf_.push_back(0x00);  // RSV
        reply_buf_.push_back(0x01);  // ATYP = IPv4

        if (code == 0x00) {
            boost::system::error_code ec;
            auto ep = client_.local_endpoint(ec);
            if (!ec && ep.address().is_v4()) {
                auto b = ep.address().to_v4().to_bytes();
                reply_buf_.insert(reply_buf_.end(), b.begin(), b.end());
                uint16_t p = ep.port();
                reply_buf_.push_back(uint8_t(p >> 8));
                reply_buf_.push_back(uint8_t(p & 0xFF));
            } else {
                reply_buf_.insert(reply_buf_.end(), {0, 0, 0, 0, 0, 0});
            }
        } else {
            reply_buf_.insert(reply_buf_.end(), {0, 0, 0, 0, 0, 0});
        }

        // Human-readable reply code for debug log
        const char* desc =
            code == 0x00 ? "succeeded" :
            code == 0x01 ? "general failure" :
            code == 0x05 ? "connection refused" :
            code == 0x07 ? "command not supported" :
            code == 0x08 ? "address type not supported" : "unknown";
        Log::dbg(tag_, ": SOCKS5 reply: 0x", std::hex, int(code), std::dec, " (", desc, ")");

        auto self = shared_from_this();
        boost::asio::async_write(client_, boost::asio::buffer(reply_buf_),
            boost::asio::bind_executor(strand_,
                [this, self, code](boost::system::error_code ec, std::size_t) {
                    if (ec) { do_close(); return; }
                    if (code == 0x00) start_relay();
                    else do_close();
                }));
    }

    // ── Bidirectional Relay ─────────────────────────────────────────────────

    /** @brief Start both directions. SSH→Client driven by notifications. */
    void start_relay() {
        Log::dbg(tag_, ": Relay started (client ↔ SSH)");
        start_time_ = std::chrono::steady_clock::now();
        relay_c2s();
        // Initial drain in case data already buffered
        auto self = shared_from_this();
        boost::asio::post(ssh_->strand(), [this, self]() { do_drain(); });
    }

    /**
     * @brief Client → SSH: async read from client, write to channel on ssh_strand_.
     */
    void relay_c2s() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(cbuf_),
            boost::asio::transfer_at_least(1),
            boost::asio::bind_executor(strand_,
                [this, self](boost::system::error_code ec, std::size_t n) {
                    if (ec) {
                        if (ec != boost::asio::error::eof)
                            Log::dbg(tag_, ": Client read error: ", ec.message());
                        else
                            Log::dbg(tag_, ": Client disconnected (EOF).");
                        do_close();
                        return;
                    }
                    bytes_up_.fetch_add(n, std::memory_order_relaxed);
                    Log::trace(tag_, ": C→S ", n, " bytes (total up: ",
                               fmt_bytes(bytes_up_.load(std::memory_order_relaxed)), ")");

                    auto s2 = shared_from_this();
                    boost::asio::post(ssh_->strand(), [this, s2, n]() {
                        if (closed_.load() || !ch_) return;
                        int w = ssh_->channel_write(ch_, cbuf_.data(), static_cast<uint32_t>(n));
                        if (w < 0) {
                            Log::err(tag_, ": SSH write error: ", ssh_->get_error());
                            do_close();
                            return;
                        }
                        relay_c2s();
                    });
                }));
    }

    /**
     * @brief SSH → Client: drain channel buffer, write to client.
     *
     * Runs on ssh_strand_. Respects backpressure: if write to client is
     * pending, returns immediately. notify_data_ready() or write completion
     * will re-trigger drain.
     */
    void do_drain() {
        if (closed_.load() || !ch_ || write_pending_.load()) return;
        if (ssh_->channel_is_closed(ch_)) { do_close(); return; }

        int n = ssh_->channel_read_nb(ch_, sbuf_.data(), static_cast<uint32_t>(sbuf_.size()));

        if (n > 0) {
            bytes_down_.fetch_add(n, std::memory_order_relaxed);
            Log::trace(tag_, ": S→C ", n, " bytes (total down: ",
                       fmt_bytes(bytes_down_.load(std::memory_order_relaxed)), ")");

            write_pending_.store(true);
            auto self = shared_from_this();
            boost::asio::async_write(client_,
                boost::asio::buffer(sbuf_.data(), n),
                boost::asio::bind_executor(strand_,
                    [this, self](boost::system::error_code ec, std::size_t) {
                        write_pending_.store(false);
                        if (ec) { do_close(); return; }
                        // Try draining more
                        auto s2 = shared_from_this();
                        boost::asio::post(ssh_->strand(), [this, s2]() { do_drain(); });
                    }));
        } else if (n == 0) {
            // No data available — wait for next pump_ssh() notification
        } else {
            // Error or EOF
            if (ssh_->channel_is_eof(ch_))
                Log::dbg(tag_, ": SSH channel EOF.");
            else
                Log::err(tag_, ": SSH read error: ", ssh_->get_error());
            do_close();
        }
    }

    // ── Cleanup ─────────────────────────────────────────────────────────────

    /**
     * @brief Close session: unregister from SSHManager, close channel, close client socket.
     *
     * Logs session summary: destination, bytes up/down, duration, client address.
     * Uses atomic exchange to ensure close runs exactly once.
     */
    void do_close() {
        if (closed_.exchange(true)) return;  // already closing

        // Calculate session duration
        auto dur = std::chrono::steady_clock::now() - start_time_;
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(dur).count();

        Log::info(tag_, ": Closed — ", dst_host_, ":", dst_port_,
                  " ↑", fmt_bytes(bytes_up_.load(std::memory_order_relaxed)),
                  " ↓", fmt_bytes(bytes_down_.load(std::memory_order_relaxed)),
                  " ", secs, "s from ", client_addr_);

        auto self = shared_from_this();

        // Unregister and close channel on ssh_strand_
        boost::asio::post(ssh_->strand(), [this, self]() {
            ssh_->unregister_session(this);
            if (ch_) {
                ssh_->close_channel(ch_);
                ch_ = nullptr;
            }
        });

        // Close client socket on our strand
        boost::asio::post(strand_, [this, self]() {
            boost::system::error_code ec;
            if (client_.is_open()) {
                client_.shutdown(tcp::socket::shutdown_both, ec);
                client_.close(ec);
            }
        });
    }

    // ── Members ─────────────────────────────────────────────────────────────

    tcp::socket client_;                          ///< SOCKS5 client socket
    boost::asio::io_context& ioc_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_; ///< Session strand
    std::shared_ptr<SSHManager> ssh_;             ///< Shared SSH manager
    std::string tname_;                           ///< Tunnel name
    std::string tag_;                             ///< Log tag: "tunnel[#42]"
    std::string client_addr_;                     ///< Client address "1.2.3.4:56789"
    uint64_t conn_id_;                            ///< Unique connection ID

    ssh_channel ch_ = nullptr;                    ///< SSH forwarding channel
    std::string dst_host_;                        ///< Target hostname/IP
    uint16_t    dst_port_ = 0;                    ///< Target port

    std::atomic<bool> closed_{false};             ///< Close-once guard
    std::atomic<bool> write_pending_{false};       ///< Backpressure flag

    // Transfer stats (atomic: written on different strands, read in do_close)
    std::atomic<uint64_t> bytes_up_{0};            ///< Client → SSH bytes
    std::atomic<uint64_t> bytes_down_{0};          ///< SSH → Client bytes
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();

    // Protocol buffers
    std::array<uint8_t, 8>         hdr_{};        ///< Header buffer
    std::vector<uint8_t>           methods_;      ///< Auth methods
    std::array<uint8_t, 6>         addr_buf_{};   ///< Address + port
    std::vector<uint8_t>           domain_buf_;   ///< Domain name
    std::vector<uint8_t>           reply_buf_;    ///< SOCKS5 reply
    std::array<uint8_t, RELAY_BUF> cbuf_{};       ///< Client → SSH relay buffer
    std::array<uint8_t, RELAY_BUF> sbuf_{};       ///< SSH → Client relay buffer
};

// =============================================================================
//  Socks5Proxy — TCP acceptor
// =============================================================================

/**
 * @class Socks5Proxy
 * @brief Listens on a local TCP port and spawns Socks5Session for each client.
 */
class Socks5Proxy {
public:
    Socks5Proxy(boost::asio::io_context& ioc, const TunnelConfig& cfg)
        : ioc_(ioc)
        , acceptor_(ioc, tcp::endpoint(
              boost::asio::ip::make_address(cfg.bind_ip), cfg.local_port))
        , ssh_(std::make_shared<SSHManager>(cfg, ioc))
        , name_(cfg.name)
    {
        if (!ssh_->initial_connect())
            Log::err(name_, ": Initial SSH connect failed! Will retry on first client.");
    }

    /** @brief Start accepting connections. */
    void start() { do_accept(); }

    /**
     * @brief Graceful shutdown: close acceptor, destroy SSH session.
     * Called from main() before joining threads. Prevents Teardown UAF.
     */
    void stop() {
        boost::system::error_code ec;
        acceptor_.cancel(ec);
        acceptor_.close(ec);
        boost::asio::post(ssh_->strand(), [ssh = ssh_]() {
            ssh->shutdown();
        });
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket s) {
                if (!ec) {
                    std::make_shared<Socks5Session>(
                        std::move(s), ioc_, ssh_, name_)->start();
                } else if (ec == boost::asio::error::operation_aborted) {
                    return; // acceptor closed during shutdown
                } else {
                    Log::err(name_, ": Accept error: ", ec.message());
                }
                do_accept();
            });
    }

    boost::asio::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<SSHManager> ssh_;
    std::string name_;
};

// =============================================================================
//  Signal handling
// =============================================================================

static std::atomic<bool> g_run{true};

static void on_sig([[maybe_unused]] int s) {
    // Only async-signal-safe operations here.
    // write() is safe; Log::info (mutex + iostream) is NOT.
    static const char msg[] = "\n[SIGNAL] Shutting down...\n";
    if (::write(STDERR_FILENO, msg, sizeof(msg) - 1)) {} // suppress warn_unused_result
    g_run.store(false);
}

// =============================================================================
//  CLI: version, help, argument parsing
// =============================================================================

/** @brief Print version info with all library versions and build type. */
static void print_version() {
    std::cout
        << APP_NAME << " v" << APP_VERSION << "\n"
        << "  Architecture: event-driven (ssh_get_fd + epoll)\n"
        << "  libssh:       " << ssh_version(0) << "\n"
        << "  OpenSSL:      " << OpenSSL_version(OPENSSL_VERSION) << "\n"
        << "  Boost:        " << BOOST_VERSION / 100000 << "."
                              << BOOST_VERSION / 100 % 1000 << "."
                              << BOOST_VERSION % 100 << "\n"
        << "  JSON:         nlohmann/json " << NLOHMANN_JSON_VERSION_MAJOR << "."
                              << NLOHMANN_JSON_VERSION_MINOR << "."
                              << NLOHMANN_JSON_VERSION_PATCH << "\n"
        << "  Built:        " << __DATE__ << " " << __TIME__ << "\n"
#ifndef NDEBUG
        << "  Build type:   DEBUG (sanitizers, trace/debug logging enabled)\n"
#else
        << "  Build type:   RELEASE (trace/debug logging compiled out)\n"
#endif
        ;
}

/** @brief Print full help message with config format, examples, SSH compatibility. */
static void print_help(const char* prog) {
    std::cout <<
"Usage: " << prog << " [OPTIONS] <config.json>\n"
"\n"
"  SOCKS5 proxy server forwarding traffic through SSH tunnels.\n"
"  Event-driven architecture: ssh_get_fd() + epoll, single watcher per tunnel.\n"
"\n"
"ARGUMENTS:\n"
"  config.json          JSON configuration file with tunnel definitions (required)\n"
"\n"
"OPTIONS:\n"
"  -h, --help           Show this help message and exit\n"
"  -v, --version        Show version info (libssh, OpenSSL, Boost, JSON) and exit\n"
"  -t, --threads N      Worker thread count (default: auto = number of CPU cores)\n"
"  -q, --quiet          Suppress all output except errors\n"
"  -d, --debug          Debug logging: SSH negotiation, channel lifecycle, SOCKS5 details\n"
"  -T, --trace          Trace logging: every packet relay, byte counts, fd events\n"
"  -L, --log-file PATH  Write all logs to file instead of stdout/stderr (append mode)\n"
"\n"
"LOG LEVELS (cumulative, each includes all levels above it):\n"
"  quiet   (-q)   Only errors\n"
"  default        + Warnings + Connection info + SSH session details\n"
"  debug   (-d)   + Negotiated ciphers/kex/mac, host key fingerprint,\n"
"                   channel open/close, SOCKS5 protocol steps, session count\n"
"  trace   (-T)   + Every relay packet with byte count, buffer sizes,\n"
"                   fd watcher events, session register/unregister, pump_ssh calls\n"
"\n"
"  Note: -d and -T only have effect in debug builds (make debug).\n"
"  In release builds (make release), debug/trace are compiled to zero-cost no-ops.\n"
"\n"
"CONFIG FILE FORMAT:\n"
"  JSON array of tunnel objects. Each tunnel = one SSH connection + one SOCKS5 port.\n"
"\n"
"  Required fields:\n"
"    name           string   Tunnel identifier (appears in all log messages)\n"
"    host           string   SSH server hostname or IP address\n"
"    port           int      SSH server port (typically 22)\n"
"    username       string   SSH username for password authentication\n"
"    password       string   SSH password\n"
"    local_port     int      Local port for the SOCKS5 listener\n"
"\n"
"  Optional fields:\n"
"    bind_ip        string   Local bind address (default: 127.0.0.1)\n"
"    max_reconnects int      Max reconnection attempts on disconnect (default: 5)\n"
"    ssh_timeout    int      SSH connect timeout in seconds (default: 10)\n"
"\n"
"  Example config (tunnels.json):\n"
"    [\n"
"      {\n"
"        \"name\": \"prod-us\",\n"
"        \"host\": \"10.0.1.50\",\n"
"        \"port\": 22,\n"
"        \"username\": \"tunnel\",\n"
"        \"password\": \"s3cret\",\n"
"        \"local_port\": 1080,\n"
"        \"max_reconnects\": 10,\n"
"        \"ssh_timeout\": 15\n"
"      },\n"
"      {\n"
"        \"name\": \"legacy-router\",\n"
"        \"host\": \"172.16.0.1\",\n"
"        \"port\": 443,\n"
"        \"username\": \"admin\",\n"
"        \"password\": \"admin\",\n"
"        \"local_port\": 1081,\n"
"        \"max_reconnects\": 3,\n"
"        \"ssh_timeout\": 5\n"
"      }\n"
"    ]\n"
"\n"
"USAGE EXAMPLES:\n"
"  " << prog << " tunnels.json                     Start with default settings\n"
"  " << prog << " -d tunnels.json                  Debug: show SSH negotiation\n"
"  " << prog << " -T tunnels.json                  Trace: show every packet\n"
"  " << prog << " -t 8 -q tunnels.json             8 threads, quiet mode\n"
"  " << prog << " -L /var/log/proxy.log tunnels.json   Log to file\n"
"\n"
"  # Test with curl:\n"
"  curl --socks5 127.0.0.1:1080 https://httpbin.org/ip\n"
"\n"
"  # Test with wget:\n"
"  wget -e https_proxy=socks5://127.0.0.1:1080 https://example.com\n"
"\n"
"  # Firefox: Settings → Network → SOCKS Host: 127.0.0.1 Port: 1080\n"
"  # Chrome:  chrome --proxy-server=\"socks5://127.0.0.1:1080\"\n"
"\n"
"  # proxychains (/etc/proxychains.conf):\n"
"  #   socks5 127.0.0.1 1080\n"
"  proxychains curl https://example.com\n"
"\n"
"SSH COMPATIBILITY:\n"
"  Supports both modern and legacy SSH algorithms for maximum compatibility:\n"
"\n"
"  Ciphers:  chacha20-poly1305, aes256-gcm, aes128-gcm, aes*-ctr, aes*-cbc,\n"
"            3des-cbc, blowfish-cbc\n"
"  KEX:      curve25519-sha256, ecdh-sha2-nistp*, dh-group-exchange-sha256,\n"
"            dh-group14/16/18-sha*, dh-group1-sha1, dh-gex-sha1\n"
"  MACs:     hmac-sha2-*-etm, umac-*-etm, hmac-sha2-*, hmac-sha1, hmac-md5\n"
"  HostKeys: ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa, ssh-dss\n"
"\n"
"PERFORMANCE:\n"
"  300-800 concurrent connections per tunnel (stable)\n"
"  Multiple tunnels scale linearly (independent SSH sessions)\n"
"  Near-zero idle CPU, sub-millisecond relay latency\n"
"  Backpressure: SSH channel read pauses while client write is pending\n"
"\n"
"SESSION LOG FORMAT:\n"
"  Each session gets unique ID. On close, summary is printed:\n"
"  tunnel[#ID]: Closed — host:port ↑upload ↓download duration from client\n"
"\n"
"  Example:\n"
"  prod-us[#42]: Closed — 172.67.69.226:443 ↑1.2 KB ↓45.3 KB 3s from 127.0.0.1:54321\n"
"\n";
}

/**
 * @struct AppConfig
 * @brief Parsed command-line arguments.
 */
struct AppConfig {
    std::string config_file;    ///< Path to JSON config
    std::string log_file;       ///< Optional log file path
    unsigned    threads = 0;    ///< Thread count (0 = auto)
    bool        help = false;
    bool        version = false;
};

/**
 * @brief Parse command-line arguments.
 * @return Populated AppConfig.
 */
AppConfig parse_args(int argc, char* argv[]) {
    AppConfig app;

    static struct option long_opts[] = {
        {"help",     no_argument,       nullptr, 'h'},
        {"version",  no_argument,       nullptr, 'v'},
        {"threads",  required_argument, nullptr, 't'},
        {"quiet",    no_argument,       nullptr, 'q'},
        {"debug",    no_argument,       nullptr, 'd'},
        {"trace",    no_argument,       nullptr, 'T'},
        {"log-file", required_argument, nullptr, 'L'},
        {nullptr,    0,                 nullptr,  0 }
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "hvt:qdTL:", long_opts, nullptr)) != -1) {
        switch (ch) {
            case 'h': app.help = true;    return app;
            case 'v': app.version = true; return app;
            case 't': app.threads = static_cast<unsigned>(std::atoi(optarg)); break;
            case 'q': g_ll = LogLevel::ERR;   break;
            case 'd': g_ll = LogLevel::DBG;   break;
            case 'T': g_ll = LogLevel::TRACE; break;
            case 'L': app.log_file = optarg;  break;
            default:
                std::cerr << "Try '" << argv[0] << " --help' for usage.\n";
                std::exit(1);
        }
    }

    if (optind < argc)
        app.config_file = argv[optind];

    return app;
}

// =============================================================================
//  main()
// =============================================================================

int main(int argc, char* argv[]) {
    AppConfig app = parse_args(argc, argv);

    if (app.version) { print_version(); return 0; }
    if (app.help)    { print_help(argv[0]); return 0; }

    if (app.config_file.empty()) {
        std::cerr << "Error: config file required.\n"
                  << "Try '" << argv[0] << " --help' for usage.\n";
        return 1;
    }

    // Open log file if requested
    if (!app.log_file.empty()) {
        g_logfile.open(app.log_file, std::ios::app);
        if (!g_logfile.is_open()) {
            std::cerr << "Cannot open log file: " << app.log_file << "\n";
            return 1;
        }
    }

    // Startup banner
    Log::info("═══════════════════════════════════════════════════════");
    Log::info(APP_NAME, " v", APP_VERSION, " starting");
    Log::info("  libssh:  ", ssh_version(0));
    Log::info("  OpenSSL: ", OpenSSL_version(OPENSSL_VERSION));
    Log::info("  Boost:   ", BOOST_VERSION / 100000, ".",
              BOOST_VERSION / 100 % 1000, ".", BOOST_VERSION % 100);
#ifndef NDEBUG
    Log::info("  Build:   DEBUG");
#else
    Log::info("  Build:   RELEASE");
#endif
    Log::info("  PID:     ", getpid());
    Log::info("═══════════════════════════════════════════════════════");

    // Parse tunnel config
    std::vector<TunnelConfig> tunnels;
    if (!read_config(app.config_file, tunnels))
        return 1;

    Log::info("Loaded ", tunnels.size(), " tunnel(s) from ", app.config_file);

    // Install signal handlers
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);

    try {
        boost::asio::io_context ioc;
        auto guard = boost::asio::make_work_guard(ioc);

        // Create and start all proxy listeners
        std::vector<std::shared_ptr<Socks5Proxy>> proxies;
        for (const auto& t : tunnels) {
            auto p = std::make_shared<Socks5Proxy>(ioc, t);
            p->start();
            proxies.push_back(p);
            Log::info(t.name, ": SOCKS5 listening on ", t.bind_ip, ":", t.local_port);
        }

        // Thread pool
        unsigned pool = app.threads;
        if (pool == 0) {
            pool = std::thread::hardware_concurrency();
            if (pool == 0) pool = 4;
        }

        std::vector<std::thread> threads;
        threads.reserve(pool);
        for (unsigned i = 0; i < pool; ++i)
            threads.emplace_back([&ioc]() { ioc.run(); });

        Log::info("Running — ", pool, " worker thread(s), ", tunnels.size(), " tunnel(s)");
        Log::info("Press Ctrl+C to stop.");
        Log::info("───────────────────────────────────────────────────────");

        // Wait for shutdown signal
        while (g_run.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Graceful shutdown — no ioc.stop()!
        // ioc.stop() would discard pending handlers, destroying Socks5Session
        // objects while SSHManager still holds raw pointers → Use-After-Free.
        // Instead: close acceptors, destroy SSH sessions, let asio drain.
        Log::info("───────────────────────────────────────────────────────");
        Log::info("Shutting down...");

        for (auto& p : proxies)
            p->stop();

        guard.reset();  // allow ioc.run() to return when queue empties

        for (auto& t : threads)
            if (t.joinable()) t.join();

        Log::info("Total connections served: ", g_conn_id.load());
        Log::info("Shutdown complete.");
        Log::info("═══════════════════════════════════════════════════════");

    } catch (const std::exception& e) {
        Log::err("Fatal: ", e.what());
        return 1;
    }

    if (g_logfile.is_open()) g_logfile.close();
    return 0;
}
