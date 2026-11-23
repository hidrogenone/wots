// ws2_32_offline: Winsock2 for a mapped title, with no network.
//
// The retail executable imports ws2_32.dll functions (by classic Winsock ordinal and by name, including getaddrinfo
// and freeaddrinfo). Bound directly to the host's ws2_32.dll a mapped title can issue live DNS queries, open real
// TCP/UDP sockets, or block on network timeouts, violating the runtime's offline contract.
//
// Like winhttp_offline.cpp, this table owns ws2_32.dll (rt::shims::owns_dll returns true, so LoadLibrary/GetProcAddress
// resolves both names and "#ordinal" entries through rt::shims::find) and answers every function in-process without
// loading or calling the host's ws2_32.dll:
//   - WSAStartup / WSACleanup maintain an initialization refcount and populate WSADATA cleanly.
//   - WSAGetLastError / WSASetLastError use the thread's Win32 last-error slot, matching Windows ws2_32.dll.
//   - socket / WSASocketA / WSASocketW allocate local synthetic SOCKET handles (never OS sockets).
//   - bind / getsockname / listen / setsockopt / getsockopt / ioctlsocket / WSAIoctl / WSAEventSelect /
//     WSAEnumNetworkEvents / shutdown / closesocket maintain per-socket state in-process so engine networking init
//     succeeds without asserting.
//   - connect / WSAConnect / WSAConnectByName* / WSAConnectByList / sendto / WSASendTo / WSASendMsg log each unique
//     destination once and fail immediately with WSAENETUNREACH; stream send / recv / getpeername fail with WSAENOTCONN;
//     bound non-blocking UDP recvfrom returns WSAEWOULDBLOCK so per-frame receive loops see "no packet".
//   - select / WSAPoll validate socket handles, clear readiness sets, and cap positive timeouts to 10 ms (1 ms for
//     infinite waits) so offline polling loops neither hang forever nor spin at 100% CPU.
//   - getaddrinfo / GetAddrInfoW / GetAddrInfoEx* resolve numeric IPv4/IPv6 literals, empty/null passive nodes, and
//     "localhost" in-process; any other hostname is logged once and fails immediately with WSAHOST_NOT_FOUND.
//   - Byte-order helpers (htons/htonl/ntohs/ntohl/WSA*), address string helpers (inet_addr/inet_ntoa/inet_pton/
//     inet_ntop/InetPtonW/InetNtopW/WSAAddressToString*/WSAStringToAddress*), __WSAFDIsSet, and WSA event helpers work
//     entirely in-process.
//
// Only images mapped by the loader see these through the shim registry; the runtime's own code is unaffected.
// All global locks/maps use constant-initialized SRWLOCK + InitOnceExecuteOnce (immortal and free of function-local
// magic-static TLS guards that can fault on guest threads under Wine).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <new>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>

#include "shims.h"

namespace rt::ws2_32 {
namespace {

constexpr DWORD kSioUdpConnreset = 0x9800000Cu;  // _WSAIOW(IOC_VENDOR, 12)
constexpr DWORD kSioUdpNetreset = 0x9800000Fu;   // _WSAIOW(IOC_VENDOR, 15)
constexpr DWORD kMaxPollSleepMs = 10u;

static_assert(WSA_INVALID_HANDLE == ERROR_INVALID_HANDLE, "WSA_INVALID_HANDLE must match Win32 ERROR_INVALID_HANDLE");

struct SrwLockGuard {
    SRWLOCK* lock;
    explicit SrwLockGuard(SRWLOCK& l) : lock(&l) { AcquireSRWLockExclusive(lock); }
    ~SrwLockGuard() { ReleaseSRWLockExclusive(lock); }
    SrwLockGuard(const SrwLockGuard&) = delete;
    SrwLockGuard& operator=(const SrwLockGuard&) = delete;
};

struct SocketState {
    int af = AF_INET;
    int type = SOCK_STREAM;
    int protocol = 0;
    bool nonblocking = false;
    bool bound = false;
    bool listening = false;
    bool shut_rd = false;
    bool shut_wr = false;
    sockaddr_storage local_addr{};
    int local_addr_len = 0;
    int so_error = 0;
    int so_rcvbuf = 65536;
    int so_sndbuf = 65536;
    int so_rcvtimeo = 0;
    int so_sndtimeo = 0;
    int so_reuseaddr = 0;
    int so_broadcast = 0;
    int so_keepalive = 0;
    int tcp_nodelay = 0;
    int ipv6_v6only = 1;
    int ip_ttl = 128;
    linger so_linger{0, 0};
    WSAEVENT event_handle = nullptr;
    long event_mask = 0;
    long pending_events = 0;
    int event_errors[FD_MAX_EVENTS]{};
};

struct GlobalState {
    std::unordered_map<SOCKET, SocketState> sockets;
    std::set<std::string> logged_targets;
    std::uint64_t next_socket = 0x4C450000ull;  // non-zero synthetic handles ("LE..")
    std::uint16_t next_ephemeral_port = 49152u;
    DWORD inet_ntoa_fls = FLS_OUT_OF_INDEXES;
};

SRWLOCK g_state_lock = SRWLOCK_INIT;
INIT_ONCE g_state_once = INIT_ONCE_STATIC_INIT;
GlobalState* g_state = nullptr;
std::atomic<int> g_wsa_refs{0};
std::atomic<bool> g_banner_logged{false};

// File-scope POD tables for gethostbyname / getprotoby* (constant-initialized in .data; no function-local init guards).
char g_lo_host_name[] = "leonida-offline";
char* g_no_aliases[] = {nullptr};
char g_lo_addr_bytes[4] = {127, 0, 0, 1};
char* g_lo_addr_list[] = {g_lo_addr_bytes, nullptr};
hostent g_lo_hostent{g_lo_host_name, g_no_aliases, AF_INET, 4, g_lo_addr_list};

char g_proto_icmp_name[] = "icmp";
char g_proto_tcp_name[] = "tcp";
char g_proto_udp_name[] = "udp";
protoent g_proto_icmp{g_proto_icmp_name, g_no_aliases, IPPROTO_ICMP};
protoent g_proto_tcp{g_proto_tcp_name, g_no_aliases, IPPROTO_TCP};
protoent g_proto_udp{g_proto_udp_name, g_no_aliases, IPPROTO_UDP};
char g_inet_ntoa_fallback[16]{};

VOID WINAPI free_inet_ntoa_fls(PVOID ptr) { std::free(ptr); }

BOOL CALLBACK init_global_state(PINIT_ONCE, PVOID, PVOID*) {
    auto* st = new GlobalState();
    st->inet_ntoa_fls = ::FlsAlloc(free_inet_ntoa_fls);
    g_state = st;
    return TRUE;
}

GlobalState& state() {
    InitOnceExecuteOnce(&g_state_once, init_global_state, nullptr, nullptr);
    return *g_state;
}

void set_wsa_error(int err) { ::SetLastError(static_cast<DWORD>(err)); }
int get_wsa_error() { return static_cast<int>(::GetLastError()); }

int fail_sock(int err) {
    set_wsa_error(err);
    return SOCKET_ERROR;
}

SOCKET fail_invalid_sock(int err) {
    set_wsa_error(err);
    return INVALID_SOCKET;
}

bool require_initialized() {
    if (g_wsa_refs.load(std::memory_order_acquire) > 0) return true;
    set_wsa_error(WSANOTINITIALISED);
    return false;
}

// ---- Byte order helpers (x86-64 little-endian) ------------------------------------------------------------------

std::uint16_t bswap16(std::uint16_t v) { return static_cast<std::uint16_t>((v >> 8) | (v << 8)); }
std::uint32_t bswap32(std::uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

u_short WSAAPI ws_htons(u_short hostshort) { return bswap16(hostshort); }
u_short WSAAPI ws_ntohs(u_short netshort) { return bswap16(netshort); }
u_long WSAAPI ws_htonl(u_long hostlong) { return bswap32(static_cast<std::uint32_t>(hostlong)); }
u_long WSAAPI ws_ntohl(u_long netlong) { return bswap32(static_cast<std::uint32_t>(netlong)); }

int WSAAPI ws_wsa_htons(SOCKET s, u_short hostshort, u_short* lpnetshort) {
    if (!require_initialized()) return SOCKET_ERROR;
    SrwLockGuard lock(g_state_lock);
    if (state().sockets.find(s) == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (!lpnetshort) return fail_sock(WSAEFAULT);
    *lpnetshort = bswap16(hostshort);
    return 0;
}
int WSAAPI ws_wsa_ntohs(SOCKET s, u_short netshort, u_short* lphostshort) {
    return ws_wsa_htons(s, netshort, lphostshort);
}
int WSAAPI ws_wsa_htonl(SOCKET s, u_long hostlong, u_long* lpnetlong) {
    if (!require_initialized()) return SOCKET_ERROR;
    SrwLockGuard lock(g_state_lock);
    if (state().sockets.find(s) == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (!lpnetlong) return fail_sock(WSAEFAULT);
    *lpnetlong = bswap32(static_cast<std::uint32_t>(hostlong));
    return 0;
}
int WSAAPI ws_wsa_ntohl(SOCKET s, u_long netlong, u_long* lphostlong) {
    return ws_wsa_htonl(s, netlong, lphostlong);
}

// ---- Pure in-process IPv4 / IPv6 parsing and formatting ---------------------------------------------------------

bool parse_ipv4_strict(const char* s, std::uint8_t out[4]) {
    if (!s || !*s) return false;
    const char* p = s;
    for (int part = 0; part < 4; ++part) {
        if (*p < '0' || *p > '9') return false;
        if (*p == '0' && p[1] >= '0' && p[1] <= '9') return false;  // reject leading zeros per inet_pton
        unsigned val = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10u + static_cast<unsigned>(*p - '0');
            if (val > 255u || ++digits > 3) return false;
            ++p;
        }
        out[part] = static_cast<std::uint8_t>(val);
        if (part < 3) {
            if (*p != '.') return false;
            ++p;
        }
    }
    return *p == '\0';
}

bool parse_ipv6_strict(const char* s, std::uint8_t out[16]) {
    if (!s || !*s) return false;
    std::uint16_t words[8]{};
    int count = 0;
    int compress_at = -1;
    const char* p = s;

    if (p[0] == ':') {
        if (p[1] != ':') return false;
        compress_at = 0;
        p += 2;
        if (*p == '\0') {
            std::memset(out, 0, 16);
            return true;
        }
    }

    while (*p != '\0') {
        if (count >= 8) return false;
        // Check for embedded IPv4 tail (e.g. ::ffff:127.0.0.1)
        const char* scan = p;
        bool has_dot = false;
        while (*scan && *scan != ':' && *scan != '%') {
            if (*scan == '.') has_dot = true;
            ++scan;
        }
        if (has_dot) {
            if (count > 6) return false;
            std::uint8_t v4[4]{};
            if (!parse_ipv4_strict(p, v4)) return false;
            words[count++] = static_cast<std::uint16_t>((static_cast<unsigned>(v4[0]) << 8) | v4[1]);
            words[count++] = static_cast<std::uint16_t>((static_cast<unsigned>(v4[2]) << 8) | v4[3]);
            p = scan;
            break;
        }
        unsigned val = 0;
        int digits = 0;
        while (*p && *p != ':') {
            unsigned d = 0;
            if (*p >= '0' && *p <= '9') d = static_cast<unsigned>(*p - '0');
            else if (*p >= 'a' && *p <= 'f') d = static_cast<unsigned>(*p - 'a' + 10);
            else if (*p >= 'A' && *p <= 'F') d = static_cast<unsigned>(*p - 'A' + 10);
            else return false;
            val = (val << 4) | d;
            if (++digits > 4) return false;
            ++p;
        }
        if (digits == 0) return false;
        words[count++] = static_cast<std::uint16_t>(val);
        if (*p == ':') {
            ++p;
            if (*p == ':') {
                if (compress_at >= 0) return false;
                compress_at = count;
                ++p;
                if (*p == '\0') break;
            } else if (*p == '\0') {
                return false;  // trailing single ':'
            }
        }
    }

    if (compress_at >= 0) {
        const int zeros = 8 - count;
        if (zeros <= 0) return false;
        const int tail = count - compress_at;
        for (int i = tail - 1; i >= 0; --i) words[compress_at + zeros + i] = words[compress_at + i];
        for (int i = 0; i < zeros; ++i) words[compress_at + i] = 0;
    } else if (count != 8) {
        return false;
    }

    for (int i = 0; i < 8; ++i) {
        out[i * 2] = static_cast<std::uint8_t>(words[i] >> 8);
        out[i * 2 + 1] = static_cast<std::uint8_t>(words[i] & 0xFFu);
    }
    return true;
}

std::string format_ipv4(const std::uint8_t b[4]) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

std::string format_ipv6(const std::uint8_t b[16]) {
    std::uint16_t w[8];
    for (int i = 0; i < 8; ++i) w[i] = static_cast<std::uint16_t>((static_cast<unsigned>(b[i * 2]) << 8) | b[i * 2 + 1]);

    // RFC 5952 longest run of >=2 zero groups.
    int best_start = -1, best_len = 0;
    int cur_start = -1, cur_len = 0;
    for (int i = 0; i < 8; ++i) {
        if (w[i] == 0) {
            if (cur_start < 0) cur_start = i;
            ++cur_len;
            if (cur_len > best_len) {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_start = -1;
            cur_len = 0;
        }
    }
    if (best_len < 2) best_start = -1;

    // IPv4-mapped ::ffff:a.b.c.d
    const bool v4_mapped = w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0 && w[4] == 0 && w[5] == 0xFFFFu;
    if (v4_mapped) {
        return "::ffff:" + format_ipv4(b + 12);
    }

    std::string out;
    for (int i = 0; i < 8;) {
        if (i == best_start) {
            out += "::";
            i += best_len;
            continue;
        }
        if (!out.empty() && out.back() != ':') out += ':';
        char hex[8];
        std::snprintf(hex, sizeof(hex), "%x", static_cast<unsigned>(w[i]));
        out += hex;
        ++i;
    }
    return out;
}

std::string format_sockaddr(const sockaddr* sa, int salen) {
    if (!sa || salen < static_cast<int>(sizeof(u_short))) return "?";
    if (sa->sa_family == AF_INET && salen >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        std::uint8_t b[4];
        std::memcpy(b, &in->sin_addr, 4);
        return format_ipv4(b) + ":" + std::to_string(bswap16(in->sin_port));
    }
    if (sa->sa_family == AF_INET6 && salen >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
        std::uint8_t b[16];
        std::memcpy(b, &in6->sin6_addr, 16);
        return "[" + format_ipv6(b) + "]:" + std::to_string(bswap16(in6->sin6_port));
    }
    return "af=" + std::to_string(sa->sa_family);
}

std::string narrow_utf8(const wchar_t* ws) {
    if (!ws || !*ws) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring widen_utf8(const char* s) {
    if (!s || !*s) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring out(static_cast<size_t>(n - 1), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), n);
    return out;
}

void log_refused_once(const char* kind, const std::string& target) {
    const std::string key = std::string(kind) + " " + target;
    bool fresh = false;
    {
        SrwLockGuard lock(g_state_lock);
        fresh = state().logged_targets.insert(key).second;
    }
    if (fresh) std::fprintf(stderr, "[rt] ws2_32: offline, refused %s %s\n", kind, target.c_str());
}

bool equals_ignore_case_ascii(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (std::tolower(static_cast<unsigned char>(*a)) != std::tolower(static_cast<unsigned char>(*b))) return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

bool parse_port_service(const char* service, std::uint16_t& port_host_order) {
    if (!service || !*service) {
        port_host_order = 0;
        return true;
    }
    char* end = nullptr;
    const unsigned long v = std::strtoul(service, &end, 10);
    if (end && *end == '\0' && service[0] >= '0' && service[0] <= '9') {
        if (v > 65535ul) return false;
        port_host_order = static_cast<std::uint16_t>(v);
        return true;
    }
    if (equals_ignore_case_ascii(service, "http")) { port_host_order = 80; return true; }
    if (equals_ignore_case_ascii(service, "https")) { port_host_order = 443; return true; }
    if (equals_ignore_case_ascii(service, "domain") || equals_ignore_case_ascii(service, "dns")) {
        port_host_order = 53;
        return true;
    }
    return false;
}

// ---- Startup / Cleanup / LastError ------------------------------------------------------------------------------

int WSAAPI ws_wsa_startup(WORD requested, LPWSADATA data) {
    if (!data) return WSAEFAULT;
    const BYTE req_major = LOBYTE(requested);
    const BYTE req_minor = HIBYTE(requested);
    if (req_major == 0) return WSAVERNOTSUPPORTED;

    std::memset(data, 0, sizeof(*data));
    if (req_major > 2 || (req_major == 2 && req_minor >= 2)) {
        data->wVersion = MAKEWORD(2, 2);
    } else if (req_major == 2) {
        data->wVersion = MAKEWORD(2, req_minor);
    } else {
        data->wVersion = MAKEWORD(1, req_minor > 1 ? 1 : req_minor);
        data->iMaxSockets = 32767;
        data->iMaxUdpDg = 65467;
    }
    data->wHighVersion = MAKEWORD(2, 2);
    static constexpr char kDesc[] = "Leonida Offline WinSock 2.2";
    static constexpr char kStat[] = "Offline";
    std::memcpy(data->szDescription, kDesc, sizeof(kDesc));
    std::memcpy(data->szSystemStatus, kStat, sizeof(kStat));

    {
        SrwLockGuard lock(g_state_lock);
        g_wsa_refs.fetch_add(1, std::memory_order_acq_rel);
    }
    if (!g_banner_logged.exchange(true, std::memory_order_relaxed)) {
        std::fprintf(stderr, "[rt] ws2_32: offline; sockets and DNS stay local (no network traffic)\n");
    }
    return 0;
}

int WSAAPI ws_wsa_cleanup() {
    SrwLockGuard lock(g_state_lock);
    const int cur = g_wsa_refs.load(std::memory_order_acquire);
    if (cur <= 0) return fail_sock(WSANOTINITIALISED);
    g_wsa_refs.store(cur - 1, std::memory_order_release);
    if (cur == 1) state().sockets.clear();
    return 0;
}

int WSAAPI ws_wsa_get_last_error() { return get_wsa_error(); }
void WSAAPI ws_wsa_set_last_error(int err) { set_wsa_error(err); }
int WSAAPI ws_wsa_cancel_blocking_call() { return require_initialized() ? fail_sock(WSAEINVAL) : SOCKET_ERROR; }
BOOL WSAAPI ws_wsa_is_blocking() { return FALSE; }

// ---- Socket lifecycle & options ---------------------------------------------------------------------------------

SOCKET create_offline_socket(int af, int type, int protocol) {
    if (!require_initialized()) return INVALID_SOCKET;
    if (af != AF_INET && af != AF_INET6 && af != AF_UNSPEC) return fail_invalid_sock(WSAEAFNOSUPPORT);
    if (af == AF_UNSPEC) af = AF_INET;
    if (type != SOCK_STREAM && type != SOCK_DGRAM && type != SOCK_RAW) return fail_invalid_sock(WSAESOCKTNOSUPPORT);
    if (protocol == 0) {
        protocol = (type == SOCK_STREAM) ? IPPROTO_TCP : (type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_IP);
    } else {
        if (type == SOCK_STREAM && protocol != IPPROTO_TCP) return fail_invalid_sock(WSAEPROTONOSUPPORT);
        if (type == SOCK_DGRAM && protocol != IPPROTO_UDP) return fail_invalid_sock(WSAEPROTONOSUPPORT);
    }

    SocketState ss;
    ss.af = af;
    ss.type = type;
    ss.protocol = protocol;

    SrwLockGuard lock(g_state_lock);
    GlobalState& st = state();
    const SOCKET handle = static_cast<SOCKET>(st.next_socket++);
    st.sockets.emplace(handle, ss);
    return handle;
}

SOCKET WSAAPI ws_socket(int af, int type, int protocol) { return create_offline_socket(af, type, protocol); }

SOCKET WSAAPI ws_wsa_socket_a(int af, int type, int protocol, LPWSAPROTOCOL_INFOA info, GROUP, DWORD) {
    if (info) {
        if (af == FROM_PROTOCOL_INFO) af = info->iAddressFamily;
        if (type == FROM_PROTOCOL_INFO) type = info->iSocketType;
        if (protocol == FROM_PROTOCOL_INFO) protocol = info->iProtocol;
    }
    return create_offline_socket(af, type, protocol);
}

SOCKET WSAAPI ws_wsa_socket_w(int af, int type, int protocol, LPWSAPROTOCOL_INFOW info, GROUP, DWORD) {
    if (info) {
        if (af == FROM_PROTOCOL_INFO) af = info->iAddressFamily;
        if (type == FROM_PROTOCOL_INFO) type = info->iSocketType;
        if (protocol == FROM_PROTOCOL_INFO) protocol = info->iProtocol;
    }
    return create_offline_socket(af, type, protocol);
}

int WSAAPI ws_closesocket(SOCKET s) {
    if (!require_initialized()) return SOCKET_ERROR;
    SrwLockGuard lock(g_state_lock);
    if (state().sockets.erase(s) == 0) return fail_sock(WSAENOTSOCK);
    return 0;
}

int WSAAPI ws_bind(SOCKET s, const sockaddr* name, int namelen) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!name) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    GlobalState& st = state();
    auto it = st.sockets.find(s);
    if (it == st.sockets.end()) return fail_sock(WSAENOTSOCK);
    SocketState& ss = it->second;
    if (ss.bound) return fail_sock(WSAEINVAL);

    if (ss.af == AF_INET) {
        if (namelen < static_cast<int>(sizeof(sockaddr_in))) return fail_sock(WSAEFAULT);
        if (name->sa_family != AF_INET) return fail_sock(WSAEAFNOSUPPORT);
        sockaddr_in bound_in{};
        std::memcpy(&bound_in, name, sizeof(bound_in));
        if (bound_in.sin_port == 0) {
            bound_in.sin_port = bswap16(st.next_ephemeral_port);
            st.next_ephemeral_port =
                st.next_ephemeral_port == 65535u ? 49152u : static_cast<std::uint16_t>(st.next_ephemeral_port + 1u);
        }
        std::memset(&ss.local_addr, 0, sizeof(ss.local_addr));
        std::memcpy(&ss.local_addr, &bound_in, sizeof(bound_in));
        ss.local_addr_len = static_cast<int>(sizeof(bound_in));
    } else if (ss.af == AF_INET6) {
        if (namelen < static_cast<int>(sizeof(sockaddr_in6))) return fail_sock(WSAEFAULT);
        if (name->sa_family != AF_INET6) return fail_sock(WSAEAFNOSUPPORT);
        sockaddr_in6 bound_in6{};
        std::memcpy(&bound_in6, name, sizeof(bound_in6));
        if (bound_in6.sin6_port == 0) {
            bound_in6.sin6_port = bswap16(st.next_ephemeral_port);
            st.next_ephemeral_port =
                st.next_ephemeral_port == 65535u ? 49152u : static_cast<std::uint16_t>(st.next_ephemeral_port + 1u);
        }
        std::memset(&ss.local_addr, 0, sizeof(ss.local_addr));
        std::memcpy(&ss.local_addr, &bound_in6, sizeof(bound_in6));
        ss.local_addr_len = static_cast<int>(sizeof(bound_in6));
    } else {
        return fail_sock(WSAEAFNOSUPPORT);
    }
    ss.bound = true;
    return 0;
}

int WSAAPI ws_getsockname(SOCKET s, sockaddr* name, int* namelen) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!name || !namelen) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    const SocketState& ss = it->second;
    if (!ss.bound) return fail_sock(WSAEINVAL);
    if (*namelen < ss.local_addr_len) {
        *namelen = ss.local_addr_len;
        return fail_sock(WSAEFAULT);
    }
    std::memcpy(name, &ss.local_addr, static_cast<size_t>(ss.local_addr_len));
    *namelen = ss.local_addr_len;
    return 0;
}

int WSAAPI ws_getpeername(SOCKET s, sockaddr* name, int* namelen) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!name || !namelen) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    if (state().sockets.find(s) == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    return fail_sock(WSAENOTCONN);
}

int WSAAPI ws_listen(SOCKET s, int) {
    if (!require_initialized()) return SOCKET_ERROR;
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (it->second.type != SOCK_STREAM) return fail_sock(WSAEOPNOTSUPP);
    if (!it->second.bound) return fail_sock(WSAEINVAL);
    it->second.listening = true;
    return 0;
}

SOCKET WSAAPI ws_accept(SOCKET s, sockaddr*, int*) {
    if (!require_initialized()) return INVALID_SOCKET;
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_invalid_sock(WSAENOTSOCK);
    if (it->second.type != SOCK_STREAM) return fail_invalid_sock(WSAEOPNOTSUPP);
    if (!it->second.listening) return fail_invalid_sock(WSAEINVAL);
    return fail_invalid_sock(it->second.nonblocking ? WSAEWOULDBLOCK : WSAENETUNREACH);
}

SOCKET WSAAPI ws_wsa_accept(SOCKET s, sockaddr* addr, LPINT addrlen, LPCONDITIONPROC, DWORD_PTR) {
    return ws_accept(s, addr, addrlen);
}

int WSAAPI ws_shutdown(SOCKET s, int how) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (how != SD_RECEIVE && how != SD_SEND && how != SD_BOTH) return fail_sock(WSAEINVAL);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    if (how == SD_RECEIVE || how == SD_BOTH) it->second.shut_rd = true;
    if (how == SD_SEND || how == SD_BOTH) it->second.shut_wr = true;
    return 0;
}

int WSAAPI ws_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!optval || optlen <= 0) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    SocketState& ss = it->second;

    auto read_int = [&](int& dst) -> bool {
        if (optlen < static_cast<int>(sizeof(int))) return false;
        std::memcpy(&dst, optval, sizeof(int));
        return true;
    };
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_REUSEADDR: return read_int(ss.so_reuseaddr) ? 0 : fail_sock(WSAEFAULT);
            case SO_BROADCAST: return read_int(ss.so_broadcast) ? 0 : fail_sock(WSAEFAULT);
            case SO_KEEPALIVE: return read_int(ss.so_keepalive) ? 0 : fail_sock(WSAEFAULT);
            case SO_RCVBUF: return read_int(ss.so_rcvbuf) ? 0 : fail_sock(WSAEFAULT);
            case SO_SNDBUF: return read_int(ss.so_sndbuf) ? 0 : fail_sock(WSAEFAULT);
            case SO_RCVTIMEO: return read_int(ss.so_rcvtimeo) ? 0 : fail_sock(WSAEFAULT);
            case SO_SNDTIMEO: return read_int(ss.so_sndtimeo) ? 0 : fail_sock(WSAEFAULT);
            case SO_LINGER:
                if (optlen < static_cast<int>(sizeof(linger))) return fail_sock(WSAEFAULT);
                std::memcpy(&ss.so_linger, optval, sizeof(linger));
                return 0;
            case SO_DONTLINGER: {
                int v = 0;
                if (!read_int(v)) return fail_sock(WSAEFAULT);
                ss.so_linger.l_onoff = v ? 0 : 1;
                return 0;
            }
            default: return 0;  // accept other advisory socket options cleanly
        }
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) {
        return read_int(ss.tcp_nodelay) ? 0 : fail_sock(WSAEFAULT);
    }
    if (level == IPPROTO_IPV6 && optname == IPV6_V6ONLY) {
        return read_int(ss.ipv6_v6only) ? 0 : fail_sock(WSAEFAULT);
    }
    if (level == IPPROTO_IP && optname == IP_TTL) {
        return read_int(ss.ip_ttl) ? 0 : fail_sock(WSAEFAULT);
    }
    return 0;
}

int WSAAPI ws_getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!optval || !optlen) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    SocketState& ss = it->second;

    auto write_int = [&](int value) -> int {
        if (*optlen < static_cast<int>(sizeof(int))) return fail_sock(WSAEFAULT);
        std::memcpy(optval, &value, sizeof(int));
        *optlen = static_cast<int>(sizeof(int));
        return 0;
    };
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_TYPE: return write_int(ss.type);
            case SO_ERROR: {
                const int err = ss.so_error;
                ss.so_error = 0;
                return write_int(err);
            }
            case SO_RCVBUF: return write_int(ss.so_rcvbuf);
            case SO_SNDBUF: return write_int(ss.so_sndbuf);
            case SO_RCVTIMEO: return write_int(ss.so_rcvtimeo);
            case SO_SNDTIMEO: return write_int(ss.so_sndtimeo);
            case SO_REUSEADDR: return write_int(ss.so_reuseaddr);
            case SO_BROADCAST: return write_int(ss.so_broadcast);
            case SO_KEEPALIVE: return write_int(ss.so_keepalive);
            case SO_ACCEPTCONN: return write_int(ss.listening ? 1 : 0);
            case SO_LINGER:
                if (*optlen < static_cast<int>(sizeof(linger))) return fail_sock(WSAEFAULT);
                std::memcpy(optval, &ss.so_linger, sizeof(linger));
                *optlen = static_cast<int>(sizeof(linger));
                return 0;
            case SO_DONTLINGER: return write_int(ss.so_linger.l_onoff ? 0 : 1);
            default: return fail_sock(WSAENOPROTOOPT);
        }
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) return write_int(ss.tcp_nodelay);
    if (level == IPPROTO_IPV6 && optname == IPV6_V6ONLY) return write_int(ss.ipv6_v6only);
    if (level == IPPROTO_IP && optname == IP_TTL) return write_int(ss.ip_ttl);
    return fail_sock(WSAENOPROTOOPT);
}

int WSAAPI ws_ioctlsocket(SOCKET s, long cmd, u_long* argp) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!argp) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (cmd == static_cast<long>(FIONBIO)) {
        it->second.nonblocking = (*argp != 0);
        return 0;
    }
    if (cmd == static_cast<long>(FIONREAD) || cmd == static_cast<long>(SIOCATMARK)) {
        *argp = 0;
        return 0;
    }
    return fail_sock(WSAEINVAL);
}

int WSAAPI ws_wsa_ioctl(SOCKET s, DWORD code, LPVOID in_buf, DWORD in_len, LPVOID out_buf, DWORD out_len,
                        LPDWORD bytes_returned, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!bytes_returned) return fail_sock(WSAEFAULT);
    *bytes_returned = 0;
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (code == static_cast<DWORD>(FIONBIO)) {
        if (!in_buf || in_len < sizeof(u_long)) return fail_sock(WSAEFAULT);
        u_long v = 0;
        std::memcpy(&v, in_buf, sizeof(v));
        it->second.nonblocking = (v != 0);
        return 0;
    }
    if (code == static_cast<DWORD>(FIONREAD)) {
        if (!out_buf || out_len < sizeof(u_long)) return fail_sock(WSAEFAULT);
        const u_long zero = 0;
        std::memcpy(out_buf, &zero, sizeof(zero));
        *bytes_returned = sizeof(zero);
        return 0;
    }
    if (code == kSioUdpConnreset || code == kSioUdpNetreset) {
        // Commonly set on Xbox/Windows UDP sockets to suppress ICMP port-unreachable resets.
        return 0;
    }
    return fail_sock(WSAEOPNOTSUPP);
}

// ---- Refused remote connections & transfers (offline wall) ------------------------------------------------------

void record_connect_failure(SocketState& ss) {
    ss.so_error = WSAENETUNREACH;
    if (ss.event_handle && (ss.event_mask & FD_CONNECT)) {
        ss.pending_events |= FD_CONNECT;
        ss.event_errors[FD_CONNECT_BIT] = WSAENETUNREACH;
        ::SetEvent(ss.event_handle);
    }
}

int WSAAPI ws_connect(SOCKET s, const sockaddr* name, int namelen) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!name || namelen < static_cast<int>(sizeof(u_short))) return fail_sock(WSAEFAULT);
    {
        SrwLockGuard lock(g_state_lock);
        auto it = state().sockets.find(s);
        if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
        record_connect_failure(it->second);
    }
    log_refused_once("connect", format_sockaddr(name, namelen));
    return fail_sock(WSAENETUNREACH);
}

int WSAAPI ws_wsa_connect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF, LPWSABUF, LPQOS, LPQOS) {
    return ws_connect(s, name, namelen);
}

BOOL WSAAPI ws_wsa_connect_by_name_a(SOCKET s, LPCSTR nodename, LPCSTR servicename, LPDWORD, LPSOCKADDR, LPDWORD,
                                     LPSOCKADDR, const timeval*, LPWSAOVERLAPPED) {
    if (!require_initialized()) return FALSE;
    {
        SrwLockGuard lock(g_state_lock);
        auto it = state().sockets.find(s);
        if (it == state().sockets.end()) {
            set_wsa_error(WSAENOTSOCK);
            return FALSE;
        }
        record_connect_failure(it->second);
    }
    log_refused_once("connect", std::string(nodename ? nodename : "?") + ":" + (servicename ? servicename : "0"));
    set_wsa_error(WSAENETUNREACH);
    return FALSE;
}

BOOL WSAAPI ws_wsa_connect_by_name_w(SOCKET s, LPWSTR nodename, LPWSTR servicename, LPDWORD, LPSOCKADDR, LPDWORD,
                                     LPSOCKADDR, const timeval*, LPWSAOVERLAPPED) {
    if (!require_initialized()) return FALSE;
    {
        SrwLockGuard lock(g_state_lock);
        auto it = state().sockets.find(s);
        if (it == state().sockets.end()) {
            set_wsa_error(WSAENOTSOCK);
            return FALSE;
        }
        record_connect_failure(it->second);
    }
    log_refused_once("connect", narrow_utf8(nodename) + ":" + narrow_utf8(servicename));
    set_wsa_error(WSAENETUNREACH);
    return FALSE;
}

BOOL WSAAPI ws_wsa_connect_by_list(SOCKET s, PSOCKET_ADDRESS_LIST, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                                   const timeval*, LPWSAOVERLAPPED) {
    if (!require_initialized()) return FALSE;
    {
        SrwLockGuard lock(g_state_lock);
        auto it = state().sockets.find(s);
        if (it == state().sockets.end()) {
            set_wsa_error(WSAENOTSOCK);
            return FALSE;
        }
        record_connect_failure(it->second);
    }
    log_refused_once("connect", "(address-list)");
    set_wsa_error(WSAENETUNREACH);
    return FALSE;
}

int WSAAPI ws_send(SOCKET s, const char* buf, int len, int) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (len < 0 || (len > 0 && !buf)) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    return fail_sock(WSAENOTCONN);
}

int WSAAPI ws_sendto(SOCKET s, const char* buf, int len, int, const sockaddr* to, int tolen) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (len < 0 || (len > 0 && !buf)) return fail_sock(WSAEFAULT);
    {
        SrwLockGuard lock(g_state_lock);
        auto it = state().sockets.find(s);
        if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
        if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    }
    if (to && tolen > 0) log_refused_once("sendto", format_sockaddr(to, tolen));
    return fail_sock(WSAENETUNREACH);
}

int WSAAPI ws_recv(SOCKET s, char* buf, int len, int) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (len < 0 || (len > 0 && !buf)) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    if (!it->second.bound) return fail_sock(WSAEINVAL);
    return fail_sock(it->second.nonblocking ? WSAEWOULDBLOCK : WSAENETUNREACH);
}

int WSAAPI ws_recvfrom(SOCKET s, char* buf, int len, int, sockaddr*, int*) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (len < 0 || (len > 0 && !buf)) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    if (!it->second.bound) return fail_sock(WSAEINVAL);
    return fail_sock(it->second.nonblocking ? WSAEWOULDBLOCK : WSAENETUNREACH);
}

int WSAAPI ws_wsa_send(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD, LPWSAOVERLAPPED,
                       LPWSAOVERLAPPED_COMPLETION_ROUTINE) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (count > 0 && !bufs) return fail_sock(WSAEFAULT);
    if (sent) *sent = 0;
    SrwLockGuard lock(g_state_lock);
    if (state().sockets.find(s) == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    return fail_sock(WSAENOTCONN);
}

int WSAAPI ws_wsa_send_to(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD, const sockaddr* to, int tolen,
                          LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (count > 0 && !bufs) return fail_sock(WSAEFAULT);
    if (sent) *sent = 0;
    {
        SrwLockGuard lock(g_state_lock);
        auto it = state().sockets.find(s);
        if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
        if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    }
    if (to && tolen > 0) log_refused_once("sendto", format_sockaddr(to, tolen));
    return fail_sock(WSAENETUNREACH);
}

int WSAAPI ws_wsa_send_msg(SOCKET s, LPWSAMSG msg, DWORD, LPDWORD sent, LPWSAOVERLAPPED,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!msg) return fail_sock(WSAEFAULT);
    if (sent) *sent = 0;
    {
        SrwLockGuard lock(g_state_lock);
        auto it = state().sockets.find(s);
        if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
        if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    }
    if (msg->name && msg->namelen > 0) log_refused_once("sendto", format_sockaddr(msg->name, msg->namelen));
    return fail_sock(WSAENETUNREACH);
}

int WSAAPI ws_wsa_recv(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvd, LPDWORD, LPWSAOVERLAPPED,
                       LPWSAOVERLAPPED_COMPLETION_ROUTINE) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (count > 0 && !bufs) return fail_sock(WSAEFAULT);
    if (recvd) *recvd = 0;
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    if (!it->second.bound) return fail_sock(WSAEINVAL);
    return fail_sock(it->second.nonblocking ? WSAEWOULDBLOCK : WSAENETUNREACH);
}

int WSAAPI ws_wsa_recv_from(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvd, LPDWORD, sockaddr*, LPINT,
                            LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (count > 0 && !bufs) return fail_sock(WSAEFAULT);
    if (recvd) *recvd = 0;
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (it->second.type == SOCK_STREAM) return fail_sock(WSAENOTCONN);
    if (!it->second.bound) return fail_sock(WSAEINVAL);
    return fail_sock(it->second.nonblocking ? WSAEWOULDBLOCK : WSAENETUNREACH);
}

int WSAAPI ws_wsa_send_disconnect(SOCKET s, LPWSABUF) { return ws_shutdown(s, SD_SEND); }
int WSAAPI ws_wsa_recv_disconnect(SOCKET s, LPWSABUF) { return ws_shutdown(s, SD_RECEIVE); }

BOOL WSAAPI ws_wsa_get_overlapped_result(SOCKET s, LPWSAOVERLAPPED overlapped, LPDWORD transfer, BOOL, LPDWORD flags) {
    if (!require_initialized()) return FALSE;
    if (!overlapped || !transfer || !flags) {
        set_wsa_error(WSAEFAULT);
        return FALSE;
    }
    SrwLockGuard lock(g_state_lock);
    if (state().sockets.find(s) == state().sockets.end()) {
        set_wsa_error(WSAENOTSOCK);
        return FALSE;
    }
    set_wsa_error(WSA_IO_INCOMPLETE);
    return FALSE;
}

// ---- Polling / Select / WSA Events ------------------------------------------------------------------------------

int PASCAL ws_wsa_fd_is_set(SOCKET fd, fd_set* set) {
    if (!set) return 0;
    for (u_int i = 0; i < set->fd_count; ++i) {
        if (set->fd_array[i] == fd) return 1;
    }
    return 0;
}

int WSAAPI ws_select(int, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const timeval* timeout) {
    if (!require_initialized()) return SOCKET_ERROR;
    const std::uint64_t total = static_cast<std::uint64_t>(readfds ? readfds->fd_count : 0u) +
                                static_cast<std::uint64_t>(writefds ? writefds->fd_count : 0u) +
                                static_cast<std::uint64_t>(exceptfds ? exceptfds->fd_count : 0u);
    if (total == 0) return fail_sock(WSAEINVAL);
    if (timeout && (timeout->tv_sec < 0 || timeout->tv_usec < 0)) return fail_sock(WSAEINVAL);

    {
        SrwLockGuard lock(g_state_lock);
        const auto& socks = state().sockets;
        auto validate = [&](const fd_set* set) -> bool {
            if (!set) return true;
            for (u_int i = 0; i < set->fd_count; ++i) {
                if (socks.find(set->fd_array[i]) == socks.end()) return false;
            }
            return true;
        };
        if (!validate(readfds) || !validate(writefds) || !validate(exceptfds)) return fail_sock(WSAENOTSOCK);
    }

    if (readfds) readfds->fd_count = 0;
    if (writefds) writefds->fd_count = 0;
    if (exceptfds) exceptfds->fd_count = 0;

    if (!timeout) {
        ::Sleep(1);
    } else if (timeout->tv_sec > 0 || timeout->tv_usec > 0) {
        const std::uint64_t sec = static_cast<std::uint64_t>(timeout->tv_sec);
        const std::uint64_t usec = static_cast<std::uint64_t>(timeout->tv_usec);
        const std::uint64_t ms =
            (sec >= kMaxPollSleepMs) ? kMaxPollSleepMs : std::min<std::uint64_t>(sec * 1000ull + (usec + 999ull) / 1000ull, kMaxPollSleepMs);
        ::Sleep(static_cast<DWORD>(ms));
    }
    return 0;
}

int WSAAPI ws_wsa_poll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (fds == 0 || !fdArray) return fail_sock(WSAEINVAL);

    int invalid_count = 0;
    {
        SrwLockGuard lock(g_state_lock);
        const auto& socks = state().sockets;
        for (ULONG i = 0; i < fds; ++i) {
            fdArray[i].revents = 0;
            if (fdArray[i].fd == INVALID_SOCKET) continue;
            if (socks.find(fdArray[i].fd) == socks.end()) {
                fdArray[i].revents = POLLNVAL;
                ++invalid_count;
            }
        }
    }
    if (invalid_count > 0) return invalid_count;
    if (timeout > 0) ::Sleep(static_cast<DWORD>(std::min<INT>(timeout, static_cast<INT>(kMaxPollSleepMs))));
    else if (timeout < 0) ::Sleep(1);
    return 0;
}

WSAEVENT WSAAPI ws_wsa_create_event() {
    if (!require_initialized()) return WSA_INVALID_EVENT;
    return ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
}
BOOL WSAAPI ws_wsa_close_event(WSAEVENT h) {
    if (!h) {
        set_wsa_error(WSA_INVALID_HANDLE);
        return FALSE;
    }
    return ::CloseHandle(h);
}
BOOL WSAAPI ws_wsa_set_event(WSAEVENT h) { return ::SetEvent(h); }
BOOL WSAAPI ws_wsa_reset_event(WSAEVENT h) { return ::ResetEvent(h); }

DWORD WSAAPI ws_wsa_wait_for_multiple_events(DWORD count, const WSAEVENT* events, BOOL wait_all, DWORD timeout,
                                             BOOL alertable) {
    if (!require_initialized()) return WSA_WAIT_FAILED;
    if (count == 0 || count > WSA_MAXIMUM_WAIT_EVENTS || !events) {
        set_wsa_error(WSA_INVALID_PARAMETER);
        return WSA_WAIT_FAILED;
    }
    return ::WaitForMultipleObjectsEx(count, events, wait_all, timeout, alertable);
}

int WSAAPI ws_wsa_event_select(SOCKET s, WSAEVENT event_object, long network_events) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!event_object && network_events != 0) return fail_sock(WSAEINVAL);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    it->second.event_handle = network_events ? event_object : nullptr;
    it->second.event_mask = event_object ? network_events : 0;
    if (event_object && network_events != 0) it->second.nonblocking = true;
    return 0;
}

int WSAAPI ws_wsa_enum_network_events(SOCKET s, WSAEVENT event_object, LPWSANETWORKEVENTS out) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!out) return fail_sock(WSAEFAULT);
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    std::memset(out, 0, sizeof(*out));
    out->lNetworkEvents = it->second.pending_events;
    std::memcpy(out->iErrorCode, it->second.event_errors, sizeof(out->iErrorCode));
    it->second.pending_events = 0;
    std::memset(it->second.event_errors, 0, sizeof(it->second.event_errors));
    if (event_object) ::ResetEvent(event_object);
    return 0;
}

int WSAAPI ws_wsa_async_select(SOCKET s, HWND, u_int, long events) {
    if (!require_initialized()) return SOCKET_ERROR;
    SrwLockGuard lock(g_state_lock);
    auto it = state().sockets.find(s);
    if (it == state().sockets.end()) return fail_sock(WSAENOTSOCK);
    if (events != 0) it->second.nonblocking = true;
    return 0;
}

int WSAAPI ws_wsa_enum_protocols_a(LPINT, LPWSAPROTOCOL_INFOA, LPDWORD buf_len) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!buf_len) return fail_sock(WSAEFAULT);
    *buf_len = 0;
    return 0;
}

int WSAAPI ws_wsa_enum_protocols_w(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD buf_len) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!buf_len) return fail_sock(WSAEFAULT);
    *buf_len = 0;
    return 0;
}

// ---- Address string conversion (pure in-process) ----------------------------------------------------------------

unsigned long WSAAPI ws_inet_addr(const char* cp) {
    if (!cp) return INADDR_NONE;
    if (std::strcmp(cp, "255.255.255.255") == 0) return INADDR_NONE;
    std::uint8_t b[4]{};
    if (!parse_ipv4_strict(cp, b)) return INADDR_NONE;
    unsigned long result = 0;
    std::memcpy(&result, b, 4);
    return result;
}

char* WSAAPI ws_inet_ntoa(in_addr in) {
    char* buf = g_inet_ntoa_fallback;
    const DWORD fls = state().inet_ntoa_fls;
    if (fls != FLS_OUT_OF_INDEXES) {
        char* slot = static_cast<char*>(::FlsGetValue(fls));
        if (!slot) {
            slot = static_cast<char*>(std::malloc(16));
            if (slot) {
                if (!::FlsSetValue(fls, slot)) {
                    std::free(slot);
                    slot = nullptr;
                }
            }
        }
        if (slot) buf = slot;
    }
    std::uint8_t b[4];
    std::memcpy(b, &in, 4);
    std::snprintf(buf, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

int WSAAPI ws_inet_pton_a(INT family, PCSTR src, PVOID dst) {
    if (!src || !dst) {
        set_wsa_error(WSAEFAULT);
        return -1;
    }
    if (family == AF_INET) {
        std::uint8_t b[4]{};
        if (!parse_ipv4_strict(src, b)) return 0;
        std::memcpy(dst, b, 4);
        return 1;
    }
    if (family == AF_INET6) {
        std::uint8_t b[16]{};
        if (!parse_ipv6_strict(src, b)) return 0;
        std::memcpy(dst, b, 16);
        return 1;
    }
    set_wsa_error(WSAEAFNOSUPPORT);
    return -1;
}

int WSAAPI ws_inet_pton_w(INT family, PCWSTR src, PVOID dst) {
    if (!src || !dst) {
        set_wsa_error(WSAEFAULT);
        return -1;
    }
    const std::string utf8 = narrow_utf8(src);
    return ws_inet_pton_a(family, utf8.c_str(), dst);
}

PCSTR WSAAPI ws_inet_ntop_a(INT family, const VOID* src, PSTR dst, size_t size) {
    if (!src || !dst) {
        set_wsa_error(WSAEFAULT);
        return nullptr;
    }
    std::string text;
    if (family == AF_INET) {
        std::uint8_t b[4];
        std::memcpy(b, src, 4);
        text = format_ipv4(b);
    } else if (family == AF_INET6) {
        std::uint8_t b[16];
        std::memcpy(b, src, 16);
        text = format_ipv6(b);
    } else {
        set_wsa_error(WSAEAFNOSUPPORT);
        return nullptr;
    }
    if (text.size() + 1 > size) {
        set_wsa_error(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    std::memcpy(dst, text.c_str(), text.size() + 1);
    return dst;
}

PCWSTR WSAAPI ws_inet_ntop_w(INT family, const VOID* src, PWSTR dst, size_t size) {
    if (!src || !dst) {
        set_wsa_error(WSAEFAULT);
        return nullptr;
    }
    char narrow[64]{};
    if (!ws_inet_ntop_a(family, src, narrow, sizeof(narrow))) return nullptr;
    const std::wstring wide = widen_utf8(narrow);
    if (wide.size() + 1 > size) {
        set_wsa_error(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    std::memcpy(dst, wide.c_str(), (wide.size() + 1) * sizeof(wchar_t));
    return dst;
}

int WSAAPI ws_wsa_address_to_string_a(LPSOCKADDR addr, DWORD addr_len, LPWSAPROTOCOL_INFOA, LPSTR out, LPDWORD out_len) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!addr || !out_len) return fail_sock(WSAEFAULT);
    std::string text;
    if (addr->sa_family == AF_INET && addr_len >= sizeof(sockaddr_in)) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(addr);
        std::uint8_t b[4];
        std::memcpy(b, &in->sin_addr, 4);
        text = format_ipv4(b);
        if (in->sin_port != 0) text += ":" + std::to_string(bswap16(in->sin_port));
    } else if (addr->sa_family == AF_INET6 && addr_len >= sizeof(sockaddr_in6)) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        std::uint8_t b[16];
        std::memcpy(b, &in6->sin6_addr, 16);
        text = format_ipv6(b);
        if (in6->sin6_port != 0) text = "[" + text + "]:" + std::to_string(bswap16(in6->sin6_port));
    } else {
        return fail_sock(WSAEFAULT);
    }
    const DWORD needed = static_cast<DWORD>(text.size() + 1);
    if (!out || *out_len < needed) {
        *out_len = needed;
        return fail_sock(WSAEFAULT);
    }
    std::memcpy(out, text.c_str(), needed);
    *out_len = needed;
    return 0;
}

int WSAAPI ws_wsa_address_to_string_w(LPSOCKADDR addr, DWORD addr_len, LPWSAPROTOCOL_INFOW, LPWSTR out, LPDWORD out_len) {
    if (!out_len) return fail_sock(WSAEFAULT);
    char narrow[128]{};
    DWORD nlen = static_cast<DWORD>(sizeof(narrow));
    if (ws_wsa_address_to_string_a(addr, addr_len, nullptr, narrow, &nlen) != 0) return SOCKET_ERROR;
    const std::wstring wide = widen_utf8(narrow);
    const DWORD needed = static_cast<DWORD>(wide.size() + 1);
    if (!out || *out_len < needed) {
        *out_len = needed;
        return fail_sock(WSAEFAULT);
    }
    std::memcpy(out, wide.c_str(), needed * sizeof(wchar_t));
    *out_len = needed;
    return 0;
}

int WSAAPI ws_wsa_string_to_address_a(LPSTR str, INT family, LPWSAPROTOCOL_INFOA, LPSOCKADDR out, LPINT out_len) {
    if (!require_initialized()) return SOCKET_ERROR;
    if (!str || !out || !out_len) return fail_sock(WSAEFAULT);
    std::string host = str;
    std::uint16_t port = 0;
    if (family == AF_INET) {
        const size_t colon = host.rfind(':');
        if (colon != std::string::npos) {
            if (!parse_port_service(host.substr(colon + 1).c_str(), port)) return fail_sock(WSAEINVAL);
            host.resize(colon);
        }
        std::uint8_t b[4]{};
        if (!parse_ipv4_strict(host.c_str(), b)) return fail_sock(WSAEINVAL);
        if (*out_len < static_cast<int>(sizeof(sockaddr_in))) {
            *out_len = static_cast<int>(sizeof(sockaddr_in));
            return fail_sock(WSAEFAULT);
        }
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = bswap16(port);
        std::memcpy(&in.sin_addr, b, 4);
        std::memcpy(out, &in, sizeof(in));
        *out_len = static_cast<int>(sizeof(in));
        return 0;
    }
    if (family == AF_INET6) {
        if (!host.empty() && host.front() == '[') {
            const size_t close = host.find(']');
            if (close == std::string::npos) return fail_sock(WSAEINVAL);
            if (close + 1 < host.size()) {
                if (host[close + 1] != ':' || !parse_port_service(host.substr(close + 2).c_str(), port))
                    return fail_sock(WSAEINVAL);
            }
            host = host.substr(1, close - 1);
        }
        std::uint8_t b[16]{};
        if (!parse_ipv6_strict(host.c_str(), b)) return fail_sock(WSAEINVAL);
        if (*out_len < static_cast<int>(sizeof(sockaddr_in6))) {
            *out_len = static_cast<int>(sizeof(sockaddr_in6));
            return fail_sock(WSAEFAULT);
        }
        sockaddr_in6 in6{};
        in6.sin6_family = AF_INET6;
        in6.sin6_port = bswap16(port);
        std::memcpy(&in6.sin6_addr, b, 16);
        std::memcpy(out, &in6, sizeof(in6));
        *out_len = static_cast<int>(sizeof(in6));
        return 0;
    }
    return fail_sock(WSAEINVAL);
}

int WSAAPI ws_wsa_string_to_address_w(LPWSTR str, INT family, LPWSAPROTOCOL_INFOW, LPSOCKADDR out, LPINT out_len) {
    if (!str) return fail_sock(WSAEFAULT);
    std::string narrow = narrow_utf8(str);
    return ws_wsa_string_to_address_a(narrow.data(), family, nullptr, out, out_len);
}

// ---- Offline DNS & Host / Protocol / Service Resolution ---------------------------------------------------------

template <typename AddrInfoT>
AddrInfoT* make_addrinfo_v4(const std::uint8_t ip[4], std::uint16_t port_host, int socktype, int protocol) {
    auto* ai = new (std::nothrow) AddrInfoT{};
    auto* sa = new (std::nothrow) sockaddr_in{};
    if (!ai || !sa) {
        delete ai;
        delete sa;
        return nullptr;
    }
    sa->sin_family = AF_INET;
    sa->sin_port = bswap16(port_host);
    std::memcpy(&sa->sin_addr, ip, 4);
    ai->ai_family = AF_INET;
    ai->ai_socktype = socktype;
    ai->ai_protocol = protocol;
    ai->ai_addrlen = sizeof(sockaddr_in);
    ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
    return ai;
}

template <typename AddrInfoT>
AddrInfoT* make_addrinfo_v6(const std::uint8_t ip[16], std::uint16_t port_host, int socktype, int protocol) {
    auto* ai = new (std::nothrow) AddrInfoT{};
    auto* sa = new (std::nothrow) sockaddr_in6{};
    if (!ai || !sa) {
        delete ai;
        delete sa;
        return nullptr;
    }
    sa->sin6_family = AF_INET6;
    sa->sin6_port = bswap16(port_host);
    std::memcpy(&sa->sin6_addr, ip, 16);
    ai->ai_family = AF_INET6;
    ai->ai_socktype = socktype;
    ai->ai_protocol = protocol;
    ai->ai_addrlen = sizeof(sockaddr_in6);
    ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
    return ai;
}

template <typename AddrInfoT>
void free_addrinfo_chain(AddrInfoT* head) {
    while (head) {
        AddrInfoT* next = head->ai_next;
        if (head->ai_addr) {
            if (head->ai_family == AF_INET6) delete reinterpret_cast<sockaddr_in6*>(head->ai_addr);
            else delete reinterpret_cast<sockaddr_in*>(head->ai_addr);
        }
        delete[] head->ai_canonname;
        delete head;
        head = next;
    }
}

template <typename AddrInfoT>
bool set_addrinfo_canonname(AddrInfoT* ai, const std::string& canon) {
    if (!ai) return false;
    using CharT = std::remove_cv_t<std::remove_pointer_t<decltype(ai->ai_canonname)>>;
    if constexpr (std::is_same_v<CharT, wchar_t>) {
        const std::wstring w = widen_utf8(canon.c_str());
        auto* copy = new (std::nothrow) wchar_t[w.size() + 1];
        if (!copy) return false;
        std::memcpy(copy, w.c_str(), (w.size() + 1) * sizeof(wchar_t));
        ai->ai_canonname = copy;
    } else {
        auto* copy = new (std::nothrow) char[canon.size() + 1];
        if (!copy) return false;
        std::memcpy(copy, canon.c_str(), canon.size() + 1);
        ai->ai_canonname = copy;
    }
    return true;
}

template <typename AddrInfoT>
int resolve_addrinfo_local(const char* node, const char* service, int family, int socktype, int protocol, int flags,
                           AddrInfoT** out) {
    if (!out) {
        set_wsa_error(WSAEFAULT);
        return WSAEFAULT;
    }
    *out = nullptr;
    if (!require_initialized()) return WSANOTINITIALISED;
    if ((!node || !*node) && (!service || !*service)) {
        set_wsa_error(WSAHOST_NOT_FOUND);
        return WSAHOST_NOT_FOUND;
    }
    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
        set_wsa_error(WSAEAFNOSUPPORT);
        return WSAEAFNOSUPPORT;
    }
    if (socktype != 0 && socktype != SOCK_STREAM && socktype != SOCK_DGRAM && socktype != SOCK_RAW) {
        set_wsa_error(WSAESOCKTNOSUPPORT);
        return WSAESOCKTNOSUPPORT;
    }
    std::uint16_t port = 0;
    if (!parse_port_service(service, port)) {
        set_wsa_error(WSATYPE_NOT_FOUND);
        return WSATYPE_NOT_FOUND;
    }
    if (protocol == 0 && socktype == SOCK_STREAM) protocol = IPPROTO_TCP;
    else if (protocol == 0 && socktype == SOCK_DGRAM) protocol = IPPROTO_UDP;

    auto attach_canon = [&](AddrInfoT* head, const std::string& canon) -> int {
        if ((flags & AI_CANONNAME) != 0 && !canon.empty()) {
            if (!set_addrinfo_canonname(head, canon)) {
                free_addrinfo_chain(head);
                set_wsa_error(WSA_NOT_ENOUGH_MEMORY);
                return WSA_NOT_ENOUGH_MEMORY;
            }
        }
        *out = head;
        return 0;
    };

    // 1. Null / empty node (AI_PASSIVE -> wildcard 0.0.0.0 / ::, else loopback 127.0.0.1 / ::1).
    if (!node || !*node) {
        const bool passive = (flags & AI_PASSIVE) != 0;
        const std::uint8_t v4[4] = {passive ? std::uint8_t(0) : std::uint8_t(127), 0, 0,
                                    passive ? std::uint8_t(0) : std::uint8_t(1)};
        std::uint8_t v6[16]{};
        if (!passive) v6[15] = 1;
        AddrInfoT* head = nullptr;
        if (family == AF_INET) {
            head = make_addrinfo_v4<AddrInfoT>(v4, port, socktype, protocol);
        } else if (family == AF_INET6) {
            head = make_addrinfo_v6<AddrInfoT>(v6, port, socktype, protocol);
        } else {
            AddrInfoT* first = make_addrinfo_v4<AddrInfoT>(v4, port, socktype, protocol);
            AddrInfoT* second = make_addrinfo_v6<AddrInfoT>(v6, port, socktype, protocol);
            if (!first || !second) {
                free_addrinfo_chain(first);
                free_addrinfo_chain(second);
                set_wsa_error(WSA_NOT_ENOUGH_MEMORY);
                return WSA_NOT_ENOUGH_MEMORY;
            }
            first->ai_next = second;
            head = first;
        }
        if (!head) {
            set_wsa_error(WSA_NOT_ENOUGH_MEMORY);
            return WSA_NOT_ENOUGH_MEMORY;
        }
        *out = head;
        return 0;
    }

    // 2. Numeric IPv4 literal.
    std::uint8_t v4[4]{};
    if (parse_ipv4_strict(node, v4)) {
        if (family == AF_INET6) {
            set_wsa_error(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        AddrInfoT* head = make_addrinfo_v4<AddrInfoT>(v4, port, socktype, protocol);
        if (!head) {
            set_wsa_error(WSA_NOT_ENOUGH_MEMORY);
            return WSA_NOT_ENOUGH_MEMORY;
        }
        return attach_canon(head, format_ipv4(v4));
    }

    // 3. Numeric IPv6 literal.
    std::uint8_t v6[16]{};
    if (parse_ipv6_strict(node, v6)) {
        if (family == AF_INET) {
            set_wsa_error(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        AddrInfoT* head = make_addrinfo_v6<AddrInfoT>(v6, port, socktype, protocol);
        if (!head) {
            set_wsa_error(WSA_NOT_ENOUGH_MEMORY);
            return WSA_NOT_ENOUGH_MEMORY;
        }
        return attach_canon(head, format_ipv6(v6));
    }

    // 4. Localhost / offline host name (unless AI_NUMERICHOST forbids name resolution).
    if ((flags & AI_NUMERICHOST) == 0 &&
        (equals_ignore_case_ascii(node, "localhost") || equals_ignore_case_ascii(node, "leonida-offline"))) {
        const std::uint8_t lo4[4] = {127, 0, 0, 1};
        std::uint8_t lo6[16]{};
        lo6[15] = 1;
        AddrInfoT* head = nullptr;
        if (family == AF_INET) {
            head = make_addrinfo_v4<AddrInfoT>(lo4, port, socktype, protocol);
        } else if (family == AF_INET6) {
            head = make_addrinfo_v6<AddrInfoT>(lo6, port, socktype, protocol);
        } else {
            AddrInfoT* first = make_addrinfo_v4<AddrInfoT>(lo4, port, socktype, protocol);
            AddrInfoT* second = make_addrinfo_v6<AddrInfoT>(lo6, port, socktype, protocol);
            if (!first || !second) {
                free_addrinfo_chain(first);
                free_addrinfo_chain(second);
                set_wsa_error(WSA_NOT_ENOUGH_MEMORY);
                return WSA_NOT_ENOUGH_MEMORY;
            }
            first->ai_next = second;
            head = first;
        }
        if (!head) {
            set_wsa_error(WSA_NOT_ENOUGH_MEMORY);
            return WSA_NOT_ENOUGH_MEMORY;
        }
        return attach_canon(head, equals_ignore_case_ascii(node, "leonida-offline") ? "leonida-offline" : "localhost");
    }

    // 5. Any remote hostname: refuse offline without touching the host DNS resolver.
    log_refused_once("DNS", node);
    set_wsa_error(WSAHOST_NOT_FOUND);
    return WSAHOST_NOT_FOUND;
}

int WSAAPI ws_getaddrinfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* out) {
    return resolve_addrinfo_local<ADDRINFOA>(node, service, hints ? hints->ai_family : AF_UNSPEC,
                                             hints ? hints->ai_socktype : 0, hints ? hints->ai_protocol : 0,
                                             hints ? hints->ai_flags : 0, out);
}

void WSAAPI ws_freeaddrinfo(PADDRINFOA ai) { free_addrinfo_chain(ai); }

int WSAAPI ws_getaddrinfo_w(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* out) {
    const std::string n = narrow_utf8(node);
    const std::string s = narrow_utf8(service);
    return resolve_addrinfo_local<ADDRINFOW>(node ? n.c_str() : nullptr, service ? s.c_str() : nullptr,
                                             hints ? hints->ai_family : AF_UNSPEC, hints ? hints->ai_socktype : 0,
                                             hints ? hints->ai_protocol : 0, hints ? hints->ai_flags : 0, out);
}

void WSAAPI ws_freeaddrinfo_w(PADDRINFOW ai) { free_addrinfo_chain(ai); }

int WSAAPI ws_getaddrinfo_ex_a(PCSTR node, PCSTR service, DWORD, LPGUID, const ADDRINFOEXA* hints, PADDRINFOEXA* out,
                               timeval*, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE cancel_handle) {
    if (cancel_handle) *cancel_handle = nullptr;
    return resolve_addrinfo_local<ADDRINFOEXA>(node, service, hints ? hints->ai_family : AF_UNSPEC,
                                               hints ? hints->ai_socktype : 0, hints ? hints->ai_protocol : 0,
                                               hints ? hints->ai_flags : 0, out);
}

int WSAAPI ws_getaddrinfo_ex_w(PCWSTR node, PCWSTR service, DWORD, LPGUID, const ADDRINFOEXW* hints, PADDRINFOEXW* out,
                               timeval*, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE cancel_handle) {
    if (cancel_handle) *cancel_handle = nullptr;
    const std::string n = narrow_utf8(node);
    const std::string s = narrow_utf8(service);
    return resolve_addrinfo_local<ADDRINFOEXW>(node ? n.c_str() : nullptr, service ? s.c_str() : nullptr,
                                               hints ? hints->ai_family : AF_UNSPEC, hints ? hints->ai_socktype : 0,
                                               hints ? hints->ai_protocol : 0, hints ? hints->ai_flags : 0, out);
}

void WSAAPI ws_freeaddrinfo_ex_a(PADDRINFOEXA ai) { free_addrinfo_chain(ai); }
void WSAAPI ws_freeaddrinfo_ex_w(PADDRINFOEXW ai) { free_addrinfo_chain(ai); }
int WSAAPI ws_getaddrinfo_ex_cancel(LPHANDLE) { return WSA_INVALID_HANDLE; }
int WSAAPI ws_getaddrinfo_ex_overlapped_result(LPOVERLAPPED) { return WSA_IO_INCOMPLETE; }

int WSAAPI ws_getnameinfo_a(const sockaddr* sa, socklen_t salen, PCHAR host, DWORD hostlen, PCHAR serv, DWORD servlen,
                            INT) {
    if (!require_initialized()) return WSANOTINITIALISED;
    if (!sa) {
        set_wsa_error(WSAEFAULT);
        return WSAEFAULT;
    }
    std::string htext;
    std::uint16_t port = 0;
    if (sa->sa_family == AF_INET && salen >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        std::uint8_t b[4];
        std::memcpy(b, &in->sin_addr, 4);
        htext = format_ipv4(b);
        port = bswap16(in->sin_port);
    } else if (sa->sa_family == AF_INET6 && salen >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
        std::uint8_t b[16];
        std::memcpy(b, &in6->sin6_addr, 16);
        htext = format_ipv6(b);
        port = bswap16(in6->sin6_port);
    } else {
        set_wsa_error(WSAEAFNOSUPPORT);
        return WSAEAFNOSUPPORT;
    }
    if (host && hostlen > 0) {
        if (htext.size() + 1 > hostlen) {
            set_wsa_error(WSAEFAULT);
            return WSAEFAULT;
        }
        std::memcpy(host, htext.c_str(), htext.size() + 1);
    }
    if (serv && servlen > 0) {
        const std::string stext = std::to_string(port);
        if (stext.size() + 1 > servlen) {
            set_wsa_error(WSAEFAULT);
            return WSAEFAULT;
        }
        std::memcpy(serv, stext.c_str(), stext.size() + 1);
    }
    return 0;
}

int WSAAPI ws_getnameinfo_w(const SOCKADDR* sa, socklen_t salen, PWCHAR host, DWORD hostlen, PWCHAR serv, DWORD servlen,
                            INT flags) {
    char hbuf[128]{};
    char sbuf[32]{};
    const int rc = ws_getnameinfo_a(sa, salen, host ? hbuf : nullptr, static_cast<DWORD>(sizeof(hbuf)),
                                    serv ? sbuf : nullptr, static_cast<DWORD>(sizeof(sbuf)), flags);
    if (rc != 0) return rc;
    if (host && hostlen > 0) {
        const std::wstring hw = widen_utf8(hbuf);
        if (hw.size() + 1 > hostlen) {
            set_wsa_error(WSAEFAULT);
            return WSAEFAULT;
        }
        std::memcpy(host, hw.c_str(), (hw.size() + 1) * sizeof(wchar_t));
    }
    if (serv && servlen > 0) {
        const std::wstring sw = widen_utf8(sbuf);
        if (sw.size() + 1 > servlen) {
            set_wsa_error(WSAEFAULT);
            return WSAEFAULT;
        }
        std::memcpy(serv, sw.c_str(), (sw.size() + 1) * sizeof(wchar_t));
    }
    return 0;
}

int WSAAPI ws_gethostname_a(char* name, int namelen) {
    if (!require_initialized()) return SOCKET_ERROR;
    static constexpr char kHost[] = "leonida-offline";
    if (!name || namelen < static_cast<int>(sizeof(kHost))) return fail_sock(WSAEFAULT);
    std::memcpy(name, kHost, sizeof(kHost));
    return 0;
}

int WSAAPI ws_gethostname_w(PWSTR name, int namelen) {
    if (!require_initialized()) return SOCKET_ERROR;
    static constexpr wchar_t kHost[] = L"leonida-offline";
    static constexpr int kChars = static_cast<int>(sizeof(kHost) / sizeof(wchar_t));
    if (!name || namelen < kChars) return fail_sock(WSAEFAULT);
    std::memcpy(name, kHost, sizeof(kHost));
    return 0;
}

hostent* WSAAPI ws_gethostbyname(const char* name) {
    if (!require_initialized()) return nullptr;
    if (!name || !*name || equals_ignore_case_ascii(name, "localhost") ||
        equals_ignore_case_ascii(name, "leonida-offline") || std::strcmp(name, "127.0.0.1") == 0) {
        return &g_lo_hostent;
    }
    log_refused_once("DNS", name);
    set_wsa_error(WSAHOST_NOT_FOUND);
    return nullptr;
}

hostent* WSAAPI ws_gethostbyaddr(const char*, int, int) {
    if (!require_initialized()) return nullptr;
    set_wsa_error(WSAHOST_NOT_FOUND);
    return nullptr;
}

protoent* WSAAPI ws_getprotobynumber(int number) {
    if (!require_initialized()) return nullptr;
    if (number == IPPROTO_TCP) return &g_proto_tcp;
    if (number == IPPROTO_UDP) return &g_proto_udp;
    if (number == IPPROTO_ICMP) return &g_proto_icmp;
    set_wsa_error(WSANO_DATA);
    return nullptr;
}

protoent* WSAAPI ws_getprotobyname(const char* name) {
    if (!require_initialized()) return nullptr;
    if (!name) {
        set_wsa_error(WSANO_DATA);
        return nullptr;
    }
    if (equals_ignore_case_ascii(name, "tcp")) return ws_getprotobynumber(IPPROTO_TCP);
    if (equals_ignore_case_ascii(name, "udp")) return ws_getprotobynumber(IPPROTO_UDP);
    if (equals_ignore_case_ascii(name, "icmp")) return ws_getprotobynumber(IPPROTO_ICMP);
    set_wsa_error(WSANO_DATA);
    return nullptr;
}

servent* WSAAPI ws_getservbyname(const char*, const char*) {
    if (!require_initialized()) return nullptr;
    set_wsa_error(WSANO_DATA);
    return nullptr;
}

servent* WSAAPI ws_getservbyport(int, const char*) {
    if (!require_initialized()) return nullptr;
    set_wsa_error(WSANO_DATA);
    return nullptr;
}

}  // namespace
}  // namespace rt::ws2_32

namespace {
using namespace rt::ws2_32;
#define WS2_EXPORT(ord, name, fn)                                      \
    {"ws2_32.dll", name, reinterpret_cast<void*>(&(fn))},              \
    {"ws2_32.dll", "#" #ord, reinterpret_cast<void*>(&(fn))}
}  // namespace

// Registered under both export names and official Windows ws2_32.dll ordinals (ordinal base 1):
// MSVC ws2_32.lib links classic Winsock 1.1 calls (#1-#23, #51-#57, #111-#116, #151) by ordinal and
// newer Winsock2 calls (getaddrinfo/freeaddrinfo/WSA*) by name.
SHIM_TABLE(ws2_32_offline,
    WS2_EXPORT(1, "accept", ws_accept),
    WS2_EXPORT(2, "bind", ws_bind),
    WS2_EXPORT(3, "closesocket", ws_closesocket),
    WS2_EXPORT(4, "connect", ws_connect),
    WS2_EXPORT(5, "getpeername", ws_getpeername),
    WS2_EXPORT(6, "getsockname", ws_getsockname),
    WS2_EXPORT(7, "getsockopt", ws_getsockopt),
    WS2_EXPORT(8, "htonl", ws_htonl),
    WS2_EXPORT(9, "htons", ws_htons),
    WS2_EXPORT(10, "ioctlsocket", ws_ioctlsocket),
    WS2_EXPORT(11, "inet_addr", ws_inet_addr),
    WS2_EXPORT(12, "inet_ntoa", ws_inet_ntoa),
    WS2_EXPORT(13, "listen", ws_listen),
    WS2_EXPORT(14, "ntohl", ws_ntohl),
    WS2_EXPORT(15, "ntohs", ws_ntohs),
    WS2_EXPORT(16, "recv", ws_recv),
    WS2_EXPORT(17, "recvfrom", ws_recvfrom),
    WS2_EXPORT(18, "select", ws_select),
    WS2_EXPORT(19, "send", ws_send),
    WS2_EXPORT(20, "sendto", ws_sendto),
    WS2_EXPORT(21, "setsockopt", ws_setsockopt),
    WS2_EXPORT(22, "shutdown", ws_shutdown),
    WS2_EXPORT(23, "socket", ws_socket),
    WS2_EXPORT(24, "FreeAddrInfoEx", ws_freeaddrinfo_ex_a),
    WS2_EXPORT(25, "FreeAddrInfoExW", ws_freeaddrinfo_ex_w),
    WS2_EXPORT(26, "FreeAddrInfoW", ws_freeaddrinfo_w),
    WS2_EXPORT(27, "GetAddrInfoExA", ws_getaddrinfo_ex_a),
    WS2_EXPORT(28, "GetAddrInfoExCancel", ws_getaddrinfo_ex_cancel),
    WS2_EXPORT(29, "GetAddrInfoExOverlappedResult", ws_getaddrinfo_ex_overlapped_result),
    WS2_EXPORT(30, "GetAddrInfoExW", ws_getaddrinfo_ex_w),
    WS2_EXPORT(31, "GetAddrInfoW", ws_getaddrinfo_w),
    WS2_EXPORT(32, "GetHostNameW", ws_gethostname_w),
    WS2_EXPORT(33, "GetNameInfoW", ws_getnameinfo_w),
    WS2_EXPORT(34, "InetNtopW", ws_inet_ntop_w),
    WS2_EXPORT(35, "InetPtonW", ws_inet_pton_w),
    WS2_EXPORT(41, "WSAAccept", ws_wsa_accept),
    WS2_EXPORT(42, "WSAAddressToStringA", ws_wsa_address_to_string_a),
    WS2_EXPORT(43, "WSAAddressToStringW", ws_wsa_address_to_string_w),
    WS2_EXPORT(45, "WSACloseEvent", ws_wsa_close_event),
    WS2_EXPORT(46, "WSAConnect", ws_wsa_connect),
    WS2_EXPORT(47, "WSAConnectByList", ws_wsa_connect_by_list),
    WS2_EXPORT(48, "WSAConnectByNameA", ws_wsa_connect_by_name_a),
    WS2_EXPORT(49, "WSAConnectByNameW", ws_wsa_connect_by_name_w),
    WS2_EXPORT(50, "WSACreateEvent", ws_wsa_create_event),
    WS2_EXPORT(51, "gethostbyaddr", ws_gethostbyaddr),
    WS2_EXPORT(52, "gethostbyname", ws_gethostbyname),
    WS2_EXPORT(53, "getprotobyname", ws_getprotobyname),
    WS2_EXPORT(54, "getprotobynumber", ws_getprotobynumber),
    WS2_EXPORT(55, "getservbyname", ws_getservbyname),
    WS2_EXPORT(56, "getservbyport", ws_getservbyport),
    WS2_EXPORT(57, "gethostname", ws_gethostname_a),
    WS2_EXPORT(64, "WSAEnumNetworkEvents", ws_wsa_enum_network_events),
    WS2_EXPORT(65, "WSAEnumProtocolsA", ws_wsa_enum_protocols_a),
    WS2_EXPORT(66, "WSAEnumProtocolsW", ws_wsa_enum_protocols_w),
    WS2_EXPORT(67, "WSAEventSelect", ws_wsa_event_select),
    WS2_EXPORT(68, "WSAGetOverlappedResult", ws_wsa_get_overlapped_result),
    WS2_EXPORT(74, "WSAHtonl", ws_wsa_htonl),
    WS2_EXPORT(75, "WSAHtons", ws_wsa_htons),
    WS2_EXPORT(78, "WSAIoctl", ws_wsa_ioctl),
    WS2_EXPORT(86, "WSANtohl", ws_wsa_ntohl),
    WS2_EXPORT(87, "WSANtohs", ws_wsa_ntohs),
    WS2_EXPORT(88, "WSAPoll", ws_wsa_poll),
    WS2_EXPORT(91, "WSARecv", ws_wsa_recv),
    WS2_EXPORT(92, "WSARecvDisconnect", ws_wsa_recv_disconnect),
    WS2_EXPORT(93, "WSARecvFrom", ws_wsa_recv_from),
    WS2_EXPORT(95, "WSAResetEvent", ws_wsa_reset_event),
    WS2_EXPORT(96, "WSASend", ws_wsa_send),
    WS2_EXPORT(97, "WSASendDisconnect", ws_wsa_send_disconnect),
    WS2_EXPORT(98, "WSASendMsg", ws_wsa_send_msg),
    WS2_EXPORT(99, "WSASendTo", ws_wsa_send_to),
    WS2_EXPORT(100, "WSASetEvent", ws_wsa_set_event),
    WS2_EXPORT(101, "WSAAsyncSelect", ws_wsa_async_select),
    WS2_EXPORT(111, "WSAGetLastError", ws_wsa_get_last_error),
    WS2_EXPORT(112, "WSASetLastError", ws_wsa_set_last_error),
    WS2_EXPORT(113, "WSACancelBlockingCall", ws_wsa_cancel_blocking_call),
    WS2_EXPORT(114, "WSAIsBlocking", ws_wsa_is_blocking),
    WS2_EXPORT(115, "WSAStartup", ws_wsa_startup),
    WS2_EXPORT(116, "WSACleanup", ws_wsa_cleanup),
    WS2_EXPORT(119, "WSASocketA", ws_wsa_socket_a),
    WS2_EXPORT(120, "WSASocketW", ws_wsa_socket_w),
    WS2_EXPORT(121, "WSAStringToAddressA", ws_wsa_string_to_address_a),
    WS2_EXPORT(122, "WSAStringToAddressW", ws_wsa_string_to_address_w),
    WS2_EXPORT(124, "WSAWaitForMultipleEvents", ws_wsa_wait_for_multiple_events),
    WS2_EXPORT(151, "__WSAFDIsSet", ws_wsa_fd_is_set),
    WS2_EXPORT(191, "freeaddrinfo", ws_freeaddrinfo),
    WS2_EXPORT(192, "getaddrinfo", ws_getaddrinfo),
    WS2_EXPORT(193, "getnameinfo", ws_getnameinfo_a),
    WS2_EXPORT(194, "inet_ntop", ws_inet_ntop_a),
    WS2_EXPORT(195, "inet_pton", ws_inet_pton_a),
);
