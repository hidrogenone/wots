// Checks the offline Winsock2 shim the runtime installs for ws2_32.dll (runtime/shims/ws2_32_offline.cpp).
//
// Every function is resolved through rt::shims::find under ws2_32.dll (both by export name and by Windows ordinal) so
// this executable links zero host ws2_32.dll imports and touches no network. Remote targets use RFC 2606 (.invalid) and
// RFC 5737 / RFC 3849 documentation addresses (192.0.2.0/24, 2001:db8::/32).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <thread>
#include <vector>

#include "shims.h"

namespace {

using WSAStartupFn = int(WSAAPI*)(WORD, LPWSADATA);
using WSACleanupFn = int(WSAAPI*)();
using WSAGetLastErrorFn = int(WSAAPI*)();
using WSASetLastErrorFn = void(WSAAPI*)(int);
using WSACancelBlockingCallFn = int(WSAAPI*)();
using WSAIsBlockingFn = BOOL(WSAAPI*)();
using SocketFn = SOCKET(WSAAPI*)(int, int, int);
using WSASocketAFn = SOCKET(WSAAPI*)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
using WSASocketWFn = SOCKET(WSAAPI*)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
using ClosesocketFn = int(WSAAPI*)(SOCKET);
using BindFn = int(WSAAPI*)(SOCKET, const sockaddr*, int);
using GetsocknameFn = int(WSAAPI*)(SOCKET, sockaddr*, int*);
using GetpeernameFn = int(WSAAPI*)(SOCKET, sockaddr*, int*);
using ListenFn = int(WSAAPI*)(SOCKET, int);
using AcceptFn = SOCKET(WSAAPI*)(SOCKET, sockaddr*, int*);
using WSAAcceptFn = SOCKET(WSAAPI*)(SOCKET, sockaddr*, LPINT, LPCONDITIONPROC, DWORD_PTR);
using ShutdownFn = int(WSAAPI*)(SOCKET, int);
using SetsockoptFn = int(WSAAPI*)(SOCKET, int, int, const char*, int);
using GetsockoptFn = int(WSAAPI*)(SOCKET, int, int, char*, int*);
using IoctlsocketFn = int(WSAAPI*)(SOCKET, long, u_long*);
using WSAIoctlFn = int(WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using ConnectFn = int(WSAAPI*)(SOCKET, const sockaddr*, int);
using WSAConnectFn = int(WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using WSAConnectByNameAFn = BOOL(WSAAPI*)(SOCKET, LPCSTR, LPCSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                                          const timeval*, LPWSAOVERLAPPED);
using WSAConnectByNameWFn = BOOL(WSAAPI*)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                                          const timeval*, LPWSAOVERLAPPED);
using WSAConnectByListFn = BOOL(WSAAPI*)(SOCKET, PSOCKET_ADDRESS_LIST, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                                         const timeval*, LPWSAOVERLAPPED);
using SendFn = int(WSAAPI*)(SOCKET, const char*, int, int);
using SendtoFn = int(WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using RecvFn = int(WSAAPI*)(SOCKET, char*, int, int);
using RecvfromFn = int(WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
using WSASendFn = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSASendToFn = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSASendMsgFn = int(WSAAPI*)(SOCKET, LPWSAMSG, DWORD, LPDWORD, LPWSAOVERLAPPED,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFn = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFromFn = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT, LPWSAOVERLAPPED,
                                   LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSASendDisconnectFn = int(WSAAPI*)(SOCKET, LPWSABUF);
using WSARecvDisconnectFn = int(WSAAPI*)(SOCKET, LPWSABUF);
using WSAGetOverlappedResultFn = BOOL(WSAAPI*)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
using WSAFDIsSetFn = int(PASCAL*)(SOCKET, fd_set*);
using SelectFn = int(WSAAPI*)(int, fd_set*, fd_set*, fd_set*, const timeval*);
using WSAPollFn = int(WSAAPI*)(LPWSAPOLLFD, ULONG, INT);
using WSACreateEventFn = WSAEVENT(WSAAPI*)();
using WSACloseEventFn = BOOL(WSAAPI*)(WSAEVENT);
using WSASetEventFn = BOOL(WSAAPI*)(WSAEVENT);
using WSAResetEventFn = BOOL(WSAAPI*)(WSAEVENT);
using WSAWaitForMultipleEventsFn = DWORD(WSAAPI*)(DWORD, const WSAEVENT*, BOOL, DWORD, BOOL);
using WSAEventSelectFn = int(WSAAPI*)(SOCKET, WSAEVENT, long);
using WSAEnumNetworkEventsFn = int(WSAAPI*)(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);
using WSAAsyncSelectFn = int(WSAAPI*)(SOCKET, HWND, u_int, long);
using WSAEnumProtocolsAFn = int(WSAAPI*)(LPINT, LPWSAPROTOCOL_INFOA, LPDWORD);
using WSAEnumProtocolsWFn = int(WSAAPI*)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD);
using HtonsFn = u_short(WSAAPI*)(u_short);
using NtohsFn = u_short(WSAAPI*)(u_short);
using HtonlFn = u_long(WSAAPI*)(u_long);
using NtohlFn = u_long(WSAAPI*)(u_long);
using WSAHtonsFn = int(WSAAPI*)(SOCKET, u_short, u_short*);
using WSANtohsFn = int(WSAAPI*)(SOCKET, u_short, u_short*);
using WSAHtonlFn = int(WSAAPI*)(SOCKET, u_long, u_long*);
using WSANtohlFn = int(WSAAPI*)(SOCKET, u_long, u_long*);
using InetAddrFn = unsigned long(WSAAPI*)(const char*);
using InetNtoaFn = char*(WSAAPI*)(in_addr);
using InetPtonAFn = int(WSAAPI*)(INT, PCSTR, PVOID);
using InetPtonWFn = int(WSAAPI*)(INT, PCWSTR, PVOID);
using InetNtopAFn = PCSTR(WSAAPI*)(INT, const VOID*, PSTR, size_t);
using InetNtopWFn = PCWSTR(WSAAPI*)(INT, const VOID*, PWSTR, size_t);
using WSAAddressToStringAFn = int(WSAAPI*)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOA, LPSTR, LPDWORD);
using WSAAddressToStringWFn = int(WSAAPI*)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);
using WSAStringToAddressAFn = int(WSAAPI*)(LPSTR, INT, LPWSAPROTOCOL_INFOA, LPSOCKADDR, LPINT);
using WSAStringToAddressWFn = int(WSAAPI*)(LPWSTR, INT, LPWSAPROTOCOL_INFOW, LPSOCKADDR, LPINT);
using GetaddrinfoFn = int(WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using FreeaddrinfoFn = void(WSAAPI*)(PADDRINFOA);
using GetAddrInfoWFn = int(WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
using FreeAddrInfoWFn = void(WSAAPI*)(PADDRINFOW);
using GetAddrInfoExAFn = int(WSAAPI*)(PCSTR, PCSTR, DWORD, LPGUID, const ADDRINFOEXA*, PADDRINFOEXA*, timeval*,
                                      LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
using GetAddrInfoExWFn = int(WSAAPI*)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW*, PADDRINFOEXW*, timeval*,
                                      LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
using FreeAddrInfoExAFn = void(WSAAPI*)(PADDRINFOEXA);
using FreeAddrInfoExWFn = void(WSAAPI*)(PADDRINFOEXW);
using GetAddrInfoExCancelFn = int(WSAAPI*)(LPHANDLE);
using GetAddrInfoExOverlappedResultFn = int(WSAAPI*)(LPOVERLAPPED);
using GetnameinfoFn = int(WSAAPI*)(const sockaddr*, socklen_t, PCHAR, DWORD, PCHAR, DWORD, INT);
using GetNameInfoWFn = int(WSAAPI*)(const SOCKADDR*, socklen_t, PWCHAR, DWORD, PWCHAR, DWORD, INT);
using GethostnameFn = int(WSAAPI*)(char*, int);
using GetHostNameWFn = int(WSAAPI*)(PWSTR, int);
using GethostbynameFn = hostent*(WSAAPI*)(const char*);
using GethostbyaddrFn = hostent*(WSAAPI*)(const char*, int, int);
using GetprotobynameFn = protoent*(WSAAPI*)(const char*);
using GetprotobynumberFn = protoent*(WSAAPI*)(int);
using GetservbynameFn = servent*(WSAAPI*)(const char*, const char*);
using GetservbyportFn = servent*(WSAAPI*)(int, const char*);

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const char* what) {
    ++g_checks;
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", what);
    if (!condition) ++g_failures;
}

template <typename Fn>
Fn resolve(const char* name) {
    return reinterpret_cast<Fn>(rt::shims::find("ws2_32.dll", name));
}

struct StderrCapture {
    int saved_fd = -1;
    int read_fd = -1;

    StderrCapture() {
        std::fflush(stderr);
        const int stderr_fd = _fileno(stderr);
        int fds[2] = {-1, -1};
        if (stderr_fd < 0 || _pipe(fds, 8192, _O_TEXT) != 0) return;
        const int dup_saved = _dup(stderr_fd);
        if (dup_saved < 0 || _dup2(fds[1], stderr_fd) != 0) {
            if (dup_saved >= 0) _close(dup_saved);
            _close(fds[0]);
            _close(fds[1]);
            return;
        }
        _close(fds[1]);
        saved_fd = dup_saved;
        read_fd = fds[0];
    }

    ~StderrCapture() { stop(); }

    std::string stop() {
        std::string out;
        if (saved_fd >= 0) {
            std::fflush(stderr);
            _dup2(saved_fd, _fileno(stderr));
            _close(saved_fd);
            saved_fd = -1;
        }
        if (read_fd >= 0) {
            char buf[512];
            for (;;) {
                const int n = _read(read_fd, buf, static_cast<unsigned int>(sizeof(buf)));
                if (n <= 0) break;
                out.append(buf, static_cast<size_t>(n));
            }
            _close(read_fd);
            read_fd = -1;
        }
        return out;
    }
};

size_t count_occurrences(const std::string& haystack, const std::string& needle) {
    size_t count = 0;
    size_t pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

void test_ownership_and_ordinal_parity() {
    check(rt::shims::owns_dll("ws2_32.dll"), "shim registry owns ws2_32.dll");
    check(rt::shims::find("ws2_32.dll", "WSADoesNotExist") == nullptr, "unknown export name returns null");
    check(rt::shims::find("ws2_32.dll", "#9999") == nullptr, "unknown ordinal returns null");

    struct ExportSpec {
        int ordinal;
        const char* name;
    };
    static constexpr ExportSpec kExports[] = {
        {1, "accept"},
        {2, "bind"},
        {3, "closesocket"},
        {4, "connect"},
        {5, "getpeername"},
        {6, "getsockname"},
        {7, "getsockopt"},
        {8, "htonl"},
        {9, "htons"},
        {10, "ioctlsocket"},
        {11, "inet_addr"},
        {12, "inet_ntoa"},
        {13, "listen"},
        {14, "ntohl"},
        {15, "ntohs"},
        {16, "recv"},
        {17, "recvfrom"},
        {18, "select"},
        {19, "send"},
        {20, "sendto"},
        {21, "setsockopt"},
        {22, "shutdown"},
        {23, "socket"},
        {24, "FreeAddrInfoEx"},
        {25, "FreeAddrInfoExW"},
        {26, "FreeAddrInfoW"},
        {27, "GetAddrInfoExA"},
        {28, "GetAddrInfoExCancel"},
        {29, "GetAddrInfoExOverlappedResult"},
        {30, "GetAddrInfoExW"},
        {31, "GetAddrInfoW"},
        {32, "GetHostNameW"},
        {33, "GetNameInfoW"},
        {34, "InetNtopW"},
        {35, "InetPtonW"},
        {41, "WSAAccept"},
        {42, "WSAAddressToStringA"},
        {43, "WSAAddressToStringW"},
        {45, "WSACloseEvent"},
        {46, "WSAConnect"},
        {47, "WSAConnectByList"},
        {48, "WSAConnectByNameA"},
        {49, "WSAConnectByNameW"},
        {50, "WSACreateEvent"},
        {51, "gethostbyaddr"},
        {52, "gethostbyname"},
        {53, "getprotobyname"},
        {54, "getprotobynumber"},
        {55, "getservbyname"},
        {56, "getservbyport"},
        {57, "gethostname"},
        {64, "WSAEnumNetworkEvents"},
        {65, "WSAEnumProtocolsA"},
        {66, "WSAEnumProtocolsW"},
        {67, "WSAEventSelect"},
        {68, "WSAGetOverlappedResult"},
        {74, "WSAHtonl"},
        {75, "WSAHtons"},
        {78, "WSAIoctl"},
        {86, "WSANtohl"},
        {87, "WSANtohs"},
        {88, "WSAPoll"},
        {91, "WSARecv"},
        {92, "WSARecvDisconnect"},
        {93, "WSARecvFrom"},
        {95, "WSAResetEvent"},
        {96, "WSASend"},
        {97, "WSASendDisconnect"},
        {98, "WSASendMsg"},
        {99, "WSASendTo"},
        {100, "WSASetEvent"},
        {101, "WSAAsyncSelect"},
        {111, "WSAGetLastError"},
        {112, "WSASetLastError"},
        {113, "WSACancelBlockingCall"},
        {114, "WSAIsBlocking"},
        {115, "WSAStartup"},
        {116, "WSACleanup"},
        {119, "WSASocketA"},
        {120, "WSASocketW"},
        {121, "WSAStringToAddressA"},
        {122, "WSAStringToAddressW"},
        {124, "WSAWaitForMultipleEvents"},
        {151, "__WSAFDIsSet"},
        {191, "freeaddrinfo"},
        {192, "getaddrinfo"},
        {193, "getnameinfo"},
        {194, "inet_ntop"},
        {195, "inet_pton"},
    };

    bool all_match = true;
    for (const auto& e : kExports) {
        const std::string ord_key = "#" + std::to_string(e.ordinal);
        void* by_name = rt::shims::find("ws2_32.dll", e.name);
        void* by_ord = rt::shims::find("ws2_32.dll", ord_key);
        if (!by_name || by_name != by_ord) {
            std::printf("  MISMATCH %s (%s): by_name=%p by_ord=%p\n", e.name, ord_key.c_str(), by_name, by_ord);
            all_match = false;
        }
    }
    char label[128];
    std::snprintf(label, sizeof(label), "all %zu ws2_32 exports resolve identically by name and Windows ordinal",
                  sizeof(kExports) / sizeof(kExports[0]));
    check(all_match, label);
}

void test_before_startup_and_pure_helpers() {
    auto fn_socket = resolve<SocketFn>("#23");
    auto fn_cleanup = resolve<WSACleanupFn>("#116");
    auto fn_getaddrinfo = resolve<GetaddrinfoFn>("getaddrinfo");
    auto fn_freeaddrinfo = resolve<FreeaddrinfoFn>("freeaddrinfo");
    auto fn_gethostname = resolve<GethostnameFn>("#57");
    auto fn_create_event = resolve<WSACreateEventFn>("WSACreateEvent");
    auto fn_get_err = resolve<WSAGetLastErrorFn>("#111");
    auto fn_set_err = resolve<WSASetLastErrorFn>("#112");
    auto fn_htons = resolve<HtonsFn>("#9");
    auto fn_ntohs = resolve<NtohsFn>("#15");
    auto fn_htonl = resolve<HtonlFn>("#8");
    auto fn_ntohl = resolve<NtohlFn>("#14");
    auto fn_inet_addr = resolve<InetAddrFn>("#11");
    auto fn_inet_ntoa = resolve<InetNtoaFn>("#12");
    auto fn_inet_pton = resolve<InetPtonAFn>("inet_pton");
    auto fn_inet_ntop = resolve<InetNtopAFn>("inet_ntop");
    auto fn_inet_pton_w = resolve<InetPtonWFn>("InetPtonW");
    auto fn_inet_ntop_w = resolve<InetNtopWFn>("InetNtopW");
    auto fn_fd_is_set = resolve<WSAFDIsSetFn>("#151");
    auto fn_is_blocking = resolve<WSAIsBlockingFn>("#114");
    auto fn_cancel_blocking = resolve<WSACancelBlockingCallFn>("#113");

    if (!fn_socket || !fn_cleanup || !fn_getaddrinfo || !fn_freeaddrinfo || !fn_gethostname || !fn_create_event ||
        !fn_get_err || !fn_set_err || !fn_htons || !fn_ntohs || !fn_htonl || !fn_ntohl || !fn_inet_addr ||
        !fn_inet_ntoa || !fn_inet_pton || !fn_inet_ntop || !fn_inet_pton_w || !fn_inet_ntop_w || !fn_fd_is_set ||
        !fn_is_blocking || !fn_cancel_blocking) {
        check(false, "core ws2_32 functions resolved before startup test");
        return;
    }

    // Operations requiring WSAStartup fail with WSANOTINITIALISED.
    check(fn_socket(AF_INET, SOCK_STREAM, 0) == INVALID_SOCKET && fn_get_err() == WSANOTINITIALISED,
          "socket before WSAStartup returns WSANOTINITIALISED");
    check(fn_cleanup() == SOCKET_ERROR && fn_get_err() == WSANOTINITIALISED,
          "WSACleanup before WSAStartup returns WSANOTINITIALISED");
    PADDRINFOA ai = nullptr;
    check(fn_getaddrinfo("127.0.0.1", "80", nullptr, &ai) == WSANOTINITIALISED && ai == nullptr,
          "getaddrinfo before WSAStartup returns WSANOTINITIALISED");
    char host[64]{};
    check(fn_gethostname(host, static_cast<int>(sizeof(host))) == SOCKET_ERROR && fn_get_err() == WSANOTINITIALISED,
          "gethostname before WSAStartup returns WSANOTINITIALISED");
    check(fn_create_event() == WSA_INVALID_EVENT && fn_get_err() == WSANOTINITIALISED,
          "WSACreateEvent before WSAStartup returns WSANOTINITIALISED");
    check(fn_cancel_blocking() == SOCKET_ERROR && fn_get_err() == WSANOTINITIALISED,
          "WSACancelBlockingCall before WSAStartup returns WSANOTINITIALISED");
    check(fn_is_blocking() == FALSE, "WSAIsBlocking returns FALSE");

    // Pure helpers work before WSAStartup.
    fn_freeaddrinfo(nullptr);
    fn_set_err(WSAEWOULDBLOCK);
    check(fn_get_err() == WSAEWOULDBLOCK, "WSASetLastError / WSAGetLastError round-trip");
    check(fn_htons(0x1234u) == 0x3412u && fn_ntohs(0x3412u) == 0x1234u, "htons / ntohs byte swap");
    check(fn_htonl(0x12345678ul) == 0x78563412ul && fn_ntohl(0x78563412ul) == 0x12345678ul,
          "htonl / ntohl byte swap");

    // inet_addr & inet_ntoa (including per-thread FLS isolation).
    const unsigned long addr_v4 = fn_inet_addr("192.0.2.42");
    in_addr ia{};
    std::memcpy(&ia, &addr_v4, 4);
    const char* s1 = fn_inet_ntoa(ia);
    check(addr_v4 != INADDR_NONE && s1 && std::strcmp(s1, "192.0.2.42") == 0, "inet_addr / inet_ntoa IPv4 round-trip");
    check(fn_inet_addr("255.255.255.255") == INADDR_NONE && fn_inet_addr("01.2.3.4") == INADDR_NONE &&
              fn_inet_addr("not-an-ip") == INADDR_NONE,
          "inet_addr rejects broadcast/leading-zero/invalid inputs");

    std::atomic<bool> thread_ok{false};
    std::thread t([&]() {
        in_addr other{};
        const unsigned long a = fn_inet_addr("198.51.100.7");
        std::memcpy(&other, &a, 4);
        const char* ts = fn_inet_ntoa(other);
        thread_ok.store(ts && std::strcmp(ts, "198.51.100.7") == 0, std::memory_order_release);
    });
    t.join();
    check(thread_ok.load(std::memory_order_acquire) && std::strcmp(s1, "192.0.2.42") == 0,
          "inet_ntoa uses isolated per-thread FLS buffer");

    // inet_pton / inet_ntop (A & W) IPv4 + IPv6.
    in_addr p4{};
    char n4[INET_ADDRSTRLEN]{};
    wchar_t nw4[INET_ADDRSTRLEN]{};
    check(fn_inet_pton(AF_INET, "192.0.2.9", &p4) == 1 && fn_inet_ntop(AF_INET, &p4, n4, sizeof(n4)) == n4 &&
              std::strcmp(n4, "192.0.2.9") == 0,
          "inet_pton / inet_ntop IPv4 round-trip");
    check(fn_inet_pton_w(AF_INET, L"192.0.2.9", &p4) == 1 &&
              fn_inet_ntop_w(AF_INET, &p4, nw4, INET_ADDRSTRLEN) == nw4 && std::wcscmp(nw4, L"192.0.2.9") == 0,
          "InetPtonW / InetNtopW IPv4 round-trip");

    in6_addr p6{};
    char n6[INET6_ADDRSTRLEN]{};
    wchar_t nw6[INET6_ADDRSTRLEN]{};
    check(fn_inet_pton(AF_INET6, "2001:0db8:0000:0000::1", &p6) == 1 &&
              fn_inet_ntop(AF_INET6, &p6, n6, sizeof(n6)) == n6 && std::strcmp(n6, "2001:db8::1") == 0,
          "inet_pton / inet_ntop IPv6 RFC 5952 compression");
    check(fn_inet_pton_w(AF_INET6, L"::ffff:192.0.2.1", &p6) == 1 &&
              fn_inet_ntop_w(AF_INET6, &p6, nw6, INET6_ADDRSTRLEN) == nw6 &&
              std::wcscmp(nw6, L"::ffff:192.0.2.1") == 0,
          "InetPtonW / InetNtopW IPv4-mapped IPv6 round-trip");
    check(fn_inet_pton(AF_INET6, "::", &p6) == 1 && fn_inet_ntop(AF_INET6, &p6, n6, sizeof(n6)) == n6 &&
              std::strcmp(n6, "::") == 0,
          "inet_pton / inet_ntop IPv6 unspecified ::");
    check(fn_inet_pton(AF_INET, "256.0.0.1", &p4) == 0 && fn_inet_pton(AF_INET6, "1::2::3", &p6) == 0 &&
              fn_inet_pton(AF_UNIX, "127.0.0.1", &p4) == -1 && fn_get_err() == WSAEAFNOSUPPORT,
          "inet_pton rejects invalid literals and unsupported address families");

    // __WSAFDIsSet.
    fd_set fds{};
    fds.fd_count = 2;
    fds.fd_array[0] = static_cast<SOCKET>(100);
    fds.fd_array[1] = static_cast<SOCKET>(200);
    check(fn_fd_is_set(static_cast<SOCKET>(200), &fds) == 1 && fn_fd_is_set(static_cast<SOCKET>(300), &fds) == 0 &&
              fn_fd_is_set(static_cast<SOCKET>(100), nullptr) == 0,
          "__WSAFDIsSet matches membership and null set safely");
}

void test_startup_cleanup_lifecycle() {
    auto fn_startup = resolve<WSAStartupFn>("#115");
    auto fn_cleanup = resolve<WSACleanupFn>("#116");
    auto fn_socket = resolve<SocketFn>("#23");
    auto fn_getsockopt = resolve<GetsockoptFn>("#7");
    auto fn_get_err = resolve<WSAGetLastErrorFn>("#111");
    auto fn_close = resolve<ClosesocketFn>("#3");
    if (!fn_startup || !fn_cleanup || !fn_socket || !fn_getsockopt || !fn_get_err || !fn_close) {
        check(false, "startup/cleanup lifecycle functions resolved");
        return;
    }

    WSADATA wd{};
    check(fn_startup(MAKEWORD(2, 2), nullptr) == WSAEFAULT, "WSAStartup rejects null WSADATA with WSAEFAULT");
    check(fn_startup(MAKEWORD(0, 0), &wd) == WSAVERNOTSUPPORTED,
          "WSAStartup rejects version 0.0 with WSAVERNOTSUPPORTED");
    check(fn_startup(MAKEWORD(1, 1), &wd) == 0 && wd.wVersion == MAKEWORD(1, 1) && wd.wHighVersion == MAKEWORD(2, 2),
          "WSAStartup(1.1) negotiates 1.1 with wHighVersion 2.2");
    check(fn_startup(MAKEWORD(2, 2), &wd) == 0 && wd.wVersion == MAKEWORD(2, 2) && wd.wHighVersion == MAKEWORD(2, 2),
          "nested WSAStartup(2.2) negotiates 2.2");

    const SOCKET s = fn_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    check(s != INVALID_SOCKET, "socket succeeds after WSAStartup");

    // First WSACleanup drops refcount 2 -> 1; socket remains valid.
    check(fn_cleanup() == 0, "first nested WSACleanup succeeds");
    int stype = 0;
    int slen = sizeof(stype);
    check(fn_getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&stype), &slen) == 0 && stype == SOCK_STREAM,
          "socket stays alive while WSAStartup refcount > 0");

    // Second WSACleanup drops refcount 1 -> 0 and clears socket table.
    check(fn_cleanup() == 0, "final WSACleanup succeeds");
    check(fn_cleanup() == SOCKET_ERROR && fn_get_err() == WSANOTINITIALISED,
          "extra WSACleanup returns WSANOTINITIALISED");

    check(fn_startup(MAKEWORD(2, 2), &wd) == 0, "re-initialize WSAStartup(2.2)");
    check(fn_getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&stype), &slen) == SOCKET_ERROR &&
              fn_get_err() == WSAENOTSOCK,
          "stale socket handle from before final WSACleanup returns WSAENOTSOCK");

    // Concurrent WSAStartup/socket/closesocket/WSACleanup stress (lock atomicity check).
    std::atomic<bool> race_ok{true};
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) {
        workers.emplace_back([&]() {
            for (int iter = 0; iter < 50; ++iter) {
                WSADATA local_wd{};
                if (fn_startup(MAKEWORD(2, 2), &local_wd) != 0) {
                    race_ok.store(false, std::memory_order_relaxed);
                    return;
                }
                const SOCKET ls = fn_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (ls == INVALID_SOCKET || fn_close(ls) != 0) {
                    race_ok.store(false, std::memory_order_relaxed);
                }
                if (fn_cleanup() != 0) {
                    race_ok.store(false, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& w : workers) w.join();
    check(race_ok.load(), "concurrent WSAStartup/socket/closesocket/WSACleanup stays consistent");
}

void test_local_sockets_and_options() {
    auto fn_socket = resolve<SocketFn>("socket");
    auto fn_wsa_socket_a = resolve<WSASocketAFn>("WSASocketA");
    auto fn_wsa_socket_w = resolve<WSASocketWFn>("WSASocketW");
    auto fn_bind = resolve<BindFn>("bind");
    auto fn_getsockname = resolve<GetsocknameFn>("getsockname");
    auto fn_getpeername = resolve<GetpeernameFn>("getpeername");
    auto fn_listen = resolve<ListenFn>("listen");
    auto fn_accept = resolve<AcceptFn>("accept");
    auto fn_wsa_accept = resolve<WSAAcceptFn>("WSAAccept");
    auto fn_shutdown = resolve<ShutdownFn>("shutdown");
    auto fn_setsockopt = resolve<SetsockoptFn>("setsockopt");
    auto fn_getsockopt = resolve<GetsockoptFn>("getsockopt");
    auto fn_ioctlsocket = resolve<IoctlsocketFn>("ioctlsocket");
    auto fn_wsa_ioctl = resolve<WSAIoctlFn>("WSAIoctl");
    auto fn_wsa_htons = resolve<WSAHtonsFn>("WSAHtons");
    auto fn_wsa_ntohs = resolve<WSANtohsFn>("WSANtohs");
    auto fn_wsa_htonl = resolve<WSAHtonlFn>("WSAHtonl");
    auto fn_wsa_ntohl = resolve<WSANtohlFn>("WSANtohl");
    auto fn_ntohs = resolve<NtohsFn>("ntohs");
    auto fn_closesocket = resolve<ClosesocketFn>("closesocket");
    auto fn_wsa_send_disc = resolve<WSASendDisconnectFn>("WSASendDisconnect");
    auto fn_wsa_recv_disc = resolve<WSARecvDisconnectFn>("WSARecvDisconnect");
    auto fn_get_err = resolve<WSAGetLastErrorFn>("WSAGetLastError");
    if (!fn_socket || !fn_wsa_socket_a || !fn_wsa_socket_w || !fn_bind || !fn_getsockname || !fn_getpeername ||
        !fn_listen || !fn_accept || !fn_wsa_accept || !fn_shutdown || !fn_setsockopt || !fn_getsockopt ||
        !fn_ioctlsocket || !fn_wsa_ioctl || !fn_wsa_htons || !fn_wsa_ntohs || !fn_wsa_htonl || !fn_wsa_ntohl ||
        !fn_ntohs || !fn_closesocket || !fn_wsa_send_disc || !fn_wsa_recv_disc || !fn_get_err) {
        check(false, "local socket and option functions resolved");
        return;
    }

    // Validation errors on socket creation.
    check(fn_socket(AF_UNIX, SOCK_STREAM, 0) == INVALID_SOCKET && fn_get_err() == WSAEAFNOSUPPORT,
          "socket rejects unsupported address family");
    check(fn_socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == INVALID_SOCKET && fn_get_err() == WSAEPROTONOSUPPORT,
          "socket rejects mismatched protocol");

    // WSASocketA with FROM_PROTOCOL_INFO.
    WSAPROTOCOL_INFOA pinfo{};
    pinfo.iAddressFamily = AF_INET;
    pinfo.iSocketType = SOCK_STREAM;
    pinfo.iProtocol = IPPROTO_TCP;
    const SOCKET tcp = fn_wsa_socket_a(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pinfo, 0, 0);
    check(tcp != INVALID_SOCKET, "WSASocketA(FROM_PROTOCOL_INFO) creates synthetic TCP socket");

    // Ephemeral bind + getsockname + double-bind error + listen + accept.
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = 0;
    sa.sin_port = 0;
    check(fn_bind(tcp, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) == 0, "bind TCP IPv4 ephemeral port");
    check(fn_bind(tcp, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR && fn_get_err() == WSAEINVAL,
          "second bind on already-bound socket fails with WSAEINVAL");

    sockaddr_in bound{};
    int bound_len = 4;
    check(fn_getsockname(tcp, reinterpret_cast<sockaddr*>(&bound), &bound_len) == SOCKET_ERROR &&
              fn_get_err() == WSAEFAULT && bound_len == static_cast<int>(sizeof(sockaddr_in)),
          "getsockname with short buffer fails with WSAEFAULT and reports needed size");
    check(fn_getsockname(tcp, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0 && bound.sin_family == AF_INET &&
              fn_ntohs(bound.sin_port) >= 49152u,
          "getsockname returns assigned ephemeral port");

    sockaddr_in peer{};
    int peer_len = sizeof(peer);
    check(fn_getpeername(tcp, reinterpret_cast<sockaddr*>(&peer), &peer_len) == SOCKET_ERROR &&
              fn_get_err() == WSAENOTCONN,
          "getpeername on offline socket returns WSAENOTCONN");

    check(fn_listen(tcp, SOMAXCONN) == 0, "listen succeeds on bound TCP socket");
    int acceptconn = 0;
    int optlen = sizeof(acceptconn);
    check(fn_getsockopt(tcp, SOL_SOCKET, SO_ACCEPTCONN, reinterpret_cast<char*>(&acceptconn), &optlen) == 0 &&
              acceptconn == 1,
          "SO_ACCEPTCONN reflects listening state");
    check(fn_accept(tcp, nullptr, nullptr) == INVALID_SOCKET && fn_get_err() == WSAENETUNREACH,
          "blocking accept returns WSAENETUNREACH");

    u_long nb = 1;
    check(fn_ioctlsocket(tcp, static_cast<long>(FIONBIO), &nb) == 0, "ioctlsocket(FIONBIO, 1) succeeds");
    check(fn_wsa_accept(tcp, nullptr, nullptr, nullptr, 0) == INVALID_SOCKET && fn_get_err() == WSAEWOULDBLOCK,
          "non-blocking WSAAccept returns WSAEWOULDBLOCK");
    u_long avail = 123;
    check(fn_ioctlsocket(tcp, static_cast<long>(FIONREAD), &avail) == 0 && avail == 0,
          "ioctlsocket(FIONREAD) reports 0 bytes");

    check(fn_shutdown(tcp, SD_BOTH) == SOCKET_ERROR && fn_get_err() == WSAENOTCONN,
          "shutdown on unconnected TCP socket returns WSAENOTCONN");

    // Socket option round-trips.
    const int one = 1;
    const int buf_sz = 131072;
    const int timeout_ms = 250;
    const linger lg{1, 5};
    check(fn_setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one)) == 0 &&
              fn_setsockopt(tcp, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&one), sizeof(one)) == 0 &&
              fn_setsockopt(tcp, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz)) == 0 &&
              fn_setsockopt(tcp, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz)) == 0 &&
              fn_setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                            sizeof(timeout_ms)) == 0 &&
              fn_setsockopt(tcp, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one)) == 0 &&
              fn_setsockopt(tcp, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg)) == 0,
          "setsockopt stores standard SOL_SOCKET / IPPROTO_TCP options");

    int got_buf = 0, got_nodelay = 0, got_dontlinger = -1;
    linger got_lg{};
    int lg_len = sizeof(got_lg);
    optlen = sizeof(int);
    check(fn_getsockopt(tcp, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&got_buf), &optlen) == 0 &&
              got_buf == buf_sz &&
              fn_getsockopt(tcp, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&got_nodelay), &optlen) == 0 &&
              got_nodelay == 1 &&
              fn_getsockopt(tcp, SOL_SOCKET, SO_LINGER, reinterpret_cast<char*>(&got_lg), &lg_len) == 0 &&
              got_lg.l_onoff == 1 && got_lg.l_linger == 5 &&
              fn_getsockopt(tcp, SOL_SOCKET, SO_DONTLINGER, reinterpret_cast<char*>(&got_dontlinger), &optlen) == 0 &&
              got_dontlinger == 0,
          "getsockopt reads back stored options and SO_DONTLINGER symmetry");

    check(fn_setsockopt(tcp, SOL_SOCKET, SO_DONTLINGER, reinterpret_cast<const char*>(&one), sizeof(one)) == 0 &&
              fn_getsockopt(tcp, SOL_SOCKET, SO_DONTLINGER, reinterpret_cast<char*>(&got_dontlinger), &optlen) == 0 &&
              got_dontlinger == 1,
          "SO_DONTLINGER toggles linger state symmetrically");

    // WSAHtons / WSANtohs / WSAHtonl / WSANtohl.
    u_short ns = 0, hs = 0;
    u_long nl = 0, hl = 0;
    check(fn_wsa_htons(tcp, 0xABCDu, &ns) == 0 && ns == 0xCDABu && fn_wsa_ntohs(tcp, ns, &hs) == 0 && hs == 0xABCDu &&
              fn_wsa_htonl(tcp, 0x01020304ul, &nl) == 0 && nl == 0x04030201ul && fn_wsa_ntohl(tcp, nl, &hl) == 0 &&
              hl == 0x01020304ul,
          "WSAHtons / WSANtohs / WSAHtonl / WSANtohl succeed on valid socket");
    check(fn_wsa_htons(INVALID_SOCKET, 1, &ns) == SOCKET_ERROR && fn_get_err() == WSAENOTSOCK,
          "WSAHtons rejects INVALID_SOCKET with WSAENOTSOCK");

    // IPv6 UDP socket via WSASocketW + WSAIoctl(SIO_UDP_CONNRESET, FIONREAD, FIONBIO).
    const SOCKET udp6 = fn_wsa_socket_w(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    check(udp6 != INVALID_SOCKET, "WSASocketW creates IPv6 UDP socket");
    int v6only = 0;
    check(fn_setsockopt(udp6, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only)) == 0,
          "setsockopt(IPV6_V6ONLY, 0) succeeds on IPv6 socket");
    sockaddr_in6 sa6{};
    sa6.sin6_family = AF_INET6;
    check(fn_bind(udp6, reinterpret_cast<const sockaddr*>(&sa6), sizeof(sa6)) == 0, "bind IPv6 UDP ephemeral port");
    sockaddr_in6 bound6{};
    int bound6_len = sizeof(bound6);
    check(fn_getsockname(udp6, reinterpret_cast<sockaddr*>(&bound6), &bound6_len) == 0 &&
              bound6.sin6_family == AF_INET6 && fn_ntohs(bound6.sin6_port) >= 49152u,
          "getsockname returns IPv6 ephemeral port");
    check(fn_listen(udp6, 4) == SOCKET_ERROR && fn_get_err() == WSAEOPNOTSUPP,
          "listen on UDP socket fails with WSAEOPNOTSUPP");

    BOOL disable_reset = FALSE;
    DWORD bytes_ret = 99;
    check(fn_wsa_ioctl(udp6, 0x9800000Cu /* SIO_UDP_CONNRESET */, &disable_reset, sizeof(disable_reset), nullptr, 0,
                       &bytes_ret, nullptr, nullptr) == 0 &&
              bytes_ret == 0,
          "WSAIoctl(SIO_UDP_CONNRESET) succeeds");
    u_long fionread_out = 42;
    check(fn_wsa_ioctl(udp6, static_cast<DWORD>(FIONREAD), nullptr, 0, &fionread_out, sizeof(fionread_out), &bytes_ret,
                       nullptr, nullptr) == 0 &&
              bytes_ret == sizeof(u_long) && fionread_out == 0,
          "WSAIoctl(FIONREAD) reports 0 bytes");
    check(fn_wsa_send_disc(udp6, nullptr) == 0 && fn_wsa_recv_disc(udp6, nullptr) == 0,
          "WSASendDisconnect / WSARecvDisconnect succeed on UDP socket");

    check(fn_closesocket(tcp) == 0 && fn_closesocket(tcp) == SOCKET_ERROR && fn_get_err() == WSAENOTSOCK,
          "closesocket closes handle once and rejects double-close with WSAENOTSOCK");
    check(fn_closesocket(udp6) == 0, "closesocket closes IPv6 UDP socket");
}

void test_offline_wall_and_logging() {
    auto fn_socket = resolve<SocketFn>("socket");
    auto fn_bind = resolve<BindFn>("bind");
    auto fn_connect = resolve<ConnectFn>("connect");
    auto fn_wsa_connect = resolve<WSAConnectFn>("WSAConnect");
    auto fn_connect_by_name_a = resolve<WSAConnectByNameAFn>("WSAConnectByNameA");
    auto fn_connect_by_name_w = resolve<WSAConnectByNameWFn>("WSAConnectByNameW");
    auto fn_connect_by_list = resolve<WSAConnectByListFn>("WSAConnectByList");
    auto fn_send = resolve<SendFn>("send");
    auto fn_sendto = resolve<SendtoFn>("sendto");
    auto fn_recv = resolve<RecvFn>("recv");
    auto fn_recvfrom = resolve<RecvfromFn>("recvfrom");
    auto fn_wsa_send = resolve<WSASendFn>("WSASend");
    auto fn_wsa_send_to = resolve<WSASendToFn>("WSASendTo");
    auto fn_wsa_send_msg = resolve<WSASendMsgFn>("WSASendMsg");
    auto fn_wsa_recv = resolve<WSARecvFn>("WSARecv");
    auto fn_wsa_recv_from = resolve<WSARecvFromFn>("WSARecvFrom");
    auto fn_get_overlapped = resolve<WSAGetOverlappedResultFn>("WSAGetOverlappedResult");
    auto fn_getsockopt = resolve<GetsockoptFn>("getsockopt");
    auto fn_ioctlsocket = resolve<IoctlsocketFn>("ioctlsocket");
    auto fn_create_event = resolve<WSACreateEventFn>("WSACreateEvent");
    auto fn_close_event = resolve<WSACloseEventFn>("WSACloseEvent");
    auto fn_event_select = resolve<WSAEventSelectFn>("WSAEventSelect");
    auto fn_enum_events = resolve<WSAEnumNetworkEventsFn>("WSAEnumNetworkEvents");
    auto fn_wait_events = resolve<WSAWaitForMultipleEventsFn>("WSAWaitForMultipleEvents");
    auto fn_closesocket = resolve<ClosesocketFn>("closesocket");
    auto fn_htons = resolve<HtonsFn>("htons");
    auto fn_inet_pton = resolve<InetPtonAFn>("inet_pton");
    auto fn_get_err = resolve<WSAGetLastErrorFn>("WSAGetLastError");
    if (!fn_socket || !fn_bind || !fn_connect || !fn_wsa_connect || !fn_connect_by_name_a || !fn_connect_by_name_w ||
        !fn_connect_by_list || !fn_send || !fn_sendto || !fn_recv || !fn_recvfrom || !fn_wsa_send || !fn_wsa_send_to ||
        !fn_wsa_send_msg || !fn_wsa_recv || !fn_wsa_recv_from || !fn_get_overlapped || !fn_getsockopt ||
        !fn_ioctlsocket || !fn_create_event || !fn_close_event || !fn_event_select || !fn_enum_events ||
        !fn_wait_events || !fn_closesocket || !fn_htons || !fn_inet_pton || !fn_get_err) {
        check(false, "offline wall functions resolved");
        return;
    }

    StderrCapture cap;

    const SOCKET tcp = fn_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const WSAEVENT ev = fn_create_event();
    check(ev != WSA_INVALID_EVENT, "WSACreateEvent succeeds after WSAStartup");
    check(fn_event_select(tcp, nullptr, FD_CONNECT) == SOCKET_ERROR && fn_get_err() == WSAEINVAL,
          "WSAEventSelect rejects null event with non-zero mask");
    check(fn_event_select(tcp, ev, FD_CONNECT) == 0, "WSAEventSelect(FD_CONNECT) succeeds");

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = fn_htons(443);
    fn_inet_pton(AF_INET, "192.0.2.1", &dst.sin_addr);

    check(fn_connect(tcp, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) == SOCKET_ERROR &&
              fn_get_err() == WSAENETUNREACH,
          "connect to 192.0.2.1:443 refused with WSAENETUNREACH");
    // Repeat to verify log deduplication.
    check(fn_wsa_connect(tcp, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst), nullptr, nullptr, nullptr,
                         nullptr) == SOCKET_ERROR &&
              fn_get_err() == WSAENETUNREACH,
          "WSAConnect to 192.0.2.1:443 refused with WSAENETUNREACH");

    // SO_ERROR recorded and cleared on read.
    int so_err = 0;
    int optlen = sizeof(so_err);
    check(fn_getsockopt(tcp, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &optlen) == 0 &&
              so_err == WSAENETUNREACH,
          "SO_ERROR reports WSAENETUNREACH after refused connect");
    check(fn_getsockopt(tcp, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &optlen) == 0 && so_err == 0,
          "SO_ERROR clears to 0 on second read");

    // FD_CONNECT event signaled and consumed via WSAEnumNetworkEvents.
    check(fn_wait_events(1, &ev, FALSE, 0, FALSE) == WSA_WAIT_EVENT_0,
          "WSAEventSelect event signaled on refused connect");
    WSANETWORKEVENTS net_ev{};
    check(fn_enum_events(tcp, ev, &net_ev) == 0 && (net_ev.lNetworkEvents & FD_CONNECT) != 0 &&
              net_ev.iErrorCode[FD_CONNECT_BIT] == WSAENETUNREACH,
          "WSAEnumNetworkEvents reports FD_CONNECT + WSAENETUNREACH");
    check(fn_wait_events(1, &ev, FALSE, 0, FALSE) == WSA_WAIT_TIMEOUT,
          "WSAEnumNetworkEvents resets the event object");

    // WSAConnectByNameA / W / List.
    wchar_t wname[] = L"connect-w.example.invalid";
    wchar_t wserv[] = L"443";
    check(fn_connect_by_name_a(tcp, "connect-a.example.invalid", "443", nullptr, nullptr, nullptr, nullptr, nullptr,
                               nullptr) == FALSE &&
              fn_get_err() == WSAENETUNREACH,
          "WSAConnectByNameA refused with WSAENETUNREACH");
    check(fn_connect_by_name_w(tcp, wname, wserv, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == FALSE &&
              fn_get_err() == WSAENETUNREACH,
          "WSAConnectByNameW refused with WSAENETUNREACH");
    check(fn_connect_by_list(tcp, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == FALSE &&
              fn_get_err() == WSAENETUNREACH,
          "WSAConnectByList refused with WSAENETUNREACH");

    // Unconnected TCP send/recv -> WSAENOTCONN.
    char buf[16] = "hello";
    WSABUF wbuf{5, buf};
    DWORD xfer = 99, flags = 0;
    check(fn_send(tcp, buf, 5, 0) == SOCKET_ERROR && fn_get_err() == WSAENOTCONN, "TCP send -> WSAENOTCONN");
    check(fn_wsa_send(tcp, &wbuf, 1, &xfer, 0, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAENOTCONN &&
              xfer == 0,
          "TCP WSASend -> WSAENOTCONN");
    check(fn_recv(tcp, buf, sizeof(buf), 0) == SOCKET_ERROR && fn_get_err() == WSAENOTCONN, "TCP recv -> WSAENOTCONN");
    check(fn_wsa_recv(tcp, &wbuf, 1, &xfer, &flags, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAENOTCONN,
          "TCP WSARecv -> WSAENOTCONN");

    WSAOVERLAPPED ov{};
    check(fn_get_overlapped(tcp, &ov, &xfer, FALSE, &flags) == FALSE && fn_get_err() == WSA_IO_INCOMPLETE,
          "WSAGetOverlappedResult -> WSA_IO_INCOMPLETE");

    // UDP sendto / WSASendTo / WSASendMsg / recvfrom / WSARecvFrom.
    const SOCKET udp = fn_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in udp_dst{};
    udp_dst.sin_family = AF_INET;
    udp_dst.sin_port = fn_htons(5353);
    fn_inet_pton(AF_INET, "192.0.2.2", &udp_dst.sin_addr);

    check(fn_sendto(udp, buf, 5, 0, reinterpret_cast<const sockaddr*>(&udp_dst), sizeof(udp_dst)) == SOCKET_ERROR &&
              fn_get_err() == WSAENETUNREACH,
          "UDP sendto refused with WSAENETUNREACH");
    check(fn_wsa_send_to(udp, &wbuf, 1, &xfer, 0, reinterpret_cast<const sockaddr*>(&udp_dst), sizeof(udp_dst), nullptr,
                         nullptr) == SOCKET_ERROR &&
              fn_get_err() == WSAENETUNREACH,
          "UDP WSASendTo refused with WSAENETUNREACH");
    WSAMSG msg{};
    msg.name = reinterpret_cast<LPSOCKADDR>(&udp_dst);
    msg.namelen = sizeof(udp_dst);
    msg.lpBuffers = &wbuf;
    msg.dwBufferCount = 1;
    check(fn_wsa_send_msg(udp, &msg, 0, &xfer, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAENETUNREACH,
          "UDP WSASendMsg refused with WSAENETUNREACH");

    check(fn_recvfrom(udp, buf, sizeof(buf), 0, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAEINVAL,
          "unbound UDP recvfrom returns WSAEINVAL");
    sockaddr_in bind_any{};
    bind_any.sin_family = AF_INET;
    check(fn_bind(udp, reinterpret_cast<const sockaddr*>(&bind_any), sizeof(bind_any)) == 0, "bind UDP socket");
    check(fn_recvfrom(udp, buf, sizeof(buf), 0, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAENETUNREACH,
          "bound blocking UDP recvfrom returns WSAENETUNREACH");
    u_long nb = 1;
    check(fn_ioctlsocket(udp, static_cast<long>(FIONBIO), &nb) == 0, "set UDP socket non-blocking");
    check(fn_recvfrom(udp, buf, sizeof(buf), 0, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAEWOULDBLOCK,
          "bound non-blocking UDP recvfrom returns WSAEWOULDBLOCK");
    check(fn_wsa_recv_from(udp, &wbuf, 1, &xfer, &flags, nullptr, nullptr, nullptr, nullptr) == SOCKET_ERROR &&
              fn_get_err() == WSAEWOULDBLOCK,
          "bound non-blocking UDP WSARecvFrom returns WSAEWOULDBLOCK");

    check(fn_event_select(tcp, nullptr, 0) == 0, "WSAEventSelect(null, 0) clears event association");
    check(fn_close_event(ev) == TRUE && fn_close_event(nullptr) == FALSE && fn_get_err() == WSA_INVALID_HANDLE,
          "WSACloseEvent closes valid event and rejects null");
    check(fn_closesocket(tcp) == 0 && fn_closesocket(udp) == 0, "close offline wall sockets");

    const std::string errlog = cap.stop();
    check(count_occurrences(errlog, "[rt] ws2_32: offline, refused connect 192.0.2.1:443") == 1,
          "refused connect 192.0.2.1:443 logged exactly once");
    check(count_occurrences(errlog, "[rt] ws2_32: offline, refused sendto 192.0.2.2:5353") == 1,
          "refused sendto 192.0.2.2:5353 logged exactly once");
    check(count_occurrences(errlog, "connect-a.example.invalid:443") == 1 &&
              count_occurrences(errlog, "connect-w.example.invalid:443") == 1,
          "refused WSAConnectByNameA/W targets logged once");
}

void test_polling_and_events() {
    auto fn_socket = resolve<SocketFn>("socket");
    auto fn_closesocket = resolve<ClosesocketFn>("closesocket");
    auto fn_select = resolve<SelectFn>("select");
    auto fn_poll = resolve<WSAPollFn>("WSAPoll");
    auto fn_create_event = resolve<WSACreateEventFn>("WSACreateEvent");
    auto fn_set_event = resolve<WSASetEventFn>("WSASetEvent");
    auto fn_reset_event = resolve<WSAResetEventFn>("WSAResetEvent");
    auto fn_wait_events = resolve<WSAWaitForMultipleEventsFn>("WSAWaitForMultipleEvents");
    auto fn_close_event = resolve<WSACloseEventFn>("WSACloseEvent");
    auto fn_async_select = resolve<WSAAsyncSelectFn>("WSAAsyncSelect");
    auto fn_enum_proto_a = resolve<WSAEnumProtocolsAFn>("WSAEnumProtocolsA");
    auto fn_enum_proto_w = resolve<WSAEnumProtocolsWFn>("WSAEnumProtocolsW");
    auto fn_get_err = resolve<WSAGetLastErrorFn>("WSAGetLastError");
    if (!fn_socket || !fn_closesocket || !fn_select || !fn_poll || !fn_create_event || !fn_set_event ||
        !fn_reset_event || !fn_wait_events || !fn_close_event || !fn_async_select || !fn_enum_proto_a ||
        !fn_enum_proto_w || !fn_get_err) {
        check(false, "polling and event functions resolved");
        return;
    }

    const SOCKET s = fn_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // select validation.
    fd_set empty{};
    check(fn_select(0, &empty, nullptr, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAEINVAL,
          "select with empty sets returns WSAEINVAL");
    fd_set bad{};
    bad.fd_count = 1;
    bad.fd_array[0] = static_cast<SOCKET>(0xDEADBEEFull);
    check(fn_select(0, &bad, nullptr, nullptr, nullptr) == SOCKET_ERROR && fn_get_err() == WSAENOTSOCK,
          "select with unknown socket returns WSAENOTSOCK");

    fd_set rfds{};
    rfds.fd_count = 1;
    rfds.fd_array[0] = s;
    const timeval neg_tv{-1, 0};
    check(fn_select(0, &rfds, nullptr, nullptr, &neg_tv) == SOCKET_ERROR && fn_get_err() == WSAEINVAL,
          "select with negative timeout returns WSAEINVAL");

    // select caps huge/infinite timeouts (and handles LONG_MAX without overflow).
    const auto t0 = std::chrono::steady_clock::now();
    const timeval zero_tv{0, 0};
    check(fn_select(0, &rfds, nullptr, nullptr, &zero_tv) == 0 && rfds.fd_count == 0,
          "select(0ms) clears fd_set and returns 0");
    rfds.fd_count = 1;
    rfds.fd_array[0] = s;
    const timeval huge_tv{LONG_MAX, LONG_MAX};
    check(fn_select(0, &rfds, nullptr, nullptr, &huge_tv) == 0 && rfds.fd_count == 0,
          "select(LONG_MAX) returns 0 promptly without overflow");
    rfds.fd_count = 1;
    rfds.fd_array[0] = s;
    check(fn_select(0, &rfds, nullptr, nullptr, nullptr) == 0 && rfds.fd_count == 0,
          "select(infinite) returns 0 promptly");
    const auto select_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    check(select_ms < 500, "select capped sleeps stay bounded (<500 ms)");

    // WSAPoll.
    WSAPOLLFD pfd[2]{};
    pfd[0].fd = s;
    pfd[0].events = POLLRDNORM;
    pfd[1].fd = INVALID_SOCKET;
    pfd[1].events = POLLRDNORM;
    check(fn_poll(pfd, 2, 0) == 0 && pfd[0].revents == 0 && pfd[1].revents == 0,
          "WSAPoll(0) ignores INVALID_SOCKET and returns 0");
    pfd[1].fd = static_cast<SOCKET>(0xBAD00001ull);
    check(fn_poll(pfd, 2, 0) == 1 && pfd[0].revents == 0 && pfd[1].revents == POLLNVAL,
          "WSAPoll reports POLLNVAL for unknown socket");

    // WSAEvent helpers.
    const WSAEVENT ev = fn_create_event();
    check(fn_wait_events(1, &ev, FALSE, 0, FALSE) == WSA_WAIT_TIMEOUT, "new WSAEVENT starts non-signaled");
    check(fn_set_event(ev) == TRUE && fn_wait_events(1, &ev, FALSE, 0, FALSE) == WSA_WAIT_EVENT_0,
          "WSASetEvent signals WSAEVENT");
    check(fn_reset_event(ev) == TRUE && fn_wait_events(1, &ev, FALSE, 0, FALSE) == WSA_WAIT_TIMEOUT,
          "WSAResetEvent resets WSAEVENT");
    check(fn_close_event(ev) == TRUE, "WSACloseEvent succeeds");

    check(fn_async_select(s, nullptr, 0x0400u, FD_READ) == 0, "WSAAsyncSelect succeeds");
    DWORD plen = 128;
    check(fn_enum_proto_a(nullptr, nullptr, &plen) == 0 && plen == 0, "WSAEnumProtocolsA returns 0 protocols");
    plen = 128;
    check(fn_enum_proto_w(nullptr, nullptr, &plen) == 0 && plen == 0, "WSAEnumProtocolsW returns 0 protocols");

    check(fn_closesocket(s) == 0, "close poll test socket");
}

void test_offline_dns_and_address_strings() {
    auto fn_gai = resolve<GetaddrinfoFn>("getaddrinfo");
    auto fn_fai = resolve<FreeaddrinfoFn>("freeaddrinfo");
    auto fn_gai_w = resolve<GetAddrInfoWFn>("GetAddrInfoW");
    auto fn_fai_w = resolve<FreeAddrInfoWFn>("FreeAddrInfoW");
    auto fn_gai_ex_a = resolve<GetAddrInfoExAFn>("GetAddrInfoExA");
    auto fn_gai_ex_w = resolve<GetAddrInfoExWFn>("GetAddrInfoExW");
    auto fn_fai_ex_a = resolve<FreeAddrInfoExAFn>("FreeAddrInfoEx");
    auto fn_fai_ex_w = resolve<FreeAddrInfoExWFn>("FreeAddrInfoExW");
    auto fn_gai_cancel = resolve<GetAddrInfoExCancelFn>("GetAddrInfoExCancel");
    auto fn_gai_ov = resolve<GetAddrInfoExOverlappedResultFn>("GetAddrInfoExOverlappedResult");
    auto fn_gni = resolve<GetnameinfoFn>("getnameinfo");
    auto fn_gni_w = resolve<GetNameInfoWFn>("GetNameInfoW");
    auto fn_ghn = resolve<GethostnameFn>("gethostname");
    auto fn_ghn_w = resolve<GetHostNameWFn>("GetHostNameW");
    auto fn_ghbn = resolve<GethostbynameFn>("gethostbyname");
    auto fn_ghba = resolve<GethostbyaddrFn>("gethostbyaddr");
    auto fn_gpbn = resolve<GetprotobynameFn>("getprotobyname");
    auto fn_gpbnr = resolve<GetprotobynumberFn>("getprotobynumber");
    auto fn_gsbn = resolve<GetservbynameFn>("getservbyname");
    auto fn_gsbp = resolve<GetservbyportFn>("getservbyport");
    auto fn_a2s_a = resolve<WSAAddressToStringAFn>("WSAAddressToStringA");
    auto fn_a2s_w = resolve<WSAAddressToStringWFn>("WSAAddressToStringW");
    auto fn_s2a_a = resolve<WSAStringToAddressAFn>("WSAStringToAddressA");
    auto fn_s2a_w = resolve<WSAStringToAddressWFn>("WSAStringToAddressW");
    auto fn_ntohs = resolve<NtohsFn>("ntohs");
    auto fn_get_err = resolve<WSAGetLastErrorFn>("WSAGetLastError");
    if (!fn_gai || !fn_fai || !fn_gai_w || !fn_fai_w || !fn_gai_ex_a || !fn_gai_ex_w || !fn_fai_ex_a ||
        !fn_fai_ex_w || !fn_gai_cancel || !fn_gai_ov || !fn_gni || !fn_gni_w || !fn_ghn || !fn_ghn_w || !fn_ghbn ||
        !fn_ghba || !fn_gpbn || !fn_gpbnr || !fn_gsbn || !fn_gsbp || !fn_a2s_a || !fn_a2s_w || !fn_s2a_a ||
        !fn_s2a_w || !fn_ntohs || !fn_get_err) {
        check(false, "offline DNS and address functions resolved");
        return;
    }

    StderrCapture cap;

    // Remote hostnames refused immediately without touching host DNS.
    PADDRINFOA res_a = nullptr;
    check(fn_gai("api.example.invalid", "https", nullptr, &res_a) == WSAHOST_NOT_FOUND && res_a == nullptr,
          "getaddrinfo refuses remote hostname with WSAHOST_NOT_FOUND");
    check(fn_gai("api.example.invalid", "443", nullptr, &res_a) == WSAHOST_NOT_FOUND,
          "repeated getaddrinfo refusal stays offline");

    PADDRINFOW res_w = nullptr;
    check(fn_gai_w(L"wide.example.invalid", L"443", nullptr, &res_w) == WSAHOST_NOT_FOUND && res_w == nullptr,
          "GetAddrInfoW refuses remote hostname with WSAHOST_NOT_FOUND");

    PADDRINFOEXA res_exa = nullptr;
    HANDLE cancel_h = reinterpret_cast<HANDLE>(1);
    check(fn_gai_ex_a("exa.example.invalid", "443", 0, nullptr, nullptr, &res_exa, nullptr, nullptr, nullptr,
                      &cancel_h) == WSAHOST_NOT_FOUND &&
              res_exa == nullptr && cancel_h == nullptr,
          "GetAddrInfoExA refuses remote hostname and clears cancel handle");

    PADDRINFOEXW res_exw = nullptr;
    check(fn_gai_ex_w(L"exw.example.invalid", L"443", 0, nullptr, nullptr, &res_exw, nullptr, nullptr, nullptr,
                      nullptr) == WSAHOST_NOT_FOUND &&
              res_exw == nullptr,
          "GetAddrInfoExW refuses remote hostname");

    check(fn_ghbn("legacy.example.invalid") == nullptr && fn_get_err() == WSAHOST_NOT_FOUND,
          "gethostbyname refuses remote hostname with WSAHOST_NOT_FOUND");
    check(fn_ghba("\x7f\x00\x00\x01", 4, AF_INET) == nullptr && fn_get_err() == WSAHOST_NOT_FOUND,
          "gethostbyaddr returns WSAHOST_NOT_FOUND");

    // Numeric IPv4 + IPv6 + AI_PASSIVE + localhost + AI_CANONNAME + AI_NUMERICHOST.
    ADDRINFOA hints_a{};
    hints_a.ai_family = AF_UNSPEC;
    hints_a.ai_socktype = SOCK_STREAM;
    hints_a.ai_flags = AI_CANONNAME;
    check(fn_gai("192.0.2.10", "https", &hints_a, &res_a) == 0 && res_a != nullptr && res_a->ai_family == AF_INET &&
              res_a->ai_protocol == IPPROTO_TCP &&
              fn_ntohs(reinterpret_cast<const sockaddr_in*>(res_a->ai_addr)->sin_port) == 443 &&
              res_a->ai_canonname != nullptr && std::strcmp(res_a->ai_canonname, "192.0.2.10") == 0,
          "getaddrinfo resolves numeric IPv4 + service + AI_CANONNAME in-process");
    fn_fai(res_a);
    res_a = nullptr;

    check(fn_gai("2001:db8::42", "8080", &hints_a, &res_a) == 0 && res_a != nullptr && res_a->ai_family == AF_INET6 &&
              fn_ntohs(reinterpret_cast<const sockaddr_in6*>(res_a->ai_addr)->sin6_port) == 8080 &&
              res_a->ai_canonname != nullptr && std::strcmp(res_a->ai_canonname, "2001:db8::42") == 0,
          "getaddrinfo resolves numeric IPv6 in-process");
    fn_fai(res_a);
    res_a = nullptr;

    // localhost returns IPv4 + IPv6 chain when AF_UNSPEC.
    check(fn_gai("localhost", "80", &hints_a, &res_a) == 0 && res_a != nullptr && res_a->ai_family == AF_INET &&
              res_a->ai_next != nullptr && res_a->ai_next->ai_family == AF_INET6 && res_a->ai_canonname != nullptr &&
              std::strcmp(res_a->ai_canonname, "localhost") == 0,
          "getaddrinfo(localhost, AF_UNSPEC) returns IPv4+IPv6 loopback chain");
    fn_fai(res_a);
    res_a = nullptr;

    // AI_NUMERICHOST rejects localhost.
    hints_a.ai_flags = AI_NUMERICHOST;
    check(fn_gai("localhost", "80", &hints_a, &res_a) == WSAHOST_NOT_FOUND && res_a == nullptr,
          "getaddrinfo(AI_NUMERICHOST) rejects localhost");

    // AI_PASSIVE with null node returns wildcard IPv4 + IPv6.
    hints_a.ai_flags = AI_PASSIVE;
    check(fn_gai(nullptr, "9000", &hints_a, &res_a) == 0 && res_a != nullptr &&
              reinterpret_cast<const sockaddr_in*>(res_a->ai_addr)->sin_addr.s_addr == 0 &&
              res_a->ai_next != nullptr && res_a->ai_next->ai_family == AF_INET6,
          "getaddrinfo(AI_PASSIVE, nullptr) returns wildcard 0.0.0.0 + :: chain");
    fn_fai(res_a);

    // Wide GetAddrInfoW & GetAddrInfoExW with AI_CANONNAME.
    ADDRINFOW hints_w{};
    hints_w.ai_family = AF_INET;
    hints_w.ai_flags = AI_CANONNAME;
    check(fn_gai_w(L"localhost", L"443", &hints_w, &res_w) == 0 && res_w != nullptr && res_w->ai_canonname != nullptr &&
              std::wcscmp(res_w->ai_canonname, L"localhost") == 0,
          "GetAddrInfoW(localhost, AI_CANONNAME) populates wide ai_canonname");
    fn_fai_w(res_w);

    ADDRINFOEXW hints_exw{};
    hints_exw.ai_family = AF_INET;
    hints_exw.ai_flags = AI_CANONNAME;
    check(fn_gai_ex_w(L"127.0.0.1", L"80", 0, nullptr, &hints_exw, &res_exw, nullptr, nullptr, nullptr, nullptr) == 0 &&
              res_exw != nullptr && res_exw->ai_canonname != nullptr &&
              std::wcscmp(res_exw->ai_canonname, L"127.0.0.1") == 0,
          "GetAddrInfoExW resolves numeric IPv4 + wide ai_canonname");
    fn_fai_ex_w(res_exw);

    check(fn_gai_ex_a("127.0.0.1", "80", 0, nullptr, nullptr, &res_exa, nullptr, nullptr, nullptr, nullptr) == 0 &&
              res_exa != nullptr,
          "GetAddrInfoExA resolves numeric IPv4");
    fn_fai_ex_a(res_exa);

    check(fn_gai_cancel(nullptr) == WSA_INVALID_HANDLE && fn_gai_ov(nullptr) == WSA_IO_INCOMPLETE,
          "GetAddrInfoExCancel / GetAddrInfoExOverlappedResult return expected offline codes");

    // gethostname / GetHostNameW / gethostbyname(localhost).
    char hn[64]{};
    wchar_t hnw[64]{};
    check(fn_ghn(hn, 4) == SOCKET_ERROR && fn_get_err() == WSAEFAULT, "gethostname rejects short buffer");
    check(fn_ghn(hn, static_cast<int>(sizeof(hn))) == 0 && std::strcmp(hn, "leonida-offline") == 0,
          "gethostname returns leonida-offline");
    check(fn_ghn_w(hnw, 64) == 0 && std::wcscmp(hnw, L"leonida-offline") == 0, "GetHostNameW returns leonida-offline");
    hostent* lo = fn_ghbn("localhost");
    check(lo != nullptr && lo->h_addrtype == AF_INET && lo->h_length == 4 && lo->h_addr_list[0] != nullptr &&
              static_cast<unsigned char>(lo->h_addr_list[0][0]) == 127 &&
              static_cast<unsigned char>(lo->h_addr_list[0][3]) == 1,
          "gethostbyname(localhost) returns 127.0.0.1");

    // getprotoby* & getservby*.
    protoent* ptcp = fn_gpbn("TCP");
    protoent* pudp = fn_gpbnr(IPPROTO_UDP);
    check(ptcp && ptcp->p_proto == IPPROTO_TCP && pudp && pudp->p_proto == IPPROTO_UDP,
          "getprotobyname / getprotobynumber resolve tcp & udp");
    check(fn_gsbn("http", "tcp") == nullptr && fn_get_err() == WSANO_DATA &&
              fn_gsbp(80, "tcp") == nullptr && fn_get_err() == WSANO_DATA,
          "getservbyname / getservbyport return WSANO_DATA");

    // WSAStringToAddressA/W <-> WSAAddressToStringA/W <-> getnameinfo/GetNameInfoW.
    sockaddr_storage ss{};
    int ss_len = sizeof(ss);
    char s_in4[] = "192.0.2.5:8080";
    check(fn_s2a_a(s_in4, AF_INET, nullptr, reinterpret_cast<LPSOCKADDR>(&ss), &ss_len) == 0 &&
              ss_len == static_cast<int>(sizeof(sockaddr_in)),
          "WSAStringToAddressA parses IPv4:port");
    char out4[64]{};
    DWORD out4_len = sizeof(out4);
    check(fn_a2s_a(reinterpret_cast<LPSOCKADDR>(&ss), static_cast<DWORD>(ss_len), nullptr, out4, &out4_len) == 0 &&
              std::strcmp(out4, "192.0.2.5:8080") == 0,
          "WSAAddressToStringA formats IPv4:port");
    char ni_host[64]{}, ni_serv[16]{};
    check(fn_gni(reinterpret_cast<const sockaddr*>(&ss), ss_len, ni_host, sizeof(ni_host), ni_serv, sizeof(ni_serv),
                 NI_NUMERICHOST | NI_NUMERICSERV) == 0 &&
              std::strcmp(ni_host, "192.0.2.5") == 0 && std::strcmp(ni_serv, "8080") == 0,
          "getnameinfo formats IPv4 + port");

    wchar_t s_in6[] = L"[2001:db8::5]:8443";
    ss_len = sizeof(ss);
    check(fn_s2a_w(s_in6, AF_INET6, nullptr, reinterpret_cast<LPSOCKADDR>(&ss), &ss_len) == 0 &&
              ss_len == static_cast<int>(sizeof(sockaddr_in6)),
          "WSAStringToAddressW parses [IPv6]:port");
    wchar_t out6[96]{};
    DWORD out6_len = 96;
    check(fn_a2s_w(reinterpret_cast<LPSOCKADDR>(&ss), static_cast<DWORD>(ss_len), nullptr, out6, &out6_len) == 0 &&
              std::wcscmp(out6, L"[2001:db8::5]:8443") == 0,
          "WSAAddressToStringW formats [IPv6]:port");
    wchar_t niw_host[96]{}, niw_serv[16]{};
    check(fn_gni_w(reinterpret_cast<const SOCKADDR*>(&ss), ss_len, niw_host, 96, niw_serv, 16,
                   NI_NUMERICHOST | NI_NUMERICSERV) == 0 &&
              std::wcscmp(niw_host, L"2001:db8::5") == 0 && std::wcscmp(niw_serv, L"8443") == 0,
          "GetNameInfoW formats IPv6 + port");

    const std::string errlog = cap.stop();
    check(count_occurrences(errlog, "[rt] ws2_32: offline, refused DNS api.example.invalid") == 1,
          "refused DNS api.example.invalid logged exactly once");
    check(count_occurrences(errlog, "wide.example.invalid") == 1 &&
              count_occurrences(errlog, "exa.example.invalid") == 1 &&
              count_occurrences(errlog, "exw.example.invalid") == 1 &&
              count_occurrences(errlog, "legacy.example.invalid") == 1,
          "refused DNS targets across W/Ex/gethostbyname each logged once");
}

}  // namespace

int main() {
    test_ownership_and_ordinal_parity();
    test_before_startup_and_pure_helpers();
    test_startup_cleanup_lifecycle();
    test_local_sockets_and_options();
    test_offline_wall_and_logging();
    test_polling_and_events();
    test_offline_dns_and_address_strings();

    // Final cleanup of the WSAStartup left active by test_startup_cleanup_lifecycle.
    if (auto fn_cleanup = resolve<WSACleanupFn>("WSACleanup")) {
        check(fn_cleanup() == 0, "final test teardown WSACleanup succeeds");
    }

    std::printf("\n%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
