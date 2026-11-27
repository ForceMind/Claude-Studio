#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>

static int WriteAll(HANDLE file, const char* data, DWORD len) {
    DWORD written = 0;
    while (written < len) {
        DWORD chunk = 0;
        if (!WriteFile(file, data + written, len - written, &chunk, NULL) || chunk == 0) return 0;
        written += chunk;
    }
    return 1;
}

static int AppendStr(char* buf, int cap, int pos, const char* s) {
    while (*s && pos < cap - 1) buf[pos++] = *s++;
    buf[pos] = '\0';
    return pos;
}

static int AppendInt64(char* buf, int cap, int pos, long long v) {
    if (v < 0) {
        if (pos < cap - 1) buf[pos++] = '-';
        v = -v;
    }
    char tmp[32];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    else { while (v > 0 && n < 31) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } }
    while (n > 0 && pos < cap - 1) buf[pos++] = tmp[--n];
    buf[pos] = '\0';
    return pos;
}

static int ParseArgs(const wchar_t* cmd, wchar_t argv[10][512]) {
    int argc = 0;
    const wchar_t* p = cmd;
    while (*p && argc < 10) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        int out = 0;
        if (*p == L'"') {
            p++;
            while (*p && *p != L'"' && out < 511) argv[argc][out++] = *p++;
            if (*p == L'"') p++;
        } else {
            while (*p && *p != L' ' && *p != L'\t' && out < 511) argv[argc][out++] = *p++;
        }
        argv[argc][out] = L'\0';
        argc++;
    }
    return argc;
}

static unsigned int ParseUInt(const wchar_t* s) {
    unsigned int v = 0;
    while (*s >= L'0' && *s <= L'9') { v = v * 10 + (unsigned int)(*s - L'0'); s++; }
    return v;
}

static void CopyWide(wchar_t* dst, int cap, const wchar_t* src) {
    int i = 0;
    while (src[i] && i < cap - 1) { dst[i] = src[i]; i++; }
    dst[i] = L'\0';
}

static void AppendWide(wchar_t* dst, int cap, const wchar_t* src) {
    int i = 0;
    while (dst[i] && i < cap - 1) i++;
    int j = 0;
    while (src[j] && i < cap - 1) dst[i++] = src[j++];
    dst[i] = L'\0';
}

static void WideToAscii(char* dst, int cap, const wchar_t* src) {
    int i = 0;
    while (src[i] && i < cap - 1) { dst[i] = (char)(src[i] & 0x7F); i++; }
    dst[i] = '\0';
}

// Usage:
//   layer2_psec_probe.exe <tcpPort> <udpPort> <marker32> <dnsQueryName> <getAddrName> <outputJson>
// Immediately attempts IPv4 TCP connect+send, IPv4 UDP sendto, DnsQuery_W, and GetAddrInfoW
// from entry with ZERO waiting or gate signals.
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;

    LARGE_INTEGER qpcEntry;
    QueryPerformanceCounter(&qpcEntry);

    wchar_t argv[10][512];
    int argc = ParseArgs(GetCommandLineW(), argv);
    if (argc != 7) return 2;

    unsigned short tcpPort = (unsigned short)ParseUInt(argv[1]);
    unsigned short udpPort = (unsigned short)ParseUInt(argv[2]);
    char marker[64];
    WideToAscii(marker, sizeof(marker), argv[3]);
    int markerLen = 0;
    while (marker[markerLen]) markerLen++;

    const wchar_t* dnsName = argv[4];
    const wchar_t* addrName = argv[5];
    const wchar_t* outputPath = argv[6];

    WSADATA wsa;
    int wsaErr = WSAStartup(MAKEWORD(2, 2), &wsa);

    LARGE_INTEGER qpcFirstSocket;
    QueryPerformanceCounter(&qpcFirstSocket);

    // 1. Direct IPv4 TCP connect + send to loopback sentinel
    int tcpConnected = 0;
    int tcpSent = 0;
    int tcpErr = 0;
    if (wsaErr == 0) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            tcpErr = WSAGetLastError();
        } else {
            DWORD timeoutMs = 1500;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
            struct sockaddr_in addr;
            ZeroMemory(&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(tcpPort);
            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                tcpConnected = 1;
                int sent = send(s, marker, markerLen, 0);
                if (sent > 0) tcpSent = sent;
                else tcpErr = WSAGetLastError();
            } else {
                tcpErr = WSAGetLastError();
            }
            closesocket(s);
        }
    } else {
        tcpErr = wsaErr;
    }

    // 2. Direct IPv4 UDP sendto to loopback sentinel
    int udpSent = 0;
    int udpErr = 0;
    if (wsaErr == 0) {
        SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (u == INVALID_SOCKET) {
            udpErr = WSAGetLastError();
        } else {
            struct sockaddr_in addr;
            ZeroMemory(&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(udpPort);
            int sent = sendto(u, marker, markerLen, 0, (struct sockaddr*)&addr, sizeof(addr));
            if (sent > 0) udpSent = sent;
            else udpErr = WSAGetLastError();
            closesocket(u);
        }
    } else {
        udpErr = wsaErr;
    }

    // 3. System DNS: DnsQuery_W
    PDNS_RECORD dnsRec = NULL;
    DNS_STATUS dnsStatus = DnsQuery_W(dnsName, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &dnsRec, NULL);
    if (dnsRec != NULL) DnsRecordListFree(dnsRec, DnsFreeRecordList);

    // 4. System DNS: GetAddrInfoW (AF_INET)
    ADDRINFOW hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    PADDRINFOW addrRes = NULL;
    int addrStatus = GetAddrInfoW(addrName, NULL, &hints, &addrRes);
    if (addrRes != NULL) FreeAddrInfoW(addrRes);

    if (wsaErr == 0) WSACleanup();

    LARGE_INTEGER qpcDone;
    QueryPerformanceCounter(&qpcDone);

    char json[1536];
    int pos = 0;
    pos = AppendStr(json, sizeof(json), pos, "{\"pid\":");
    pos = AppendInt64(json, sizeof(json), pos, (long long)GetCurrentProcessId());
    pos = AppendStr(json, sizeof(json), pos, ",\"tid\":");
    pos = AppendInt64(json, sizeof(json), pos, (long long)GetCurrentThreadId());
    pos = AppendStr(json, sizeof(json), pos, ",\"qpcEntry\":");
    pos = AppendInt64(json, sizeof(json), pos, qpcEntry.QuadPart);
    pos = AppendStr(json, sizeof(json), pos, ",\"qpcFirstSocket\":");
    pos = AppendInt64(json, sizeof(json), pos, qpcFirstSocket.QuadPart);
    pos = AppendStr(json, sizeof(json), pos, ",\"qpcDone\":");
    pos = AppendInt64(json, sizeof(json), pos, qpcDone.QuadPart);
    pos = AppendStr(json, sizeof(json), pos, ",\"wsaErr\":");
    pos = AppendInt64(json, sizeof(json), pos, wsaErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"tcpConnected\":");
    pos = AppendStr(json, sizeof(json), pos, tcpConnected ? "true" : "false");
    pos = AppendStr(json, sizeof(json), pos, ",\"tcpSent\":");
    pos = AppendInt64(json, sizeof(json), pos, tcpSent);
    pos = AppendStr(json, sizeof(json), pos, ",\"tcpErr\":");
    pos = AppendInt64(json, sizeof(json), pos, tcpErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"udpSent\":");
    pos = AppendInt64(json, sizeof(json), pos, udpSent);
    pos = AppendStr(json, sizeof(json), pos, ",\"udpErr\":");
    pos = AppendInt64(json, sizeof(json), pos, udpErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"dnsQueryStatus\":");
    pos = AppendInt64(json, sizeof(json), pos, (long long)dnsStatus);
    pos = AppendStr(json, sizeof(json), pos, ",\"getAddrInfoStatus\":");
    pos = AppendInt64(json, sizeof(json), pos, (long long)addrStatus);
    pos = AppendStr(json, sizeof(json), pos, "}");

    wchar_t tmpPath[520];
    CopyWide(tmpPath, 520, outputPath);
    AppendWide(tmpPath, 520, L".tmp");
    HANDLE f = CreateFileW(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteAll(f, json, (DWORD)pos);
        CloseHandle(f);
        MoveFileExW(tmpPath, outputPath, MOVEFILE_REPLACE_EXISTING);
    }
    return 0;
}
