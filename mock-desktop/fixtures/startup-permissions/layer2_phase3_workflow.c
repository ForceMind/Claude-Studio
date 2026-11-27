#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>

// Phase 3 native Layer-2 dual-space workflow client (pure Win32 + Winsock + Schannel TLS 1.2).
// Runs inside hardened PSEC AppContainer with ZERO .NET/WinHTTP dependencies.
// Supports:
//   - Immediate cold-start pre-blocking probe (before command loop)
//   - Real Win32 top-level window for space focus & UI language inspection
//   - Isolated profile persistence & cross-profile access denial checks
//   - Interleaved synthetic auth callback state machine (nonce/email/replay/expiry/restart)
//   - Shared synthetic project repo R/W vs R/O & unauthorized path OS enforcement
//   - All 5 AGENTS.md locale/timezone readings (window language, renderer TZ, HTTPS Accept-Language,
//     real spawned child process LANG/TZ preferences, and Win32 GetTimeZoneInformation)

typedef struct {
    char space[8];
    char email[64];
    char uiLang[32];
    char acceptLang[64];
    char rendererTz[64];
    int tzOffsetMin;
    char childLang[32];
    char prefix[64];
    char host[128];
    char pin[80];
    char workDir[512];
    char profileDir[512];
    char peerProfileDir[512];
    char repoDir[512];
    char ungrantedDir[512];
    char coldPhase[32];
    int p;
    int peerPort;
    int u;
    int httpPort;
    int tlsPort;
    int sentinelTcp;
    int sentinelUdp;
} WorkflowCfg;

typedef struct { int connected; int sent; int err; int port; } TcpRes;
typedef struct { int sent; int err; int port; } UdpRes;
typedef struct { int ok; int status; int winErr; char marker[32]; char statusText[64]; } ProxyRes;

typedef struct {
    SOCKET sock;
    CredHandle hCred;
    CtxtHandle hCtx;
    int hasCred;
    int hasCtx;
    SecPkgContext_StreamSizes sizes;
    BYTE encBuf[32768]; int encLen;
    BYTE decBuf[32768]; int decOff; int decLen;
} TlsConn;

typedef struct {
    char state[32];       // "unauthenticated" | "pending" | "authenticated"
    char authEmail[64];   // persisted authenticated email
    char pendingNonce[48];
    char pendingEmail[64];
    long long pendingExpires;
} AuthState;

static long long QpcNow(void) { LARGE_INTEGER li; QueryPerformanceCounter(&li); return li.QuadPart; }
static int StrLenA(const char* s) { int n = 0; while (s[n]) n++; return n; }
static void CopyStrA(char* dst, int cap, const char* src) { int i = 0; while (src[i] && i < cap - 1) { dst[i] = src[i]; i++; } dst[i] = '\0'; }
static int EqStrA(const char* a, const char* b) { while (*a && *b) { if (*a != *b) return 0; a++; b++; } return *a == *b; }
static int StartsWithA(const char* s, const char* pref) { while (*pref) { if (*s != *pref) return 0; s++; pref++; } return 1; }
static int EqHexI(const char* a, const char* b) {
    while (*a && *b) {
        char ca = (*a >= 'a' && *a <= 'z') ? (char)(*a - 32) : *a;
        char cb = (*b >= 'a' && *b <= 'z') ? (char)(*b - 32) : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}
static int ParseIntA(const char* s) {
    int neg = 0, v = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return neg ? -v : v;
}
static long long ParseInt64A(const char* s) {
    int neg = 0; long long v = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return neg ? -v : v;
}
static int AppendStr(char* buf, int cap, int pos, const char* s) { while (*s && pos < cap - 1) buf[pos++] = *s++; buf[pos] = '\0'; return pos; }
static int AppendInt64(char* buf, int cap, int pos, long long v) {
    char tmp[32]; int n = 0; unsigned long long uv;
    if (v < 0) { if (pos < cap - 1) buf[pos++] = '-'; uv = (unsigned long long)(-v); }
    else uv = (unsigned long long)v;
    if (uv == 0) tmp[n++] = '0';
    else { while (uv > 0 && n < 31) { tmp[n++] = (char)('0' + (uv % 10)); uv /= 10; } }
    while (n > 0 && pos < cap - 1) buf[pos++] = tmp[--n];
    buf[pos] = '\0';
    return pos;
}
static int AppendJsonStr(char* buf, int cap, int pos, const char* s) {
    pos = AppendStr(buf, cap, pos, "\"");
    while (*s && pos < cap - 4) {
        if (*s == '\\' || *s == '"') { buf[pos++] = '\\'; buf[pos++] = *s++; }
        else if (*s == '\r') { buf[pos++] = '\\'; buf[pos++] = 'r'; s++; }
        else if (*s == '\n') { buf[pos++] = '\\'; buf[pos++] = 'n'; s++; }
        else if ((unsigned char)*s < 32) { s++; }
        else buf[pos++] = *s++;
    }
    return AppendStr(buf, cap, pos, "\"");
}

static void ToWide(const char* src, wchar_t* dst, int cap) { MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, cap); }
static void ToUtf8(const wchar_t* src, char* dst, int cap) { WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, cap, NULL, NULL); }

static void FreshMarker(char out[32]) {
    static const char hex[] = "0123456789abcdef";
    static volatile LONG counter = 0;
    LARGE_INTEGER li; QueryPerformanceCounter(&li);
    LONG seq = InterlockedIncrement(&counter);
    unsigned long long a = (unsigned long long)li.QuadPart ^ ((unsigned long long)GetCurrentProcessId() << 32) ^ (unsigned long long)GetTickCount64();
    unsigned long long b = (unsigned long long)seq * 2654435761ULL ^ ((unsigned long long)GetCurrentThreadId() << 16) ^ (a >> 7);
    for (int i = 0; i < 8; i++) out[i] = hex[(a >> (i * 4)) & 0xF];
    for (int i = 0; i < 8; i++) out[8 + i] = hex[(b >> (i * 4)) & 0xF];
    out[16] = '\0';
}

static int WriteAllFile(HANDLE f, const char* data, DWORD len) {
    DWORD written = 0;
    while (written < len) {
        DWORD chunk = 0;
        if (!WriteFile(f, data + written, len - written, &chunk, NULL) || chunk == 0) return 0;
        written += chunk;
    }
    return 1;
}

static DWORD WriteFileDirectA(const char* path, const char* content, int len) {
    wchar_t wPath[600]; ToWide(path, wPath, 600);
    HANDLE f = CreateFileW(wPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return GetLastError();
    int ok = WriteAllFile(f, content, (DWORD)len);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(f);
    return err;
}

static void WriteAtomicFileA(const char* path, const char* content, int len) {
    wchar_t wPath[600], wTmp[620];
    ToWide(path, wPath, 600);
    int i = 0; while (wPath[i] && i < 600) { wTmp[i] = wPath[i]; i++; }
    wTmp[i++] = L'.'; wTmp[i++] = L't'; wTmp[i++] = L'm'; wTmp[i++] = L'p'; wTmp[i] = L'\0';
    HANDLE f = CreateFileW(wTmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteAllFile(f, content, (DWORD)len);
        CloseHandle(f);
        MoveFileExW(wTmp, wPath, MOVEFILE_REPLACE_EXISTING);
    }
}

static int ReadFileTextWithErrA(const char* path, char* buf, int cap, DWORD* outErr) {
    if (outErr) *outErr = 0;
    wchar_t wPath[600]; ToWide(path, wPath, 600);
    HANDLE f = CreateFileW(wPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { if (outErr) *outErr = GetLastError(); buf[0] = '\0'; return -1; }
    DWORD total = 0;
    while ((int)total < cap - 1) {
        DWORD chunk = 0;
        if (!ReadFile(f, buf + total, (DWORD)(cap - 1 - (int)total), &chunk, NULL) || chunk == 0) break;
        total += chunk;
    }
    CloseHandle(f);
    buf[total] = '\0';
    return (int)total;
}

static int LoadCfg(const char* path, WorkflowCfg* cfg) {
    ZeroMemory(cfg, sizeof(*cfg));
    CopyStrA(cfg->coldPhase, sizeof(cfg->coldPhase), "cold");
    char buf[8192]; DWORD err = 0;
    if (ReadFileTextWithErrA(path, buf, sizeof(buf), &err) <= 0) return 0;
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        char* eq = line; while (*eq && *eq != '=') eq++;
        if (*eq != '=') continue;
        *eq = '\0';
        const char* k = line; const char* v = eq + 1;
        if (EqStrA(k, "space")) CopyStrA(cfg->space, sizeof(cfg->space), v);
        else if (EqStrA(k, "email")) CopyStrA(cfg->email, sizeof(cfg->email), v);
        else if (EqStrA(k, "uiLang")) CopyStrA(cfg->uiLang, sizeof(cfg->uiLang), v);
        else if (EqStrA(k, "acceptLang")) CopyStrA(cfg->acceptLang, sizeof(cfg->acceptLang), v);
        else if (EqStrA(k, "rendererTz")) CopyStrA(cfg->rendererTz, sizeof(cfg->rendererTz), v);
        else if (EqStrA(k, "tzOffsetMin")) cfg->tzOffsetMin = ParseIntA(v);
        else if (EqStrA(k, "childLang")) CopyStrA(cfg->childLang, sizeof(cfg->childLang), v);
        else if (EqStrA(k, "prefix")) CopyStrA(cfg->prefix, sizeof(cfg->prefix), v);
        else if (EqStrA(k, "host")) CopyStrA(cfg->host, sizeof(cfg->host), v);
        else if (EqStrA(k, "pin")) CopyStrA(cfg->pin, sizeof(cfg->pin), v);
        else if (EqStrA(k, "workDir")) CopyStrA(cfg->workDir, sizeof(cfg->workDir), v);
        else if (EqStrA(k, "profileDir")) CopyStrA(cfg->profileDir, sizeof(cfg->profileDir), v);
        else if (EqStrA(k, "peerProfileDir")) CopyStrA(cfg->peerProfileDir, sizeof(cfg->peerProfileDir), v);
        else if (EqStrA(k, "repoDir")) CopyStrA(cfg->repoDir, sizeof(cfg->repoDir), v);
        else if (EqStrA(k, "ungrantedDir")) CopyStrA(cfg->ungrantedDir, sizeof(cfg->ungrantedDir), v);
        else if (EqStrA(k, "coldPhase")) CopyStrA(cfg->coldPhase, sizeof(cfg->coldPhase), v);
        else if (EqStrA(k, "p")) cfg->p = ParseIntA(v);
        else if (EqStrA(k, "peerPort")) cfg->peerPort = ParseIntA(v);
        else if (EqStrA(k, "u")) cfg->u = ParseIntA(v);
        else if (EqStrA(k, "http")) cfg->httpPort = ParseIntA(v);
        else if (EqStrA(k, "tls")) cfg->tlsPort = ParseIntA(v);
        else if (EqStrA(k, "sentinelTcp")) cfg->sentinelTcp = ParseIntA(v);
        else if (EqStrA(k, "sentinelUdp")) cfg->sentinelUdp = ParseIntA(v);
    }
    return cfg->p > 0 && cfg->prefix[0] != '\0' && cfg->workDir[0] != '\0';
}

// --- Network + TLS 1.2 (identical verified native stack from Phase 1/2, plus Accept-Language inside TLS) ---

static int SendAllSock(SOCKET s, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, len - sent, 0);
        if (n <= 0) return 0;
        sent += n;
    }
    return 1;
}

static SOCKET ConnectLoopback(int port, DWORD timeoutMs, int* outErr) {
    *outErr = 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { *outErr = WSAGetLastError(); return INVALID_SOCKET; }
    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    struct sockaddr_in addr; ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        *outErr = WSAGetLastError();
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static TcpRes TryDirectTcp(int port, const char* marker) {
    TcpRes r; ZeroMemory(&r, sizeof(r)); r.port = port;
    SOCKET s = ConnectLoopback(port, 800, &r.err);
    if (s == INVALID_SOCKET) return r;
    r.connected = 1;
    int n = send(s, marker, StrLenA(marker), 0);
    if (n > 0) r.sent = n; else r.err = WSAGetLastError();
    closesocket(s);
    return r;
}

static UdpRes TryDirectUdp(int port, const char* marker) {
    UdpRes r; ZeroMemory(&r, sizeof(r)); r.port = port;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { r.err = WSAGetLastError(); return r; }
    struct sockaddr_in addr; ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);
    int n = sendto(s, marker, StrLenA(marker), 0, (struct sockaddr*)&addr, sizeof(addr));
    if (n > 0) r.sent = n; else r.err = WSAGetLastError();
    closesocket(s);
    return r;
}

static void RunDnsChecks(const char* prefix, const char* phase, int* outDnsStatus, int* outAddrStatus, char dnsName[160], char addrName[160]) {
    int p1 = 0; p1 = AppendStr(dnsName, 160, p1, prefix); p1 = AppendStr(dnsName, 160, p1, "-psec-"); p1 = AppendStr(dnsName, 160, p1, phase); AppendStr(dnsName, 160, p1, "-dns.test.");
    int p2 = 0; p2 = AppendStr(addrName, 160, p2, prefix); p2 = AppendStr(addrName, 160, p2, "-psec-"); p2 = AppendStr(addrName, 160, p2, phase); AppendStr(addrName, 160, p2, "-addr.test.");
    wchar_t wDns[160], wAddr[160];
    ToWide(dnsName, wDns, 160);
    ToWide(addrName, wAddr, 160);
    PDNS_RECORD recs = NULL;
    *outDnsStatus = (int)DnsQuery_W(wDns, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &recs, NULL);
    if (recs) DnsRecordListFree(recs, DnsFreeRecordList);
    ADDRINFOW hints; ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    PADDRINFOW res = NULL;
    *outAddrStatus = GetAddrInfoW(wAddr, NULL, &hints, &res);
    if (res) FreeAddrInfoW(res);
}

static int RecvUntilHeaderEnd(SOCKET s, char* buf, int cap) {
    int used = 0;
    while (used < cap - 1) {
        int n = recv(s, buf + used, 1, 0);
        if (n <= 0) return -1;
        used += n;
        if (used >= 4 && buf[used - 4] == '\r' && buf[used - 3] == '\n' && buf[used - 2] == '\r' && buf[used - 1] == '\n') {
            buf[used] = '\0';
            return used;
        }
    }
    return -1;
}

static int ParseHttpStatusCode(const char* hdr) {
    if (!StartsWithA(hdr, "HTTP/1.")) return 0;
    const char* sp = hdr;
    while (*sp && *sp != ' ') sp++;
    while (*sp == ' ') sp++;
    return ParseIntA(sp);
}

static int FindHeaderEnd(const char* buf, int len) {
    for (int i = 3; i < len; i++) {
        if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n') return i + 1;
    }
    return -1;
}

static void TlsClose(TlsConn* tc) {
    if (tc->hasCtx) { DeleteSecurityContext(&tc->hCtx); tc->hasCtx = 0; }
    if (tc->hasCred) { FreeCredentialsHandle(&tc->hCred); tc->hasCred = 0; }
}

static int TlsHandshakeAndPin(TlsConn* tc, SOCKET s, const char* host, const char* expectedPin, char errText[64], int* outSecErr) {
    ZeroMemory(tc, sizeof(*tc));
    tc->sock = s;
    if (outSecErr) *outSecErr = 0;

    SCHANNEL_CRED cred; ZeroMemory(&cred, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    TimeStamp expiry; ZeroMemory(&expiry, sizeof(expiry));
    SECURITY_STATUS ss = AcquireCredentialsHandleW(NULL, UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &tc->hCred, &expiry);
    if (ss != SEC_E_OK) { if (outSecErr) *outSecErr = (int)ss; CopyStrA(errText, 64, "CredFail"); return 0; }
    tc->hasCred = 1;

    wchar_t wHost[128]; ToWide(host, wHost, 128);
    DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION;
    DWORD outFlags = 0;
    SecBuffer outBuf = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc outDesc = { SECBUFFER_VERSION, 1, &outBuf };
    ss = InitializeSecurityContextW(&tc->hCred, NULL, wHost, flags, 0, 0, NULL, 0, &tc->hCtx, &outDesc, &outFlags, NULL);
    if (ss != SEC_I_CONTINUE_NEEDED) { if (outSecErr) *outSecErr = (int)ss; CopyStrA(errText, 64, "IscInitFail"); TlsClose(tc); return 0; }
    tc->hasCtx = 1;

    if (outBuf.cbBuffer > 0 && outBuf.pvBuffer != NULL) {
        int ok = SendAllSock(s, (const char*)outBuf.pvBuffer, (int)outBuf.cbBuffer);
        FreeContextBuffer(outBuf.pvBuffer);
        if (!ok) { if (outSecErr) *outSecErr = WSAGetLastError(); CopyStrA(errText, 64, "TlsSendInitFail"); TlsClose(tc); return 0; }
    }

    while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
        if (tc->encLen == 0 || ss == SEC_E_INCOMPLETE_MESSAGE) {
            int n = recv(s, (char*)tc->encBuf + tc->encLen, (int)sizeof(tc->encBuf) - tc->encLen, 0);
            if (n <= 0) { if (outSecErr) *outSecErr = WSAGetLastError(); CopyStrA(errText, 64, "TlsRecvFail"); TlsClose(tc); return 0; }
            tc->encLen += n;
        }
        SecBuffer inBufs[2];
        inBufs[0].pvBuffer = tc->encBuf; inBufs[0].cbBuffer = (unsigned long)tc->encLen; inBufs[0].BufferType = SECBUFFER_TOKEN;
        inBufs[1].pvBuffer = NULL; inBufs[1].cbBuffer = 0; inBufs[1].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc inDesc = { SECBUFFER_VERSION, 2, inBufs };
        outBuf.pvBuffer = NULL; outBuf.cbBuffer = 0; outBuf.BufferType = SECBUFFER_TOKEN;
        outDesc.cBuffers = 1; outDesc.pBuffers = &outBuf;

        ss = InitializeSecurityContextW(&tc->hCred, &tc->hCtx, wHost, flags, 0, 0, &inDesc, 0, NULL, &outDesc, &outFlags, NULL);
        if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED || (FAILED(ss) && (outFlags & ISC_RET_EXTENDED_ERROR))) {
            if (outBuf.cbBuffer > 0 && outBuf.pvBuffer != NULL) {
                int ok = SendAllSock(s, (const char*)outBuf.pvBuffer, (int)outBuf.cbBuffer);
                FreeContextBuffer(outBuf.pvBuffer);
                if (!ok) { if (outSecErr) *outSecErr = WSAGetLastError(); CopyStrA(errText, 64, "TlsSendFail"); TlsClose(tc); return 0; }
            }
        }
        if (ss == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0) {
            int extra = (int)inBufs[1].cbBuffer;
            MoveMemory(tc->encBuf, tc->encBuf + (tc->encLen - extra), (SIZE_T)extra);
            tc->encLen = extra;
        } else {
            tc->encLen = 0;
        }
        if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
            if (outSecErr) *outSecErr = (int)ss;
            CopyStrA(errText, 64, "TlsHandshakeFail");
            TlsClose(tc);
            return 0;
        }
    }

    PCCERT_CONTEXT pCert = NULL;
    if (QueryContextAttributesW(&tc->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert) != SEC_E_OK || !pCert) {
        CopyStrA(errText, 64, "NoCert"); TlsClose(tc); return 0;
    }
    BYTE hash[32]; DWORD hashLen = 32; int pinOk = 0;
    if (CryptHashCertificate(0, CALG_SHA_256, 0, pCert->pbCertEncoded, pCert->cbCertEncoded, hash, &hashLen) && hashLen == 32) {
        static const char hex[] = "0123456789ABCDEF";
        char actual[65];
        for (int i = 0; i < 32; i++) { actual[i * 2] = hex[(hash[i] >> 4) & 0xF]; actual[i * 2 + 1] = hex[hash[i] & 0xF]; }
        actual[64] = '\0';
        pinOk = EqHexI(actual, expectedPin);
    }
    CertFreeCertificateContext(pCert);
    if (!pinOk) { CopyStrA(errText, 64, "TrustFailure"); TlsClose(tc); return 0; }
    if (QueryContextAttributesW(&tc->hCtx, SECPKG_ATTR_STREAM_SIZES, &tc->sizes) != SEC_E_OK) {
        CopyStrA(errText, 64, "SizesFail"); TlsClose(tc); return 0;
    }
    return 1;
}

static int TlsWrite(TlsConn* tc, const char* data, int len) {
    BYTE buf[16384];
    if ((DWORD)len > tc->sizes.cbMaximumMessage || tc->sizes.cbHeader + (DWORD)len + tc->sizes.cbTrailer > sizeof(buf)) return 0;
    CopyMemory(buf + tc->sizes.cbHeader, data, (SIZE_T)len);
    SecBuffer bufs[4];
    bufs[0].pvBuffer = buf; bufs[0].cbBuffer = tc->sizes.cbHeader; bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[1].pvBuffer = buf + tc->sizes.cbHeader; bufs[1].cbBuffer = (unsigned long)len; bufs[1].BufferType = SECBUFFER_DATA;
    bufs[2].pvBuffer = buf + tc->sizes.cbHeader + len; bufs[2].cbBuffer = tc->sizes.cbTrailer; bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0; bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
    if (EncryptMessage(&tc->hCtx, 0, &desc, 0) != SEC_E_OK) return 0;
    return SendAllSock(tc->sock, (const char*)buf, (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer));
}

static int TlsRead(TlsConn* tc, char* out, int cap) {
    for (;;) {
        if (tc->decOff < tc->decLen) {
            int avail = tc->decLen - tc->decOff;
            int take = avail < cap ? avail : cap;
            CopyMemory(out, tc->decBuf + tc->decOff, (SIZE_T)take);
            tc->decOff += take;
            if (tc->decOff == tc->decLen) { tc->decOff = 0; tc->decLen = 0; }
            return take;
        }
        if (tc->encLen == 0) {
            int n = recv(tc->sock, (char*)tc->encBuf, (int)sizeof(tc->encBuf), 0);
            if (n <= 0) return n;
            tc->encLen = n;
        }
        SecBuffer bufs[4];
        bufs[0].pvBuffer = tc->encBuf; bufs[0].cbBuffer = (unsigned long)tc->encLen; bufs[0].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = NULL; bufs[1].cbBuffer = 0; bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].pvBuffer = NULL; bufs[2].cbBuffer = 0; bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0; bufs[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
        SECURITY_STATUS ss = DecryptMessage(&tc->hCtx, &desc, 0, NULL);
        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            if (tc->encLen >= (int)sizeof(tc->encBuf)) return -1;
            int n = recv(tc->sock, (char*)tc->encBuf + tc->encLen, (int)sizeof(tc->encBuf) - tc->encLen, 0);
            if (n <= 0) return n;
            tc->encLen += n;
            continue;
        }
        if (ss == SEC_I_CONTEXT_EXPIRED) return 0;
        if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE) return -1;
        BYTE* dataPtr = NULL; int dataLen = 0;
        BYTE* extraPtr = NULL; int extraLen = 0;
        for (int i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA) { dataPtr = (BYTE*)bufs[i].pvBuffer; dataLen = (int)bufs[i].cbBuffer; }
            else if (bufs[i].BufferType == SECBUFFER_EXTRA) { extraPtr = (BYTE*)bufs[i].pvBuffer; extraLen = (int)bufs[i].cbBuffer; }
        }
        if (dataPtr && dataLen > 0) {
            int copy = dataLen < (int)sizeof(tc->decBuf) ? dataLen : (int)sizeof(tc->decBuf);
            CopyMemory(tc->decBuf, dataPtr, (SIZE_T)copy);
            tc->decOff = 0; tc->decLen = copy;
        }
        if (extraPtr && extraLen > 0) {
            MoveMemory(tc->encBuf, extraPtr, (SIZE_T)extraLen);
            tc->encLen = extraLen;
        } else tc->encLen = 0;
    }
}

static ProxyRes RunProxyProbe(const WorkflowCfg* cfg, int isTls, const char* marker, int timeoutMs) {
    ProxyRes r; ZeroMemory(&r, sizeof(r));
    CopyStrA(r.marker, sizeof(r.marker), marker);
    CopyStrA(r.statusText, sizeof(r.statusText), "ConnectFailure");

    SOCKET s = ConnectLoopback(cfg->p, (DWORD)timeoutMs, &r.winErr);
    if (s == INVALID_SOCKET) return r;

    char req[768], resp[4096];
    int respLen = 0;
    if (!isTls) {
        int p = 0;
        p = AppendStr(req, sizeof(req), p, "GET http://"); p = AppendStr(req, sizeof(req), p, cfg->host);
        p = AppendStr(req, sizeof(req), p, "/n3/"); p = AppendStr(req, sizeof(req), p, marker);
        p = AppendStr(req, sizeof(req), p, " HTTP/1.1\r\nHost: "); p = AppendStr(req, sizeof(req), p, cfg->host);
        p = AppendStr(req, sizeof(req), p, "\r\nConnection: close\r\n\r\n");
        if (!SendAllSock(s, req, p)) { r.winErr = WSAGetLastError(); closesocket(s); return r; }
        for (;;) {
            int n = recv(s, resp + respLen, (int)sizeof(resp) - 1 - respLen, 0);
            if (n <= 0) break;
            respLen += n;
        }
        resp[respLen] = '\0';
        closesocket(s);
    } else {
        int p = 0;
        p = AppendStr(req, sizeof(req), p, "CONNECT "); p = AppendStr(req, sizeof(req), p, cfg->host);
        p = AppendStr(req, sizeof(req), p, ":443 HTTP/1.1\r\nHost: "); p = AppendStr(req, sizeof(req), p, cfg->host);
        p = AppendStr(req, sizeof(req), p, ":443\r\n\r\n");
        if (!SendAllSock(s, req, p)) { r.winErr = WSAGetLastError(); closesocket(s); return r; }
        char cHdr[1024];
        if (RecvUntilHeaderEnd(s, cHdr, sizeof(cHdr)) <= 0) { r.winErr = WSAGetLastError(); closesocket(s); return r; }
        int cCode = ParseHttpStatusCode(cHdr);
        if (cCode != 200) { r.status = cCode; CopyStrA(r.statusText, sizeof(r.statusText), "ConnectStatus"); closesocket(s); return r; }

        TlsConn tc;
        if (!TlsHandshakeAndPin(&tc, s, cfg->host, cfg->pin, r.statusText, &r.winErr)) { closesocket(s); return r; }

        p = 0;
        p = AppendStr(req, sizeof(req), p, "GET /n3/"); p = AppendStr(req, sizeof(req), p, marker);
        p = AppendStr(req, sizeof(req), p, " HTTP/1.1\r\nHost: "); p = AppendStr(req, sizeof(req), p, cfg->host);
        if (cfg->acceptLang[0] != '\0') {
            p = AppendStr(req, sizeof(req), p, "\r\nAccept-Language: ");
            p = AppendStr(req, sizeof(req), p, cfg->acceptLang);
        }
        p = AppendStr(req, sizeof(req), p, "\r\nConnection: close\r\n\r\n");
        if (!TlsWrite(&tc, req, p)) { CopyStrA(r.statusText, sizeof(r.statusText), "TlsWriteFail"); TlsClose(&tc); closesocket(s); return r; }
        for (;;) {
            int n = TlsRead(&tc, resp + respLen, (int)sizeof(resp) - 1 - respLen);
            if (n <= 0) break;
            respLen += n;
        }
        resp[respLen] = '\0';
        TlsClose(&tc);
        closesocket(s);
    }

    int bodyOff = FindHeaderEnd(resp, respLen);
    if (bodyOff < 0) { CopyStrA(r.statusText, sizeof(r.statusText), "NoHttpResponse"); return r; }
    r.status = ParseHttpStatusCode(resp);
    char expected[64];
    int ep = 0; ep = AppendStr(expected, sizeof(expected), ep, "target:"); AppendStr(expected, sizeof(expected), ep, marker);
    if (r.status == 200 && EqStrA(resp + bodyOff, expected)) {
        r.ok = 1; CopyStrA(r.statusText, sizeof(r.statusText), "200");
    } else CopyStrA(r.statusText, sizeof(r.statusText), "HttpStatus");
    return r;
}

// --- Auth Persistence Helpers (strictly inside own isolated profileDir) ---

static void BuildPath(char dst[600], const char* dir, const char* leaf) {
    int p = 0;
    p = AppendStr(dst, 600, p, dir);
    p = AppendStr(dst, 600, p, "\\");
    AppendStr(dst, 600, p, leaf);
}

static void LoadPersistedAuth(const WorkflowCfg* cfg, AuthState* st) {
    ZeroMemory(st, sizeof(*st));
    CopyStrA(st->state, sizeof(st->state), "unauthenticated");
    char path[600], buf[1024];
    BuildPath(path, cfg->profileDir, "auth-state.cfg");
    DWORD err = 0;
    if (ReadFileTextWithErrA(path, buf, sizeof(buf), &err) <= 0) return;
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        char* eq = line; while (*eq && *eq != '=') eq++;
        if (*eq != '=') continue;
        *eq = '\0';
        if (EqStrA(line, "authEmail") && eq[1] != '\0') {
            CopyStrA(st->authEmail, sizeof(st->authEmail), eq + 1);
            CopyStrA(st->state, sizeof(st->state), "authenticated");
        }
    }
    // Intentionally NEVER load pendingNonce across restarts so stale pre-restart callbacks are always rejected!
}

static void SavePersistedAuth(const WorkflowCfg* cfg, const AuthState* st) {
    char path[600], body[256];
    BuildPath(path, cfg->profileDir, "auth-state.cfg");
    int p = 0;
    p = AppendStr(body, sizeof(body), p, "space="); p = AppendStr(body, sizeof(body), p, cfg->space);
    p = AppendStr(body, sizeof(body), p, "\nauthEmail="); p = AppendStr(body, sizeof(body), p, st->authEmail);
    p = AppendStr(body, sizeof(body), p, "\n");
    WriteAtomicFileA(path, body, p);
}

// --- Native Timezone & Child Env Probe ---

static int AppendWinTzJson(char* b, int cap, int p) {
    TIME_ZONE_INFORMATION tzi; ZeroMemory(&tzi, sizeof(tzi));
    DWORD tzId = GetTimeZoneInformation(&tzi);
    char stdName[96], dstName[96];
    ToUtf8(tzi.StandardName, stdName, sizeof(stdName));
    ToUtf8(tzi.DaylightName, dstName, sizeof(dstName));
    p = AppendStr(b, cap, p, "{\"id\":"); p = AppendInt64(b, cap, p, (long long)tzId);
    p = AppendStr(b, cap, p, ",\"biasMinutes\":"); p = AppendInt64(b, cap, p, (long long)tzi.Bias);
    p = AppendStr(b, cap, p, ",\"standardName\":"); p = AppendJsonStr(b, cap, p, stdName);
    p = AppendStr(b, cap, p, ",\"daylightName\":"); p = AppendJsonStr(b, cap, p, dstName);
    return AppendStr(b, cap, p, "}");
}

static void FormatRefUtcWithOffset(int offsetMin, char out[64]) {
    // Reference fixed instant: 2026-07-01T12:00:00Z (720 minutes into day)
    int totalMin = 12 * 60 + offsetMin;
    int day = 1;
    while (totalMin < 0) { totalMin += 1440; day--; }
    while (totalMin >= 1440) { totalMin -= 1440; day++; }
    int hh = totalMin / 60;
    int mm = totalMin % 60;
    int absOff = offsetMin < 0 ? -offsetMin : offsetMin;
    int oh = absOff / 60;
    int om = absOff % 60;
    int p = 0;
    p = AppendStr(out, 64, p, "2026-07-0"); p = AppendInt64(out, 64, p, day);
    p = AppendStr(out, 64, p, "T");
    if (hh < 10) p = AppendStr(out, 64, p, "0"); p = AppendInt64(out, 64, p, hh);
    p = AppendStr(out, 64, p, ":");
    if (mm < 10) p = AppendStr(out, 64, p, "0"); p = AppendInt64(out, 64, p, mm);
    p = AppendStr(out, 64, p, ":00");
    p = AppendStr(out, 64, p, offsetMin >= 0 ? "+" : "-");
    if (oh < 10) p = AppendStr(out, 64, p, "0"); p = AppendInt64(out, 64, p, oh);
    p = AppendStr(out, 64, p, ":");
    if (om < 10) p = AppendStr(out, 64, p, "0"); AppendInt64(out, 64, p, om);
}

static int RunChildEnvProbeMode(const char* outPath) {
    char lang[64] = "", tz[64] = "", sp[32] = "";
    GetEnvironmentVariableA("LANG", lang, sizeof(lang));
    GetEnvironmentVariableA("TZ", tz, sizeof(tz));
    GetEnvironmentVariableA("CLAUDE_STUDIO_SPACE", sp, sizeof(sp));

    int isAc = 0;
    DWORD val = 0, req = 0;
    if (GetTokenInformation((HANDLE)(LONG_PTR)-4, TokenIsAppContainer, &val, sizeof(val), &req)) {
        isAc = (val != 0);
    } else {
        HANDLE tok = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            if (GetTokenInformation(tok, TokenIsAppContainer, &val, sizeof(val), &req)) isAc = (val != 0);
            CloseHandle(tok);
        }
    }

    char json[1024]; int p = 0;
    p = AppendStr(json, sizeof(json), p, "{\"pid\":"); p = AppendInt64(json, sizeof(json), p, (long long)GetCurrentProcessId());
    p = AppendStr(json, sizeof(json), p, ",\"appContainer\":"); p = AppendStr(json, sizeof(json), p, isAc ? "true" : "false");
    p = AppendStr(json, sizeof(json), p, ",\"spaceEnv\":"); p = AppendJsonStr(json, sizeof(json), p, sp);
    p = AppendStr(json, sizeof(json), p, ",\"langEnv\":"); p = AppendJsonStr(json, sizeof(json), p, lang);
    p = AppendStr(json, sizeof(json), p, ",\"tzEnv\":"); p = AppendJsonStr(json, sizeof(json), p, tz);
    p = AppendStr(json, sizeof(json), p, ",\"windowsNativeTimezone\":"); p = AppendWinTzJson(json, sizeof(json), p);
    p = AppendStr(json, sizeof(json), p, "}");
    WriteAtomicFileA(outPath, json, p);
    return 0;
}

static int SpawnChildEnvProbe(const WorkflowCfg* cfg, char childJson[1024]) {
    SetEnvironmentVariableA("LANG", cfg->childLang);
    SetEnvironmentVariableA("TZ", cfg->rendererTz);
    SetEnvironmentVariableA("CLAUDE_STUDIO_SPACE", cfg->space);

    char outPath[600];
    BuildPath(outPath, cfg->workDir, "child-env-probe.json");
    wchar_t wOut[600]; ToWide(outPath, wOut, 600);
    DeleteFileW(wOut);

    wchar_t selfExe[512];
    if (!GetModuleFileNameW(NULL, selfExe, 512)) { CopyStrA(childJson, 1024, "{\"error\":\"GetModuleFileName\"}"); return 0; }
    wchar_t cmd[1200];
    int n = 0;
    cmd[n++] = L'"';
    for (int i = 0; selfExe[i] && n < 520; i++) cmd[n++] = selfExe[i];
    const wchar_t* flag = L"\" --child-env \"";
    for (int i = 0; flag[i] && n < 560; i++) cmd[n++] = flag[i];
    for (int i = 0; wOut[i] && n < 1190; i++) cmd[n++] = wOut[i];
    cmd[n++] = L'"'; cmd[n] = L'\0';

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(selfExe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        int p = 0; p = AppendStr(childJson, 1024, p, "{\"error\":\"CreateProcess\",\"code\":");
        p = AppendInt64(childJson, 1024, p, (long long)GetLastError()); AppendStr(childJson, 1024, p, "}");
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DWORD rErr = 0;
    if (ReadFileTextWithErrA(outPath, childJson, 1024, &rErr) <= 0) {
        CopyStrA(childJson, 1024, "{\"error\":\"ReadChildOutput\"}");
        return 0;
    }
    return 1;
}

// --- Win32 Space Window (verifies UI thread & localized title inside hardened PSEC) ---

static LRESULT CALLBACK SpaceWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

static HWND CreateSpaceWindow(const WorkflowCfg* cfg, char titleOut[128]) {
    WNDCLASSW wc; ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = SpaceWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"ClaudeStudioPhase3SpaceWindow";
    RegisterClassW(&wc);

    int tp = 0;
    tp = AppendStr(titleOut, 128, tp, "Claude Studio | Space ");
    tp = AppendStr(titleOut, 128, tp, cfg->space);
    tp = AppendStr(titleOut, 128, tp, " | ");
    tp = AppendStr(titleOut, 128, tp, cfg->uiLang);
    tp = AppendStr(titleOut, 128, tp, " | ");
    AppendStr(titleOut, 128, tp, cfg->rendererTz);
    wchar_t wTitle[128]; ToWide(titleOut, wTitle, 128);

    HWND hw = CreateWindowExW(0, wc.lpszClassName, wTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 360, 120, NULL, NULL, wc.hInstance, NULL);
    if (hw) {
        ShowWindow(hw, SW_SHOWNOACTIVATE);
        UpdateWindow(hw);
    }
    return hw;
}

static void PumpMessages(void) {
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

// --- JSON Helpers & Command Parsing ---

static int AppendTcpJson(char* b, int cap, int p, const TcpRes* r) {
    p = AppendStr(b, cap, p, "{\"port\":"); p = AppendInt64(b, cap, p, r->port);
    p = AppendStr(b, cap, p, ",\"connected\":"); p = AppendStr(b, cap, p, r->connected ? "true" : "false");
    p = AppendStr(b, cap, p, ",\"sent\":"); p = AppendInt64(b, cap, p, r->sent);
    p = AppendStr(b, cap, p, ",\"error\":"); p = AppendInt64(b, cap, p, r->err);
    return AppendStr(b, cap, p, "}");
}
static int AppendUdpJson(char* b, int cap, int p, const UdpRes* r) {
    p = AppendStr(b, cap, p, "{\"port\":"); p = AppendInt64(b, cap, p, r->port);
    p = AppendStr(b, cap, p, ",\"sent\":"); p = AppendInt64(b, cap, p, r->sent);
    p = AppendStr(b, cap, p, ",\"error\":"); p = AppendInt64(b, cap, p, r->err);
    return AppendStr(b, cap, p, "}");
}
static int AppendProxyJson(char* b, int cap, int p, const char* proto, const ProxyRes* r) {
    p = AppendStr(b, cap, p, "{\"protocol\":"); p = AppendJsonStr(b, cap, p, proto);
    p = AppendStr(b, cap, p, ",\"marker\":"); p = AppendJsonStr(b, cap, p, r->marker);
    p = AppendStr(b, cap, p, ",\"ok\":"); p = AppendStr(b, cap, p, r->ok ? "true" : "false");
    p = AppendStr(b, cap, p, ",\"status\":");
    if (r->status > 0) p = AppendInt64(b, cap, p, r->status);
    else p = AppendJsonStr(b, cap, p, r->statusText);
    p = AppendStr(b, cap, p, ",\"nativeError\":"); p = AppendInt64(b, cap, p, (long long)r->winErr);
    return AppendStr(b, cap, p, "}");
}

typedef struct {
    char action[32];
    char phase[40];
    char arg1[512];
    char arg2[256];
    char arg3[64];
} CmdMsg;

static int ParseCmdFile(const char* path, CmdMsg* c) {
    ZeroMemory(c, sizeof(*c));
    CopyStrA(c->phase, sizeof(c->phase), "none");
    char buf[2048]; DWORD err = 0;
    if (ReadFileTextWithErrA(path, buf, sizeof(buf), &err) <= 0) return 0;
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        char* eq = line; while (*eq && *eq != '=') eq++;
        if (*eq != '=') continue;
        *eq = '\0';
        if (EqStrA(line, "action")) CopyStrA(c->action, sizeof(c->action), eq + 1);
        else if (EqStrA(line, "phase")) CopyStrA(c->phase, sizeof(c->phase), eq + 1);
        else if (EqStrA(line, "arg1")) CopyStrA(c->arg1, sizeof(c->arg1), eq + 1);
        else if (EqStrA(line, "arg2")) CopyStrA(c->arg2, sizeof(c->arg2), eq + 1);
        else if (EqStrA(line, "arg3")) CopyStrA(c->arg3, sizeof(c->arg3), eq + 1);
    }
    return c->action[0] != '\0';
}

static int ParseCliArgs(char a1[512], char a2[512]) {
    a1[0] = '\0'; a2[0] = '\0';
    const wchar_t* p = GetCommandLineW();
    int idx = 0;
    while (*p && idx < 3) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        wchar_t wTmp[512]; int n = 0;
        if (*p == L'"') { p++; while (*p && *p != L'"' && n < 511) wTmp[n++] = *p++; if (*p == L'"') p++; }
        else { while (*p && *p != L' ' && *p != L'\t' && n < 511) wTmp[n++] = *p++; }
        wTmp[n] = L'\0';
        if (idx == 1) ToUtf8(wTmp, a1, 512);
        else if (idx == 2) ToUtf8(wTmp, a2, 512);
        idx++;
    }
    return idx - 1;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;
    long long qpcEntry = QpcNow();

    char arg1[512], arg2[512];
    int nArgs = ParseCliArgs(arg1, arg2);
    if (nArgs >= 2 && EqStrA(arg1, "--child-env")) {
        return RunChildEnvProbeMode(arg2);
    }
    if (nArgs < 1) return 2;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 3;

    WorkflowCfg cfg;
    if (!LoadCfg(arg1, &cfg)) { WSACleanup(); return 4; }

    // 1. IMMEDIATE cold-start pre-blocking probe (ZERO wait before first socket!)
    long long qpcFirstSocket = QpcNow();
    char coldTag[32]; FreshMarker(coldTag);
    TcpRes rPa = TryDirectTcp(cfg.p, coldTag);
    TcpRes rPeer; ZeroMemory(&rPeer, sizeof(rPeer));
    if (cfg.peerPort > 0) rPeer = TryDirectTcp(cfg.peerPort, coldTag);
    TcpRes rSt = TryDirectTcp(cfg.sentinelTcp, coldTag);
    UdpRes rSu = TryDirectUdp(cfg.sentinelUdp, coldTag);
    UdpRes rUp = TryDirectUdp(cfg.p, coldTag);
    TcpRes rPu = TryDirectTcp(cfg.u, coldTag);
    int dnsSt = 0, addrSt = 0;
    char dnsName[160], addrName[160];
    RunDnsChecks(cfg.prefix, cfg.coldPhase, &dnsSt, &addrSt, dnsName, addrName);
    long long qpcColdDone = QpcNow();

    // Create localized space window & load persisted auth state
    char winTitle[128] = "";
    HWND hWnd = CreateSpaceWindow(&cfg, winTitle);
    AuthState auth;
    LoadPersistedAuth(&cfg, &auth);

    char* outBuf = (char*)HeapAlloc(GetProcessHeap(), 0, 65536);
    if (!outBuf) { if (hWnd) DestroyWindow(hWnd); WSACleanup(); return 5; }

    int pos = 0;
    pos = AppendStr(outBuf, 65536, pos, "{\"pid\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)GetCurrentProcessId());
    pos = AppendStr(outBuf, 65536, pos, ",\"tid\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)GetCurrentThreadId());
    pos = AppendStr(outBuf, 65536, pos, ",\"windowHandle\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)(ULONG_PTR)hWnd);
    pos = AppendStr(outBuf, 65536, pos, ",\"windowVisible\":"); pos = AppendStr(outBuf, 65536, pos, (hWnd && IsWindowVisible(hWnd)) ? "true" : "false");
    pos = AppendStr(outBuf, 65536, pos, ",\"windowTitle\":"); pos = AppendJsonStr(outBuf, 65536, pos, winTitle);
    pos = AppendStr(outBuf, 65536, pos, ",\"persistedAuthState\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.state);
    pos = AppendStr(outBuf, 65536, pos, ",\"persistedAuthEmail\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.authEmail);
    pos = AppendStr(outBuf, 65536, pos, ",\"qpcEntry\":"); pos = AppendInt64(outBuf, 65536, pos, qpcEntry);
    pos = AppendStr(outBuf, 65536, pos, ",\"qpcFirstSocket\":"); pos = AppendInt64(outBuf, 65536, pos, qpcFirstSocket);
    pos = AppendStr(outBuf, 65536, pos, ",\"directPa\":"); pos = AppendTcpJson(outBuf, 65536, pos, &rPa);
    if (cfg.peerPort > 0) { pos = AppendStr(outBuf, 65536, pos, ",\"crossPort\":"); pos = AppendTcpJson(outBuf, 65536, pos, &rPeer); }
    pos = AppendStr(outBuf, 65536, pos, ",\"sentinelTcp\":"); pos = AppendTcpJson(outBuf, 65536, pos, &rSt);
    pos = AppendStr(outBuf, 65536, pos, ",\"sentinelUdp\":"); pos = AppendUdpJson(outBuf, 65536, pos, &rSu);
    pos = AppendStr(outBuf, 65536, pos, ",\"udpToPa\":"); pos = AppendUdpJson(outBuf, 65536, pos, &rUp);
    pos = AppendStr(outBuf, 65536, pos, ",\"directPu\":"); pos = AppendTcpJson(outBuf, 65536, pos, &rPu);
    pos = AppendStr(outBuf, 65536, pos, ",\"dns\":{\"dnsName\":"); pos = AppendJsonStr(outBuf, 65536, pos, dnsName);
    pos = AppendStr(outBuf, 65536, pos, ",\"dnsQueryStatus\":"); pos = AppendInt64(outBuf, 65536, pos, dnsSt);
    pos = AppendStr(outBuf, 65536, pos, ",\"addrName\":"); pos = AppendJsonStr(outBuf, 65536, pos, addrName);
    pos = AppendStr(outBuf, 65536, pos, ",\"getAddrInfoStatus\":"); pos = AppendInt64(outBuf, 65536, pos, addrSt);
    pos = AppendStr(outBuf, 65536, pos, "},\"qpcDone\":"); pos = AppendInt64(outBuf, 65536, pos, qpcColdDone);
    pos = AppendStr(outBuf, 65536, pos, "}");

    char coldPath[600]; BuildPath(coldPath, cfg.workDir, "cold-result.json");
    WriteAtomicFileA(coldPath, outBuf, pos);

    // 2. Bounded workflow command loop (max 120s)
    ULONGLONG startMs = GetTickCount64();
    for (int seq = 1; GetTickCount64() - startMs < 120000; seq++) {
        char cmdPath[600], resPath[600];
        int pA = 0; pA = AppendStr(cmdPath, sizeof(cmdPath), pA, cfg.workDir); pA = AppendStr(cmdPath, sizeof(cmdPath), pA, "\\cmd-"); pA = AppendInt64(cmdPath, sizeof(cmdPath), pA, seq); AppendStr(cmdPath, sizeof(cmdPath), pA, ".cfg");
        int pB = 0; pB = AppendStr(resPath, sizeof(resPath), pB, cfg.workDir); pB = AppendStr(resPath, sizeof(resPath), pB, "\\res-"); pB = AppendInt64(resPath, sizeof(resPath), pB, seq); AppendStr(resPath, sizeof(resPath), pB, ".json");

        wchar_t wCmd[600]; ToWide(cmdPath, wCmd, 600);
        while (GetFileAttributesW(wCmd) == INVALID_FILE_ATTRIBUTES) {
            PumpMessages();
            if (GetTickCount64() - startMs >= 120000) goto done;
            Sleep(15);
        }

        CmdMsg cm;
        if (!ParseCmdFile(cmdPath, &cm)) goto done;
        pos = 0;

        if (EqStrA(cm.action, "probe")) {
            char mHttp[32], mTls[32], tag[32];
            FreshMarker(mHttp); FreshMarker(mTls); FreshMarker(tag);
            ProxyRes pHttp = RunProxyProbe(&cfg, 0, mHttp, 1800);
            ProxyRes pTls = RunProxyProbe(&cfg, 1, mTls, 1800);
            TcpRes dSt = TryDirectTcp(cfg.sentinelTcp, tag);
            UdpRes dSu = TryDirectUdp(cfg.sentinelUdp, tag);
            TcpRes dPu = TryDirectTcp(cfg.u, tag);
            TcpRes dTh = TryDirectTcp(cfg.httpPort, tag);
            TcpRes dTt = TryDirectTcp(cfg.tlsPort, tag);
            TcpRes dPeer; ZeroMemory(&dPeer, sizeof(dPeer));
            if (cfg.peerPort > 0) dPeer = TryDirectTcp(cfg.peerPort, tag);
            int pDnsSt = 0, pAddrSt = 0; char pDnsN[160], pAddrN[160];
            RunDnsChecks(cfg.prefix, cm.phase, &pDnsSt, &pAddrSt, pDnsN, pAddrN);

            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"probe\",\"ok\":true,\"data\":{\"phase\":"); pos = AppendJsonStr(outBuf, 65536, pos, cm.phase);
            pos = AppendStr(outBuf, 65536, pos, ",\"http\":"); pos = AppendProxyJson(outBuf, 65536, pos, "http", &pHttp);
            pos = AppendStr(outBuf, 65536, pos, ",\"tls\":"); pos = AppendProxyJson(outBuf, 65536, pos, "tls", &pTls);
            pos = AppendStr(outBuf, 65536, pos, ",\"direct\":{\"sentinelTcp\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dSt);
            pos = AppendStr(outBuf, 65536, pos, ",\"sentinelUdp\":"); pos = AppendUdpJson(outBuf, 65536, pos, &dSu);
            pos = AppendStr(outBuf, 65536, pos, ",\"directPu\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dPu);
            pos = AppendStr(outBuf, 65536, pos, ",\"directTargetHttp\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dTh);
            pos = AppendStr(outBuf, 65536, pos, ",\"directTargetTls\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dTt);
            if (cfg.peerPort > 0) { pos = AppendStr(outBuf, 65536, pos, ",\"crossPort\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dPeer); }
            pos = AppendStr(outBuf, 65536, pos, "},\"dns\":{\"dnsName\":"); pos = AppendJsonStr(outBuf, 65536, pos, pDnsN);
            pos = AppendStr(outBuf, 65536, pos, ",\"dnsQueryStatus\":"); pos = AppendInt64(outBuf, 65536, pos, pDnsSt);
            pos = AppendStr(outBuf, 65536, pos, ",\"addrName\":"); pos = AppendJsonStr(outBuf, 65536, pos, pAddrN);
            pos = AppendStr(outBuf, 65536, pos, ",\"getAddrInfoStatus\":"); pos = AppendInt64(outBuf, 65536, pos, pAddrSt);
            pos = AppendStr(outBuf, 65536, pos, "}}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "profile-write")) {
            char pFile[600]; BuildPath(pFile, cfg.profileDir, "session-note.txt");
            DWORD wErr = WriteFileDirectA(pFile, cm.arg1, StrLenA(cm.arg1));
            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"profile-write\",\"ok\":"); pos = AppendStr(outBuf, 65536, pos, wErr == 0 ? "true" : "false");
            pos = AppendStr(outBuf, 65536, pos, ",\"error\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)wErr);
            pos = AppendStr(outBuf, 65536, pos, "}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "profile-read-and-cross")) {
            char ownFile[600], peerFile[600], peerProbe[600];
            BuildPath(ownFile, cfg.profileDir, "session-note.txt");
            BuildPath(peerFile, cfg.peerProfileDir, "session-note.txt");
            BuildPath(peerProbe, cfg.peerProfileDir, "cross-write.tmp");
            char ownTxt[512] = "", peerTxt[512] = "";
            DWORD ownErr = 0, peerReadErr = 0, peerWriteErr = 0;
            ReadFileTextWithErrA(ownFile, ownTxt, sizeof(ownTxt), &ownErr);
            ReadFileTextWithErrA(peerFile, peerTxt, sizeof(peerTxt), &peerReadErr);
            peerWriteErr = WriteFileDirectA(peerProbe, "unauthorized", 12);

            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"profile-read-and-cross\",\"ok\":true,\"data\":{\"ownReadError\":");
            pos = AppendInt64(outBuf, 65536, pos, (long long)ownErr);
            pos = AppendStr(outBuf, 65536, pos, ",\"ownText\":"); pos = AppendJsonStr(outBuf, 65536, pos, ownTxt);
            pos = AppendStr(outBuf, 65536, pos, ",\"peerReadError\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)peerReadErr);
            pos = AppendStr(outBuf, 65536, pos, ",\"peerWriteError\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)peerWriteErr);
            pos = AppendStr(outBuf, 65536, pos, ",\"persistedAuthState\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.state);
            pos = AppendStr(outBuf, 65536, pos, ",\"persistedAuthEmail\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.authEmail);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "auth-begin")) {
            char nonce[32]; FreshMarker(nonce);
            CopyStrA(auth.pendingNonce, sizeof(auth.pendingNonce), nonce);
            CopyStrA(auth.pendingEmail, sizeof(auth.pendingEmail), cfg.email);
            auth.pendingExpires = 100000; // synthetic clock epoch bound
            if (!EqStrA(auth.state, "authenticated")) CopyStrA(auth.state, sizeof(auth.state), "pending");
            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"auth-begin\",\"ok\":true,\"data\":{\"state\":");
            pos = AppendJsonStr(outBuf, 65536, pos, auth.state);
            pos = AppendStr(outBuf, 65536, pos, ",\"email\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.pendingEmail);
            pos = AppendStr(outBuf, 65536, pos, ",\"nonce\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.pendingNonce);
            pos = AppendStr(outBuf, 65536, pos, ",\"expires\":"); pos = AppendInt64(outBuf, 65536, pos, auth.pendingExpires);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "auth-deliver")) {
            // arg1 = nonce, arg2 = email, arg3 = syntheticNow (default 1000)
            long long nowTs = (cm.arg3[0] != '\0') ? ParseInt64A(cm.arg3) : 1000;
            const char* reason = "OK";
            int accepted = 0;
            if (auth.pendingNonce[0] == '\0') {
                reason = "NO_PENDING_LOGIN";
            } else if (!EqStrA(cm.arg1, auth.pendingNonce) || !EqStrA(cm.arg2, auth.pendingEmail)) {
                reason = "INVALID_CALLBACK";
            } else if (nowTs >= auth.pendingExpires) {
                reason = "EXPIRED_CALLBACK";
            } else {
                accepted = 1;
                CopyStrA(auth.state, sizeof(auth.state), "authenticated");
                CopyStrA(auth.authEmail, sizeof(auth.authEmail), auth.pendingEmail);
                auth.pendingNonce[0] = '\0';
                auth.pendingEmail[0] = '\0';
                auth.pendingExpires = 0;
                SavePersistedAuth(&cfg, &auth);
            }
            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"auth-deliver\",\"ok\":true,\"data\":{\"accepted\":");
            pos = AppendStr(outBuf, 65536, pos, accepted ? "true" : "false");
            pos = AppendStr(outBuf, 65536, pos, ",\"reason\":"); pos = AppendJsonStr(outBuf, 65536, pos, reason);
            pos = AppendStr(outBuf, 65536, pos, ",\"state\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.state);
            pos = AppendStr(outBuf, 65536, pos, ",\"authEmail\":"); pos = AppendJsonStr(outBuf, 65536, pos, auth.authEmail);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "project-read")) {
            char notePath[600], ungrPath[600], ungrProbe[600];
            BuildPath(notePath, cfg.repoDir, "note.txt");
            BuildPath(ungrPath, cfg.ungrantedDir, "secret.txt");
            BuildPath(ungrProbe, cfg.ungrantedDir, "probe.tmp");
            char noteTxt[512] = "", ungrTxt[128] = "";
            DWORD noteErr = 0, ungrReadErr = 0, ungrWriteErr = 0;
            ReadFileTextWithErrA(notePath, noteTxt, sizeof(noteTxt), &noteErr);
            ReadFileTextWithErrA(ungrPath, ungrTxt, sizeof(ungrTxt), &ungrReadErr);
            ungrWriteErr = WriteFileDirectA(ungrProbe, "no", 2);

            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"project-read\",\"ok\":true,\"data\":{\"readError\":");
            pos = AppendInt64(outBuf, 65536, pos, (long long)noteErr);
            pos = AppendStr(outBuf, 65536, pos, ",\"text\":"); pos = AppendJsonStr(outBuf, 65536, pos, noteTxt);
            pos = AppendStr(outBuf, 65536, pos, ",\"ungrantedReadError\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)ungrReadErr);
            pos = AppendStr(outBuf, 65536, pos, ",\"ungrantedWriteError\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)ungrWriteErr);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "project-write")) {
            char notePath[600], tmpProbe[600];
            BuildPath(notePath, cfg.repoDir, "note.txt");
            BuildPath(tmpProbe, cfg.repoDir, "write-check.tmp");
            char payload[512]; int lp = 0;
            lp = AppendStr(payload, sizeof(payload), lp, cm.arg1);
            lp = AppendStr(payload, sizeof(payload), lp, "\n");
            DWORD wErr = WriteFileDirectA(notePath, payload, lp);
            DWORD newErr = WriteFileDirectA(tmpProbe, "x", 1);
            if (newErr == 0) { wchar_t wp[600]; ToWide(tmpProbe, wp, 600); DeleteFileW(wp); }

            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"project-write\",\"ok\":true,\"data\":{\"writeError\":");
            pos = AppendInt64(outBuf, 65536, pos, (long long)wErr);
            pos = AppendStr(outBuf, 65536, pos, ",\"createNewError\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)newErr);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "locale-tz-matrix")) {
            // 1. Window language; 2. Renderer TZ; 3. HTTPS Accept-Language via proxy;
            // 4. Real spawned child process LANG/TZ; 5. Win32 GetTimeZoneInformation.
            char mTls[32]; FreshMarker(mTls);
            ProxyRes pTls = RunProxyProbe(&cfg, 1, mTls, 1800);
            char refFmt[64] = "";
            FormatRefUtcWithOffset(cfg.tzOffsetMin, refFmt);
            char childJson[1024] = "";
            SpawnChildEnvProbe(&cfg, childJson);

            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"locale-tz-matrix\",\"ok\":true,\"data\":{\"space\":");
            pos = AppendJsonStr(outBuf, 65536, pos, cfg.space);
            pos = AppendStr(outBuf, 65536, pos, ",\"windowLanguage\":{\"configuredUiLang\":"); pos = AppendJsonStr(outBuf, 65536, pos, cfg.uiLang);
            pos = AppendStr(outBuf, 65536, pos, ",\"windowTitle\":"); pos = AppendJsonStr(outBuf, 65536, pos, winTitle);
            pos = AppendStr(outBuf, 65536, pos, ",\"windowHandle\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)(ULONG_PTR)hWnd);
            pos = AppendStr(outBuf, 65536, pos, ",\"userDefaultUiLangId\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)GetUserDefaultUILanguage());
            pos = AppendStr(outBuf, 65536, pos, "},\"rendererTimezone\":{\"configuredTz\":"); pos = AppendJsonStr(outBuf, 65536, pos, cfg.rendererTz);
            pos = AppendStr(outBuf, 65536, pos, ",\"offsetMinutes\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)cfg.tzOffsetMin);
            pos = AppendStr(outBuf, 65536, pos, ",\"refUtcFormatted\":"); pos = AppendJsonStr(outBuf, 65536, pos, refFmt);
            pos = AppendStr(outBuf, 65536, pos, "},\"requestLanguage\":{\"sentAcceptLanguage\":"); pos = AppendJsonStr(outBuf, 65536, pos, cfg.acceptLang);
            pos = AppendStr(outBuf, 65536, pos, ",\"tlsProbe\":"); pos = AppendProxyJson(outBuf, 65536, pos, "tls", &pTls);
            pos = AppendStr(outBuf, 65536, pos, "},\"childProcessPreferences\":"); pos = AppendStr(outBuf, 65536, pos, childJson);
            pos = AppendStr(outBuf, 65536, pos, ",\"windowsNativeTimezone\":"); pos = AppendWinTzJson(outBuf, 65536, pos);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(cm.action, "finish")) {
            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"finish\",\"ok\":true}");
            WriteAtomicFileA(resPath, outBuf, pos);
            break;
        }
    }

done:
    if (hWnd) DestroyWindow(hWnd);
    HeapFree(GetProcessHeap(), 0, outBuf);
    WSACleanup();
    return 0;
}
