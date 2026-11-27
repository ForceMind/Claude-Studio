#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>

typedef struct {
    char prefix[64];
    char host[128];
    char pin[80];
    char workDir[512];
    char coldPhase[32];
    int p;
    int peerPort;
    int u;
    int httpPort;
    int tlsPort;
    int sentinelTcp;
    int sentinelUdp;
} ClientCfg;

typedef struct {
    int connected;
    int sent;
    int err;
    int port;
} TcpRes;

typedef struct {
    int sent;
    int err;
    int port;
} UdpRes;

typedef struct {
    int ok;
    int status;
    int winErr;
    char marker[32];
    char statusText[64];
} ProxyRes;

typedef struct {
    SOCKET sock;
    CredHandle hCred;
    CtxtHandle hCtx;
    int hasCred;
    int hasCtx;
    SecPkgContext_StreamSizes sizes;
    BYTE encBuf[32768];
    int encLen;
    BYTE decBuf[32768];
    int decOff;
    int decLen;
} TlsConn;

typedef struct {
    CRITICAL_SECTION cs;
    ClientCfg* cfg;
    int isTls;
    char marker[32];
    char state[32];
    char marks[160][40];
    long long ticks[160];
    int markCount;
    volatile LONG stopping;
    SOCKET sock;
    HANDLE hThread;
} HeldStream;

static long long QpcNow(void) {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return li.QuadPart;
}

static int StrLenA(const char* s) { int n = 0; while (s[n]) n++; return n; }

static void CopyStrA(char* dst, int cap, const char* src) {
    int i = 0;
    while (src[i] && i < cap - 1) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static int EqStrA(const char* a, const char* b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

static int StartsWithA(const char* s, const char* pref) {
    while (*pref) { if (*s != *pref) return 0; s++; pref++; }
    return 1;
}

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
    int v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v;
}

static int AppendStr(char* buf, int cap, int pos, const char* s) {
    while (*s && pos < cap - 1) buf[pos++] = *s++;
    buf[pos] = '\0';
    return pos;
}

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
    while (*s && pos < cap - 3) {
        if (*s == '\\' || *s == '"') buf[pos++] = '\\';
        buf[pos++] = *s++;
    }
    return AppendStr(buf, cap, pos, "\"");
}

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

static void ToWide(const char* src, wchar_t* dst, int cap) {
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, cap);
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

static int ReadFileTextA(const char* path, char* buf, int cap) {
    wchar_t wPath[600]; ToWide(path, wPath, 600);
    HANDLE f = CreateFileW(wPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;
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

static int LoadCfg(const char* path, ClientCfg* cfg) {
    ZeroMemory(cfg, sizeof(*cfg));
    CopyStrA(cfg->coldPhase, sizeof(cfg->coldPhase), "cold");
    char buf[4096];
    if (ReadFileTextA(path, buf, sizeof(buf)) <= 0) return 0;
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        char* eq = line; while (*eq && *eq != '=') eq++;
        if (*eq != '=') continue;
        *eq = '\0';
        const char* k = line; const char* v = eq + 1;
        if (EqStrA(k, "prefix")) CopyStrA(cfg->prefix, sizeof(cfg->prefix), v);
        else if (EqStrA(k, "host")) CopyStrA(cfg->host, sizeof(cfg->host), v);
        else if (EqStrA(k, "pin")) CopyStrA(cfg->pin, sizeof(cfg->pin), v);
        else if (EqStrA(k, "workDir")) CopyStrA(cfg->workDir, sizeof(cfg->workDir), v);
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
    // "HTTP/1.1 200 ..."
    if (!StartsWithA(hdr, "HTTP/1.")) return 0;
    const char* sp = hdr;
    while (*sp && *sp != ' ') sp++;
    while (*sp == ' ') sp++;
    return ParseIntA(sp);
}

static void TlsClose(TlsConn* tc) {
    if (tc->hasCtx) { DeleteSecurityContext(&tc->hCtx); tc->hasCtx = 0; }
    if (tc->hasCred) { FreeCredentialsHandle(&tc->hCred); tc->hasCred = 0; }
}

static int TlsHandshakeAndPin(TlsConn* tc, SOCKET s, const char* host, const char* expectedPin, char errText[64], int* outSecErr) {
    ZeroMemory(tc, sizeof(*tc));
    tc->sock = s;
    if (outSecErr) *outSecErr = 0;

    SCHANNEL_CRED cred;
    ZeroMemory(&cred, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

    TimeStamp expiry;
    ZeroMemory(&expiry, sizeof(expiry));
    SECURITY_STATUS ss = AcquireCredentialsHandleW(NULL, UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &tc->hCred, &expiry);
    if (ss != SEC_E_OK) {
        if (outSecErr) *outSecErr = (int)ss;
        HANDLE selfTok = NULL;
        DWORD tokErr = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &selfTok) ? 0 : GetLastError();
        if (selfTok) CloseHandle(selfTok);
        ULONG cPkg = 0; PSecPkgInfoW pPkg = NULL;
        SECURITY_STATUS es = EnumerateSecurityPackagesW(&cPkg, &pPkg);
        if (pPkg) FreeContextBuffer(pPkg);
        HMODULE hSch = LoadLibraryW(L"schannel.dll");
        DWORD llErr = hSch ? 0 : GetLastError();
        if (hSch) FreeLibrary(hSch);
        int ep = 0;
        ep = AppendStr(errText, 64, ep, "CredFail:t="); ep = AppendInt64(errText, 64, ep, (long long)tokErr);
        ep = AppendStr(errText, 64, ep, ",p="); ep = AppendInt64(errText, 64, ep, (long long)cPkg);
        ep = AppendStr(errText, 64, ep, ",e="); ep = AppendInt64(errText, 64, ep, (long long)es);
        ep = AppendStr(errText, 64, ep, ",l="); AppendInt64(errText, 64, ep, (long long)llErr);
        return 0;
    }
    tc->hasCred = 1;

    wchar_t wHost[128];
    ToWide(host, wHost, 128);
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

    // Verify leaf certificate SHA-256 pin strictly!
    PCCERT_CONTEXT pCert = NULL;
    if (QueryContextAttributesW(&tc->hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert) != SEC_E_OK || !pCert) {
        CopyStrA(errText, 64, "NoCert");
        TlsClose(tc);
        return 0;
    }
    BYTE hash[32]; DWORD hashLen = 32;
    int pinOk = 0;
    if (CryptHashCertificate(0, CALG_SHA_256, 0, pCert->pbCertEncoded, pCert->cbCertEncoded, hash, &hashLen) && hashLen == 32) {
        static const char hex[] = "0123456789ABCDEF";
        char actual[65];
        for (int i = 0; i < 32; i++) { actual[i * 2] = hex[(hash[i] >> 4) & 0xF]; actual[i * 2 + 1] = hex[hash[i] & 0xF]; }
        actual[64] = '\0';
        pinOk = EqHexI(actual, expectedPin);
    }
    CertFreeCertificateContext(pCert);
    if (!pinOk) {
        CopyStrA(errText, 64, "TrustFailure");
        TlsClose(tc);
        return 0;
    }

    if (QueryContextAttributesW(&tc->hCtx, SECPKG_ATTR_STREAM_SIZES, &tc->sizes) != SEC_E_OK) {
        CopyStrA(errText, 64, "SizesFail");
        TlsClose(tc);
        return 0;
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
    int total = (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
    return SendAllSock(tc->sock, (const char*)buf, total);
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
        } else {
            tc->encLen = 0;
        }
    }
}

static int FindHeaderEnd(const char* buf, int len) {
    for (int i = 3; i < len; i++) {
        if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n') return i + 1;
    }
    return -1;
}

static ProxyRes RunProxyProbe(const ClientCfg* cfg, int isTls, const char* marker, int timeoutMs) {
    ProxyRes r; ZeroMemory(&r, sizeof(r));
    CopyStrA(r.marker, sizeof(r.marker), marker);
    CopyStrA(r.statusText, sizeof(r.statusText), "ConnectFailure");

    SOCKET s = ConnectLoopback(cfg->p, (DWORD)timeoutMs, &r.winErr);
    if (s == INVALID_SOCKET) return r;

    char req[512], resp[4096];
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
        r.ok = 1;
        CopyStrA(r.statusText, sizeof(r.statusText), "200");
    } else {
        CopyStrA(r.statusText, sizeof(r.statusText), "HttpStatus");
    }
    return r;
}

static void FeedHeldBytes(HeldStream* hs, const char* data, int len, char lineBuf[128], int* lineLen) {
    for (int i = 0; i < len; i++) {
        char ch = data[i];
        if (ch == '\n') {
            lineBuf[*lineLen] = '\0';
            if (*lineLen > 0) {
                // Skip chunked-transfer hex size lines (marker lines always contain ':')
                int hasColon = 0;
                for (int k = 0; k < *lineLen; k++) if (lineBuf[k] == ':') { hasColon = 1; break; }
                if (hasColon) {
                    EnterCriticalSection(&hs->cs);
                    if (hs->markCount < 160) {
                        CopyStrA(hs->marks[hs->markCount], 40, lineBuf);
                        hs->ticks[hs->markCount] = QpcNow();
                        hs->markCount++;
                        CopyStrA(hs->state, sizeof(hs->state), "active");
                    }
                    LeaveCriticalSection(&hs->cs);
                }
            }
            *lineLen = 0;
        } else if (ch != '\r' && *lineLen < 127) {
            lineBuf[(*lineLen)++] = ch;
        }
    }
}

static DWORD WINAPI HeldStreamProc(LPVOID param) {
    HeldStream* hs = (HeldStream*)param;
    int err = 0;
    SOCKET s = ConnectLoopback(hs->cfg->p, 6000, &err);
    if (s == INVALID_SOCKET) {
        EnterCriticalSection(&hs->cs); CopyStrA(hs->state, sizeof(hs->state), "connect-err"); LeaveCriticalSection(&hs->cs);
        return 0;
    }
    EnterCriticalSection(&hs->cs); hs->sock = s; LeaveCriticalSection(&hs->cs);

    char req[512];
    char hdr[2048]; int hdrLen = 0; int hdrDone = 0;
    char lineBuf[128]; int lineLen = 0;

    if (!hs->isTls) {
        int p = 0;
        p = AppendStr(req, sizeof(req), p, "GET http://"); p = AppendStr(req, sizeof(req), p, hs->cfg->host);
        p = AppendStr(req, sizeof(req), p, "/hold/"); p = AppendStr(req, sizeof(req), p, hs->marker);
        p = AppendStr(req, sizeof(req), p, " HTTP/1.1\r\nHost: "); p = AppendStr(req, sizeof(req), p, hs->cfg->host);
        p = AppendStr(req, sizeof(req), p, "\r\nConnection: close\r\n\r\n");
        if (!SendAllSock(s, req, p)) {
            EnterCriticalSection(&hs->cs); CopyStrA(hs->state, sizeof(hs->state), "send-err"); LeaveCriticalSection(&hs->cs);
        } else {
            while (!hs->stopping) {
                char chunk[512];
                int n = recv(s, chunk, sizeof(chunk), 0);
                if (n <= 0) {
                    EnterCriticalSection(&hs->cs); CopyStrA(hs->state, sizeof(hs->state), n == 0 ? "eof" : "io-error"); LeaveCriticalSection(&hs->cs);
                    break;
                }
                if (!hdrDone) {
                    int take = n; if (hdrLen + take >= (int)sizeof(hdr)) take = (int)sizeof(hdr) - 1 - hdrLen;
                    CopyMemory(hdr + hdrLen, chunk, (SIZE_T)take); hdrLen += take; hdr[hdrLen] = '\0';
                    int bodyOff = FindHeaderEnd(hdr, hdrLen);
                    if (bodyOff >= 0) {
                        hdrDone = 1;
                        if (hdrLen > bodyOff) FeedHeldBytes(hs, hdr + bodyOff, hdrLen - bodyOff, lineBuf, &lineLen);
                    }
                } else {
                    FeedHeldBytes(hs, chunk, n, lineBuf, &lineLen);
                }
            }
        }
    } else {
        int p = 0;
        p = AppendStr(req, sizeof(req), p, "CONNECT "); p = AppendStr(req, sizeof(req), p, hs->cfg->host);
        p = AppendStr(req, sizeof(req), p, ":443 HTTP/1.1\r\nHost: "); p = AppendStr(req, sizeof(req), p, hs->cfg->host);
        p = AppendStr(req, sizeof(req), p, ":443\r\n\r\n");
        char cHdr[1024];
        if (!SendAllSock(s, req, p) || RecvUntilHeaderEnd(s, cHdr, sizeof(cHdr)) <= 0 || ParseHttpStatusCode(cHdr) != 200) {
            EnterCriticalSection(&hs->cs); CopyStrA(hs->state, sizeof(hs->state), "connect-err"); LeaveCriticalSection(&hs->cs);
        } else {
            TlsConn tc; char tlsErr[64]; int tlsSecErr = 0;
            if (!TlsHandshakeAndPin(&tc, s, hs->cfg->host, hs->cfg->pin, tlsErr, &tlsSecErr)) {
                EnterCriticalSection(&hs->cs); CopyStrA(hs->state, sizeof(hs->state), tlsErr); LeaveCriticalSection(&hs->cs);
            } else {
                p = 0;
                p = AppendStr(req, sizeof(req), p, "GET /hold/"); p = AppendStr(req, sizeof(req), p, hs->marker);
                p = AppendStr(req, sizeof(req), p, " HTTP/1.1\r\nHost: "); p = AppendStr(req, sizeof(req), p, hs->cfg->host);
                p = AppendStr(req, sizeof(req), p, "\r\nConnection: close\r\n\r\n");
                if (!TlsWrite(&tc, req, p)) {
                    EnterCriticalSection(&hs->cs); CopyStrA(hs->state, sizeof(hs->state), "tls-send-err"); LeaveCriticalSection(&hs->cs);
                } else {
                    while (!hs->stopping) {
                        char chunk[512];
                        int n = TlsRead(&tc, chunk, sizeof(chunk));
                        if (n <= 0) {
                            EnterCriticalSection(&hs->cs); CopyStrA(hs->state, sizeof(hs->state), n == 0 ? "eof" : "io-error"); LeaveCriticalSection(&hs->cs);
                            break;
                        }
                        if (!hdrDone) {
                            int take = n; if (hdrLen + take >= (int)sizeof(hdr)) take = (int)sizeof(hdr) - 1 - hdrLen;
                            CopyMemory(hdr + hdrLen, chunk, (SIZE_T)take); hdrLen += take; hdr[hdrLen] = '\0';
                            int bodyOff = FindHeaderEnd(hdr, hdrLen);
                            if (bodyOff >= 0) {
                                hdrDone = 1;
                                if (hdrLen > bodyOff) FeedHeldBytes(hs, hdr + bodyOff, hdrLen - bodyOff, lineBuf, &lineLen);
                            }
                        } else {
                            FeedHeldBytes(hs, chunk, n, lineBuf, &lineLen);
                        }
                    }
                }
                TlsClose(&tc);
            }
        }
    }

    EnterCriticalSection(&hs->cs);
    SOCKET closing = hs->sock; hs->sock = INVALID_SOCKET;
    if (EqStrA(hs->state, "starting") || EqStrA(hs->state, "active")) CopyStrA(hs->state, sizeof(hs->state), "closed");
    LeaveCriticalSection(&hs->cs);
    if (closing != INVALID_SOCKET) closesocket(closing);
    return 0;
}

static HeldStream* StartHeldStream(ClientCfg* cfg, int isTls) {
    HeldStream* hs = (HeldStream*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HeldStream));
    InitializeCriticalSection(&hs->cs);
    hs->cfg = cfg;
    hs->isTls = isTls;
    hs->sock = INVALID_SOCKET;
    FreshMarker(hs->marker);
    CopyStrA(hs->state, sizeof(hs->state), "starting");
    hs->hThread = CreateThread(NULL, 0, HeldStreamProc, hs, 0, NULL);
    return hs;
}

static void StopHeldStream(HeldStream* hs) {
    if (!hs) return;
    InterlockedExchange(&hs->stopping, 1);
    EnterCriticalSection(&hs->cs);
    SOCKET closing = hs->sock; hs->sock = INVALID_SOCKET;
    LeaveCriticalSection(&hs->cs);
    if (closing != INVALID_SOCKET) closesocket(closing);
    if (hs->hThread) {
        WaitForSingleObject(hs->hThread, 2000);
        CloseHandle(hs->hThread);
    }
    DeleteCriticalSection(&hs->cs);
    HeapFree(GetProcessHeap(), 0, hs);
}

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

static int AppendHeldJson(char* b, int cap, int p, HeldStream* hs) {
    if (!hs) return AppendStr(b, cap, p, "null");
    EnterCriticalSection(&hs->cs);
    p = AppendStr(b, cap, p, "{\"marker\":"); p = AppendJsonStr(b, cap, p, hs->marker);
    p = AppendStr(b, cap, p, ",\"state\":"); p = AppendJsonStr(b, cap, p, hs->state);
    p = AppendStr(b, cap, p, ",\"marks\":[");
    for (int i = 0; i < hs->markCount; i++) {
        if (i > 0) p = AppendStr(b, cap, p, ",");
        p = AppendJsonStr(b, cap, p, hs->marks[i]);
    }
    p = AppendStr(b, cap, p, "],\"ticks\":[");
    for (int i = 0; i < hs->markCount; i++) {
        if (i > 0) p = AppendStr(b, cap, p, ",");
        p = AppendInt64(b, cap, p, hs->ticks[i]);
    }
    p = AppendStr(b, cap, p, "]}");
    LeaveCriticalSection(&hs->cs);
    return p;
}

static int ParseCmdFile(const char* path, char action[32], char phase[40]) {
    char buf[512];
    if (ReadFileTextA(path, buf, sizeof(buf)) <= 0) return 0;
    action[0] = '\0'; CopyStrA(phase, 40, "none");
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        char* eq = line; while (*eq && *eq != '=') eq++;
        if (*eq != '=') continue;
        *eq = '\0';
        if (EqStrA(line, "action")) CopyStrA(action, 32, eq + 1);
        else if (EqStrA(line, "phase")) CopyStrA(phase, 40, eq + 1);
    }
    return action[0] != '\0';
}

static int ParseFirstArgA(char out[512]) {
    const wchar_t* cmd = GetCommandLineW();
    const wchar_t* p = cmd;
    while (*p == L' ' || *p == L'\t') p++;
    if (*p == L'"') { p++; while (*p && *p != L'"') p++; if (*p == L'"') p++; }
    else { while (*p && *p != L' ' && *p != L'\t') p++; }
    while (*p == L' ' || *p == L'\t') p++;
    if (!*p) return 0;
    wchar_t wArg[512]; int n = 0;
    if (*p == L'"') { p++; while (*p && *p != L'"' && n < 511) wArg[n++] = *p++; }
    else { while (*p && *p != L' ' && *p != L'\t' && n < 511) wArg[n++] = *p++; }
    wArg[n] = L'\0';
    WideCharToMultiByte(CP_UTF8, 0, wArg, -1, out, 512, NULL, NULL);
    return n > 0;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;
    long long qpcEntry = QpcNow();

    char cfgPath[512];
    if (!ParseFirstArgA(cfgPath)) return 2;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 3;

    ClientCfg cfg;
    if (!LoadCfg(cfgPath, &cfg)) { WSACleanup(); return 4; }

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

    char* outBuf = (char*)HeapAlloc(GetProcessHeap(), 0, 65536);
    if (!outBuf) { WSACleanup(); return 5; }

    int pos = 0;
    pos = AppendStr(outBuf, 65536, pos, "{\"pid\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)GetCurrentProcessId());
    pos = AppendStr(outBuf, 65536, pos, ",\"tid\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)GetCurrentThreadId());
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

    char coldPath[600];
    int cp = 0; cp = AppendStr(coldPath, sizeof(coldPath), cp, cfg.workDir); AppendStr(coldPath, sizeof(coldPath), cp, "\\cold-result.json");
    WriteAtomicFileA(coldPath, outBuf, pos);

    // 2. Bounded command loop (max 120s)
    ULONGLONG startMs = GetTickCount64();
    HeldStream* heldHttp = NULL;
    HeldStream* heldTls = NULL;

    for (int seq = 1; GetTickCount64() - startMs < 120000; seq++) {
        char cmdPath[600], resPath[600];
        int pA = 0; pA = AppendStr(cmdPath, sizeof(cmdPath), pA, cfg.workDir); pA = AppendStr(cmdPath, sizeof(cmdPath), pA, "\\cmd-"); pA = AppendInt64(cmdPath, sizeof(cmdPath), pA, seq); AppendStr(cmdPath, sizeof(cmdPath), pA, ".cfg");
        int pB = 0; pB = AppendStr(resPath, sizeof(resPath), pB, cfg.workDir); pB = AppendStr(resPath, sizeof(resPath), pB, "\\res-"); pB = AppendInt64(resPath, sizeof(resPath), pB, seq); AppendStr(resPath, sizeof(resPath), pB, ".json");

        wchar_t wCmd[600]; ToWide(cmdPath, wCmd, 600);
        while (GetFileAttributesW(wCmd) == INVALID_FILE_ATTRIBUTES) {
            if (GetTickCount64() - startMs >= 120000) goto done;
            Sleep(15);
        }

        char action[32], phase[40];
        if (!ParseCmdFile(cmdPath, action, phase)) goto done;

        pos = 0;
        if (EqStrA(action, "probe")) {
            char mHttp[32], mTls[32], tag[32];
            FreshMarker(mHttp); FreshMarker(mTls); FreshMarker(tag);
            ProxyRes pHttp = RunProxyProbe(&cfg, 0, mHttp, 1800);
            ProxyRes pTls = RunProxyProbe(&cfg, 1, mTls, 1800);
            TcpRes dSt = TryDirectTcp(cfg.sentinelTcp, tag);
            UdpRes dSu = TryDirectUdp(cfg.sentinelUdp, tag);
            UdpRes dUp = TryDirectUdp(cfg.p, tag);
            TcpRes dPu = TryDirectTcp(cfg.u, tag);
            TcpRes dTh = TryDirectTcp(cfg.httpPort, tag);
            TcpRes dTt = TryDirectTcp(cfg.tlsPort, tag);
            TcpRes dPeer; ZeroMemory(&dPeer, sizeof(dPeer));
            if (cfg.peerPort > 0) dPeer = TryDirectTcp(cfg.peerPort, tag);
            int pDnsSt = 0, pAddrSt = 0;
            char pDnsN[160], pAddrN[160];
            RunDnsChecks(cfg.prefix, phase, &pDnsSt, &pAddrSt, pDnsN, pAddrN);

            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"probe\",\"phase\":"); pos = AppendJsonStr(outBuf, 65536, pos, phase);
            pos = AppendStr(outBuf, 65536, pos, ",\"ok\":true,\"data\":{\"phase\":"); pos = AppendJsonStr(outBuf, 65536, pos, phase);
            pos = AppendStr(outBuf, 65536, pos, ",\"pid\":"); pos = AppendInt64(outBuf, 65536, pos, (long long)GetCurrentProcessId());
            pos = AppendStr(outBuf, 65536, pos, ",\"http\":"); pos = AppendProxyJson(outBuf, 65536, pos, "http", &pHttp);
            pos = AppendStr(outBuf, 65536, pos, ",\"tls\":"); pos = AppendProxyJson(outBuf, 65536, pos, "tls", &pTls);
            pos = AppendStr(outBuf, 65536, pos, ",\"direct\":{\"sentinelTcp\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dSt);
            pos = AppendStr(outBuf, 65536, pos, ",\"sentinelUdp\":"); pos = AppendUdpJson(outBuf, 65536, pos, &dSu);
            pos = AppendStr(outBuf, 65536, pos, ",\"udpToPa\":"); pos = AppendUdpJson(outBuf, 65536, pos, &dUp);
            pos = AppendStr(outBuf, 65536, pos, ",\"directPu\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dPu);
            pos = AppendStr(outBuf, 65536, pos, ",\"directTargetHttp\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dTh);
            pos = AppendStr(outBuf, 65536, pos, ",\"directTargetTls\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dTt);
            if (cfg.peerPort > 0) { pos = AppendStr(outBuf, 65536, pos, ",\"crossPort\":"); pos = AppendTcpJson(outBuf, 65536, pos, &dPeer); }
            pos = AppendStr(outBuf, 65536, pos, "},\"dns\":{\"dnsName\":"); pos = AppendJsonStr(outBuf, 65536, pos, pDnsN);
            pos = AppendStr(outBuf, 65536, pos, ",\"dnsQueryStatus\":"); pos = AppendInt64(outBuf, 65536, pos, pDnsSt);
            pos = AppendStr(outBuf, 65536, pos, ",\"addrName\":"); pos = AppendJsonStr(outBuf, 65536, pos, pAddrN);
            pos = AppendStr(outBuf, 65536, pos, ",\"getAddrInfoStatus\":"); pos = AppendInt64(outBuf, 65536, pos, pAddrSt);
            pos = AppendStr(outBuf, 65536, pos, "},\"qpcDone\":"); pos = AppendInt64(outBuf, 65536, pos, QpcNow());
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(action, "hold")) {
            StopHeldStream(heldHttp); heldHttp = NULL;
            StopHeldStream(heldTls); heldTls = NULL;
            heldHttp = StartHeldStream(&cfg, 0);
            heldTls = StartHeldStream(&cfg, 1);
            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"hold\",\"ok\":true,\"data\":{\"httpMarker\":");
            pos = AppendJsonStr(outBuf, 65536, pos, heldHttp->marker);
            pos = AppendStr(outBuf, 65536, pos, ",\"tlsMarker\":");
            pos = AppendJsonStr(outBuf, 65536, pos, heldTls->marker);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(action, "held")) {
            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"held\",\"ok\":true,\"data\":{\"http\":");
            pos = AppendHeldJson(outBuf, 65536, pos, heldHttp);
            pos = AppendStr(outBuf, 65536, pos, ",\"tls\":");
            pos = AppendHeldJson(outBuf, 65536, pos, heldTls);
            pos = AppendStr(outBuf, 65536, pos, "}}");
            WriteAtomicFileA(resPath, outBuf, pos);
        } else if (EqStrA(action, "finish")) {
            pos = AppendStr(outBuf, 65536, pos, "{\"seq\":"); pos = AppendInt64(outBuf, 65536, pos, seq);
            pos = AppendStr(outBuf, 65536, pos, ",\"action\":\"finish\",\"ok\":true}");
            WriteAtomicFileA(resPath, outBuf, pos);
            break;
        } else {
            break;
        }
    }

done:
    StopHeldStream(heldHttp);
    StopHeldStream(heldTls);
    HeapFree(GetProcessHeap(), 0, outBuf);
    WSACleanup();
    return 0;
}
