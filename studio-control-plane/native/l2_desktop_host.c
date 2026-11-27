#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Pure-KERNEL32 Layer-2 PSEC Container Guardian for Desktop Apps (Electron / .NET WinForms).
// Runs inside the hardened Layer-2 Process/Thread SD (receives 4 Static BLOCK ALE_PACKAGE_ID WFP BEFORE ResumeThread),
// injects strictly isolated per-space user-profile environment variables, and spawns the real Desktop root process
// inside the SAME PSEC 1.1 container & Job object.

static void ToWide(const char* s, wchar_t* d, int cap) {
    MultiByteToWideChar(CP_UTF8, 0, s, -1, d, cap);
}

static int ParseArgs(wchar_t a[4][512]) {
    const wchar_t* p = GetCommandLineW();
    int idx = 0;
    while (*p && idx < 4) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        int n = 0;
        if (*p == L'"') {
            p++;
            while (*p && *p != L'"' && n < 511) a[idx][n++] = *p++;
            if (*p == L'"') p++;
        } else {
            while (*p && *p != L' ' && *p != L'\t' && n < 511) a[idx][n++] = *p++;
        }
        a[idx][n] = L'\0';
        idx++;
    }
    return idx;
}

int WINAPI wWinMain(HINSTANCE h1, HINSTANCE h2, PWSTR c, int s) {
    (void)h1; (void)h2; (void)c; (void)s;
    wchar_t a[4][512];
    if (ParseArgs(a) < 2) return 2;

    HANDLE f = CreateFileW(a[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 3;
    char buf[4096];
    DWORD got = 0;
    ReadFile(f, buf, sizeof(buf) - 1, &got, NULL);
    CloseHandle(f);
    buf[got] = '\0';

    wchar_t exePath[512] = L"", cmdLine[1536] = L"", stopPath[512] = L"";
    wchar_t homeDir[512] = L"", localDir[512] = L"", roamDir[512] = L"", tmpDir[512] = L"";
    wchar_t userName[128] = L"", proxyUrl[128] = L"", langVal[64] = L"", tzVal[64] = L"";

    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (*p) { *p++ = '\0'; while (*p == '\r' || *p == '\n') p++; }
        if (line[0] == 'e' && line[1] == '=') ToWide(line + 2, exePath, 512);
        else if (line[0] == 'a' && line[1] == '=') ToWide(line + 2, cmdLine, 1536);
        else if (line[0] == 's' && line[1] == '=') ToWide(line + 2, stopPath, 512);
        else if (line[0] == 'h' && line[1] == '=') ToWide(line + 2, homeDir, 512);
        else if (line[0] == 'L' && line[1] == '=') ToWide(line + 2, localDir, 512);
        else if (line[0] == 'R' && line[1] == '=') ToWide(line + 2, roamDir, 512);
        else if (line[0] == 'T' && line[1] == '=') ToWide(line + 2, tmpDir, 512);
        else if (line[0] == 'u' && line[1] == '=') ToWide(line + 2, userName, 128);
        else if (line[0] == 'p' && line[1] == '=') ToWide(line + 2, proxyUrl, 128);
        else if (line[0] == 'g' && line[1] == '=') ToWide(line + 2, langVal, 64);
        else if (line[0] == 'z' && line[1] == '=') ToWide(line + 2, tzVal, 64);
    }

    if (homeDir[0]) { SetEnvironmentVariableW(L"USERPROFILE", homeDir); SetEnvironmentVariableW(L"HOME", homeDir); }
    if (localDir[0]) SetEnvironmentVariableW(L"LOCALAPPDATA", localDir);
    if (roamDir[0]) SetEnvironmentVariableW(L"APPDATA", roamDir);
    if (tmpDir[0]) { SetEnvironmentVariableW(L"TEMP", tmpDir); SetEnvironmentVariableW(L"TMP", tmpDir); }
    if (userName[0]) SetEnvironmentVariableW(L"USERNAME", userName);
    if (proxyUrl[0]) {
        SetEnvironmentVariableW(L"HTTP_PROXY", proxyUrl);
        SetEnvironmentVariableW(L"HTTPS_PROXY", proxyUrl);
        SetEnvironmentVariableW(L"NO_PROXY", L"");
    }
    if (langVal[0]) SetEnvironmentVariableW(L"LANG", langVal);
    if (tzVal[0]) SetEnvironmentVariableW(L"TZ", tzVal);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(exePath, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return (int)GetLastError();
    }

    // Keep container guardian alive until stop signal or target process exits
    for (;;) {
        if (stopPath[0] && GetFileAttributesW(stopPath) != INVALID_FILE_ATTRIBUTES) break;
        if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) break;
    }

    if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 3000);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
