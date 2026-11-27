#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>

typedef HANDLE HPROCESS_SECURITY_ENVIRONMENT;
typedef HRESULT (WINAPI *PFN_CreateProcessSecurityEnvironment)(
    const BYTE* specification,
    DWORD specificationSizeBytes,
    DWORD creationFlags,
    HPROCESS_SECURITY_ENVIRONMENT* securityEnvironment
);
typedef VOID (WINAPI *PFN_CloseProcessSecurityEnvironment)(
    HPROCESS_SECURITY_ENVIRONMENT securityEnvironment
);

#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT
#define PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT ((SIZE_T)(35 | 0x00020000))
#endif

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

static int AppendUInt64(char* buf, int cap, int pos, unsigned long long v) {
    char tmp[32];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    else { while (v > 0 && n < 31) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } }
    while (n > 0 && pos < cap - 1) buf[pos++] = tmp[--n];
    buf[pos] = '\0';
    return pos;
}

static int AppendHex32(char* buf, int cap, int pos, DWORD v) {
    static const char hex[] = "0123456789ABCDEF";
    pos = AppendStr(buf, cap, pos, "\"0x");
    for (int i = 7; i >= 0 && pos < cap - 1; i--) {
        buf[pos++] = hex[(v >> (i * 4)) & 0xF];
    }
    if (pos < cap - 1) buf[pos++] = '"';
    buf[pos] = '\0';
    return pos;
}

static int ParseArgs(const wchar_t* cmd, wchar_t argv[12][512]) {
    int argc = 0;
    const wchar_t* p = cmd;
    while (*p && argc < 12) {
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

static int FileExistsW(const wchar_t* path) {
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

static BYTE* ReadFileBytes(const wchar_t* path, DWORD* outSize, DWORD* outErr) {
    *outSize = 0;
    *outErr = 0;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { *outErr = GetLastError(); return NULL; }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 1048576) {
        *outErr = GetLastError();
        if (*outErr == 0) *outErr = ERROR_INVALID_DATA;
        CloseHandle(f);
        return NULL;
    }
    DWORD size = (DWORD)sz.QuadPart;
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) { *outErr = ERROR_OUTOFMEMORY; CloseHandle(f); return NULL; }
    DWORD total = 0;
    while (total < size) {
        DWORD chunk = 0;
        if (!ReadFile(f, buf + total, size - total, &chunk, NULL) || chunk == 0) {
            *outErr = GetLastError();
            HeapFree(GetProcessHeap(), 0, buf);
            CloseHandle(f);
            return NULL;
        }
        total += chunk;
    }
    CloseHandle(f);
    *outSize = size;
    return buf;
}

// Usage:
//   layer1_psec_launcher.exe <psecBinPath> <childExe> <childCmdLine> <childCwd> <hostSid> <readyJson> <stopFile>
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;

    wchar_t argv[12][512];
    int argc = ParseArgs(GetCommandLineW(), argv);
    if (argc != 8) return 2;

    const wchar_t* psecBinPath = argv[1];
    const wchar_t* childExe = argv[2];
    const wchar_t* childCmdArg = argv[3];
    const wchar_t* childCwd = argv[4];
    const wchar_t* hostSid = argv[5];
    const wchar_t* readyPath = argv[6];
    const wchar_t* stopPath = argv[7];

    DWORD specSize = 0, specErr = 0;
    BYTE* specBytes = ReadFileBytes(psecBinPath, &specSize, &specErr);

    HMODULE pm = NULL;
    PFN_CreateProcessSecurityEnvironment pCreatePsec = NULL;
    PFN_CloseProcessSecurityEnvironment pClosePsec = NULL;
    HPROCESS_SECURITY_ENVIRONMENT hPsec = NULL;
    HRESULT psecHr = E_FAIL;
    DWORD loadErr = 0;

    if (specBytes != NULL) {
        pm = LoadLibraryExW(L"processmodel.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (pm != NULL) {
            pCreatePsec = (PFN_CreateProcessSecurityEnvironment)GetProcAddress(pm, "CreateProcessSecurityEnvironment");
            pClosePsec = (PFN_CloseProcessSecurityEnvironment)GetProcAddress(pm, "CloseProcessSecurityEnvironment");
            if (pCreatePsec != NULL && pClosePsec != NULL) {
                psecHr = pCreatePsec(specBytes, specSize, 0, &hPsec);
            } else {
                loadErr = GetLastError();
            }
        } else {
            loadErr = GetLastError();
        }
    }

    // Build explicit hardened security descriptor for Layer-2 Process & Thread:
    // Protected DACL granting GENERIC_ALL only to Host SID and SYSTEM, and read-only query (0x00121400) to OWNER RIGHTS (S-1-3-4).
    // Zero overlap with any of the 9 critical process rights, 5 critical thread rights, or PROCESS/THREAD_TERMINATE.
    PSECURITY_DESCRIPTOR childSd = NULL;
    DWORD sdErr = 0;
    {
        wchar_t sddl[512];
        sddl[0] = L'\0';
        AppendWide(sddl, 512, L"D:P(A;;GA;;;");
        AppendWide(sddl, 512, hostSid);
        AppendWide(sddl, 512, L")(A;;GA;;;SY)(A;;0x00121400;;;S-1-3-4)");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &childSd, NULL)) {
            sdErr = GetLastError();
        }
    }

    HANDLE childJob = CreateJobObjectW(NULL, NULL);
    DWORD jobErr = (childJob == NULL) ? GetLastError() : 0;
    if (childJob != NULL) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
        ZeroMemory(&limits, sizeof(limits));
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(childJob, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
            jobErr = GetLastError();
        }
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    int childCreated = 0;
    int childInJob = 0;
    DWORD childErr = 0;
    const char* childStage = "none";
    DWORD assignJobErr = 0;
    unsigned long long childStartTicks = 0;

    if (SUCCEEDED(psecHr) && hPsec != NULL && childSd != NULL && childJob != NULL && jobErr == 0) {
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
        LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
        if (attrList != NULL && InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
            HANDLE envVal = hPsec;
            if (UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT, &envVal, sizeof(HANDLE), NULL, NULL)) {
                STARTUPINFOEXW si;
                ZeroMemory(&si, sizeof(si));
                si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
                si.lpAttributeList = attrList;

                SECURITY_ATTRIBUTES sa;
                sa.nLength = sizeof(SECURITY_ATTRIBUTES);
                sa.lpSecurityDescriptor = childSd;
                sa.bInheritHandle = FALSE;

                wchar_t cmdLine[1536];
                cmdLine[0] = L'\0';
                AppendWide(cmdLine, 1536, L"\"");
                AppendWide(cmdLine, 1536, childExe);
                AppendWide(cmdLine, 1536, L"\" ");
                AppendWide(cmdLine, 1536, childCmdArg);

                childStage = "createProcessWithSd";
                // Strictly CREATE_SUSPENDED! Host will inspect container SID, install & read back WFP, and call ResumeThread itself.
                if (CreateProcessW(
                        childExe,
                        cmdLine,
                        &sa,
                        &sa,
                        FALSE,
                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        NULL,
                        childCwd,
                        &si.StartupInfo,
                        &pi)) {
                    childCreated = 1;
                    childStage = "created";
                    if (!AssignProcessToJobObject(childJob, pi.hProcess)) {
                        assignJobErr = GetLastError();
                        TerminateProcess(pi.hProcess, 0x4e34);
                        WaitForSingleObject(pi.hProcess, 3000);
                        CloseHandle(pi.hProcess); pi.hProcess = NULL;
                        CloseHandle(pi.hThread); pi.hThread = NULL;
                        childCreated = 0;
                    } else {
                        BOOL inJob = FALSE;
                        if (IsProcessInJob(pi.hProcess, childJob, &inJob) && inJob) childInJob = 1;
                        FILETIME c, e, k, u;
                        if (GetProcessTimes(pi.hProcess, &c, &e, &k, &u)) {
                            ULARGE_INTEGER li;
                            li.LowPart = c.dwLowDateTime;
                            li.HighPart = c.dwHighDateTime;
                            childStartTicks = li.QuadPart + 504911232000000000ULL;
                        }
                    }
                } else {
                    childErr = GetLastError();
                }
            } else {
                childStage = "updateAttr";
                childErr = GetLastError();
            }
            DeleteProcThreadAttributeList(attrList);
        } else {
            childStage = "initAttr";
            childErr = GetLastError();
        }
        if (attrList != NULL) HeapFree(GetProcessHeap(), 0, attrList);
    }

    // Write atomic receipt JSON for host.
    char json[1024];
    int pos = 0;
    pos = AppendStr(json, sizeof(json), pos, "{\"layer1Pid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)GetCurrentProcessId());
    pos = AppendStr(json, sizeof(json), pos, ",\"layer1Tid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)GetCurrentThreadId());
    pos = AppendStr(json, sizeof(json), pos, ",\"specSize\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)specSize);
    pos = AppendStr(json, sizeof(json), pos, ",\"specErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)specErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"loadErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)loadErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"psecHr\":");
    pos = AppendHex32(json, sizeof(json), pos, (DWORD)psecHr);
    pos = AppendStr(json, sizeof(json), pos, ",\"psecCreated\":");
    pos = AppendStr(json, sizeof(json), pos, (SUCCEEDED(psecHr) && hPsec != NULL) ? "true" : "false");
    pos = AppendStr(json, sizeof(json), pos, ",\"sdErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)sdErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"jobErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)jobErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"assignJobErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)assignJobErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"childCreated\":");
    pos = AppendStr(json, sizeof(json), pos, childCreated ? "true" : "false");
    pos = AppendStr(json, sizeof(json), pos, ",\"childStage\":\"");
    pos = AppendStr(json, sizeof(json), pos, childStage);
    pos = AppendStr(json, sizeof(json), pos, "\",\"childErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)childErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"childPid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)pi.dwProcessId);
    pos = AppendStr(json, sizeof(json), pos, ",\"childTid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)pi.dwThreadId);
    pos = AppendStr(json, sizeof(json), pos, ",\"childInJob\":");
    pos = AppendStr(json, sizeof(json), pos, childInJob ? "true" : "false");
    pos = AppendStr(json, sizeof(json), pos, ",\"childStartTicks\":");
    pos = AppendUInt64(json, sizeof(json), pos, childStartTicks);
    pos = AppendStr(json, sizeof(json), pos, ",\"layer1ResumeCallsOnChild\":0}");

    wchar_t tmpPath[520];
    CopyWide(tmpPath, 520, readyPath);
    AppendWide(tmpPath, 520, L".tmp");
    HANDLE f = CreateFileW(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteAll(f, json, (DWORD)pos);
        CloseHandle(f);
        MoveFileExW(tmpPath, readyPath, MOVEFILE_REPLACE_EXISTING);
    }

    // Keep PSEC handle and Job alive until host writes stop file (bounded 130s).
    DWORD elapsed = 0;
    while (!FileExistsW(stopPath) && elapsed < 130000) {
        Sleep(25);
        elapsed += 25;
    }

    if (pi.hProcess != NULL) {
        if (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 0x4e34);
            WaitForSingleObject(pi.hProcess, 3000);
        }
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread != NULL) {
        WaitForSingleObject(pi.hThread, 1000);
        CloseHandle(pi.hThread);
    }
    if (childJob != NULL) CloseHandle(childJob);
    if (hPsec != NULL && pClosePsec != NULL) pClosePsec(hPsec);
    if (childSd != NULL) LocalFree(childSd);
    if (specBytes != NULL) HeapFree(GetProcessHeap(), 0, specBytes);
    return (childCreated && childInJob) ? 0 : 1;
}
