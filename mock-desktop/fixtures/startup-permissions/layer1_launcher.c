#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct WorkerState {
    HANDLE doneEvent;
    volatile LONG ran;
} WorkerState;

static DWORD WINAPI WorkerProc(LPVOID param) {
    WorkerState* state = (WorkerState*)param;
    InterlockedExchange(&state->ran, 1);
    SetEvent(state->doneEvent);
    return 0;
}

static int WriteAll(HANDLE file, const char* data, DWORD len) {
    DWORD written = 0;
    while (written < len) {
        DWORD chunk = 0;
        if (!WriteFile(file, data + written, len - written, &chunk, NULL) || chunk == 0) {
            return 0;
        }
        written += chunk;
    }
    return 1;
}

static int AppendStr(char* buf, int cap, int pos, const char* s) {
    while (*s && pos < cap - 1) {
        buf[pos++] = *s++;
    }
    buf[pos] = '\0';
    return pos;
}

static int AppendUInt64(char* buf, int cap, int pos, unsigned long long v) {
    char tmp[32];
    int n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0 && n < 31) {
            tmp[n++] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    while (n > 0 && pos < cap - 1) {
        buf[pos++] = tmp[--n];
    }
    buf[pos] = '\0';
    return pos;
}

static int ParseArgs(const wchar_t* cmd, wchar_t argv[6][512]) {
    int argc = 0;
    const wchar_t* p = cmd;
    while (*p && argc < 6) {
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

static int WideEq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
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

static void DirName(wchar_t* dst, int cap, const wchar_t* path) {
    CopyWide(dst, cap, path);
    int last = -1;
    for (int i = 0; dst[i]; i++) {
        if (dst[i] == L'\\' || dst[i] == L'/') last = i;
    }
    if (last > 0) dst[last] = L'\0';
}

static int FileExistsW(const wchar_t* path) {
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;

    wchar_t argv[6][512];
    int argc = ParseArgs(GetCommandLineW(), argv);
    if (argc == 2 && WideEq(argv[1], L"inert")) {
        return 0;
    }
    if (argc != 5 || !WideEq(argv[1], L"launch")) {
        return 2;
    }

    const wchar_t* childExe = argv[2];
    const wchar_t* readyPath = argv[3];
    const wchar_t* stopPath = argv[4];

    // 1. Verify internal thread + event creation works under hardened TokenDefaultDacl.
    WorkerState ws;
    ws.ran = 0;
    ws.doneEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    int workerOk = 0;
    DWORD workerErr = 0;
    if (ws.doneEvent != NULL) {
        HANDLE wt = CreateThread(NULL, 0, WorkerProc, &ws, 0, NULL);
        if (wt != NULL) {
            DWORD w = WaitForSingleObject(wt, 5000);
            DWORD ew = WaitForSingleObject(ws.doneEvent, 5000);
            if (w == WAIT_OBJECT_0 && ew == WAIT_OBJECT_0 && ws.ran == 1) {
                workerOk = 1;
            } else {
                workerErr = GetLastError();
            }
            CloseHandle(wt);
        } else {
            workerErr = GetLastError();
        }
        CloseHandle(ws.doneEvent);
    } else {
        workerErr = GetLastError();
    }

    // 2. Create cleanup Job and spawn suspended Layer-2 child via CreateProcessW + STARTUPINFOEXW.
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
    DWORD childErr = 0;
    int childInJob = 0;
    unsigned long long childStartTicks = 0;

    if (childJob != NULL && jobErr == 0) {
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
        LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
        if (attrList != NULL && InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
            if (UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &childJob, sizeof(HANDLE), NULL, NULL)) {
                STARTUPINFOEXW si;
                ZeroMemory(&si, sizeof(si));
                si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
                si.lpAttributeList = attrList;

                wchar_t childDir[512];
                DirName(childDir, 512, childExe);
                wchar_t childCmd[1024];
                childCmd[0] = L'\0';
                AppendWide(childCmd, 1024, L"\"");
                AppendWide(childCmd, 1024, childExe);
                AppendWide(childCmd, 1024, L"\" inert");

                // Never call ResumeThread on Layer-2!
                if (CreateProcessW(
                        childExe,
                        childCmd,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        NULL,
                        childDir,
                        &si.StartupInfo,
                        &pi)) {
                    childCreated = 1;
                    BOOL inJob = FALSE;
                    if (IsProcessInJob(pi.hProcess, childJob, &inJob) && inJob) {
                        childInJob = 1;
                    }
                    FILETIME c, e, k, u;
                    if (GetProcessTimes(pi.hProcess, &c, &e, &k, &u)) {
                        ULARGE_INTEGER li;
                        li.LowPart = c.dwLowDateTime;
                        li.HighPart = c.dwHighDateTime;
                        // Convert Windows FILETIME (1601 epoch) to .NET UTC ticks (0001 epoch).
                        childStartTicks = li.QuadPart + 504911232000000000ULL;
                    }
                } else {
                    childErr = GetLastError();
                }
            } else {
                childErr = GetLastError();
            }
            DeleteProcThreadAttributeList(attrList);
        } else {
            childErr = GetLastError();
        }
        if (attrList != NULL) HeapFree(GetProcessHeap(), 0, attrList);
    }

    // 3. Write atomic ready receipt for host.
    char json[1024];
    int pos = 0;
    pos = AppendStr(json, sizeof(json), pos, "{\"layer1Pid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)GetCurrentProcessId());
    pos = AppendStr(json, sizeof(json), pos, ",\"layer1Tid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)GetCurrentThreadId());
    pos = AppendStr(json, sizeof(json), pos, ",\"workerOk\":");
    pos = AppendStr(json, sizeof(json), pos, workerOk ? "true" : "false");
    pos = AppendStr(json, sizeof(json), pos, ",\"workerErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)workerErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"jobErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)jobErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"childCreated\":");
    pos = AppendStr(json, sizeof(json), pos, childCreated ? "true" : "false");
    pos = AppendStr(json, sizeof(json), pos, ",\"childErr\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)childErr);
    pos = AppendStr(json, sizeof(json), pos, ",\"childPid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)pi.dwProcessId);
    pos = AppendStr(json, sizeof(json), pos, ",\"childTid\":");
    pos = AppendUInt64(json, sizeof(json), pos, (unsigned long long)pi.dwThreadId);
    pos = AppendStr(json, sizeof(json), pos, ",\"childInJob\":");
    pos = AppendStr(json, sizeof(json), pos, childInJob ? "true" : "false");
    pos = AppendStr(json, sizeof(json), pos, ",\"childStartTicks\":");
    pos = AppendUInt64(json, sizeof(json), pos, childStartTicks);
    pos = AppendStr(json, sizeof(json), pos, ",\"layer2ResumeCalls\":0}");

    wchar_t tmpPath[520];
    CopyWide(tmpPath, 520, readyPath);
    AppendWide(tmpPath, 520, L".tmp");
    HANDLE f = CreateFileW(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteAll(f, json, (DWORD)pos);
        CloseHandle(f);
        MoveFileExW(tmpPath, readyPath, MOVEFILE_REPLACE_EXISTING);
    }

    // 4. Hold Layer-2 suspended until host signals stop (max 20s bounded wait).
    DWORD elapsed = 0;
    while (!FileExistsW(stopPath) && elapsed < 20000) {
        Sleep(25);
        elapsed += 25;
    }

    // 5. Terminate Layer-2 cleanly (never resumed) and release Job.
    if (pi.hProcess != NULL) {
        TerminateProcess(pi.hProcess, 0x4e34);
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread != NULL) {
        WaitForSingleObject(pi.hThread, 1000);
        CloseHandle(pi.hThread);
    }
    if (childJob != NULL) {
        CloseHandle(childJob);
    }

    return (workerOk && childCreated && childInJob) ? 0 : 1;
}
