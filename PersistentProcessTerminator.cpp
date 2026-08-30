/*
PersistentProcessTerminator.cpp
用户态进程终止程序

首次运行需注册服务:命令行(管理员):sc create KillProcessService binPath ="%ExecutablePath%\PersistentProcessTerminator.exe"
运行:命令行(管理员):sc start KillProcessService <进程PID>

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\PersistentProcessTerminator.cpp" -o "%ExecutablePath%\PersistentProcessTerminator.exe" -luser32 -ladvapi32

运行权限：LocalSYSTEM(通过管理员权限的命令行启动)

注意：不推荐使用该程序结束系统进程

局限：
无法结束PPL进程、受保护进程（实现需内核驱动）
若相关API被恶意HOOK，程序失效
*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <map>
#include <vector>
#include <queue>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

// ------------------------------------------------------------
// 类型定义
// ------------------------------------------------------------
typedef NTSTATUS (NTAPI *pNtSetInfoProc)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtTermProc)(HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI *pNtQueryInfoProc)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// ------------------------------------------------------------
// 全局变量
// ------------------------------------------------------------
SERVICE_STATUS          g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE   g_ServiceStatusHandle = NULL;

pNtSetInfoProc   g_pNtSetInformationProcess = NULL;
pNtTermProc      g_pNtTerminateProcess = NULL;
pNtQueryInfoProc g_pNtQueryInformationProcess = NULL;

// ------------------------------------------------------------
// 启用 SeDebugPrivilege
// ------------------------------------------------------------
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ret && (err == ERROR_SUCCESS);
}

// ------------------------------------------------------------
// 设置目标进程的 ProcessBreakOnTermination 为 FALSE
// ------------------------------------------------------------
BOOL SetProcessBreakOnTermination(HANDLE hProcess, BOOL bEnable)
{
    if (!g_pNtSetInformationProcess)
    {
        HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
        if (!hNtdll) return FALSE;
        g_pNtSetInformationProcess = (pNtSetInfoProc)GetProcAddress(hNtdll, "NtSetInformationProcess");
        if (!g_pNtSetInformationProcess) return FALSE;
    }

    ULONG value = bEnable ? 1 : 0;
    NTSTATUS status = g_pNtSetInformationProcess(hProcess,
                                                  (PROCESSINFOCLASS)0x1D,   // ProcessBreakOnTermination
                                                  &value,
                                                  sizeof(value));
    return NT_SUCCESS(status);
}

// ------------------------------------------------------------
// 获取目标进程所属的作业句柄 (若进程在作业中)
// 返回的句柄需由调用者 CloseHandle
// ------------------------------------------------------------
BOOL GetProcessJob(HANDLE hProcess, HANDLE* phJob)
{
    if (!phJob) return FALSE;
    *phJob = NULL;

    if (!g_pNtQueryInformationProcess)
    {
        HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
        if (!hNtdll) return FALSE;
        g_pNtQueryInformationProcess = (pNtQueryInfoProc)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!g_pNtQueryInformationProcess) return FALSE;
    }

    HANDLE hJob = NULL;
    NTSTATUS status = g_pNtQueryInformationProcess(hProcess,
                                                    (PROCESSINFOCLASS)0x1B,
                                                    &hJob,
                                                    sizeof(HANDLE),
                                                    NULL);
    if (NT_SUCCESS(status) && hJob)
    {
        *phJob = hJob;
        return TRUE;
    }
    return FALSE;
}

// ------------------------------------------------------------
// 核心终止逻辑（单进程）
// ------------------------------------------------------------
DWORD TerminateProcessByPid(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                                  FALSE, pid);
    if (!hProcess)
    {
        hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess)
            return GetLastError();
    }

    DWORD dwLastError = 0;

    // ---- 若进程在作业中，则尝试终止整个作业 ----
    HANDLE hJob = NULL;
    if (GetProcessJob(hProcess, &hJob) && hJob)
    {
        if (TerminateJobObject(hJob, 0))
        {
            CloseHandle(hJob);
            CloseHandle(hProcess);
            return 0;
        }
        CloseHandle(hJob);
    }

    // 1. 清除 ProcessBreakOnTermination
    SetProcessBreakOnTermination(hProcess, FALSE);

    // 2. TerminateProcess
    if (TerminateProcess(hProcess, 0))
    {
        CloseHandle(hProcess);
        return 0;
    }
    dwLastError = GetLastError();

    // 3. taskkill
    TCHAR cmdLine[256];
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    wsprintf(cmdLine, TEXT("taskkill /f /pid %d"), pid);
    if (CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (exitCode == 0)
        {
            CloseHandle(hProcess);
            return 0;
        }
    }

    // 4. wmic
    wsprintf(cmdLine, TEXT("wmic process where \"processid=%d\" delete"), pid);
    if (CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (exitCode == 0)
        {
            CloseHandle(hProcess);
            return 0;
        }
    }

    // 5. NtTerminateProcess
    if (!g_pNtTerminateProcess)
    {
        HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
        if (hNtdll)
            g_pNtTerminateProcess = (pNtTermProc)GetProcAddress(hNtdll, "NtTerminateProcess");
    }
    if (g_pNtTerminateProcess)
    {
        NTSTATUS status = g_pNtTerminateProcess(hProcess, 0);
        if (NT_SUCCESS(status))
        {
            CloseHandle(hProcess);
            return 0;
        }
    }

    CloseHandle(hProcess);
    return dwLastError;
}

// ------------------------------------------------------------
// 获取目标进程的所有后代 PID（不包含自身）
// ------------------------------------------------------------
BOOL GetProcessTree(DWORD pid, std::vector<DWORD>& descendants)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    PROCESSENTRY32 pe = { sizeof(pe) };
    std::map<DWORD, std::vector<DWORD>> children;

    if (Process32First(hSnapshot, &pe))
    {
        do {
            children[pe.th32ParentProcessID].push_back(pe.th32ProcessID);
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    // BFS 收集所有后代
    std::queue<DWORD> q;
    q.push(pid);
    while (!q.empty())
    {
        DWORD cur = q.front(); q.pop();
        auto it = children.find(cur);
        if (it != children.end())
        {
            for (DWORD child : it->second)
            {
                descendants.push_back(child);
                q.push(child);
            }
        }
    }
    return TRUE;
}

// ------------------------------------------------------------
//获取进程的可执行文件路径
// ------------------------------------------------------------
BOOL GetProcessPath(DWORD pid, std::wstring& path)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
    WCHAR buffer[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    BOOL ret = QueryFullProcessImageNameW(hProcess, 0, buffer, &size);
    if (ret) path = buffer;
    CloseHandle(hProcess);
    return ret ? TRUE : FALSE;
}

// ------------------------------------------------------------
// 获取进程的命令行（通过 PEB）
// ------------------------------------------------------------
BOOL GetProcessCommandLine(DWORD pid, std::wstring& cmdLine)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;

    // 获取 PEB 地址
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(status)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 读取 PEB
    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 读取 RTL_USER_PROCESS_PARAMETERS
    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    UNICODE_STRING cmd = params.CommandLine;
    if (cmd.Length == 0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    std::vector<WCHAR> buffer(cmd.Length / sizeof(WCHAR) + 1);
    if (!ReadProcessMemory(hProcess, cmd.Buffer, buffer.data(), cmd.Length, NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    cmdLine = std::wstring(buffer.data(), cmd.Length / sizeof(WCHAR));
    CloseHandle(hProcess);
    return TRUE;
}

// ------------------------------------------------------------
//根据路径或命令行终止匹配的进程（守护进程清理）
// ------------------------------------------------------------
DWORD KillMatchingProcesses(const std::wstring& targetPath, const std::wstring& targetCmdLine, DWORD excludePid)
{
    DWORD lastError = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return GetLastError();

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            if (pid == excludePid) continue;

            std::wstring path, cmdLine;
            BOOL bMatch = FALSE;

            // 比较路径（若可获取）
            if (GetProcessPath(pid, path)) {
                if (_wcsicmp(path.c_str(), targetPath.c_str()) == 0)
                    bMatch = TRUE;
            }

            // 若路径不匹配，再比较命令行（完全匹配，可按需改为包含）
            if (!bMatch && GetProcessCommandLine(pid, cmdLine)) {
                if (cmdLine == targetCmdLine)
                    bMatch = TRUE;
            }

            if (bMatch) {
                DWORD ret = TerminateProcessByPid(pid);
                if (ret != 0) lastError = ret;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return lastError;
}

// ------------------------------------------------------------
//终止整个进程树 + 守护进程清理循环
// ------------------------------------------------------------
DWORD TerminateProcessTree(DWORD pid)
{
    // 1. 记录目标进程特征
    std::wstring targetPath, targetCmdLine;
    GetProcessPath(pid, targetPath);
    GetProcessCommandLine(pid, targetCmdLine);

    // 2. 先尝试终止目标所在作业（可能包含整个树）
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess) {
        HANDLE hJob = NULL;
        if (GetProcessJob(hProcess, &hJob) && hJob) {
            if (TerminateJobObject(hJob, 0)) {
                CloseHandle(hJob);
                CloseHandle(hProcess);
                return 0;
            }
            CloseHandle(hJob);
        }
        CloseHandle(hProcess);
    }

    // 3. 收集所有子进程（递归）
    std::vector<DWORD> descendants;
    if (!GetProcessTree(pid, descendants)) {
        // 若收集失败，至少尝试终止目标自身
        return TerminateProcessByPid(pid);
    }

    // 4. 先终止所有后代
    for (DWORD childPid : descendants) {
        TerminateProcessByPid(childPid);
    }

    // 5. 终止目标自身
    DWORD ret = TerminateProcessByPid(pid);

    // 6. 守护进程清理循环（最多 5 次，间隔 2 秒）
    const int MAX_RETRY = 5;
    const int RETRY_INTERVAL_MS = 2000;
    for (int i = 0; i < MAX_RETRY; i++) {
        Sleep(RETRY_INTERVAL_MS);

        // 检查是否还有匹配的进程（排除原 PID）
        DWORD killRet = KillMatchingProcesses(targetPath, targetCmdLine, pid);
        if (killRet == 0) {
            // 没有找到匹配进程，认为已清理干净
            break;
        } else {
            // 若有匹配但终止失败，记录错误但继续重试
            ret = killRet;
        }
    }

    return ret;
}

// ------------------------------------------------------------
// 服务控制处理
// ------------------------------------------------------------
void WINAPI ServiceCtrlHandler(DWORD dwCtrl)
{
    switch (dwCtrl)
    {
    case SERVICE_CONTROL_STOP:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
        break;
    default:
        break;
    }
}

// ------------------------------------------------------------
// 服务入口
// ------------------------------------------------------------
void WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 3000;

    g_ServiceStatusHandle = RegisterServiceCtrlHandler(TEXT("KillProcessService"), ServiceCtrlHandler);
    if (!g_ServiceStatusHandle)
        return;

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    DWORD pid = 0;
    if (argc >= 2)
        pid = _ttoi(argv[1]);
    else
    {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = ERROR_BAD_ARGUMENTS;
        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
        return;
    }

    EnableDebugPrivilege();

    DWORD exitCode = TerminateProcessTree(pid);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = exitCode;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

// ------------------------------------------------------------
// 主函数
// ------------------------------------------------------------
int _tmain(int argc, TCHAR* argv[])
{
    SERVICE_TABLE_ENTRY DispatchTable[] =
    {
        { (LPSTR)"KillProcessService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(DispatchTable))
    {
        if (argc > 1 && _tcscmp(argv[1], TEXT("install")) == 0)
        {
            TCHAR szPath[MAX_PATH];
            GetModuleFileName(NULL, szPath, MAX_PATH);
            SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
            if (hSCM)
            {
                SC_HANDLE hService = CreateService(hSCM,
                    TEXT("KillProcessService"),
                    TEXT("Kill Process Service"),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    szPath,
                    NULL, NULL, NULL, NULL, NULL);
                if (hService)
                {
                    _tprintf(TEXT("Service installed successfully.\n"));
                    CloseServiceHandle(hService);
                }
                else
                    _tprintf(TEXT("Install failed, error: %d\n"), GetLastError());
                CloseServiceHandle(hSCM);
            }
        }
        else if (argc > 1 && _tcscmp(argv[1], TEXT("uninstall")) == 0)
        {
            SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
            if (hSCM)
            {
                SC_HANDLE hService = OpenService(hSCM, TEXT("KillProcessService"), DELETE);
                if (hService)
                {
                    if (DeleteService(hService))
                        _tprintf(TEXT("Service uninstalled.\n"));
                    else
                        _tprintf(TEXT("Uninstall failed, error: %d\n"), GetLastError());
                    CloseServiceHandle(hService);
                }
                else
                    _tprintf(TEXT("Service not found.\n"));
                CloseServiceHandle(hSCM);
            }
        }
        else
        {
            _tprintf(TEXT("Usage:\n"));
            _tprintf(TEXT("  %s install   - install the service\n"), argv[0]);
            _tprintf(TEXT("  %s uninstall - uninstall the service\n"), argv[0]);
            _tprintf(TEXT("  (run as service with PID parameter)\n"));
        }
    }
    return 0;
}