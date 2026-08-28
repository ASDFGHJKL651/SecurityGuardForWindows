/*
SandBox.cpp
响应层

将进程放入作业对象，严格限制权限运行可疑程序

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\SandBox.cpp" -o "%ExecutablePath%\SandBox.exe" -mwindows

运行权限：管理员权限
*/
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include <string>
#include <vector>
#include <sddl.h>
#include <winbase.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")

// 
// 动态加载 AppContainer 相关 API 所需的类型定义和函数指针
// 
typedef BOOL (WINAPI *pfnCreateAppContainerProfile)(
    PCWSTR pszAppContainerName,
    PCWSTR pszDisplayName,
    PCWSTR pszDescription,
    PSECURITY_CAPABILITIES pCapabilities,
    DWORD dwCapabilityCount,
    PSID *ppSid
);

typedef HANDLE (WINAPI *pfnOpenAppContainerProfile)(
    PCWSTR pszAppContainerName
);

typedef BOOL (WINAPI *pfnDeriveAppContainerSidFromAppContainerName)(
    PCWSTR pszAppContainerName,
    PSID *ppsid
);

typedef BOOL (WINAPI *pfnCreateAppContainerToken)(
    HANDLE ExistingToken,
    PSID AppContainerSid,
    HANDLE *pToken
);

typedef BOOL (WINAPI *pfnDeleteAppContainerProfile)(
    PCWSTR pszAppContainerName
);

// 全局函数指针
static pfnCreateAppContainerProfile         fpCreateAppContainerProfile = nullptr;
static pfnOpenAppContainerProfile           fpOpenAppContainerProfile = nullptr;
static pfnDeriveAppContainerSidFromAppContainerName fpDeriveAppContainerSidFromAppContainerName = nullptr;
static pfnCreateAppContainerToken           fpCreateAppContainerToken = nullptr;
static pfnDeleteAppContainerProfile         fpDeleteAppContainerProfile = nullptr;

// 
// 加载 AppContainer API
// 
bool LoadAppContainerAPI() {
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hAdvapi32 || !hKernel32) {
        return false;
    }

    fpCreateAppContainerProfile = (pfnCreateAppContainerProfile)GetProcAddress(hAdvapi32, "CreateAppContainerProfile");
    fpOpenAppContainerProfile = (pfnOpenAppContainerProfile)GetProcAddress(hAdvapi32, "OpenAppContainerProfile");
    fpDeriveAppContainerSidFromAppContainerName = (pfnDeriveAppContainerSidFromAppContainerName)GetProcAddress(hAdvapi32, "DeriveAppContainerSidFromAppContainerName");
    fpCreateAppContainerToken = (pfnCreateAppContainerToken)GetProcAddress(hKernel32, "CreateAppContainerToken");
    fpDeleteAppContainerProfile = (pfnDeleteAppContainerProfile)GetProcAddress(hAdvapi32, "DeleteAppContainerProfile");

    return (fpCreateAppContainerProfile && fpOpenAppContainerProfile &&
            fpDeriveAppContainerSidFromAppContainerName && fpCreateAppContainerToken &&
            fpDeleteAppContainerProfile);
}

// 
// 辅助函数
// 
std::wstring toWideString(const char* str) {
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if (len == 0) return std::wstring();
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], len);
    wstr.pop_back();
    return wstr;
}

bool EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed, error: " << GetLastError() << std::endl;
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        std::cerr << "LookupPrivilegeValue failed, error: " << GetLastError() << std::endl;
        return false;
    }
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        std::cerr << "AdjustTokenPrivileges failed, error: " << GetLastError() << std::endl;
        return false;
    }
    CloseHandle(hToken);
    return true;
}

bool IsWindows8OrGreater() {
    typedef LONG (WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return false;
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
    if (!RtlGetVersion) return false;

    RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
    if (RtlGetVersion(&osvi) != 0) return false;
    return (osvi.dwMajorVersion > 6) || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 2);
}

// 
// 主函数
// 
int main(int argc, char* argv[]) {
    //  1. 解析命令行 
    if (argc < 2) {
        std::cerr << "Usage: SandBox.exe <file_path> [arguments...]" << std::endl;
        return 1;
    }

    std::vector<std::wstring> argsW;
    for (int i = 1; i < argc; ++i) {
        argsW.push_back(toWideString(argv[i]));
    }

    std::wstring cmdLine = L"\"" + argsW[0] + L"\"";
    for (size_t i = 1; i < argsW.size(); ++i) {
        cmdLine += L" \"" + argsW[i] + L"\"";
    }
    std::vector<wchar_t> cmdLineBuf(cmdLine.begin(), cmdLine.end());
    cmdLineBuf.push_back(L'\0');

    //  2. 检查管理员权限 
    BOOL isAdmin = FALSE;
    PSID adminSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adminSid)) {
        CheckTokenMembership(NULL, adminSid, &isAdmin);
        FreeSid(adminSid);
        adminSid = NULL;
    }
    if (!isAdmin) {
        std::cerr << "This program requires administrative privileges to run." << std::endl;
        std::cin.get();
        return 1;
    }

    //  3. 创建作业对象 
    HANDLE hJob = CreateJobObject(NULL, NULL);
    if (hJob == NULL) {
        std::cerr << "[Error] Failed to create job object. Error code: " << GetLastError() << std::endl;
        std::cin.get();
        return 1;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = {0};
    jobInfo.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_PROCESS_MEMORY |
        JOB_OBJECT_LIMIT_JOB_TIME |
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    jobInfo.ProcessMemoryLimit = 3000ULL * 1024 * 1024;
    jobInfo.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = 100 * 10000000;
    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo))) {
        std::cerr << "[Error] Failed to set job restrictions. Error code: " << GetLastError() << std::endl;
        CloseHandle(hJob);
        std::cin.get();
        return 1;
    }

    //  4. 启用必要特权 
    if (!EnablePrivilege(L"SeAssignPrimaryTokenPrivilege") ||
        !EnablePrivilege(L"SeIncreaseQuotaPrivilege") ||
        !EnablePrivilege(L"SeRelabelPrivilege")) {
        std::cerr << "Privilege activation failed." << std::endl;
        CloseHandle(hJob);
        std::cin.get();
        return 1;
    }

    //  5. 获取当前进程令牌 
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        std::cerr << "Failed to open ProcessToken, error code: " << GetLastError() << std::endl;
        CloseHandle(hJob);
        std::cin.get();
        return 1;
    }

    //  6. 决定是否使用 AppContainer 
    bool useAppContainer = false;
    HANDLE hPrimaryToken = NULL;
    PSID   pContainerSid = NULL;
    WCHAR  containerName[64] = {0};

    if (IsWindows8OrGreater() && LoadAppContainerAPI()) {
        useAppContainer = true;
        std::wcout << L"[Info] Using AppContainer isolation (Windows 8+ with loaded APIs)." << std::endl;

        // 生成唯一容器名称 (修正：使用 wsprintfW)
        wsprintfW(containerName, L"SandBox_%u_%u", GetCurrentProcessId(), GetTickCount());

        // 构造 InternetClient 能力 SID (S-1-15-3-1)
        PSID pInternetSid = NULL;
        if (!ConvertStringSidToSidW(L"S-1-15-3-1", (PSID*)&pInternetSid)) {
            std::cerr << "ConvertStringSidToSid (InternetClient) failed. Proceeding without network capability." << std::endl;
        }

        SID_AND_ATTRIBUTES capsAttr = { pInternetSid, 0 };
        SECURITY_CAPABILITIES caps = { NULL, &capsAttr, (pInternetSid ? 1 : 0), 0 };

        BOOL created = fpCreateAppContainerProfile(containerName,
                                                   L"My Sandbox Display",
                                                   L"Sandbox container for isolated execution",
                                                   &caps,
                                                   (pInternetSid ? 1 : 0),
                                                   &pContainerSid);
        if (!created) {
            DWORD err = GetLastError();
            if (err == ERROR_ALREADY_EXISTS) {
                HANDLE hProfile = fpOpenAppContainerProfile(containerName);
                if (hProfile) {
                    if (!fpDeriveAppContainerSidFromAppContainerName(containerName, &pContainerSid)) {
                        std::cerr << "DeriveAppContainerSidFromAppContainerName failed. Error: " << GetLastError() << std::endl;
                    }
                    CloseHandle(hProfile);
                } else {
                    std::cerr << "OpenAppContainerProfile failed. Error: " << GetLastError() << std::endl;
                }
            } else {
                std::cerr << "CreateAppContainerProfile failed. Error: " << err << std::endl;
            }
        }

        if (pInternetSid) FreeSid(pInternetSid);

        if (pContainerSid) {
            if (!fpCreateAppContainerToken(hToken, pContainerSid, &hPrimaryToken)) {
                std::cerr << "CreateAppContainerToken failed. Error: " << GetLastError() << std::endl;
                FreeSid(pContainerSid);
                pContainerSid = NULL;
                useAppContainer = false;
            } else {
                std::wcout << L"[Info] AppContainer token created successfully." << std::endl;
            }
        } else {
            useAppContainer = false;
        }
    }

    //  降级：受限令牌 
    if (!useAppContainer) {
        std::wcout << L"[Info] Using restricted token (legacy) isolation." << std::endl;

        PSID pAdminSid = NULL;
        if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                      DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &pAdminSid)) {
            std::cerr << "AllocateAndInitializeSid (Admin) failed." << std::endl;
            CloseHandle(hToken);
            CloseHandle(hJob);
            std::cin.get();
            return 1;
        }
        SID_AND_ATTRIBUTES sidToDelete = { pAdminSid, 0 };

        HANDLE hRestrictedToken;
        if (!CreateRestrictedToken(hToken,
                                   DISABLE_MAX_PRIVILEGE,
                                   1, &sidToDelete,
                                   0, NULL,
                                   0, NULL,
                                   &hRestrictedToken)) {
            std::cerr << "CreateRestrictedToken failed. Error code: " << GetLastError() << std::endl;
            FreeSid(pAdminSid);
            CloseHandle(hToken);
            CloseHandle(hJob);
            std::cin.get();
            return 1;
        }
        FreeSid(pAdminSid);

        if (!DuplicateTokenEx(hRestrictedToken,
                              TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT,
                              NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
            std::cerr << "DuplicateTokenEx failed. Error code: " << GetLastError() << std::endl;
            CloseHandle(hRestrictedToken);
            CloseHandle(hToken);
            CloseHandle(hJob);
            std::cin.get();
            return 1;
        }
        CloseHandle(hRestrictedToken);

        // 设置低完整性级别
        PSID pLowIntegritySid = NULL;
        SID_IDENTIFIER_AUTHORITY mandatoryLabelAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
        if (!AllocateAndInitializeSid(&mandatoryLabelAuth, 1, SECURITY_MANDATORY_LOW_RID,
                                      0,0,0,0,0,0,0, &pLowIntegritySid)) {
            std::cerr << "AllocateAndInitializeSid (Low Integrity) failed." << std::endl;
            CloseHandle(hPrimaryToken);
            CloseHandle(hToken);
            CloseHandle(hJob);
            std::cin.get();
            return 1;
        }
        TOKEN_MANDATORY_LABEL tml = {0};
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pLowIntegritySid;
        if (!SetTokenInformation(hPrimaryToken, TokenIntegrityLevel, &tml, sizeof(tml))) {
            std::cerr << "SetTokenInformation (Integrity Level) failed. Error code: " << GetLastError() << std::endl;
            FreeSid(pLowIntegritySid);
            CloseHandle(hPrimaryToken);
            CloseHandle(hToken);
            CloseHandle(hJob);
            std::cin.get();
            return 1;
        }
        FreeSid(pLowIntegritySid);
    }

    CloseHandle(hToken);

    //  7. 创建子进程 
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessAsUserW(hPrimaryToken,
                              NULL,
                              cmdLineBuf.data(),
                              NULL, NULL, FALSE,
                              CREATE_SUSPENDED,
                              NULL, NULL,
                              &si, &pi)) {
        DWORD err = GetLastError();
        std::cerr << "[Error] CreateProcessAsUser failed. Error code: " << err << std::endl;
        CloseHandle(hPrimaryToken);
        CloseHandle(hJob);
        std::cin.get();
        return 1;
    }

    CloseHandle(hPrimaryToken);

    //  8. 附加作业对象 
    if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
        DWORD err = GetLastError();
        std::cerr << "[Error] AssignProcessToJobObject failed. Error code: " << err << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hJob);
        std::cin.get();
        return 1;
    }

    //  9. 恢复线程 
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    std::wcout << L"Child process (PID=" << pi.dwProcessId << L") started with "
               << (useAppContainer ? L"AppContainer" : L"restricted token")
               << L" isolation and job restrictions. Press any key to exit..." << std::endl;

    //  10. 等待进程结束 
    DWORD waitResult = WaitForSingleObject(pi.hProcess, INFINITE);
    if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            std::wcout << L"Child process exited. Exit code: " << exitCode
                       << L" (0x" << std::hex << exitCode << L")" << std::endl;
            if (exitCode != 0) {
                std::cerr << "Child process exited abnormally (possibly terminated by job restrictions)." << std::endl;
            }
        }
    } else if (waitResult == WAIT_TIMEOUT) {
        std::wcout << L"Child process still running (wait timeout)." << std::endl;
    } else {
        std::cerr << "WaitForSingleObject failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(hJob);

    //  11. 清理 AppContainer 
    if (useAppContainer && containerName[0] != L'\0') {
        if (fpDeleteAppContainerProfile(containerName)) {
            std::wcout << L"[Info] AppContainer profile deleted." << std::endl;
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                std::wcout << L"[Info] AppContainer profile still in use or cannot delete (ignored)." << std::endl;
            } else {
                std::wcerr << L"[Warning] DeleteAppContainerProfile failed. Error: " << err << std::endl;
            }
        }
        if (pContainerSid) FreeSid(pContainerSid);
    }

    std::wcout << L"Parent process exiting. Child process will be terminated." << std::endl;
    return 0;
}