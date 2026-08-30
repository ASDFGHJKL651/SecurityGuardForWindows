/*ForceDeleteFile.cpp
顽固文件删除程序(需系统服务：KillProcessService，详见PersistentProcessTerminator.cpp)

g++编译:
cd %g++Path%
g++ -fdiagnostics-color=always -g "%SourceCodePath%\ForceDelete.cpp" -o "%ExecutablePath%\ForceDelete.exe" -lrstrtmgr -ladvapi32 -lole32 -lshell32 -lshlwapi -luser32 -lkernel32 -DUNICODE -D_UNICODE -mconsole -municode

运行：命令行(管理员):ForceDelete <文件路径>

*/
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include <restartmanager.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <map>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rstrtmgr.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ------------------------------------------------------------
// 工具函数：启用指定特权
// ------------------------------------------------------------
bool EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ret && GetLastError() == ERROR_SUCCESS;
}

// 启用 SeRestorePrivilege（用于 MoveFileEx 延迟删除）
bool EnableRestorePrivilege() {
    return EnablePrivilege(SE_RESTORE_NAME);
}

// ------------------------------------------------------------
// 获取当前用户的 SID
// ------------------------------------------------------------
PSID GetCurrentUserSID() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return NULL;
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return NULL;
    }
    BYTE* buffer = new BYTE[size];
    TOKEN_USER* pUser = (TOKEN_USER*)buffer;
    if (!GetTokenInformation(hToken, TokenUser, pUser, size, &size)) {
        delete[] buffer;
        CloseHandle(hToken);
        return NULL;
    }
    CloseHandle(hToken);
    DWORD sidLen = GetLengthSid(pUser->User.Sid);
    PSID pSid = (PSID)new BYTE[sidLen];
    CopySid(sidLen, pSid, pUser->User.Sid);
    delete[] buffer;
    return pSid;
}

// ------------------------------------------------------------
// 获取文件所有权并设置完全控制（使用当前用户）
// ------------------------------------------------------------
bool TakeOwnershipAndSetFullControl(LPCWSTR filePath) {
    if (!EnablePrivilege(SE_TAKE_OWNERSHIP_NAME)) {
        wprintf(L"无法启用 SeTakeOwnershipPrivilege\n");
        return false;
    }
    PSID pSid = GetCurrentUserSID();
    if (!pSid) return false;

    DWORD dwRes = SetNamedSecurityInfoW(
        (LPWSTR)filePath,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        pSid,
        NULL, NULL, NULL
    );
    if (dwRes != ERROR_SUCCESS) {
        wprintf(L"设置所有者失败，错误码: %lu\n", dwRes);
    }

    EXPLICIT_ACCESS_W ea;
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPWSTR)pSid;

    PACL pNewDacl = NULL;
    dwRes = SetEntriesInAclW(1, &ea, NULL, &pNewDacl);
    if (dwRes != ERROR_SUCCESS) {
        wprintf(L"创建 ACL 失败，错误码: %lu\n", dwRes);
        FreeSid(pSid);
        return false;
    }

    dwRes = SetNamedSecurityInfoW(
        (LPWSTR)filePath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDacl, NULL
    );
    if (dwRes != ERROR_SUCCESS) {
        wprintf(L"设置 DACL 失败，错误码: %lu\n", dwRes);
    }
    LocalFree(pNewDacl);
    FreeSid(pSid);
    return (dwRes == ERROR_SUCCESS);
}

// ------------------------------------------------------------
// 通过 Restart Manager 获取占用文件的进程 PID 和名称
// ------------------------------------------------------------
std::map<DWORD, std::wstring> GetLockingProcesses(LPCWSTR filePath) {
    std::map<DWORD, std::wstring> procMap;
    DWORD dwSession = 0;
    WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
    if (RmStartSession(&dwSession, 0, szSessionKey) != ERROR_SUCCESS)
        return procMap;

    LPCWSTR files[] = { filePath };
    if (RmRegisterResources(dwSession, 1, files, 0, NULL, 0, NULL) != ERROR_SUCCESS) {
        RmEndSession(dwSession);
        return procMap;
    }

    DWORD dwReason = 0;
    UINT nProcInfo = 0;
    UINT nProcInfoNeeded = 0;
    RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
    if (nProcInfoNeeded == 0) {
        RmEndSession(dwSession);
        return procMap;
    }

    std::vector<RM_PROCESS_INFO> procInfos(nProcInfoNeeded);
    nProcInfo = nProcInfoNeeded;
    if (RmGetList(dwSession, &nProcInfo, &nProcInfo, procInfos.data(), &dwReason) == ERROR_SUCCESS) {
        for (UINT i = 0; i < nProcInfo; ++i) {
            DWORD pid = procInfos[i].Process.dwProcessId;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProc) {
                WCHAR name[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, name, &size)) {
                    WCHAR* p = wcsrchr(name, L'\\');
                    if (p) procMap[pid] = p + 1;
                    else procMap[pid] = name;
                }
                CloseHandle(hProc);
            }
        }
    }
    RmEndSession(dwSession);
    return procMap;
}

// ------------------------------------------------------------
// 结束进程（通过 sc start KillProcessService，若失败则直接 TerminateProcess）
// 增强：支持多次重试
// ------------------------------------------------------------
bool KillProcessByPID(DWORD pid, int retries = 3, int delayMs = 500) {
    for (int i = 0; i < retries; ++i) {
        // 先检查进程是否还存在
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hCheck) {
            // 进程已不存在
            return true;
        }
        CloseHandle(hCheck);

        // 尝试通过服务终止
        WCHAR cmd[256];
        swprintf_s(cmd, L"sc start KillProcessService %u", pid);
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000); // 等待服务执行
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            // 检查进程是否已死
            HANDLE hCheck2 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hCheck2) return true;
            CloseHandle(hCheck2);
        }

        // 若服务未成功，直接 TerminateProcess
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProc) {
            TerminateProcess(hProc, 1);
            CloseHandle(hProc);
            Sleep(delayMs);
            HANDLE hCheck3 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hCheck3) return true;
            CloseHandle(hCheck3);
        }
        Sleep(delayMs);
    }
    // 最后一次检查
    HANDLE hFinal = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    bool alive = (hFinal != NULL);
    if (hFinal) CloseHandle(hFinal);
    return !alive;
}

// ------------------------------------------------------------
// 判断是否为系统进程（需要保留并重启）
// ------------------------------------------------------------
bool IsSystemProcess(const std::wstring& name) {
    return (_wcsicmp(name.c_str(), L"explorer.exe") == 0);
}

// ------------------------------------------------------------
// 重新启动 explorer.exe
// ------------------------------------------------------------
bool RestartExplorer() {
    WCHAR sysDir[MAX_PATH];
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) return false;
    wcscat_s(sysDir, L"\\..\\explorer.exe");
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    return CreateProcessW(NULL, sysDir, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) != 0;
}

// ------------------------------------------------------------
// 主删除函数（增强版：重试 + 延迟删除）
// ------------------------------------------------------------
bool ForceDeleteFile(LPCWSTR originalPath) {
    // 启用所需特权
    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
    EnableRestorePrivilege();   // 为 MoveFileEx 准备

    std::wstring path = originalPath;
    bool prefixAdded = false;
    bool ownershipTried = false;

    // 重试参数
    const int MAX_RETRIES = 5;
    int retryDelay = 1000; // 起始 1 秒，每次翻倍

    for (int attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        // 尝试删除
        if (DeleteFileW(path.c_str())) {
            wprintf(L"成功删除文件: %s\n", path.c_str());
            return true;
        }

        DWORD err = GetLastError();
        wprintf(L"第 %d 次删除失败，错误码: %lu, 路径: %s\n", attempt+1, err, path.c_str());

        // 处理特殊路径错误
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            wprintf(L"文件不存在，视为已删除\n");
            return true;
        }
        else if (err == ERROR_INVALID_NAME || err == ERROR_BAD_PATHNAME) {
            if (!prefixAdded) {
                if (path.compare(0, 4, L"\\\\?\\") != 0) {
                    path = L"\\\\?\\" + path;
                    prefixAdded = true;
                    wprintf(L"添加 \"\\\\?\\\" 前缀后重试\n");
                    continue;
                }
            }
            // 已加前缀仍失败，跳到最终手段
            break;
        }
        else if (err == ERROR_ACCESS_DENIED) {
            if (!ownershipTried) {
                wprintf(L"尝试获取所有权并修改权限...\n");
                if (TakeOwnershipAndSetFullControl(path.c_str())) {
                    ownershipTried = true;
                    wprintf(L"权限修改完成，重试删除\n");
                    continue;
                }
                else {
                    wprintf(L"权限修改失败\n");
                }
            }
            // 若权限修复无效，继续尝试其他方法（如重命名后删除）
        }
        else if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
            wprintf(L"文件被占用，获取占用进程...\n");
            auto procMap = GetLockingProcesses(path.c_str());
            if (procMap.empty()) {
                wprintf(L"未找到占用进程，可能已释放，重试删除\n");
                Sleep(retryDelay);
                retryDelay *= 2;
                continue;
            }

            // 显示占用进程
            for (auto& kv : procMap) {
                DWORD pid = kv.first;
                std::wstring name = kv.second;
                wprintf(L"  占用进程: PID=%u, 名称=%s\n", pid, name.c_str());
            }

            // 结束所有占用进程（增强版：循环重试）
            bool allKilled = true;
            for (auto& kv : procMap) {
                DWORD pid = kv.first;
                std::wstring name = kv.second;
                if (IsSystemProcess(name)) {
                    wprintf(L"结束系统进程 explorer.exe (PID=%u)...\n", pid);
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (hProc) {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                    }
                    Sleep(1000);
                } else {
                    wprintf(L"结束进程 PID=%u (多次重试)...\n", pid);
                    // 调用增强的 KillProcessByPID，重试 5 次，间隔 500ms
                    if (!KillProcessByPID(pid, 5, 500)) {
                        allKilled = false;
                        wprintf(L"警告：进程 %u 未能终止\n", pid);
                    }
                }
            }

            if (!allKilled) {
                wprintf(L"部分进程无法终止，可能影响删除\n");
            }

            Sleep(retryDelay);
            retryDelay *= 2;
            continue;
        }
        else {
            wprintf(L"错误码 %lu 不在处理范围内，进入最终手段\n", err);
            break;
        }

        // 其他情况：非预期错误，跳出循环尝试最终手段
        break;
    }

    // --- 所有常规手段失败，使用 MoveFileEx 延迟删除 ---
    wprintf(L"常规删除失败，尝试使用重启时删除...\n");

    // 确保路径为绝对路径且格式正确（最好带 \\?\）
    std::wstring finalPath = path;
    if (finalPath.compare(0, 4, L"\\\\?\\") != 0) {
        WCHAR fullPath[MAX_PATH];
        if (GetFullPathNameW(originalPath, MAX_PATH, fullPath, NULL)) {
            finalPath = L"\\\\?\\" + std::wstring(fullPath);
        } else {
            finalPath = L"\\\\?\\" + finalPath;
        }
    }

    // 设置文件属性（去除只读、隐藏、系统等，避免 MoveFileEx 失败）
    SetFileAttributesW(finalPath.c_str(), FILE_ATTRIBUTE_NORMAL);

    // 调用 MoveFileEx 标记为重启删除
    if (MoveFileExW(finalPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
        wprintf(L"文件已标记为重启时删除: %s\n", finalPath.c_str());
        RestartExplorer();
        return true;
    } else {
        DWORD lastErr = GetLastError();
        wprintf(L"MoveFileEx 失败，错误码: %lu\n", lastErr);
        // 作为最后补救，尝试重命名后删除（也可能失败）
        WCHAR renamePath[MAX_PATH];
        wcscpy_s(renamePath, finalPath.c_str());
        wcscat_s(renamePath, L"._del");
        if (MoveFileExW(finalPath.c_str(), renamePath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT)) {
            wprintf(L"文件已重命名并标记为重启删除\n");
            RestartExplorer();
            return true;
        }
        RestartExplorer();
        return false;
    }
}

// ------------------------------------------------------------
// 主入口
// ------------------------------------------------------------
int wmain(int argc, WCHAR* argv[]) {
    if (argc != 2) {
        wprintf(L"用法: ForceDeleteFile.exe <完整文件路径>\n");
        return 1;
    }

    // 检查管理员权限（建议）
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup);
    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);
    if (!isAdmin) {
        wprintf(L"警告：程序未以管理员身份运行，可能无法启用所需特权\n");
    }

    bool ret = ForceDeleteFile(argv[1]);
    return ret ? 0 : 1;
}