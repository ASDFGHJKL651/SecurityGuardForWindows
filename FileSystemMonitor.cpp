/*
FileSystemMonitor.cpp
端点层

监控文件系统的写入/修改操作，并将相关文件路径传递给 Fileanalyzer 进行分析

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\FileSystemMonitor.cpp" -o "%ExecutablePath%\FileSystemMonitor.exe" -lbcrypt -lshell32 -ladvapi32 -lshlwapi -lole32 -luser32 -mwindows

运行权限：管理员权限
*/
#define WINVER        0x0A00
#define _WIN32_WINNT  0x0A00

#include <windows.h>
#include <winioctl.h>
#include <fileapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <io.h>
#include <fcntl.h>
#include <wchar.h>
#include <cstdlib>
#include <set>
#include <atomic>
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <chrono>
#include <fstream>
#include <cctype>
#include <winternl.h>
#include "shutdown_handler.h"
#include "nlohmann/json.hpp"
#include "AES-256-CBCEncryptionCommon.h"
#include "logrecord.h"

#pragma comment(lib, "user32.lib")

using json = nlohmann::json;

//全局线程安全队列
std::mutex g_mutex;
std::condition_variable g_cv;
std::vector<std::wstring> g_pendingPaths;
std::atomic<bool> g_stop(false);

//白名单相关
std::vector<std::wstring> whiteListFiles;   // 存储小写完整路径
std::vector<std::wstring> whiteListPaths;   // 存储小写目录路径（以反斜杠结尾）
std::mutex whiteListMutex;
std::atomic<bool> whiteListStop(false);
std::thread whiteListThread;

struct CommandFromUser_UI {
    int command;   // 1 = 退出
};
HANDLE g_hExitEvent = nullptr;
HANDLE g_whiteListExitEvent = nullptr; 

bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed, error: " << GetLastError() << std::endl;
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        std::cerr << "LookupPrivilegeValueW failed, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_SUCCESS) {
        std::cout << "SeDebugPrivilege enabled successfully." << std::endl;
        CloseHandle(hToken);
        return true;
    } else {
        std::cerr << "SeDebugPrivilege not enabled, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }
}

bool SetProcessCritical(bool bSet) {
    // 首次调用时加载函数指针
    if (g_pRtlSetProcessIsCritical == nullptr) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            g_pRtlSetProcessIsCritical = (RtlSetProcessIsCritical_t)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
        }
        if (g_pRtlSetProcessIsCritical == nullptr) {
            std::cerr << "[Critical] RtlSetProcessIsCritical not available." << std::endl;
            return false;
        }
    }

    NTSTATUS status = g_pRtlSetProcessIsCritical(bSet ? TRUE : FALSE, NULL, FALSE);
    if (status == 0) {
        std::cout << "[Critical] Process " << (bSet ? "set" : "unset") << " as system critical." << std::endl;
        return true;
    } else {
        std::cerr << "[Critical] " << (bSet ? "Set" : "Unset") << " failed, status: 0x" << std::hex << status << std::endl;
        return false;
    }
}

void PipeServerThread() {
    while (!g_stop.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_FileSystemMonitor",
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(CommandFromUser_UI),
            sizeof(CommandFromUser_UI),
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            wprintf(L"[管道] CreateNamedPipe 失败，错误码: %lu\n", GetLastError());
            break;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }

        wprintf(L"[管道] 控制客户端已连接\n");

        CommandFromUser_UI msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            if (msg.command == 1) {
                wprintf(L"[管道] 收到退出命令，正在关闭...\n");
                g_stop.store(true);
                if (g_hExitEvent) SetEvent(g_hExitEvent);
                if (g_whiteListExitEvent) SetEvent(g_whiteListExitEvent);
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                break;
            }
        }

        if (hPipe != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }
    wprintf(L"[管道] 控制线程已退出\n");
}

//辅助函数
// 将路径统一为小写且将斜杠转为反斜杠
std::wstring NormalizePath(const std::wstring& path) {
    std::wstring result = path;
    for (auto& ch : result) {
        if (ch == L'/') ch = L'\\';
        ch = towlower(ch);
    }
    return result;
}

//辅助转换函数：UTF-8 转 UTF-16 (Windows)
std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    if (len == 0) return L"";
    std::wstring wstr(len - 1, 0); // len 包含末尾空字符，减 1 得到实际字符数
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], len);
    return wstr;
}

//加载白名单
bool LoadWhiteList() {
    // 获取本程序所在目录
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        exeDir = exeDir.substr(0, pos + 1);
    }
    std::wstring jsonPathW = exeDir + L"WhiteList\\HighTrustWhiteList.json";

    // 使用 Win32 API 打开加密文件
    HANDLE hFile = CreateFileW(jsonPathW.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        char detail[256];
        sprintf_s(detail, sizeof(detail), "Failed to open WhiteList file, error: %lu", err);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\FileSystemMonitor.log", "[ERROR]", "[FileSystemMonitor]", detail);
        return false;
    }

    // 获取文件大小
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        DWORD err = GetLastError();
        char detail[256];
        sprintf_s(detail, sizeof(detail), "GetFileSizeEx failed, error: %lu", err);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\FileSystemMonitor.log", "[ERROR]", "[FileSystemMonitor]", detail);
        CloseHandle(hFile);
        return false;
    }
    if (fileSize.QuadPart == 0) {
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\FileSystemMonitor.log", "[ERROR]", "[FileSystemMonitor]", "WhiteList file is empty");
        CloseHandle(hFile);
        return false;
    }

    // 读取整个文件到内存
    std::vector<BYTE> encryptedData(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, encryptedData.data(), static_cast<DWORD>(encryptedData.size()), &bytesRead, NULL) ||
        bytesRead != encryptedData.size()) {
        DWORD err = GetLastError();
        char detail[256];
        sprintf_s(detail, sizeof(detail), "ReadFile failed, error: %lu", err);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\FileSystemMonitor.log", "[ERROR]", "[FileSystemMonitor]", detail);
        CloseHandle(hFile);
        SecureZeroVector(encryptedData);
        return false;
    }
    CloseHandle(hFile);

    // 解密
    std::string password = "9#Kp$LmQ@2wXz&Yv!5nR*TjH^3bC&Vg7";
    std::vector<BYTE> key(password.begin(), password.end());
    std::vector<BYTE> plaintext = AesDecrypt(encryptedData, key);
    SecureZeroString(password);
    SecureZeroVector(key);
    SecureZeroVector(encryptedData);

    if (plaintext.empty()) {
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\FileSystemMonitor.log", "[ERROR]", "[FileSystemMonitor]", "Decryption failed for WhiteList file");
        return false;
    }

    std::string jsonStr(plaintext.begin(), plaintext.end());
    SecureZeroVector(plaintext);

    try {
        json j = json::parse(jsonStr);
        SecureZeroString(jsonStr);

        std::vector<std::wstring> newFiles, newPaths;
        if (j.contains("Files") && j["Files"].is_array()) {
            for (const auto& item : j["Files"]) {
                if (item.is_string()) {
                    std::string utf8 = item.get<std::string>();
                    std::wstring path = Utf8ToWide(utf8);
                    newFiles.push_back(NormalizePath(path));
                }
            }
        }
        if (j.contains("Paths") && j["Paths"].is_array()) {
            for (const auto& item : j["Paths"]) {
                if (item.is_string()) {
                    std::string utf8 = item.get<std::string>();
                    std::wstring path = Utf8ToWide(utf8);
                    path = NormalizePath(path);
                    if (!path.empty() && path.back() != L'\\') {
                        path += L'\\';
                    }
                    newPaths.push_back(path);
                }
            }
        }

        // 加锁更新白名单
        std::lock_guard<std::mutex> lock(whiteListMutex);
        whiteListFiles.swap(newFiles);
        whiteListPaths.swap(newPaths);
        return true;
    } catch (const std::exception& e) {
        char detail[512];
        sprintf_s(detail, sizeof(detail), "JSON parse failed: %s", e.what());
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\FileSystemMonitor.log", "[ERROR]", "[FileSystemMonitor]", detail);
        SecureZeroString(jsonStr);
        return false;
    } catch (...) {
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\FileSystemMonitor.log", "[ERROR]", "[FileSystemMonitor]", "Unknown JSON parse error");
        SecureZeroString(jsonStr);
        return false;
    }
}

//白名单自动重载线程
void WhiteListReloadThread() {
    LoadWhiteList();   // 首次加载

    while (!whiteListStop) {
        // 等待 5 分钟，或退出事件被触发
        DWORD waitResult = WaitForSingleObject(g_whiteListExitEvent, 5 * 60 * 1000);
        if (waitResult == WAIT_OBJECT_0) {
            // 被退出事件唤醒，立即终止循环
            break;
        }
        // 超时（5 分钟），重新加载白名单
        if (!whiteListStop) {
            LoadWhiteList();
        }
    }
}

//后台处理函数
void BackgroundProcessor(const std::wstring& fileAnalyzerPath, int intervalMs) {
    while (!g_stop) {
        std::vector<std::wstring> paths;
        {
            std::unique_lock<std::mutex> lock(g_mutex);
            if (g_pendingPaths.empty()) {
                g_cv.wait_for(lock, std::chrono::seconds(1), [&]() {
                    return !g_pendingPaths.empty() || g_stop.load();
                });
            }
            if (g_stop && g_pendingPaths.empty()) break;
            paths.swap(g_pendingPaths);   // 取出所有待处理路径，清空队列
        }

        if (paths.empty()) continue;

        // 排序并去重
        std::sort(paths.begin(), paths.end());
        paths.erase(std::unique(paths.begin(), paths.end()), paths.end());

        // 依次启动 Fileanalyzer，并限速
        for (const auto& filePath : paths) {
            if (g_stop) break;

            std::wstring cmdLine = L"\"" + fileAnalyzerPath + L"\" \"" + filePath + L"\" --onlywithUi";
            wchar_t* lpCommandLine = new wchar_t[cmdLine.length() + 1];
            wcscpy_s(lpCommandLine, cmdLine.length() + 1, cmdLine.c_str());

            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi = {0};

            BOOL bRet = CreateProcessW(
                fileAnalyzerPath.c_str(),
                lpCommandLine,
                NULL,
                NULL,
                FALSE,
                CREATE_NO_WINDOW,
                NULL,
                NULL,
                &si,
                &pi
            );

            delete[] lpCommandLine;

            if (bRet) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                wprintf(L"[后台] 已启动 Fileanalyzer 分析: %ls\n", filePath.c_str());
            } else {
                wprintf(L"[后台] 启动 Fileanalyzer 失败，错误码: %lu\n", GetLastError());
            }

            // 限速间隔
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
    }
}

//监控线程函数
void MonitorVolume(std::wstring volumePath) {
    // 获取本程序所在目录
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        exeDir = exeDir.substr(0, pos + 1);
    }
    std::wstring appTempDir = exeDir + L"Temp\\";

    // 获取系统 %Temp% 目录
    wchar_t sysTempBuf[MAX_PATH] = {0};
    DWORD len = GetTempPathW(MAX_PATH, sysTempBuf);
    std::wstring sysTempDir;
    if (len > 0 && len < MAX_PATH) {
        sysTempDir = sysTempBuf;
        if (!sysTempDir.empty() && sysTempDir.back() != L'\\') {
            sysTempDir += L'\\';
        }
    } else {
        wprintf(L"[警告] 无法获取系统 Temp 目录，将无法识别系统临时文件。\n");
        sysTempDir = L"";
    }

    // 允许的系统 Temp 扩展名（小写）
    static const std::set<std::wstring> allowedExts = {
        L".exe", L".dll", L".sys", L".ps1", L".cmd", L".bat"
    };

    // 打开卷设备
    HANDLE hVolume = CreateFileW(
        volumePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hVolume == INVALID_HANDLE_VALUE) {
        wprintf(L"[%ls] 无法打开卷, 错误码: %lu\n", volumePath.c_str(), GetLastError());
        return;
    }

    // 查询或创建 USN Journal
    USN_JOURNAL_DATA journalData = {0};
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL,
                         NULL, 0,
                         &journalData, sizeof(journalData),
                         &bytesReturned, NULL)) {
        wprintf(L"[%ls] USN Journal 不存在，正在创建...\n", volumePath.c_str());

        CREATE_USN_JOURNAL_DATA createData = {0};
        createData.MaximumSize = 1ULL << 30;
        createData.AllocationDelta = 1ULL << 20;

        if (!DeviceIoControl(hVolume, FSCTL_CREATE_USN_JOURNAL,
                             &createData, sizeof(createData),
                             NULL, 0,
                             &bytesReturned, NULL)) {
            wprintf(L"[%ls] 创建 USN Journal 失败，错误码: %lu\n", volumePath.c_str(), GetLastError());
            CloseHandle(hVolume);
            return;
        }

        if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL,
                             NULL, 0,
                             &journalData, sizeof(journalData),
                             &bytesReturned, NULL)) {
            wprintf(L"[%ls] 查询 USN Journal 失败，错误码: %lu\n", volumePath.c_str(), GetLastError());
            CloseHandle(hVolume);
            return;
        }
    }

    wprintf(L"[%ls] USN Journal ID: %llu\n", volumePath.c_str(), journalData.UsnJournalID);
    wprintf(L"[%ls] 当前 NextUsn: %llu\n", volumePath.c_str(), journalData.NextUsn);

    READ_USN_JOURNAL_DATA readData = {0};
    readData.StartUsn = journalData.NextUsn;
    readData.ReasonMask = 0xFFFFFFFF;
    readData.ReturnOnlyOnClose = FALSE;
    readData.Timeout = 0;
    readData.BytesToWaitFor = 0;
    readData.UsnJournalID = journalData.UsnJournalID;

    const DWORD BUFFER_SIZE = 64 * 1024;
    std::vector<BYTE> buffer(BUFFER_SIZE);

    wprintf(L"[%ls] 开始监控文件写入/修改操作...\n", volumePath.c_str());
    wprintf(L"[调试] App Temp 目录: %ls\n", appTempDir.c_str());
    if (!sysTempDir.empty()) {
        wprintf(L"[调试] 系统 Temp 目录: %ls\n", sysTempDir.c_str());
    }

    while (!g_stop.load()) {
        if (!DeviceIoControl(hVolume, FSCTL_READ_USN_JOURNAL,
                             &readData, sizeof(readData),
                             buffer.data(), BUFFER_SIZE,
                             &bytesReturned, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF) {
                Sleep(100);
                continue;
            }
            wprintf(L"[%ls] 读取 USN Journal 失败，错误码: %lu\n", volumePath.c_str(), err);
            break;
        }

        if (bytesReturned <= sizeof(USN)) {
            Sleep(100);
            continue;
        }

        USN nextUsn = *reinterpret_cast<USN*>(buffer.data());
        PUSN_RECORD record = reinterpret_cast<PUSN_RECORD>(buffer.data() + sizeof(USN));
        DWORD offset = sizeof(USN);

        while (offset < bytesReturned) {
            std::wstring fileName(
                reinterpret_cast<WCHAR*>(reinterpret_cast<BYTE*>(record) + record->FileNameOffset),
                record->FileNameLength / sizeof(WCHAR)
            );

            DWORD reason = record->Reason;

            if (reason & (USN_REASON_DATA_EXTEND |
                          USN_REASON_DATA_TRUNCATION |
                          USN_REASON_DATA_OVERWRITE)) {

                wchar_t fullPath[32768] = {0};
                bool gotPath = false;

                // 使用 OpenFileById 获取完整路径
                FILE_ID_DESCRIPTOR fileIdDesc = {0};
                fileIdDesc.dwSize = sizeof(FILE_ID_DESCRIPTOR);
                fileIdDesc.Type = FileIdType;
                fileIdDesc.FileId.QuadPart = record->FileReferenceNumber;

                HANDLE hFile = OpenFileById(
                    hVolume,
                    &fileIdDesc,
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL,
                    FILE_FLAG_BACKUP_SEMANTICS
                );

                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD len = GetFinalPathNameByHandleW(hFile, fullPath, _countof(fullPath), VOLUME_NAME_DOS);
                    if (len > 0 && len < _countof(fullPath)) {
                        gotPath = true;
                    }
                    CloseHandle(hFile);
                } else {
                    // 备用方案（不建议用于生产）
                    FILE_ID_DESCRIPTOR fileIdDesc2 = {0};
                    fileIdDesc2.dwSize = sizeof(FILE_ID_DESCRIPTOR);
                    fileIdDesc2.Type = FileIdType;
                    fileIdDesc2.FileId.QuadPart = record->FileReferenceNumber;

                    wchar_t rootPath[4] = { volumePath[4], L':', L'\\', L'\0' };

                    HANDLE hFile2 = CreateFileW(
                        rootPath,
                        FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        (LPSECURITY_ATTRIBUTES)&fileIdDesc2,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_BY_FILE_ID,
                        NULL
                    );

                    if (hFile2 != INVALID_HANDLE_VALUE) {
                        DWORD len = GetFinalPathNameByHandleW(hFile2, fullPath, _countof(fullPath), VOLUME_NAME_DOS);
                        if (len > 0 && len < _countof(fullPath)) {
                            gotPath = true;
                        }
                        CloseHandle(hFile2);
                    }
                }

                if (gotPath) {
                    std::wstring filePath = fullPath + 4; // 去掉 "\\?\"

                    wprintf(L"[%ls] 事件: %ls 原因: 0x%08X FRN: %llu\n      完整路径: %ls\n",
                            volumePath.c_str(), fileName.c_str(), record->Reason, record->FileReferenceNumber, filePath.c_str());

                    //过滤逻辑
                    bool shouldAnalyze = false;
                    std::wstring skipReason;

                    // 1. 检查白名单（最高优先级）
                    bool isWhiteListed = false;
                    {
                        std::lock_guard<std::mutex> lock(whiteListMutex);
                        std::wstring filePathLower = NormalizePath(filePath);
                        for (const auto& wf : whiteListFiles) {
                            if (wf == filePathLower) {
                                isWhiteListed = true;
                                break;
                            }
                        }
                        if (!isWhiteListed) {
                            for (const auto& wp : whiteListPaths) {
                                if (filePathLower.compare(0, wp.size(), wp) == 0) {
                                    isWhiteListed = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (isWhiteListed) {
                        skipReason = L"白名单匹配";
                    } else {
                        // 2. 检查是否位于 App Temp 目录（跳过所有）
                        bool isInAppTemp = (filePath.length() >= appTempDir.length() &&
                                            _wcsnicmp(filePath.c_str(), appTempDir.c_str(), appTempDir.length()) == 0);
                        if (isInAppTemp) {
                            skipReason = L"位于 App Temp 目录（跳过所有）";
                        } else {
                            // 3. 检查是否位于系统 Temp 目录（仅允许特定扩展名）
                            bool isInSysTemp = (!sysTempDir.empty() &&
                                                filePath.length() >= sysTempDir.length() &&
                                                _wcsnicmp(filePath.c_str(), sysTempDir.c_str(), sysTempDir.length()) == 0);
                            if (isInSysTemp) {
                                std::wstring ext;
                                size_t dotPos = filePath.find_last_of(L'.');
                                if (dotPos != std::wstring::npos) {
                                    ext = filePath.substr(dotPos);
                                    std::wstring extLower = ext;
                                    for (auto& ch : extLower) ch = towlower(ch);
                                    if (allowedExts.find(extLower) != allowedExts.end()) {
                                        shouldAnalyze = true;
                                    } else {
                                        skipReason = L"位于系统 Temp，但扩展名不匹配 (" + ext + L")";
                                    }
                                } else {
                                    skipReason = L"位于系统 Temp，但没有扩展名";
                                }
                            } else {
                                // 其他目录 -> 全部分析
                                shouldAnalyze = true;
                            }
                        }
                    }

                    if (!shouldAnalyze) {
                        wprintf(L"[%ls] 跳过文件: %ls (%ls)\n", volumePath.c_str(), filePath.c_str(), skipReason.c_str());
                    } else {
                        // 将文件路径加入全局队列，由后台线程处理
                        {
                            std::lock_guard<std::mutex> lock(g_mutex);
                            g_pendingPaths.push_back(filePath);
                        }
                        g_cv.notify_one();
                        wprintf(L"[%ls] 加入分析队列: %ls\n", volumePath.c_str(), filePath.c_str());
                    }
                } else {
                    wprintf(L"[%ls] 事件: %ls 原因: 0x%08X FRN: %llu (无法获取完整路径)\n",
                            volumePath.c_str(), fileName.c_str(), record->Reason, record->FileReferenceNumber);
                }
            }

            offset += record->RecordLength;
            if (offset < bytesReturned) {
                record = reinterpret_cast<PUSN_RECORD>(
                    reinterpret_cast<BYTE*>(record) + record->RecordLength
                );
            }
        }

        readData.StartUsn = nextUsn;
    }

    CloseHandle(hVolume);
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_SHUTDOWN_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT) {
        // 在系统强制终止前，立即解除关键状态
        SetProcessCritical(false);
        return TRUE;
    }
    return FALSE;
}

//主函数
int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    _setmode(_fileno(stdout), _O_U16TEXT);
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    EnableDebugPrivilege();
    SetProcessCritical(true);
    InstallShutdownHandler();
    SetProcessShutdownParameters(0x100, 0);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // 1. 创建退出事件
    g_hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hExitEvent) {
        wprintf(L"创建退出事件失败\n");
        SetProcessCritical(false);
        return 1;
    }

    // 2. 获取 Fileanalyzer 路径
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        exeDir = exeDir.substr(0, pos + 1);
    }
    std::wstring fileAnalyzerPath = exeDir + L"Fileanalyzer.exe";

    // 3. 启动后台处理线程
    const int PROCESS_INTERVAL_MS = 200;
    std::thread backgroundThread(BackgroundProcessor, std::cref(fileAnalyzerPath), PROCESS_INTERVAL_MS);

    // 4. 启动白名单自动重载线程
    g_whiteListExitEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    whiteListThread = std::thread(WhiteListReloadThread);

    // 5. 启动管道控制线程
    std::thread pipeThread(PipeServerThread);

    // 6. 枚举固定驱动器并启动监控线程
    DWORD drives = GetLogicalDrives();
    std::vector<std::thread> monitorThreads;

    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        if (drives & (1 << (drive - 'A'))) {
            std::wstring root = std::wstring(1, drive) + L":\\";
            UINT type = GetDriveTypeW(root.c_str());
            if (type == DRIVE_FIXED) {
                std::wstring volumePath = L"\\\\.\\" + std::wstring(1, drive) + L":";
                wprintf(L"启动监控线程: %ls\n", volumePath.c_str());
                monitorThreads.emplace_back(MonitorVolume, volumePath);
            }
        }
    }

    if (monitorThreads.empty()) {
        wprintf(L"没有找到固定驱动器。\n");
        SetProcessCritical(false);
        // 直接触发退出流程
        g_stop = true;
        g_cv.notify_all();
        backgroundThread.join();
        whiteListStop = true;
        if (whiteListThread.joinable()) whiteListThread.join();
        pipeThread.join();
        CloseHandle(g_hExitEvent);
        return 0;
    }

    // 7. 主线程等待退出事件（阻塞直到收到命令）
    wprintf(L"主程序运行中，可通过命名管道发送 command=1 退出。\n");
    WaitForSingleObject(g_hExitEvent, INFINITE);

    // 8. 收到退出信号，开始清理
    WaitForSingleObject(g_hExitEvent, INFINITE);
    SetProcessCritical(false);

    // 4. 收到退出，开始清理
    g_stop.store(true);
    g_cv.notify_all();    // 唤醒后台处理线程

    // 5. 唤醒白名单线程（可能已经在等待）
    whiteListStop = true;
    if (g_whiteListExitEvent) SetEvent(g_whiteListExitEvent);

    // 6. 等待所有工作线程结束
    for (auto& t : monitorThreads) { if (t.joinable()) t.join(); }
    if (backgroundThread.joinable()) backgroundThread.join();
    if (whiteListThread.joinable()) whiteListThread.join();
    if (pipeThread.joinable()) pipeThread.join();

    // 7. 释放事件句柄
    if (g_whiteListExitEvent) { CloseHandle(g_whiteListExitEvent); g_whiteListExitEvent = nullptr; }
    if (g_hExitEvent) { CloseHandle(g_hExitEvent); g_hExitEvent = nullptr; }

    wprintf(L"程序已正常退出。\n");
    return 0;
}