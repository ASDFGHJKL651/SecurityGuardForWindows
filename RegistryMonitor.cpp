/*
RegistryMonitor.cpp
端点层

监控注册表修改

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\RegistryMonitor.cpp" -o "%ExecutablePath%\RegistryMonitor.exe" -lole32 -lshlwapi -ladvapi32 -lpsapi -ltdh -mwindows 

运行权限：管理员权限
*/
#include <windows.h>
#include <evntrace.h>
#include <psapi.h>
#include <tdh.h>
#include <winreg.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <fstream>
#include <ctime>
#include <memory>   // for std::unique_ptr
#include <winternl.h>
#include "shutdown_handler.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "tdh.lib")

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_RegistryMonitor"
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_RegistryMonitor"

//  全局常量与类型定义 

const GUID SystemTraceControlGuid = { 0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39} };
const GUID Microsoft_Windows_Kernel_General = { 0xA68CA8B7, 0x004F, 0xD7B6, {0xA6, 0x98, 0x07, 0xE2, 0xDE, 0x0F, 0x1F, 0x5D} };
const GUID Microsoft_Windows_Kernel_Registry = { 0x70EB4F03, 0xC1DE, 0x4F73, {0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD} };

const std::map<DWORD, std::string> g_RegRootMap = {
    {0, "HKCR"}, {1, "HKCU"}, {2, "HKLM"}, {3, "HKUS"},
    {4, "HKCC"}, {5, "HKDD"}, {6, "HKPD"}, {7, "HKMU"}, {8, "HKU"}
};

const std::map<DWORD, std::string> g_ValueTypeMap = {
    {0, "REG_NONE"}, {1, "REG_SZ"}, {2, "REG_EXPAND_SZ"}, {3, "REG_BINARY"},
    {4, "REG_DWORD"}, {5, "REG_DWORD_BIG_ENDIAN"}, {6, "REG_LINK"},
    {7, "REG_MULTI_SZ"}, {8, "REG_RESOURCE_LIST"}, {9, "REG_FULL_RESOURCE_DESCRIPTOR"},
    {10, "REG_RESOURCE_REQUIREMENTS_LIST"}, {11, "REG_QWORD"}
};

const std::map<USHORT, std::string> g_EventIdToOperation = {
    {2, "RegCreateKey"}, {3, "RegOpenKey"}, {4, "RegDeleteKey"}, {5, "RegQueryKey"},
    {6, "RegSetValue"}, {7, "RegQueryValue"}, {8, "RegDeleteValue"}, {9, "RegEnumValue"},
    {10, "RegSetInfoKey"}, {11, "RegQueryMultipleValueKey"}, {12, "RegRestoreKey"},
    {13, "RegSaveKey"}, {14, "RegLoadKey"}, {15, "RegUnLoadKey"}, {16, "RegRenameKey"},
    {17, "RegReplaceKey"}, {18, "RegEnumKey"}, {19, "RegFlushKey"}, {20, "RegKCBDeleteKey"},
    {21, "RegKCBRenameKey"}, {22, "RegKCBVirtualize"}, {23, "RegKCBCacheDeleteKey"},
    {24, "RegKCBCacheFreeze"}, {25, "RegKCBCacheUnlock"}, {26, "RegKCBCacheLock"},
    {27, "RegKCBReadSettings"}, {28, "RegKCBWriteSettings"}
};

//  快照数据结构 
using ValueMap = std::map<std::wstring, std::pair<DWORD, std::vector<BYTE>>>;
using Snapshot = std::map<std::wstring, ValueMap>;

bool withUi;
struct MessagetoControlCenter_by_RegistryMonitor {
    char type[256];
    BYTE key[32768]; 
    BYTE oldvalue[32768];
    DWORD oldvalue_len;
    BYTE newvalue[32768];
    DWORD newvalue_len;
    BYTE valuetype[256];
};
struct CommandFromUser_UI{
    int command;
};
#define PIPE_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_RegistryMonitor)
#define PIPE_CommandFromUser_UI_SIZE sizeof(CommandFromUser_UI)

//  多监控项 
struct MonitorItem {
    HKEY rootKey;
    std::wstring subPath;
    std::wstring fullPath;
    std::wstring snapshotFile;          // 快照文件路径
    Snapshot snapshot;
    std::mutex mtx;
    std::atomic<bool> stop{false};

    MonitorItem() = default;
    MonitorItem(MonitorItem&& other) noexcept
        : rootKey(other.rootKey),
          subPath(std::move(other.subPath)),
          fullPath(std::move(other.fullPath)),
          snapshotFile(std::move(other.snapshotFile)),
          snapshot(std::move(other.snapshot)),
          stop(other.stop.load()) {
    }
    MonitorItem& operator=(MonitorItem&& other) noexcept {
        if (this != &other) {
            rootKey = other.rootKey;
            subPath = std::move(other.subPath);
            fullPath = std::move(other.fullPath);
            snapshotFile = std::move(other.snapshotFile);
            snapshot = std::move(other.snapshot);
            stop.store(other.stop.load());
        }
        return *this;
    }
};

// 全局监控列表
std::vector<std::unique_ptr<MonitorItem>> g_MonitorItems;

//  ETW 相关 
TRACEHANDLE g_hSession = 0;
TRACEHANDLE g_hTrace = 0;
HANDLE g_hExitEvent = nullptr;

typedef ULONG (WINAPI *TdhGetEventInformationFunc)(PEVENT_RECORD, ULONG, PTDH_CONTEXT, PTRACE_EVENT_INFO, PULONG);
typedef ULONG (WINAPI *TdhGetPropertySizeFunc)(PEVENT_RECORD, ULONG, PTDH_CONTEXT, ULONG, PROPERTY_DATA_DESCRIPTOR*, PULONG);
typedef ULONG (WINAPI *TdhGetPropertyFunc)(PEVENT_RECORD, ULONG, PTDH_CONTEXT, ULONG, PROPERTY_DATA_DESCRIPTOR*, ULONG, UCHAR*);
TdhGetEventInformationFunc pTdhGetEventInformation = nullptr;
TdhGetPropertySizeFunc pTdhGetPropertySize = nullptr;
TdhGetPropertyFunc pTdhGetProperty = nullptr;

// 进程名缓存
std::map<DWORD, std::string> g_ProcessCache;
std::mutex g_ProcessCacheMutex;

std::atomic<bool> g_bExit(false);

//  辅助函数 

std::string GetCurrentTimeString() {
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char buffer[100];
    strftime(buffer, 100, "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(buffer);
}

std::string WideCharToUTF8(PCWSTR wideStr) {
    if (!wideStr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (len == 0) return "";
    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::wstring UTF8ToWide(const std::string& utf8Str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);
    if (len == 0) return L"";
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &result[0], len);
    return result;
}

std::string DataToHex(const BYTE* data, DWORD size) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (DWORD i = 0; i < size; ++i) {
        oss << std::setw(2) << (int)data[i];
        if (i < size - 1) oss << " ";
    }
    return oss.str();
}

HANDLE ConnectToPipe(const wchar_t* pipeName) {
    while (true) {
        if (WaitNamedPipeW(pipeName, 1000)) {
            SetConsoleOutputCP(CP_ACP);
            SetConsoleCP(CP_ACP);
            HANDLE hPipe = CreateFileW(
                pipeName,
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL
            );
            if (hPipe != INVALID_HANDLE_VALUE) {
                std::cout << "Success connecting to pipe" << std::endl;
                return hPipe;
            }
        }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            std::cout << "Waiting for server to create pipe" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        } else if (err == ERROR_PIPE_BUSY) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        } else {
            std::cerr << "Connecting to pipe encountered an unknown error, code: " << err << std::endl;
            return INVALID_HANDLE_VALUE;
        }
    }
}

void ClientThread_to_ControlCenter(MessagetoControlCenter_by_RegistryMonitor* msg) {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Process A: Always failed to connect to pipe, exiting send thread" << std::endl;
        return;
    }

    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
        std::cerr << "Process A: Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}

void ServerThread_from_User_UI() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (!g_bExit.load()) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_FROM_CONTROLCENTER_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_CommandFromUser_UI_SIZE, PIPE_CommandFromUser_UI_SIZE,
            0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateNamedPipe failed, error: " << GetLastError() << std::endl;
            break;  // 严重错误，退出循环
        }

        // 等待客户端连接
        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::cerr << "ConnectNamedPipe failed, error: " << GetLastError() << std::endl;
            CloseHandle(hPipe);
            continue;  // 继续尝试创建新管道
        }

        std::cout << "Client connected." << std::endl;
        CommandFromUser_UI msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)){
            if (msg.command == 1){
                                // 执行退出
                std::cout << "Received exit command, shutting down..." << std::endl;
                g_bExit.store(true);
                SetEvent(g_hExitEvent);
                // 断开并关闭管道，使 ReadFile 返回失败，跳出内层循环
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE; // 防止重复关闭
                break;
            }
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

std::string GetProcessName(DWORD pid) {
    std::lock_guard<std::mutex> lock(g_ProcessCacheMutex);
    auto it = g_ProcessCache.find(pid);
    if (it != g_ProcessCache.end()) return it->second;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "pid:" + std::to_string(pid);
    CHAR szName[MAX_PATH] = {0};
    DWORD dwSize = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, szName, &dwSize)) {
        char* p = strrchr(szName, '\\');
        if (p) ++p; else p = szName;
        g_ProcessCache[pid] = p;
        CloseHandle(hProcess);
        return p;
    }
    CloseHandle(hProcess);
    return "pid:" + std::to_string(pid);
}

bool IsSystemProcess(const std::string& procName) {
    static const std::vector<std::string> sysProcs = {
        "svchost.exe", "services.exe", "lsass.exe", "winlogon.exe",
        "csrss.exe", "smss.exe", "wininit.exe", "System", "Registry"
    };
    for (const auto& s : sysProcs)
        if (_stricmp(procName.c_str(), s.c_str()) == 0) return true;
    return false;
}

//  快照文件操作 

// 去除文件非法字符（\ / : * ? " < > |）
std::wstring SanitizeFileName(const std::wstring& path) {
    std::wstring result;
    for (wchar_t ch : path) {
        if (ch == L'\\' || ch == L'/' || ch == L':' || ch == L'*' || ch == L'?' ||
            ch == L'\"' || ch == L'<' || ch == L'>' || ch == L'|')
            result += L'_';
        else
            result += ch;
    }
    return result;
}

// 生成快照文件名：根键+子键（去除非法字符）.snapshot
std::wstring GetSnapshotFileName(const std::wstring& fullPath) {
    std::wstring sanitized = SanitizeFileName(fullPath);
    return sanitized + L".snapshot";
}

// 从文件加载快照
bool LoadSnapshotFromFile(const std::wstring& filePath, Snapshot& snap) {
    std::string filePathStr = WideCharToUTF8(filePath.c_str());
    std::ifstream file(filePathStr);
    if (!file) return false;

    std::string line;
    std::wstring currentKey;
    while (std::getline(file, line)) {
        // 移除行尾 \r
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (line.find("[KEY] ") == 0) {
            std::string keyUtf8 = line.substr(6); // 跳过 "[KEY] "
            currentKey = UTF8ToWide(keyUtf8);
            snap[currentKey] = ValueMap();
        } else if (!currentKey.empty() && line.find("  ") == 0) {
            // 值行：去掉前导两个空格
            std::string valueLine = line.substr(2);
            size_t pipe1 = valueLine.find(" | ");
            if (pipe1 == std::string::npos) continue;
            std::string nameUtf8 = valueLine.substr(0, pipe1);
            std::string rest = valueLine.substr(pipe1 + 3);
            size_t pipe2 = rest.find(" | ");
            if (pipe2 == std::string::npos) continue;
            std::string typePart = rest.substr(0, pipe2);
            std::string dataPart = rest.substr(pipe2 + 3);
            DWORD type = 0;
            if (typePart.find("type=") == 0) {
                type = std::stoul(typePart.substr(5));
            }
            std::vector<BYTE> data;
            std::istringstream dataStream(dataPart);
            std::string hexByte;
            while (dataStream >> hexByte) {
                BYTE b = static_cast<BYTE>(std::stoul(hexByte, nullptr, 16));
                data.push_back(b);
            }
            std::wstring wname = UTF8ToWide(nameUtf8);
            snap[currentKey][wname] = std::make_pair(type, data);
        }
    }
    return true;
}

//  注册表遍历与快照 

void TraverseRegistry(HKEY hRootKey, const std::wstring& subPath, Snapshot& snap, int depth = 0) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(hRootKey, subPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD cSubKeys = 0, cValues = 0, cbMaxSubKey = 0, cchMaxValue = 0, cbMaxValueData = 0;
    FILETIME ft;
    if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &cSubKeys, &cbMaxSubKey, nullptr,
                         &cValues, &cchMaxValue, &cbMaxValueData, nullptr, &ft) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return;
    }

    ValueMap values;
    for (DWORD i = 0; i < cValues; ++i) {
        WCHAR valueName[MAX_PATH] = {0};
        DWORD cchValue = MAX_PATH;
        DWORD type = 0;
        BYTE data[4096] = {0};
        DWORD dataSize = sizeof(data);
        if (RegEnumValueW(hKey, i, valueName, &cchValue, nullptr, &type, data, &dataSize) == ERROR_SUCCESS) {
            std::vector<BYTE> vec(data, data + dataSize);
            values[valueName] = std::make_pair(type, vec);
        }
    }

    std::wstring fullPath = subPath.empty() ? L"" : subPath;
    if (!values.empty())
        snap[fullPath] = values;

    for (DWORD i = 0; i < cSubKeys; ++i) {
        WCHAR subKeyName[MAX_KEY_LENGTH] = {0};
        DWORD cbName = MAX_KEY_LENGTH;
        if (RegEnumKeyExW(hKey, i, subKeyName, &cbName, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
            std::wstring newSub = fullPath.empty() ? subKeyName : fullPath + L"\\" + subKeyName;
            TraverseRegistry(hRootKey, newSub, snap, depth + 1);
        }
    }
    RegCloseKey(hKey);
}

Snapshot TakeSnapshot(HKEY rootKey, const std::wstring& subPath) {
    Snapshot snap;
    TraverseRegistry(rootKey, subPath, snap);
    return snap;
}

void SaveSnapshotToFile(const Snapshot& snap, const std::wstring& filePath) {
    std::string filePathStr = WideCharToUTF8(filePath.c_str());
    std::ofstream ofs(filePathStr);
    if (!ofs) return;
    for (const auto& keyPair : snap) {
        ofs << "[KEY] " << WideCharToUTF8(keyPair.first.c_str()) << "\n";
        for (const auto& valPair : keyPair.second) {
            const std::wstring& vname = valPair.first;
            DWORD type = valPair.second.first;
            const std::vector<BYTE>& data = valPair.second.second;
            ofs << "  " << WideCharToUTF8(vname.c_str())
                << " | type=" << type
                << " | data=" << DataToHex(data.data(), (DWORD)data.size())
                << "\n";
        }
    }
    ofs.close();
}

//  对比函数（含键值输出）

void CompareSnapshots(const Snapshot& oldSnap, const Snapshot& newSnap, const std::wstring& path) {
    std::cout << "\n===== 变化检测 [" << WideCharToUTF8(path.c_str()) << "] =====\n";

    for (const auto& newKey : newSnap) {
        auto oldIt = oldSnap.find(newKey.first);
        if (oldIt == oldSnap.end()) {
            std::cout << "[新增键] " << WideCharToUTF8(newKey.first.c_str()) << "\n";
            for (const auto& val : newKey.second) {
                std::cout << "    值: " << WideCharToUTF8(val.first.c_str())
                          << " | 类型: " << g_ValueTypeMap.at(val.second.first)
                          << " | 数据: " << DataToHex(val.second.second.data(), (DWORD)val.second.second.size())
                          << "\n";
            }
        } else {
            const ValueMap& oldVals = oldIt->second;
            const ValueMap& newVals = newKey.second;
            for (const auto& newVal : newVals) {
                auto oldValIt = oldVals.find(newVal.first);
                bool changed = false;
                if (oldValIt == oldVals.end()) {
                    changed=true;
                    std::cout << "[新增值] " << WideCharToUTF8(newKey.first.c_str())
                              << " -> " << WideCharToUTF8(newVal.first.c_str())
                              << " | 类型: " << g_ValueTypeMap.at(newVal.second.first)
                              << " | 数据: " << DataToHex(newVal.second.second.data(), (DWORD)newVal.second.second.size())
                              << "\n";
                } else if (oldValIt->second.second != newVal.second.second ||
                           oldValIt->second.first != newVal.second.first) {
                    changed=true;
                    std::cout << "[修改值] " << WideCharToUTF8(newKey.first.c_str())
                              << " -> " << WideCharToUTF8(newVal.first.c_str())
                              << "\n  旧类型: " << g_ValueTypeMap.at(oldValIt->second.first)
                              << " | 旧数据: " << DataToHex(oldValIt->second.second.data(), (DWORD)oldValIt->second.second.size())
                              << "\n  新类型: " << g_ValueTypeMap.at(newVal.second.first)
                              << " | 新数据: " << DataToHex(newVal.second.second.data(), (DWORD)newVal.second.second.size())
                              << "\n";
                }
                if (withUi && changed) {
                    MessagetoControlCenter_by_RegistryMonitor msg;
                    strcpy_s(msg.type, "RegistryMonitor");

                    // 构造完整键路径
                    std::wstring rootAbbr;
                    size_t pos = path.find(L'\\');
                    if (pos != std::wstring::npos) {
                        rootAbbr = path.substr(0, pos);
                    } else {
                        rootAbbr = path;   // 若路径没有反斜杠，则整个路径就是根键缩写
                    }

                    // 构造完整键路径：根键缩写 + 快照中的子键路径
                    std::wstring keyW = rootAbbr;
                    if (!newKey.first.empty()) {
                        keyW += L"\\";
                        keyW += newKey.first;
                    }
                    // 追加值名称
                    if (!newVal.first.empty()) {
                        keyW += L"\\";
                        keyW += newVal.first;
                    } else {
                        keyW += L"\\(Default)";
                    }
                    std::string keyStr = WideCharToUTF8(keyW.c_str());
                    strncpy_s(reinterpret_cast<char*>(msg.key), sizeof(msg.key), keyStr.c_str(), _TRUNCATE);

                    //  复制旧值数据 
                    DWORD oldLen = 0;
                    if (oldValIt != oldVals.end()) {   // 只有修改值才有旧数据
                        oldLen = static_cast<DWORD>(oldValIt->second.second.size());
                        if (oldLen > sizeof(msg.oldvalue)) oldLen = sizeof(msg.oldvalue);
                        if (oldLen > 0) {
                            memcpy(msg.oldvalue, oldValIt->second.second.data(), oldLen);
                        }
                    }
                    msg.oldvalue_len = oldLen;

                    //  复制新值数据 
                    DWORD newLen = static_cast<DWORD>(newVal.second.second.size());
                    if (newLen > sizeof(msg.newvalue)) newLen = sizeof(msg.newvalue);
                    if (newLen > 0) {
                        memcpy(msg.newvalue, newVal.second.second.data(), newLen);
                    }
                    msg.newvalue_len = newLen;

                    // 值类型名称
                    std::string typeStr = g_ValueTypeMap.at(newVal.second.first);
                    strncpy_s(reinterpret_cast<char*>(msg.valuetype), sizeof(msg.valuetype), typeStr.c_str(), _TRUNCATE);

                    // 发送消息
                    std::thread sender(ClientThread_to_ControlCenter, &msg);
                    sender.join();
                }
            }
            for (const auto& oldVal : oldVals) {
                if (newVals.find(oldVal.first) == newVals.end()) {
                    std::cout << "[删除值] " << WideCharToUTF8(newKey.first.c_str())
                              << " -> " << WideCharToUTF8(oldVal.first.c_str())
                              << " (旧类型: " << g_ValueTypeMap.at(oldVal.second.first) << ")"
                              << "\n";
                }
            }
        }
    }

    for (const auto& oldKey : oldSnap) {
        if (newSnap.find(oldKey.first) == newSnap.end()) {
            std::cout << "[删除键] " << WideCharToUTF8(oldKey.first.c_str()) << "\n";
        }
    }
    std::cout << "===== 变化检测结束 =====\n";
}

//  RegNotify 监控线程 

void RegNotifyThread(MonitorItem* item) {
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(item->rootKey, item->subPath.c_str(), 0, KEY_NOTIFY, &hKey);
    if (result != ERROR_SUCCESS) {
        std::cerr << "RegNotify: 无法打开 " << WideCharToUTF8(item->fullPath.c_str()) << "，错误码 " << result << std::endl;
        return;
    }

    std::cout << "RegNotify 监控已启动: " << WideCharToUTF8(item->fullPath.c_str()) << std::endl;

    while (!item->stop.load() && !g_bExit.load()) {
        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!hEvent) break;

        result = RegNotifyChangeKeyValue(
            hKey,
            TRUE,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES |
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
            hEvent,
            TRUE
        );

        if (result != ERROR_SUCCESS) {
            std::cerr << "RegNotifyChangeKeyValue 失败 (路径: " << WideCharToUTF8(item->fullPath.c_str()) << ")，错误码 " << result << std::endl;
            CloseHandle(hEvent);
            break;
        }

        HANDLE handles[2] = { hEvent, g_hExitEvent };
        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        CloseHandle(hEvent);

        if (wait == WAIT_OBJECT_0) {
            // 注册表发生变更
            std::cout << "\n[RegNotify] 检测到修改: " << WideCharToUTF8(item->fullPath.c_str()) << std::endl;
            std::lock_guard<std::mutex> lock(item->mtx);
            Snapshot newSnap = TakeSnapshot(item->rootKey, item->subPath);
            CompareSnapshots(item->snapshot, newSnap, item->fullPath);
            item->snapshot = std::move(newSnap);
            SaveSnapshotToFile(item->snapshot, item->snapshotFile);
        } else if (wait == WAIT_OBJECT_0 + 1) {
            // 退出事件触发，退出循环
            break;
        } else {
            // 其他错误（WAIT_FAILED）
            std::cerr << "WaitForMultipleObjects 失败，错误码 " << GetLastError() << std::endl;
            break;
        }
    }

    RegCloseKey(hKey);
}

//  ETW 回调（仅非系统进程）

void WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (g_bExit.load()) return;

    if (!IsEqualGUID(pEventRecord->EventHeader.ProviderId, Microsoft_Windows_Kernel_Registry))
        return;

    if (!pTdhGetEventInformation) return;

    DWORD status;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    status = pTdhGetEventInformation(pEventRecord, 0, nullptr, pInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (pInfo) status = pTdhGetEventInformation(pEventRecord, 0, nullptr, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS || !pInfo) {
        if (pInfo) free(pInfo);
        return;
    }

    DWORD pid = pEventRecord->EventHeader.ProcessId;
    std::string procName = GetProcessName(pid);
    if (IsSystemProcess(procName)) {
        free(pInfo);
        return;  // 只输出非系统进程
    }

    USHORT eventId = pEventRecord->EventHeader.EventDescriptor.Id;
    std::string op = "Unknown";
    auto it = g_EventIdToOperation.find(eventId);
    if (it != g_EventIdToOperation.end()) op = it->second;

    SYSTEMTIME st;
    FILETIME ft;
    ULARGE_INTEGER uli;
    uli.LowPart = pEventRecord->EventHeader.TimeStamp.LowPart;
    uli.HighPart = pEventRecord->EventHeader.TimeStamp.HighPart;
    FileTimeToLocalFileTime((FILETIME*)&uli, &ft);
    FileTimeToSystemTime(&ft, &st);
    std::ostringstream timeStream;
    timeStream << std::setfill('0') << std::setw(4) << st.wYear << "-"
               << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay << " "
               << std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute << ":"
               << std::setw(2) << st.wSecond << "." << std::setw(3) << st.wMilliseconds;
/*
    std::cout << "[ETW] " << timeStream.str()
              << " | " << op
              << " | 进程: " << procName << " (PID:" << pid << ")"
              << std::endl;
*/
    free(pInfo);
}

//  ETW 监控线程 

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success;
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

void EtwThread() {
    HMODULE hTdh = LoadLibrary(TEXT("tdh.dll"));
    if (!hTdh) {
        std::cerr << "ETW: 无法加载 tdh.dll" << std::endl;
        return;
    }
    pTdhGetEventInformation = (TdhGetEventInformationFunc)GetProcAddress(hTdh, "TdhGetEventInformation");
    pTdhGetPropertySize = (TdhGetPropertySizeFunc)GetProcAddress(hTdh, "TdhGetPropertySize");
    pTdhGetProperty = (TdhGetPropertyFunc)GetProcAddress(hTdh, "TdhGetProperty");
    if (!pTdhGetEventInformation || !pTdhGetPropertySize || !pTdhGetProperty) {
        std::cerr << "ETW: 获取TDH函数失败" << std::endl;
        FreeLibrary(hTdh);
        return;
    }

    ULONG size = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH * sizeof(WCHAR);
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)malloc(size);
    if (!pProps) return;
    ZeroMemory(pProps, size);
    pProps->Wnode.BufferSize = size;
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pProps->EnableFlags = EVENT_TRACE_FLAG_REGISTRY;
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->FlushTimer = 1;
    pProps->BufferSize = 1024;
    pProps->MinimumBuffers = 10;
    pProps->MaximumBuffers = 100;
    wcscpy_s((wchar_t*)((char*)pProps + pProps->LoggerNameOffset), MAX_PATH, L"RegistryMonitorSession");

    ULONG status = StartTraceW(&g_hSession, L"RegistryMonitorSession", pProps);
    if (status != ERROR_SUCCESS) {
        std::cerr << "ETW: StartTrace 失败，错误码 " << status << std::endl;
        free(pProps);
        FreeLibrary(hTdh);
        return;
    }

    status = EnableTraceEx2(g_hSession, &Microsoft_Windows_Kernel_Registry,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0x0000001F, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        std::cerr << "ETW: EnableTraceEx2 失败，错误码 " << status << std::endl;
        StopTrace(g_hSession, NULL, pProps);
        free(pProps);
        FreeLibrary(hTdh);
        return;
    }

    EVENT_TRACE_LOGFILEW logFile = {0};
    wchar_t loggerName[] = L"RegistryMonitorSession";
    logFile.LoggerName = loggerName;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    g_hTrace = OpenTraceW(&logFile);
    if (g_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "ETW: OpenTrace 失败，错误码 " << GetLastError() << std::endl;
        StopTrace(g_hSession, NULL, pProps);
        free(pProps);
        FreeLibrary(hTdh);
        return;
    }

    std::cout << "ETW 监控已启动（仅显示非系统进程）" << std::endl;

    status = ProcessTrace(&g_hTrace, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && !g_bExit.load())
        std::cerr << "ETW: ProcessTrace 失败，错误码 " << status << std::endl;

    if (g_hTrace != INVALID_PROCESSTRACE_HANDLE) CloseTrace(g_hTrace);
    if (g_hSession) StopTraceW(g_hSession, L"RegistryMonitorSession", pProps);
    free(pProps);
    FreeLibrary(hTdh);
}

//  主函数 

BOOL WINAPI ConsoleHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
        std::cout << "\n收到退出信号，正在停止..." << std::endl;
        g_bExit.store(true);
        if (g_hExitEvent) SetEvent(g_hExitEvent); 
        if (g_hSession) ControlTrace(g_hSession, nullptr, nullptr, EVENT_TRACE_CONTROL_STOP);
        return TRUE;
    }
    return FALSE;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_SHUTDOWN_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT) {
        // 在系统强制终止前，立即解除关键状态
        SetProcessCritical(false);
        return TRUE;
    }
    return FALSE;
}

bool ParseRegistryPath(const std::wstring& fullPath, HKEY& rootKey, std::wstring& subPath) {
    size_t pos = fullPath.find(L'\\');
    std::wstring rootName = (pos == std::wstring::npos) ? fullPath : fullPath.substr(0, pos);
    subPath = (pos == std::wstring::npos) ? L"" : fullPath.substr(pos + 1);

    if (rootName == L"HKEY_CLASSES_ROOT" || rootName == L"HKCR") rootKey = HKEY_CLASSES_ROOT;
    else if (rootName == L"HKEY_CURRENT_USER" || rootName == L"HKCU") rootKey = HKEY_CURRENT_USER;
    else if (rootName == L"HKEY_LOCAL_MACHINE" || rootName == L"HKLM") rootKey = HKEY_LOCAL_MACHINE;
    else if (rootName == L"HKEY_USERS" || rootName == L"HKU") rootKey = HKEY_USERS;
    else if (rootName == L"HKEY_CURRENT_CONFIG" || rootName == L"HKCC") rootKey = HKEY_CURRENT_CONFIG;
    else return false;
    return true;
}

int main(int argc, char* argv[]) {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    SetConsoleOutputCP(CP_UTF8);
    std::wcout << L"Windows 注册表监控整合程序（支持多路径）\n";
    std::wcout << L"用法: " << (argc > 0 ? argv[0] : "REGMON") << L" [路径1[;路径2;...]] [--withoutUi]\n";
    std::wcout << L"示例: " << (argc > 0 ? argv[0] : "REGMON") << L" \"HKLM\\SOFTWARE;HKCU\\Control Panel\"\n";
    std::wcout << L"按 Ctrl+C 退出\n\n";

    // 解析命令行参数
    std::vector<std::wstring> paths;
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    bool hasWithoutUi = false;
    if (wargc > 1) {
        for (int i = 1; i < wargc; ++i) {
            std::wstring arg = wargv[i];
            if (arg == L"--withoutUi") {
                hasWithoutUi = true;
            } else {
                // 可能包含分号分隔的路径
                size_t pos = 0;
                while ((pos = arg.find(L';')) != std::wstring::npos) {
                    paths.push_back(arg.substr(0, pos));
                    arg.erase(0, pos + 1);
                }
                if (!arg.empty()) paths.push_back(arg);
            }
        }
    }
    if (wargv) LocalFree(wargv);
    withUi = !hasWithoutUi;   // 默认为true，若指定--withoutUi则为false

    // 若无路径，使用默认示例
    if (paths.empty()) {
        paths.push_back(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        paths.push_back(L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        paths.push_back(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        paths.push_back(L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        paths.push_back(L"HKLM\\SECURITY");
        paths.push_back(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies");
        paths.push_back(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        paths.push_back(L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server");
        paths.push_back(L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        paths.push_back(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
        paths.push_back(L"HKLM\\SAM\\Domains\\Account");
        paths.push_back(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
        paths.push_back(L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa");
        paths.push_back(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinSock2");
        paths.push_back(L"HKCR\\*\\shellex\\ContextMenuHandlers");
        paths.push_back(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
        paths.push_back(L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs");
    }

    if (paths.empty()) {
        std::wcerr << L"未指定有效路径" << std::endl;
        return 1;
    }

    g_hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hExitEvent) {
        std::cerr << "创建退出事件失败" << std::endl;
        return 1;
    }

    // 初始化每个监控项
    for (const auto& fullPath : paths) {
        auto item = std::make_unique<MonitorItem>();
        if (!ParseRegistryPath(fullPath, item->rootKey, item->subPath)) {
            std::wcerr << L"无效路径格式: " << fullPath << std::endl;
            continue;
        }
        item->fullPath = fullPath;
        item->snapshotFile = GetSnapshotFileName(fullPath);

        std::cout << "正在为 " << WideCharToUTF8(fullPath.c_str()) << " 生成当前快照..." << std::endl;
        Snapshot currentSnap = TakeSnapshot(item->rootKey, item->subPath);

        // 直接保存快照（无论文件是否存在都覆盖）
        item->snapshot = std::move(currentSnap);
        SaveSnapshotToFile(item->snapshot, item->snapshotFile);
        std::cout << "已保存初始快照。" << std::endl;

        g_MonitorItems.push_back(std::move(item));
    }

    if (g_MonitorItems.empty()) {
        std::cerr << "没有有效的监控项，退出。" << std::endl;
        return 1;
    }

    // 提升权限
    if (!EnableDebugPrivilege())
        std::cerr << "警告: 无法启用调试权限，部分功能可能受限，建议以管理员身份运行。" << std::endl;
    InstallShutdownHandler();
    SetProcessShutdownParameters(0x100, 0);
    SetProcessCritical(true);
    // 设置 Ctrl+C 处理
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // 启动 RegNotify 线程（每个监控项一个）
    std::vector<std::thread> regThreads;
    for (auto& item : g_MonitorItems) {
        regThreads.emplace_back(RegNotifyThread, item.get());
    }

    std::thread client(ServerThread_from_User_UI);
    client.detach();

    // 启动 ETW 线程（注释掉，如需启用取消注释）
    //std::thread etwThread(EtwThread);

    // 等待退出信号
    while (!g_bExit.load()) {
        Sleep(100);
    }

    SetProcessCritical(false);

    // 通知所有监控项停止
    for (auto& item : g_MonitorItems) {
        item->stop.store(true);
    }

    // 等待线程结束
    for (auto& t : regThreads) {
        if (t.joinable()) t.join();
    }
    //if (etwThread.joinable()) etwThread.join();
    if (g_hExitEvent) {
        CloseHandle(g_hExitEvent);
        g_hExitEvent = nullptr;
    }

    std::cout << "程序已退出" << std::endl;
    return 0;
}