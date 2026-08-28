/*
ControlCenter.cpp
汇聚层+分析层

处理来自分析层的消息并协调系统行为，分析注册表修改事件的可疑性

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\ControlCenter.cpp" -o "%ExecutablePath%\ControlCenter.exe" -lole32 -mwindows

运行权限：管理员权限
*/
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <iomanip>
#include <set>
#include <fstream>
#include <sstream>
#include <random>
#include <regex>
#include <shellapi.h>
#include <cctype>
#include <atomic> 
#include <winternl.h>
#include "shutdown_handler.h"
#pragma comment(lib, "Shell32.lib") 

#define PIPE_TO_CMDAndPowerShell_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_CMDAndPowerShell"
#define PIPE_FROM_CMDAndPowerShell_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_CMDAndPowerShell"
#define PIPE_TO_CreateWindows_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_CreateWindows"
#define PIPE_FROM_CreateWindows_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_CreateWindows"
#define PIPE_TO_SystemService_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_SystemService"
#define PIPE_FROM_SystemService_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_SystemService"
#define PIPE_TO_TaskScheduler_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_TaskScheduler"
#define PIPE_FROM_TaskScheduler_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_TaskScheduler"
#define PIPE_TO_MemoryGuard_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_MemoryGuard"
#define PIPE_FROM_MemoryGuard_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_MemoryGuard"
#define PIPE_TO_RegistryMonitor_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_RegistryMonitor"
#define PIPE_FROM_RegistryMonitor_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_RegistryMonitor"
#define PIPE_TO_CMDanalyzer_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_CMDanalyzer"
#define PIPE_FROM_CMDanalyzer_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_CMDanalyzer"
#define PIPE_TO_Lnkanalyzer_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_Lnkanalyzer"
#define PIPE_FROM_Lnkanalyzer_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_Lnkanalyzer"
#define PIPE_TO_DOSanalyzer_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_DOSanalyzer"
#define PIPE_FROM_DOSanalyzer_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_DOSanalyzer"
#define PIPE_TO_PEanalyzer_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_PEanalyzer"
#define PIPE_FROM_PEanalyzer_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_PEanalyzer"
#define PIPE_TO_OLEanalyzer_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_OLEanalyzer"
#define PIPE_FROM_OLEanalyzer_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_OLEanalyzer"
#define PIPE_TO_PDFanalyzer_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_PDFanalyzer"
#define PIPE_FROM_PDFanalyzer_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_PDFanalyzer"
#define PIPE_TO_Imageanalyzer_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_Imageanalyzer"
#define PIPE_FROM_Imageanalyzer_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_Imageanalyzer"
#define PIPE_TO_NetworkGuard_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_NetworkGuard"
#define PIPE_FROM_NetworkGuard_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_NetworkGuard"
#define PIPE_TO_UserUI_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_USERUI"
#define PIPE_FROM_UserUI_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_USERUI"

#pragma pack(push, 1)
struct MessagefromCMDAndPowerShell {
    char type[256];
    int ParentPID;
    int parentPID;
    int newPID;
};

struct MessagefromCreateWindows {
    char type[256];
    int PID;
    int ParentPID;
    char windowTitle[256];
    char className[256];
};
struct MessagefromSystemService {
    char type[256];
    wchar_t serviceName[512];
    wchar_t displayName[512];
    wchar_t binaryPath[512];
    DWORD currentState;
};
struct MessagefromTaskScheduler {
    char type[256];
    wchar_t taskName[512];
    wchar_t taskPath[512];
    int taskEnabled;
};
struct MessagefromMemoryGuard {
    char type[256];
    int PID;
    int ParentPID;
    char path[32768];
    int score;
};
struct MessagefromRegistryMonitor {
    char type[256];
    BYTE key[32768]; 
    BYTE oldvalue[32768];
    DWORD oldvalue_len;
    BYTE newvalue[32768];
    DWORD newvalue_len;
    BYTE valuetype[256];
};
struct MessagefromCMDanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
struct MessagefromDOSanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
struct MessagefromLnkanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
struct MessagefromPEanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
struct MessagefromOLEanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
struct MessagefromPDFanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
struct MessagefromImageanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
struct MessagefromZIPanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;

    char details[131072];
};
struct MessagefromNetworkGuard {
    char type[64];
    UINT8  protocol;
    UINT32 localAddr;      // 网络字节序
    UINT16 localPort;      // 主机字节序
    UINT32 remoteAddr;     // 网络字节序
    UINT16 remotePort;     // 主机字节序
    DWORD  pid;
    wchar_t processPath[MAX_PATH];
    char   ip[64];         // 远程 IP 字符串（如 "192.168.1.1"）
    char   domain[256];    // 域名（HTTP Host / DNS 域名 / TLS SNI）
};
struct MessageToUserUI {
    int WindowType=-1;
    int PID=-1;
    wchar_t path[32768]=L"";
    wchar_t details[32768]=L"";
    int score=0;
    BYTE key[32768]=""; 
    BYTE oldvalue[32768]="";
    DWORD oldvalue_len=0;
    BYTE newvalue[32768]="";
    DWORD newvalue_len=0;
    BYTE valuetype[256]="";
    UINT8  protocol=0;
    UINT32 localAddr=0;      // 网络字节序
    UINT16 localPort=0;      // 主机字节序
    UINT32 remoteAddr=0;     // 网络字节序
    UINT16 remotePort=0;     // 主机字节序
    char   ip[64]="";         // 远程 IP 字符串（如 "192.168.1.1"）
    char   domain[256]="";   
};
#pragma pack(pop)

#define BUFFER_SIZE_fromCMDAndPowerShell sizeof(MessagefromCMDAndPowerShell)
#define BUFFER_SIZE_fromCreateWindows sizeof(MessagefromCreateWindows)
#define BUFFER_SIZE_fromSystemService sizeof(MessagefromSystemService)
#define BUFFER_SIZE_fromTaskScheduler sizeof(MessagefromTaskScheduler)
#define BUFFER_SIZE_fromMemoryGuard sizeof(MessagefromMemoryGuard)
#define BUFFER_SIZE_fromRegistryMonitor sizeof(MessagefromRegistryMonitor)
#define BUFFER_SIZE_fromCMDanalyzer sizeof(MessagefromCMDanalyzer)
#define BUFFER_SIZE_fromDOSanalyzer sizeof(MessagefromDOSanalyzer)
#define BUFFER_SIZE_fromLnkanalyzer sizeof(MessagefromLnkanalyzer)
#define BUFFER_SIZE_fromPEanalyzer sizeof(MessagefromPEanalyzer)
#define BUFFER_SIZE_fromOLEanalyzer sizeof(MessagefromOLEanalyzer)
#define BUFFER_SIZE_fromPDFanalyzer sizeof(MessagefromPDFanalyzer)
#define BUFFER_SIZE_fromImageanalyzer sizeof(MessagefromImageanalyzer)
#define BUFFER_SIZE_fromNetworkGuard sizeof(MessagefromNetworkGuard)
#define BUFFER_SIZE_toUserUI sizeof(MessageToUserUI)

std::atomic<bool> g_bExit{false};
HANDLE g_hExitEvent = nullptr;      // 用于唤醒主线程

// 控制命令结构
struct CommandFromUserUI {
    int command;   // 1 = 退出
};

void ClientThread_to_USERUI(MessageToUserUI* msg) ;

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

// 获取当前可执行文件所在目录
std::wstring GetExeDirectoryW() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring exePath(path);
    size_t pos = exePath.find_last_of(L"\\/");
    if (pos != std::string::npos) {
        return exePath.substr(0, pos + 1); // 包含末尾反斜杠
    }
    return L"";
}
static std::wstring g_baseDirW = GetExeDirectoryW();
static std::wstring g_targetPrefixW = g_baseDirW + L"Temp\\";

// 将 UTF-8 字符串转为宽字符串
std::wstring Utf8ToWide(const std::string& utf8) {
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    if (len <= 0) return L"";
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], len);
    wstr.pop_back(); // 移除末尾多余的 L'\0'
    return wstr;
}

// 将宽字符串转为 UTF-8
std::string WideToUtf8(const std::wstring& wstr) {
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string utf8(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &utf8[0], len, NULL, NULL);
    utf8.pop_back();
    return utf8;
}

// 将路径中的非法字符替换为 '_'（用于生成文件名）
std::string SanitizeForFilename(const std::string& path) {
    std::string result = path;
    for (char& c : result) {
        if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' ||
            c == '"' || c == '<' || c == '>' || c == '|') {
            c = '_';
        }
    }
    return result;
}

// 从字符串中提取第一个包含指定扩展名的文件路径（去除引号和参数）
std::string ExtractFilePath(const std::string& text, const std::vector<std::string>& extensions) {
    if (text.empty()) return "";

    // 去除首尾空白
    std::string str = text;
    str.erase(0, str.find_first_not_of(" \t\r\n"));
    str.erase(str.find_last_not_of(" \t\r\n") + 1);
    if (str.empty()) return "";

    // 1. 尝试提取引号内的内容
    if (str.front() == '"') {
        size_t endQuote = str.find('"', 1);
        if (endQuote != std::string::npos) {
            std::string quoted = str.substr(1, endQuote - 1);
            // 检查是否包含目标扩展名
            for (const auto& ext : extensions) {
                if (quoted.find(ext) != std::string::npos) {
                    return quoted;  // 直接返回引号内路径
                }
            }
        }
    }

    // 2. 按空格分割，逐个检查 token
    std::vector<std::string> tokens;
    size_t start = 0, end = 0;
    bool inQuote = false;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '"') {
            inQuote = !inQuote;
            continue;
        }
        if (!inQuote && std::isspace(str[i])) {
            if (start < i) {
                tokens.push_back(str.substr(start, i - start));
            }
            start = i + 1;
        }
    }
    if (start < str.length()) {
        tokens.push_back(str.substr(start));
    }

    // 对每个 token，检查是否包含扩展名
    for (const auto& token : tokens) {
        // 去除可能的尾随引号（如果 token 内有引号，说明之前没有正确处理，这里简单清理）
        std::string cleanToken = token;
        if (cleanToken.front() == '"') cleanToken.erase(0, 1);
        if (cleanToken.back() == '"') cleanToken.pop_back();

        for (const auto& ext : extensions) {
            size_t extPos = cleanToken.find(ext);
            if (extPos != std::string::npos) {
                return cleanToken;
            }
        }
    }

    // 3. 如果仍未找到，尝试第一个 token（通常为可执行文件）
    if (!tokens.empty()) {
        std::string first = tokens[0];
        for (const auto& ext : extensions) {
            if (first.find(ext) != std::string::npos) {
                // 去除首尾引号
                if (first.front() == '"') first.erase(0, 1);
                if (first.back() == '"') first.pop_back();
                return first;
            }
        }
    }

    return "";
}

// 检测是否包含命令行调用特征
bool ContainsCommandLine(const std::string& text) {
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return (lower.find("powershell") != std::string::npos ||
            lower.find("cmd /c") != std::string::npos ||
            lower.find("cmd.exe /c") != std::string::npos ||
            lower.find("wmic") != std::string::npos ||
            lower.find("cscript") != std::string::npos ||
            lower.find("wscript") != std::string::npos);
}

// 提取整个命令行内容（此处简单返回原字符串，可根据需要裁剪）
std::string ExtractCommand(const std::string& text) {
    // 实际可提取更精细，这里直接返回整段
    return text;
}

// 生成临时文件路径：程序目录\Temp\<随机GUID>\<随机GUID>.temp
std::wstring GenerateTempFilePath() {
    std::wstring tempDir = g_baseDirW + L"Temp\\";
    CreateDirectoryW(tempDir.c_str(), NULL); // 确保目录存在

    // 生成随机 GUID 作为子目录名
    GUID guid;
    CoCreateGuid(&guid);
    wchar_t guidStr[40];
    StringFromGUID2(guid, guidStr, 40);
    std::wstring subDir = tempDir + guidStr + L"\\";
    CreateDirectoryW(subDir.c_str(), NULL);

    // 生成随机文件名
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 999999);
    wchar_t fileName[20];
    swprintf(fileName, 20, L"%d.temp", dis(gen));
    return subDir + fileName;
}

// 将内容写入临时文件，返回文件路径（宽字符）
std::wstring WriteTempFile(const std::string& content) {
    std::wstring tempFile = GenerateTempFilePath();
    HANDLE hFile = CreateFileW(tempFile.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return L"";
    DWORD written;
    WriteFile(hFile, content.c_str(), (DWORD)content.size(), &written, NULL);
    CloseHandle(hFile);
    return tempFile;
}

// 去除首尾空白，并将连续空格数量压缩为原来的 floor(count/2)
std::string NormalizePathSpaces(const std::string& path) {
    std::string result;
    result.reserve(path.size());  // 预分配空间提升性能
    for (char c : path) {
        if (c != '\0') {
            result.push_back(c);
        }
    }
    return result;
}

// 运行分析器并获取评分
std::wstring NormalizePathSpacesW(const std::wstring& path) {
    std::wstring result;
    result.reserve(path.size());
    for (wchar_t c : path) {
        if (c != L'\0') {
            result.push_back(c);
        }
    }
    // 去除首尾空白（可选）
    size_t start = result.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return L"";
    size_t end = result.find_last_not_of(L" \t\r\n");
    return result.substr(start, end - start + 1);
}

// 文件名净化
std::wstring SanitizeForFilenameW(const std::wstring& path) {
    std::wstring result = path;
    for (wchar_t& c : result) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' ||
            c == L'\"' || c == L'<' || c == L'>' || c == L'|') {
            c = L'_';
        }
    }
    return result;
}

//RunAnalyzerAndGetScore（支持 Unicode 路径）
int RunAnalyzerAndGetScore(const std::string& filePathUtf8, const std::wstring& analyzerExeW) {
    // 1. 将 UTF-8 路径转为宽字符串
    std::wstring pathW = Utf8ToWide(filePathUtf8);
    if (pathW.empty()) {
        std::cerr << "[Analyzer] File path is empty or conversion failed." << std::endl;
        return 0;
    }

    // 2. 规范化路径（去除引号、压缩空格）
    pathW = NormalizePathSpacesW(pathW);
    // 去除首尾引号
    if (!pathW.empty() && pathW.front() == L'"') pathW.erase(0, 1);
    if (!pathW.empty() && pathW.back() == L'"') pathW.pop_back();

    wprintf(L"[Analyzer] Starting %ls on: %ls\n", analyzerExeW.c_str(), pathW.c_str());
    // 3. 获取可执行文件完整路径（宽）
    std::wstring exePathW = g_baseDirW + analyzerExeW;

    // 4. 构造命令行（宽字符串）
    std::wstring cmdLine = L"\"" + exePathW + L"\" \"" + pathW + L"\" --withoutUi --XML";
    wprintf(L"[Analyzer] Command: %ls\n", cmdLine.c_str());

    // 5. 使用 CreateProcessW 启动分析器
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    // cmdLine 必须可修改，传递 &cmdLine[0]
    if (!CreateProcessW(exePathW.c_str(), &cmdLine[0], NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        std::cerr << "[Analyzer] Failed to launch " << WideToUtf8(analyzerExeW)
                  << ", error: " << GetLastError() << std::endl;
        return 0;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // 6. 构建 XML 路径（宽）
    std::wstring sanitized = SanitizeForFilenameW(pathW);
    std::wstring xmlPathW = g_baseDirW + L"Logs\\" + sanitized + L".xml";
    wprintf(L"[Analyzer] Looking for XML: %ls\n", xmlPathW.c_str());

    // 7. 使用 CreateFileW 打开 XML
    HANDLE hFile = CreateFileW(xmlPathW.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[Analyzer] XML file not found: " << WideToUtf8(xmlPathW) << std::endl;
        return 0;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > 8388608) {
        std::cerr << "[Analyzer] XML file size invalid: " << fileSize << std::endl;
        CloseHandle(hFile);
        return 0;
    }

    std::vector<char> buffer(fileSize + 1, 0);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        std::cerr << "[Analyzer] Failed to read XML file." << std::endl;
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);
    buffer[bytesRead] = '\0';

    // 8. 解析分数（XML 内容一般为 UTF-8，直接处理）
    std::string content(buffer.data());
    std::regex scoreRegex(R"(<score>\s*(\d+)\s*</score>)");
    std::smatch match;
    if (std::regex_search(content, match, scoreRegex)) {
        int score = std::stoi(match[1].str());
        std::cout << "[Analyzer] Extracted score: " << score << std::endl;
        return score;
    }
    std::cout << "[Analyzer] No <score> found in XML." << std::endl;
    return 0;
}


// 从 g_baseDirW + L"Temp\\" + dirName + L"\\_filepath_.txt" 读取内容
// 返回宽字符串内容，失败返回空字符串
std::wstring ReadFilePathContent(const std::wstring& dirName) {
    if (dirName.empty()) return L"";

    std::wstring filePath = g_baseDirW + L"Temp\\" + dirName + L"\\_filepath_.txt";

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return L"";

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > 65536) {
        CloseHandle(hFile);
        return L"";
    }

    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        return L"";
    }
    CloseHandle(hFile);

    //解码逻辑
    std::wstring content;
    const BYTE* data = buffer.data();
    DWORD size = buffer.size();

    // 优先检测无 BOM 的 UTF‑16 LE
    if (size >= 2 && (size % 2 == 0) &&
        !(size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)) {
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(data);
        int wlen = size / sizeof(wchar_t);
        int actualLen = 0;
        while (actualLen < wlen && wstr[actualLen] != L'\0') {
            wchar_t ch = wstr[actualLen];
            if (ch >= 0x20 || ch == L'\t' || ch == L'\r' || ch == L'\n') {
                // 可打印字符
            } else {
                break;
            }
            actualLen++;
        }
        if (actualLen > 0) {
            content.assign(wstr, actualLen);
            while (!content.empty() && (content.back() == L'\r' || content.back() == L'\n'))
                content.pop_back();
            if (!content.empty())
                return content;
        }
    }

    // UTF‑16 LE BOM
    if (size >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(data + 2);
        int wlen = (size - 2) / sizeof(wchar_t);
        content.assign(wstr, wlen);
    }
    // UTF‑16 BE BOM
    else if (size >= 2 && data[0] == 0xFE && data[1] == 0xFF) {
        const wchar_t* src = reinterpret_cast<const wchar_t*>(data + 2);
        int wlen = (size - 2) / sizeof(wchar_t);
        content.resize(wlen);
        for (int i = 0; i < wlen; ++i) {
            wchar_t ch = src[i];
            content[i] = (ch >> 8) | (ch << 8);
        }
    }
    // UTF‑8 / ANSI
    else {
        int offset = 0;
        if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            offset = 3;

        int wlen = MultiByteToWideChar(CP_UTF8, 0,
                                       reinterpret_cast<const char*>(data + offset),
                                       size - offset, NULL, 0);
        if (wlen > 0) {
            content.resize(wlen);
            MultiByteToWideChar(CP_UTF8, 0,
                                reinterpret_cast<const char*>(data + offset),
                                size - offset, &content[0], wlen);
        } else {
            wlen = MultiByteToWideChar(CP_ACP, 0,
                                       reinterpret_cast<const char*>(data),
                                       size, NULL, 0);
            if (wlen > 0) {
                content.resize(wlen);
                MultiByteToWideChar(CP_ACP, 0,
                                    reinterpret_cast<const char*>(data),
                                    size, &content[0], wlen);
            } else {
                return L"";
            }
        }
    }

    while (!content.empty() && (content.back() == L'\r' || content.back() == L'\n'))
        content.pop_back();

    return content;
}

// 递归解析路径：若 path 仍指向 Temp 子目录，则继续读取新的 _filepath_.txt
// depth 用于防止无限递归（上限 100 层）
std::wstring ResolvePathRecursive(const std::wstring& path, int depth = 0) {
    const int MAX_DEPTH = 100;
    if (depth > MAX_DEPTH)
        return path;

    // 检查是否以 g_targetPrefixW 开头（不区分大小写）
    if (_wcsnicmp(path.c_str(), g_targetPrefixW.c_str(), g_targetPrefixW.length()) != 0) {
        return path;  // 不再指向 Temp，结束递归
    }

    // 提取 Temp 后的第一个子目录名
    const wchar_t* p = path.c_str() + g_targetPrefixW.length();
    const wchar_t* slash = wcschr(p, L'\\');
    if (slash == nullptr) {
        return path;  // 格式不合法，返回原路径
    }
    std::wstring dirName(p, slash - p);

    // 读取该目录下的 _filepath_.txt
    std::wstring content = ReadFilePathContent(dirName);
    if (content.empty()) {
        return path;  // 读取失败，返回原路径
    }

    // 提取剩余部分（第一个反斜杠之后的所有内容）
    std::wstring remainder;
    if (*(slash + 1) != L'\0') {
        remainder = std::wstring(slash + 1);
    }

    // 构造新路径：content + "\\" + remainder（保留后续子路径）
    std::wstring newPath = content;
    if (!remainder.empty()) {
        if (!newPath.empty() && newPath.back() != L'\\') {
            newPath += L'\\';
        }
        newPath += remainder;
    }
    // 若 remainder 为空，newPath 即为 content

    // 递归解析新路径（可能继续指向 Temp）
    return ResolvePathRecursive(newPath, depth + 1);
}

// 检查原始路径，若符合条件则返回 _filepath_.txt 的内容，否则返回原路径
std::wstring GetActualPathFromAnalyzer(const char* originalPath) {
    if (originalPath == nullptr || originalPath[0] == '\0')
        return L"";

    // 将 ANSI 转为宽字符串
    int len = MultiByteToWideChar(CP_ACP, 0, originalPath, -1, NULL, 0);
    if (len <= 0) return L"";
    std::wstring wOriginal(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, originalPath, -1, &wOriginal[0], len);
    wOriginal.pop_back();

    // 获取绝对路径
    wchar_t absPath[MAX_PATH];
    if (GetFullPathNameW(wOriginal.c_str(), MAX_PATH, absPath, NULL) == 0) {
        return wOriginal;
    }
    std::wstring fullPath(absPath);

    // 检查是否以 g_targetPrefixW 开头
    if (_wcsnicmp(fullPath.c_str(), g_targetPrefixW.c_str(), g_targetPrefixW.length()) != 0) {
        return wOriginal;
    }

    // 调用递归解析
    return ResolvePathRecursive(fullPath);
}

std::string GetProcessPathByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        // 打开进程失败，可以记录错误码
        // DWORD err = GetLastError();
        return "";
    }

    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    BOOL success = QueryFullProcessImageNameA(hProcess, 0, path, &size);

    CloseHandle(hProcess);

    if (!success) {
        // 获取路径失败，可以记录错误码
        // DWORD err = GetLastError();
        return "";
    }

    return std::string(path);
}

HANDLE ConnectToPipe(const wchar_t* pipeName) {
    while (true) {
        if (WaitNamedPipe(pipeName, 1000)) {
            SetConsoleOutputCP(CP_UTF8);
            SetConsoleCP(CP_UTF8);
            HANDLE hPipe = CreateFile(
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

void ServerThread_from_CMDAndPowerShell() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_CMDAndPowerShell_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromCMDAndPowerShell, BUFFER_SIZE_fromCMDAndPowerShell,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromCMDAndPowerShell msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                      << "\nPparentPID=" << msg.ParentPID
                      << "\nparentPID=" << msg.parentPID
                      << "\nnewPID=" << msg.newPID << std::endl;
            MessageToUserUI message = {};
            message.WindowType=1;
            message.PID = msg.parentPID;
            
            std::string ansiPath = GetProcessPathByPID(msg.parentPID);
            if (!ansiPath.empty()) {
                int required = MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, NULL, 0);
                if (required > 0) {
                    std::wstring wpath(required, L'\0');
                    MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, &wpath[0], required);
                    
                    lstrcpyW(message.path, wpath.c_str());
                } else {
                    message.path[0] = L'\0';
                }
            } else {
                message.path[0] = L'\0';
            }
            
            std::wstring details = std::wstring(L"SubPID:") + std::to_wstring(msg.newPID) + std::wstring(L" ParentPID:") + std::to_wstring(msg.ParentPID);
            lstrcpyW(message.details, details.c_str());
            message.score=0;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            // 启动线程发送消息，并等待完成（阻塞回调，但简化处理）
            std::thread server(ClientThread_to_USERUI, &message);
            server.join(); 
        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_CreateWindows() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_CreateWindows_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromCreateWindows, BUFFER_SIZE_fromCreateWindows,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromCreateWindows msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                      << "\nParentPID=" << msg.ParentPID
                      << "\nPID=" << msg.PID
                      << "\nwindowTitle=" << msg.windowTitle << "\nclassName=" << msg.className << std::endl;
            MessageToUserUI message = {};
            message.WindowType=1;
            message.PID = msg.PID;
            
            std::string ansiPath = GetProcessPathByPID(msg.PID);
            if (!ansiPath.empty()) {
                int required = MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, NULL, 0);
                if (required > 0) {
                    std::wstring wpath(required, L'\0');
                    MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, &wpath[0], required);
                    
                    lstrcpyW(message.path, wpath.c_str());
                } else {
                    message.path[0] = L'\0';
                }
            } else {
                message.path[0] = L'\0';
            }
            
            std::wstring wWindowTitle;
            if (msg.windowTitle[0] != '\0') {
                int req = MultiByteToWideChar(CP_ACP, 0, msg.windowTitle, -1, NULL, 0);
                if (req > 0) {
                    wWindowTitle.resize(req);
                    MultiByteToWideChar(CP_ACP, 0, msg.windowTitle, -1, &wWindowTitle[0], req);
                    
                    if (!wWindowTitle.empty() && wWindowTitle.back() == L'\0') wWindowTitle.pop_back();
                }
            }
            std::wstring details = std::wstring(L"windowTitle:") + wWindowTitle + std::wstring(L" ParentPID:") + std::to_wstring(msg.ParentPID);
            lstrcpyW(message.details, details.c_str());
            message.score=0;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            // 启动线程发送消息，并等待完成（阻塞回调，但简化处理）
            std::thread server(ClientThread_to_USERUI, &message);
            server.join(); 

        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_SystemService() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_SystemService_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromSystemService, BUFFER_SIZE_fromSystemService,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromSystemService msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
             wprintf(L"Received: \nType: %s",msg.type);
             wprintf(L"\nServiceName=%S", msg.serviceName);
             wprintf(L"\nDisplayName=%S", msg.displayName);
             wprintf(L"\nBinaryPath=%S", msg.binaryPath);
             wprintf(L"\ncurrentState=%lu", msg.currentState);
            MessageToUserUI message = {};
            message.WindowType=5;
            message.PID = -1;
            lstrcpyW(message.path, msg.serviceName);
            lstrcpyW(message.details,L"new service");
            message.score=0;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            // 启动线程发送消息，并等待完成（阻塞回调，但简化处理）
            std::thread server(ClientThread_to_USERUI, &message);
            server.join(); 

        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_TaskScheduler() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_TaskScheduler_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromTaskScheduler, BUFFER_SIZE_fromTaskScheduler,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromTaskScheduler msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
             wprintf(L"Received: \nType: %s",msg.type);
             wprintf(L"\nTaskName=%S", msg.taskName);
             wprintf(L"\nTaskPath=%S", msg.taskPath);
             wprintf(L"\nTaskEnabled=%d", msg.taskEnabled);
            MessageToUserUI message = {};
            message.WindowType=5;
            message.PID = -1;
            lstrcpyW(message.path, msg.taskPath);
            lstrcpyW(message.details,L"new task");
            message.score=0;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            // 启动线程发送消息，并等待完成（阻塞回调，但简化处理）
            std::thread server(ClientThread_to_USERUI, &message);
            server.join(); 

        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_MemoryGuard() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_MemoryGuard_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromMemoryGuard, BUFFER_SIZE_fromMemoryGuard,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromMemoryGuard msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
             std::cout << "Received: \nType: " << msg.type
             << "\nPID=" << msg.PID
             << "\nParentPID=" << msg.ParentPID
             << "\npath=" << msg.path
             << "\nscore=" << msg.score << std::endl;
            MessageToUserUI message = {};
            message.WindowType=1;
            message.PID = msg.PID;
            if (msg.path[0] != '\0') {
                int required = MultiByteToWideChar(CP_ACP, 0, msg.path, -1, NULL, 0);
                if (required > 0) {
                    std::wstring wpath(required, L'\0');
                    MultiByteToWideChar(CP_ACP, 0, msg.path, -1, &wpath[0], required);
                    lstrcpyW(message.path, wpath.c_str());
                } else {
                    message.path[0] = L'\0';
                }
            } else {
                message.path[0] = L'\0';
            }
            if(message.path[0]==L'\0'){            
                std::string ansiPath = GetProcessPathByPID(msg.PID);
                if (!ansiPath.empty()) {
                    int required = MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, NULL, 0);
                    if (required > 0) {
                        std::wstring wpath(required, L'\0');
                        MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, &wpath[0], required);
                        
                        lstrcpyW(message.path, wpath.c_str());
                    } else {
                        message.path[0] = L'\0';
                    }
                } else {
                    message.path[0] = L'\0';
                }
            }
            message.score=msg.score;
            std::wstring details =std::wstring(L" ParentPID:") + std::to_wstring(msg.ParentPID);
            lstrcpyW(message.details, details.c_str());
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            // 启动线程发送消息，并等待完成（阻塞回调，但简化处理）
            std::thread server(ClientThread_to_USERUI, &message);
            server.join(); 

        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_RegistryMonitor() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_RegistryMonitor_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromRegistryMonitor, BUFFER_SIZE_fromRegistryMonitor,
            0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "[RegistryMonitor] CreateNamedPipe failed, error: " << GetLastError() << std::endl;
            break;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::cerr << "[RegistryMonitor] ConnectNamedPipe failed, error: " << GetLastError() << std::endl;
            CloseHandle(hPipe);
            continue;
        }

        std::cout << "[RegistryMonitor] Client connected." << std::endl;

        MessagefromRegistryMonitor msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "[RegistryMonitor] Received a registry change message." << std::endl;

            // 准备上报消息结构
            MessageToUserUI outMsg = {};
            bool shouldReport = false;

            //1. 提取值名
            std::string keyStr(reinterpret_cast<const char*>(msg.key));
            size_t lastSlash = keyStr.find_last_of('\\');
            std::string valueName = (lastSlash != std::string::npos) ? keyStr.substr(lastSlash + 1) : keyStr;
            std::cout << "[RegistryMonitor] Full key: " << keyStr << std::endl;
            std::cout << "[RegistryMonitor] Value name: " << valueName << std::endl;

            // 值列表（大小写不敏感）
            static const std::set<std::string> interestingValues = {
                "userinit", "shell", "taskman", "autoadminlogon", "defaultusername",
                "appinit_dlls", "loadappinit_dlls", "security packages",
                "authentication packages", "notification packages", "imagepath",
                "bootexecute", "servicedll", "debugger", "monitorprocess",
                "enablelua", "consentpro", "ptbehavioradmin", "shutdownwithoutlogon",
                "hidefastuserswitching"
            };

            std::string lowerValueName = valueName;
            std::transform(lowerValueName.begin(), lowerValueName.end(), lowerValueName.begin(), ::tolower);

            // 条件1：值名命中兴趣列表 -> 立即上报
            if (interestingValues.find(lowerValueName) != interestingValues.end()) {
                std::cout << "[RegistryMonitor] Value name is interesting. Reporting directly." << std::endl;
                shouldReport = true;
                outMsg.WindowType = 3;
                outMsg.PID = -1;
                outMsg.score = 0;
                memcpy(outMsg.key, msg.key, sizeof(msg.key));
                memcpy(outMsg.oldvalue, msg.oldvalue, sizeof(msg.oldvalue));
                memcpy(outMsg.newvalue, msg.newvalue, sizeof(msg.newvalue));
                outMsg.oldvalue_len = msg.oldvalue_len;
                outMsg.newvalue_len = msg.newvalue_len;
                memcpy(outMsg.valuetype, msg.valuetype, sizeof(msg.valuetype));
                outMsg.path[0] = L'\0';
                outMsg.details[0] = L'\0';
            } else {
                std::cout << "[RegistryMonitor] Value name not in interesting list, checking data content." << std::endl;

                //获取注册表值类型
                DWORD regType = 0;
                memcpy(&regType, msg.valuetype, sizeof(DWORD));

                //按 UTF-16 LE 解析 newvalue，并转为 UTF-8 
                std::vector<std::string> utf8Strings;   // 存储所有 UTF-8 字符串

                const BYTE* data = msg.newvalue;
                size_t dataLen = msg.newvalue_len;

                if (regType == REG_SZ || regType == REG_EXPAND_SZ) {
                    // 单字符串：UTF-16 LE，以宽字符 null 结尾
                    const wchar_t* wdata = reinterpret_cast<const wchar_t*>(data);
                    size_t wcharCount = dataLen / sizeof(wchar_t);
                    size_t stringLen = 0;
                    while (stringLen < wcharCount && wdata[stringLen] != L'\0')
                        stringLen++;
                    if (stringLen > 0) {
                        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wdata, (int)stringLen, NULL, 0, NULL, NULL);
                        if (utf8Len > 0) {
                            std::string utf8Str(utf8Len, '\0');
                            WideCharToMultiByte(CP_UTF8, 0, wdata, (int)stringLen, &utf8Str[0], utf8Len, NULL, NULL);
                            utf8Strings.push_back(utf8Str);
                        }
                    }
                } else if (regType == REG_MULTI_SZ) {
                    // 多字符串：多个 UTF-16 LE 字符串以宽字符 null 分隔，最后双 null
                    const wchar_t* wdata = reinterpret_cast<const wchar_t*>(data);
                    size_t wcharCount = dataLen / sizeof(wchar_t);
                    size_t pos = 0;
                    while (pos < wcharCount) {
                        size_t start = pos;
                        while (pos < wcharCount && wdata[pos] != L'\0')
                            pos++;
                        size_t len = pos - start;
                        if (len > 0) {
                            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wdata + start, (int)len, NULL, 0, NULL, NULL);
                            if (utf8Len > 0) {
                                std::string utf8Str(utf8Len, '\0');
                                WideCharToMultiByte(CP_UTF8, 0, wdata + start, (int)len, &utf8Str[0], utf8Len, NULL, NULL);
                                utf8Strings.push_back(utf8Str);
                            }
                        }
                        // 跳过当前 null
                        pos++;
                        // 如果下一个也是 null，说明结束
                        if (pos < wcharCount && wdata[pos] == L'\0')
                            break;
                    }
                } else {
                    // 其他类型（如 REG_BINARY）：尝试按 UTF-16 LE 解码，若有可打印字符则转换
                    const wchar_t* wdata = reinterpret_cast<const wchar_t*>(data);
                    size_t wcharCount = dataLen / sizeof(wchar_t);
                    size_t stringLen = 0;
                    while (stringLen < wcharCount && wdata[stringLen] != L'\0')
                        stringLen++;
                    if (stringLen > 0) {
                        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wdata, (int)stringLen, NULL, 0, NULL, NULL);
                        if (utf8Len > 0) {
                            std::string utf8Str(utf8Len, '\0');
                            WideCharToMultiByte(CP_UTF8, 0, wdata, (int)stringLen, &utf8Str[0], utf8Len, NULL, NULL);
                            utf8Strings.push_back(utf8Str);
                        }
                    }
                }
                try{wprintf(L"Registry value data: %S\n", reinterpret_cast<const wchar_t*>(data));}catch(...){}
                // 如果没有任何字符串可分析，则跳过
                if (utf8Strings.empty()) {
                    std::cout << "[RegistryMonitor] No valid string data found." << std::endl;
                } else {
                    int finalScore = 0;
                    std::wstring reportPath;

                    // 遍历每个字符串进行条件检查
                    for (size_t i = 0; i < utf8Strings.size() && !shouldReport; ++i) {
                        const std::string& str = utf8Strings[i];
                        std::string preview = str.size() > 100 ? str.substr(0, 100) + "..." : str;
                        std::cout << "[RegistryMonitor] Checking string[" << i << "]: " << preview << std::endl;

                        // PE 文件 (.exe, .dll, .sys)
                        std::string pePath = ExtractFilePath(str, {".exe", ".dll", ".sys"});
                        if (!pePath.empty()) {
                            std::cout << "[RegistryMonitor] Extracted PE path: " << pePath << std::endl;
                            int score = RunAnalyzerAndGetScore(pePath, L"PEanalyzer.exe");
                            std::cout << "[RegistryMonitor] PE analyzer score: " << score << std::endl;
                            if (score >= 90) {
                                shouldReport = true;
                                finalScore = score;
                                reportPath = Utf8ToWide(pePath);
                                std::cout << "[RegistryMonitor] Condition 2 met (PE, score >= 90)." << std::endl;
                                break;
                            }
                        }

                        //脚本文件 (.bat, .cmd, .ps1) 
                        std::string scriptPath = ExtractFilePath(str, {".bat", ".cmd", ".ps1"});
                        if (!scriptPath.empty()) {
                            std::cout << "[RegistryMonitor] Extracted script path: " << scriptPath << std::endl;
                            int score = RunAnalyzerAndGetScore(scriptPath, L"CMDanalyzer.exe");
                            std::cout << "[RegistryMonitor] Script analyzer score: " << score << std::endl;
                            if (score >= 50) {
                                shouldReport = true;
                                finalScore = score;
                                reportPath = Utf8ToWide(scriptPath);
                                std::cout << "[RegistryMonitor] Condition 3 met (script, score >= 50)." << std::endl;
                                break;
                            }
                        }

                        // 命令行调用特征
                        if (ContainsCommandLine(str)) {
                            std::cout << "[RegistryMonitor] Detected command-line invocation features." << std::endl;
                            std::string cmdContent = ExtractCommand(str);
                            std::wstring tempFile = WriteTempFile(cmdContent);
                            if (!tempFile.empty()) {
                                std::string tempFileUtf8 = WideToUtf8(tempFile);
                                std::cout << "[RegistryMonitor] Wrote command to temp file: " << tempFileUtf8 << std::endl;
                                int score = RunAnalyzerAndGetScore(tempFileUtf8, L"CMDanalyzer.exe");
                                std::cout << "[RegistryMonitor] Command analyzer score: " << score << std::endl;
                                if (score >= 5) {
                                    shouldReport = true;
                                    finalScore = score;
                                    reportPath = tempFile;
                                    std::cout << "[RegistryMonitor] Condition 4 met (command, score >= 5)." << std::endl;
                                    break;
                                }
                            } else {
                                std::cerr << "[RegistryMonitor] Failed to create temp file for command." << std::endl;
                            }
                        }
                    }

                    // 如果条件2/3/4触发，构造上报消息
                    if (shouldReport) {
                        outMsg.WindowType = 3;
                        outMsg.PID = -1;
                        outMsg.score = finalScore;
                        lstrcpyW(outMsg.path, reportPath.c_str());
                        memcpy(outMsg.key, msg.key, sizeof(msg.key));
                        memcpy(outMsg.oldvalue, msg.oldvalue, sizeof(msg.oldvalue));
                        memcpy(outMsg.newvalue, msg.newvalue, sizeof(msg.newvalue));
                        outMsg.oldvalue_len = msg.oldvalue_len;
                        outMsg.newvalue_len = msg.newvalue_len;
                        memcpy(outMsg.valuetype, msg.valuetype, sizeof(msg.valuetype));
                        outMsg.details[0] = L'\0';
                    }
                }
            }

            //如果需要上报，发送到 UI 
            if (shouldReport) {
                wprintf(L"[RegistryMonitor] Reporting to UI with score: %d, path: %s\n", outMsg.score, outMsg.path);
                std::thread server(ClientThread_to_USERUI, &outMsg);
                server.join();
            } else {
                std::cout << "[RegistryMonitor] No condition met; this registry change will not be reported." << std::endl;
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_CMDanalyzer() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_CMDanalyzer_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromCMDanalyzer, BUFFER_SIZE_fromCMDanalyzer,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromCMDanalyzer msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\npath=" << msg.path
                    << "\nscore=" << msg.score << std::endl;

            //  获取实际的 path（可能被替换） 
            std::wstring actualPath = GetActualPathFromAnalyzer(msg.path);

            MessageToUserUI message = {};
            message.WindowType = msg.WindowType;
            message.PID = -1;

            lstrcpyW(message.path, actualPath.c_str());
            message.score = msg.score;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }
        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_DOSanalyzer() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_DOSanalyzer_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromDOSanalyzer, BUFFER_SIZE_fromDOSanalyzer,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromDOSanalyzer msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\npath=" << msg.path
                    << "\nscore=" << msg.score << std::endl;

            //获取实际的 path
            std::wstring actualPath = GetActualPathFromAnalyzer(msg.path);

            MessageToUserUI message = {};
            message.WindowType = msg.WindowType;
            message.PID = -1;

            lstrcpyW(message.path, actualPath.c_str());
            message.score = msg.score;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_Lnkanalyzer() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_Lnkanalyzer_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromLnkanalyzer, BUFFER_SIZE_fromLnkanalyzer,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromLnkanalyzer msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\npath=" << msg.path
                    << "\nscore=" << msg.score << std::endl;

            // 获取实际的 path
            std::wstring actualPath = GetActualPathFromAnalyzer(msg.path);

            MessageToUserUI message = {};
            message.WindowType = msg.WindowType;
            message.PID = -1;

            lstrcpyW(message.path, actualPath.c_str());
            message.score = msg.score;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_PEanalyzer() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_PEanalyzer_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromPEanalyzer, BUFFER_SIZE_fromPEanalyzer,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromPEanalyzer msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\npath=" << msg.path
                    << "\nscore=" << msg.score << std::endl;

            // 获取实际的 path
            std::wstring actualPath = GetActualPathFromAnalyzer(msg.path);

            MessageToUserUI message = {};
            message.WindowType = msg.WindowType;
            message.PID = -1;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            lstrcpyW(message.path, actualPath.c_str());
            message.score = msg.score;

            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_OLEanalyzer() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_OLEanalyzer_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromOLEanalyzer, BUFFER_SIZE_fromOLEanalyzer,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromOLEanalyzer msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\npath=" << msg.path
                    << "\nscore=" << msg.score << std::endl;

            //获取实际的 path
            std::wstring actualPath = GetActualPathFromAnalyzer(msg.path);

            MessageToUserUI message = {};
            message.WindowType = msg.WindowType;
            message.PID = -1;

            lstrcpyW(message.path, actualPath.c_str());
            message.score = msg.score;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_PDFanalyzer() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_PDFanalyzer_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromPDFanalyzer, BUFFER_SIZE_fromPDFanalyzer,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromPDFanalyzer msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\npath=" << msg.path
                    << "\nscore=" << msg.score << std::endl;

            // 获取实际的 path
            std::wstring actualPath = GetActualPathFromAnalyzer(msg.path);

            MessageToUserUI message = {};
            message.WindowType = msg.WindowType;
            message.PID = -1;

            lstrcpyW(message.path, actualPath.c_str());
            message.score = msg.score;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_Imageanalyzer() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_Imageanalyzer_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromImageanalyzer, BUFFER_SIZE_fromImageanalyzer,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromImageanalyzer msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\npath=" << msg.path
                    << "\nscore=" << msg.score << std::endl;

            //  获取实际的 path（可能被替换） 
            std::wstring actualPath = GetActualPathFromAnalyzer(msg.path);

            MessageToUserUI message = {};
            message.WindowType = msg.WindowType;
            message.PID = -1;

            lstrcpyW(message.path, actualPath.c_str());
            message.score = msg.score;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }

        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ServerThread_from_NetWorkGuard() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        // 每次循环重新创建管道实例
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_NetworkGuard_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_fromNetworkGuard, BUFFER_SIZE_fromNetworkGuard,
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

        // 循环读取来自该客户端的消息（客户端通常发送一次即关闭）
        MessagefromNetworkGuard msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            std::cout << "Received: \nType: " << msg.type
                    << "\ndomain:" << msg.domain
                    << "\nip:" << msg.ip 
                    << "\npid:" << msg.pid
                    << std::endl;

            MessageToUserUI message = {};
            message.WindowType = 6;
            message.PID = msg.pid;
            std::wstring path = msg.processPath;
            lstrcpyW(message.path, path.c_str());
            message.score = 0;
            message.key[0]=0;
            message.oldvalue[0]=0;
            message.oldvalue_len=0;
            message.newvalue[0]=0;
            message.newvalue_len=0;
            message.valuetype[0]=0;
            message.protocol=msg.protocol;
            message.localAddr=msg.localAddr;
            message.remoteAddr=msg.remoteAddr;
            message.localPort=msg.localPort;
            message.remotePort=msg.remotePort;
            strcpy_s(message.ip, sizeof(message.ip), msg.ip);
            strcpy_s(message.domain, sizeof(message.domain), msg.domain);
            std::thread server(ClientThread_to_USERUI, &message);
            server.join();
        }
        // 客户端已断开，清理当前连接，准备下一个
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

void ClientThread_to_USERUI(MessageToUserUI* msg) 
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    HANDLE hPipe = ConnectToPipe(PIPE_TO_UserUI_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Process CMDAndPowerShell: Always failed to connect to pipe, exiting send thread" << std::endl;
        return;
    }

    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, BUFFER_SIZE_toUserUI, &bytesWritten, NULL) || bytesWritten != BUFFER_SIZE_toUserUI) {
        std::cerr << "Process A: Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}

void ServerThread_from_UserUI_Control() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (!g_bExit) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_FROM_UserUI_NAME,        
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(CommandFromUserUI),
            sizeof(CommandFromUserUI),
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "[Control] CreateNamedPipe failed, error: " << GetLastError() << std::endl;
            break;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::cerr << "[Control] ConnectNamedPipe failed, error: " << GetLastError() << std::endl;
            CloseHandle(hPipe);
            continue;
        }

        std::cout << "[Control] Client connected." << std::endl;

        CommandFromUserUI msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            if (msg.command == 1) {   // 退出命令
                std::cout << "[Control] Received exit command. Shutting down..." << std::endl;
                g_bExit = true;
                if (g_hExitEvent) SetEvent(g_hExitEvent);   // 唤醒主线程
                break;
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_SHUTDOWN_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT) {
        // 在系统强制终止前，立即解除关键状态
        SetProcessCritical(false);
        return TRUE;
    }
    return FALSE;
}

int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::cout << "=== Process A Startup ===" << std::endl;

    EnableDebugPrivilege();
    SetProcessCritical(true);
    InstallShutdownHandler();
    SetProcessShutdownParameters(0x100, 0);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    g_hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hExitEvent) {
        std::cerr << "Failed to create exit event." << std::endl;
        SetProcessCritical(false);
        return 1;
    }

    //std::thread client1(ServerThread_from_CMDAndPowerShell);
    std::thread client2(ServerThread_from_CreateWindows);
    std::thread client3(ServerThread_from_SystemService);
    std::thread client4(ServerThread_from_TaskScheduler);
    std::thread client5(ServerThread_from_RegistryMonitor);
    std::thread client6(ServerThread_from_MemoryGuard);
    std::thread client7(ServerThread_from_CMDanalyzer);
    std::thread client8(ServerThread_from_DOSanalyzer);
    std::thread client9(ServerThread_from_Lnkanalyzer);
    std::thread client10(ServerThread_from_PEanalyzer);
    std::thread client11(ServerThread_from_OLEanalyzer);
    std::thread client12(ServerThread_from_PDFanalyzer);
    std::thread client13(ServerThread_from_Imageanalyzer);
    std::thread client14(ServerThread_from_NetWorkGuard);
    //client1.join();
    client2.detach();
    client3.detach();
    client4.detach();
    client5.detach();
    client6.detach();
    client7.detach();
    client8.detach();
    client9.detach();
    client10.detach();
    client11.detach();
    client12.detach();
    client13.detach();
    client14.detach();

    std::thread controlThread(ServerThread_from_UserUI_Control);
    controlThread.detach();

    // 主线程阻塞等待退出事件
    WaitForSingleObject(g_hExitEvent, INFINITE);

    // 收到退出命令，等待 2 秒让工作线程有机会清理（如有需要）
    std::cout << "Main thread received exit signal, waiting 2 seconds before exit..." << std::endl;
    SetProcessCritical(false);
    Sleep(2000);

    // 清理资源
    if (g_hExitEvent) {
        CloseHandle(g_hExitEvent);
        g_hExitEvent = nullptr;
    }

    std::cout << "=== Process A Exit ===" << std::endl;
    return 0;
}