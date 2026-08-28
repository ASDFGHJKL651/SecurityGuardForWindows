/*
Lnkanalyzer.cpp
分析层

分析.lnk快捷方式文件，评估潜在风险

命令行参数：
argv[0] --- Lnkanalyzer.exe
argv[1] --- 需要分析的.lnk文件路径
argv[2] --- 可选参数，"--withoutUi"表示不弹窗，"--onlywithUi"表示仅高危弹窗，其他情况默认弹窗+分析

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\Lnkanalyzer.cpp" -o "%ExecutablePath%\Lnkanalyzer.exe" -lole32 -lshell32 -lshlwapi -ladvapi32 -lcrypt32 -lwintrust -luuid -mwindows

运行权限：管理员权限
*/
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <comdef.h>
#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <io.h>
#include <fcntl.h>
#include <regex>
#include <memory>
#include <map>
#include <set>
#include <fstream>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>
#include <thread>

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

int withUi;
char filepath[32768];

#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_Lnkanalyzer"
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_Lnkanalyzer"

#pragma pack(push, 1)
struct MessagetoControlCenter_by_Lnkanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
#pragma pack(pop)

#define PIPE_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_Lnkanalyzer)

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

void ClientThread_to_ControlCenter(MessagetoControlCenter_by_Lnkanalyzer* msg) {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Process CMDAndPowerShell: Always failed to connect to pipe, exiting send thread" << std::endl;
        return;
    }

    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
        std::cerr << "Process A: Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}

//结构体
struct LnkInfo {
    std::wstring originalPath;
    std::wstring targetPath;
    std::wstring arguments;
    std::wstring workingDir;
    std::wstring iconPath;
    int iconIndex = 0;
    int showCmd = SW_SHOWNORMAL;
    std::wstring description;
    bool targetExists = false;
    bool success = false;
    std::wstring fullTarget;
    bool isLnkChain = false;
    int chainDepth = 0;
    std::wstring displayName;
    DWORD lnkFileAttributes = 0;
    FILETIME lnkCreationTime{};
    FILETIME lnkLastWriteTime{};
    FILETIME lnkLastAccessTime{};
    bool hasValidSignature = false;
    bool isTargetPE = false;
    std::wstring targetFileExt;
    int riskScore = 0;
    std::vector<std::wstring> warnings;
    std::wstring secondaryTargetPath;        // 从 IDList 获取的绝对路径（第二候选）
    bool hasSecondaryTarget = false;
    std::wstring extraEnvTarget;             // 环境变量数据块解析出的路径
    bool hasEnvironmentBlock = false;
    std::wstring specialFolderTarget;        // 特殊文件夹数据块解析出的路径
    bool hasSpecialFolderBlock = false;
    bool isRemotePath = false;               // 远程路径（\\ 或 http）
    bool isWebDAVOrOneDrive = false;         // WebDAV 或 OneDrive
    bool iconSpoofing = false;               // 图标伪装
    bool systemIconWithScript = false;       // 系统图标 + 脚本目标
};

//辅助函数
std::wstring ExpandEnv(const std::wstring& input) {
    if (input.empty()) return input;
    wchar_t buffer[32767] = {0};
    DWORD size = ExpandEnvironmentStringsW(input.c_str(), buffer, _countof(buffer));
    if (size == 0 || size > _countof(buffer))
        return input;
    return std::wstring(buffer);
}

std::wstring TrimQuotesAndSpaces(const std::wstring& str) {
    size_t start = str.find_first_not_of(L" \t\r\n\"");
    if (start == std::wstring::npos) return L"";
    size_t end = str.find_last_not_of(L" \t\r\n\"");
    return str.substr(start, end - start + 1);
}

bool IsBase64String(const std::wstring& s) {
    if (s.length() % 4 != 0) return false;
    static const std::wstring base64Chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    for (wchar_t c : s) {
        if (base64Chars.find(c) == std::wstring::npos)
            return false;
    }
    return true;
}

std::wstring GetFileExtLower(const std::wstring& path) {
    size_t pos = path.find_last_of(L'.');
    if (pos == std::wstring::npos) return L"";
    std::wstring ext = path.substr(pos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    return ext;
}

bool IsScriptExtension(const std::wstring& ext) {
    static std::set<std::wstring> scriptExts = {
        L".js", L".vbs", L".ps1", L".scr", L".com", L".pif", L".cmd", L".bat", L".jar", L".hta"
    };
    return scriptExts.find(ext) != scriptExts.end();
}

bool IsExecutableExtension(const std::wstring& ext) {
    static std::set<std::wstring> exeExts = {
        L".exe", L".dll", L".cpl", L".msi", L".msp", L".appref-ms"
    };
    return exeExts.find(ext) != exeExts.end();
}

bool IsPEFile(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD dwSize = GetFileSize(hFile, nullptr);
    if (dwSize < 0x1000) { CloseHandle(hFile); return false; }
    IMAGE_DOS_HEADER dos;
    DWORD read = 0;
    if (!ReadFile(hFile, &dos, sizeof(dos), &read, nullptr) || read != sizeof(dos)) {
        CloseHandle(hFile); return false;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) { CloseHandle(hFile); return false; }
    IMAGE_NT_HEADERS nt;
    SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN);
    if (!ReadFile(hFile, &nt, sizeof(nt), &read, nullptr) || read != sizeof(nt)) {
        CloseHandle(hFile); return false;
    }
    CloseHandle(hFile);
    return nt.Signature == IMAGE_NT_SIGNATURE;
}

bool VerifyDigitalSignature(const std::wstring& path) {
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = NULL;
    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(WINTRUST_DATA);
    data.pFile = &fileInfo;
    data.dwUIChoice = WTD_UI_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG;
    LONG status = WinVerifyTrust(NULL, &guidAction, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &data);
    return status == ERROR_SUCCESS;
}

bool GetFileTimeInfo(const std::wstring& path, FILETIME* create, FILETIME* access, FILETIME* write) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    BOOL ret = GetFileTime(hFile, create, access, write);
    CloseHandle(hFile);
    return ret == TRUE;
}

//二进制解析附加数据块
#pragma pack(push, 1)
typedef struct {
    DWORD HeaderSize;           // 0x4C
    GUID  LinkCLSID;            // {00021401-0000-0000-C000-000000000046}
    DWORD LinkFlags;
    DWORD FileAttributes;
    FILETIME CreationTime;
    FILETIME AccessTime;
    FILETIME WriteTime;
    DWORD FileSize;
    DWORD IconIndex;
    DWORD ShowCommand;
    WORD  HotKey;
    WORD  Reserved1;
    DWORD Reserved2;
    DWORD Reserved3;
    DWORD LinkTargetIDListSize;
    DWORD LinkInfoSize;
    DWORD StringDataSize;
    DWORD ExtraDataSize;
} ShellLinkHeader;
#pragma pack(pop)

bool ParseLnkExtraData(const std::wstring& lnkPath, LnkInfo& info) {
    HANDLE hFile = CreateFileW(lnkPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD dwSize = GetFileSize(hFile, NULL);
    if (dwSize < sizeof(ShellLinkHeader)) { CloseHandle(hFile); return false; }

    BYTE* buffer = new BYTE[dwSize];
    DWORD read = 0;
    if (!ReadFile(hFile, buffer, dwSize, &read, NULL) || read != dwSize) {
        delete[] buffer; CloseHandle(hFile); return false;
    }
    CloseHandle(hFile);

    ShellLinkHeader* header = (ShellLinkHeader*)buffer;
    // 检查 LinkCLSID 是否匹配
    // 直接计算偏移
    DWORD offset = header->HeaderSize + header->LinkTargetIDListSize +
                   header->LinkInfoSize + header->StringDataSize;

    // 预定义 GUID
    static const GUID GUID_Env = {0x00021435, 0x0000, 0x0000, {0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
    static const GUID GUID_Console = {0x00021434, 0x0000, 0x0000, {0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
    static const GUID GUID_Special = {0x00021436, 0x0000, 0x0000, {0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
    static const GUID GUID_Darwin = {0x00121437, 0x0000, 0x0000, {0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};

    while (offset < dwSize) {
        DWORD blockSize = *(DWORD*)(buffer + offset);
        if (blockSize == 0) break; // TerminalBlock
        GUID* pGuid = (GUID*)(buffer + offset + 4);

        if (memcmp(pGuid, &GUID_Env, sizeof(GUID)) == 0) {
            // EnvironmentVariableDataBlock: 大小4 + GUID16 + 可变ANSI字符串
            const char* pAnsi = (const char*)(buffer + offset + 20);
            std::string ansiStr(pAnsi);
            if (!ansiStr.empty()) {
                int wlen = MultiByteToWideChar(CP_ACP, 0, ansiStr.c_str(), -1, NULL, 0);
                if (wlen > 0) {
                    std::wstring wstr(wlen - 1, L'\0');
                    MultiByteToWideChar(CP_ACP, 0, ansiStr.c_str(), -1, &wstr[0], wlen);
                    info.extraEnvTarget = ExpandEnv(wstr);
                    info.hasEnvironmentBlock = true;
                }
            }
        }
        else if (memcmp(pGuid, &GUID_Special, sizeof(GUID)) == 0) {
            // SpecialFolderDataBlock: 大小4 + GUID16 + DWORD特殊文件夹ID + 字符串
            // 跳过 SpecialFolderID (4字节) 后取路径
            const char* pPath = (const char*)(buffer + offset + 24);
            std::string ansiPath(pPath);
            if (!ansiPath.empty()) {
                int wlen = MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, NULL, 0);
                if (wlen > 0) {
                    std::wstring wstr(wlen - 1, L'\0');
                    MultiByteToWideChar(CP_ACP, 0, ansiPath.c_str(), -1, &wstr[0], wlen);
                    info.specialFolderTarget = ExpandEnv(wstr);
                    info.hasSpecialFolderBlock = true;
                }
            }
        }
        offset += blockSize;
    }

    delete[] buffer;
    return true;
}

//核心解析函数
bool GetLnkInfoEnhanced(const std::wstring& lnkFilePath, LnkInfo& info, int depth = 0) {
    if (depth > 5) {
        info.success = false;
        info.warnings.push_back(L"LNK recursion depth exceeded 5, stopping解析");
        return false;
    }

    info.originalPath = lnkFilePath;
    info.success = false;
    info.targetExists = false;
    info.chainDepth = depth;
    info.isLnkChain = (depth > 0);

    std::wstring expandedPath = ExpandEnv(lnkFilePath);
    if (expandedPath != lnkFilePath) {
        info.warnings.push_back(L"Path contains environment variable, expanded to: " + expandedPath);
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"CoInitializeEx failed. HRESULT: 0x" << std::hex << hr << std::endl;
        return false;
    }

    IShellLinkW* pShellLink = nullptr;
    IPersistFile* pPersistFile = nullptr;
    bool ret = false;

    do {
        hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                              IID_IShellLinkW, (void**)&pShellLink);
        if (FAILED(hr) || !pShellLink) {
            std::wcerr << L"CoCreateInstance failed. HRESULT: 0x" << std::hex << hr << std::endl;
            break;
        }

        hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
        if (FAILED(hr) || !pPersistFile) {
            std::wcerr << L"QueryInterface for IPersistFile failed. HRESULT: 0x" << std::hex << hr << std::endl;
            break;
        }

        hr = pPersistFile->Load(expandedPath.c_str(), STGM_READ);
        if (FAILED(hr)) {
            std::wcerr << L"IPersistFile::Load failed. HRESULT: 0x" << std::hex << hr << std::endl;
            break;
        }

        pShellLink->Resolve(nullptr, SLR_NO_UI | SLR_NOSEARCH | SLR_NOTRACK | SLR_NOUPDATE);

        wchar_t pathBuffer[MAX_PATH * 4] = {0};
        hr = pShellLink->GetPath(pathBuffer, _countof(pathBuffer), nullptr, SLGP_RAWPATH);
        if (SUCCEEDED(hr) && wcslen(pathBuffer) > 0) {
            info.targetPath = pathBuffer;
        } else {
            // 尝试通过 IDList 获取路径
            LPITEMIDLIST pidl = nullptr;
            hr = pShellLink->GetIDList(&pidl);
            if (SUCCEEDED(hr) && pidl) {
                wchar_t displayName[MAX_PATH * 2] = {0};
                if (SHGetPathFromIDListW(pidl, displayName)) {
                    info.targetPath = displayName;
                    // 同时存储为第二候选
                    info.secondaryTargetPath = displayName;
                    info.hasSecondaryTarget = true;
                } else {
                    info.displayName.clear();
                }
                CoTaskMemFree(pidl);
            }
        }

        if (!info.targetPath.empty()) {
            std::wstring expandedTarget = ExpandEnv(info.targetPath);
            if (expandedTarget != info.targetPath) {
                info.warnings.push_back(L"Target path expanded environment variable: " + info.targetPath + L" -> " + expandedTarget);
                info.targetPath = expandedTarget;
            }
        }

        // 额外获取 IDList 作为第二候选（如果尚未获取且 targetPath 非空也获取）
        if (info.secondaryTargetPath.empty()) {
            LPITEMIDLIST pidl2 = nullptr;
            hr = pShellLink->GetIDList(&pidl2);
            if (SUCCEEDED(hr) && pidl2) {
                wchar_t displayName2[MAX_PATH * 2] = {0};
                if (SHGetPathFromIDListW(pidl2, displayName2)) {
                    info.secondaryTargetPath = displayName2;
                    info.hasSecondaryTarget = true;
                }
                CoTaskMemFree(pidl2);
            }
        }

        wchar_t argsBuffer[MAX_PATH * 2] = {0};
        hr = pShellLink->GetArguments(argsBuffer, _countof(argsBuffer));
        if (SUCCEEDED(hr)) info.arguments = argsBuffer;
        else info.arguments.clear();

        wchar_t workDir[MAX_PATH] = {0};
        hr = pShellLink->GetWorkingDirectory(workDir, _countof(workDir));
        if (SUCCEEDED(hr)) {
            info.workingDir = ExpandEnv(workDir);
        } else info.workingDir.clear();

        wchar_t iconPath[MAX_PATH] = {0};
        int iconIdx = 0;
        hr = pShellLink->GetIconLocation(iconPath, _countof(iconPath), &iconIdx);
        if (SUCCEEDED(hr)) {
            info.iconPath = ExpandEnv(iconPath);
            info.iconIndex = iconIdx;
        } else {
            info.iconPath.clear();
            info.iconIndex = 0;
        }

        int showCmd = 0;
        hr = pShellLink->GetShowCmd(&showCmd);
        if (SUCCEEDED(hr)) info.showCmd = showCmd;
        else info.showCmd = SW_SHOWNORMAL;

        wchar_t desc[MAX_PATH] = {0};
        hr = pShellLink->GetDescription(desc, _countof(desc));
        if (SUCCEEDED(hr)) info.description = desc;
        else info.description.clear();

        if (!info.targetPath.empty()) {
            DWORD attr = GetFileAttributesW(info.targetPath.c_str());
            info.targetExists = (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
        }

        info.fullTarget = info.targetPath;
        if (!info.arguments.empty()) {
            info.fullTarget += L" ";
            info.fullTarget += info.arguments;
        }

        DWORD lnkAttr = GetFileAttributesW(expandedPath.c_str());
        if (lnkAttr != INVALID_FILE_ATTRIBUTES) {
            info.lnkFileAttributes = lnkAttr;
        }
        GetFileTimeInfo(expandedPath, &info.lnkCreationTime, &info.lnkLastAccessTime, &info.lnkLastWriteTime);

        // 递归解析快捷方式链
        if (!info.targetPath.empty()) {
            std::wstring ext = GetFileExtLower(info.targetPath);
            if (ext == L".lnk") {
                LnkInfo childInfo;
                if (GetLnkInfoEnhanced(info.targetPath, childInfo, depth + 1)) {
                    info.targetPath = childInfo.targetPath;
                    if (!childInfo.arguments.empty()) {
                        if (!info.arguments.empty())
                            info.arguments += L" " + childInfo.arguments;
                        else
                            info.arguments = childInfo.arguments;
                    }
                    info.workingDir = childInfo.workingDir.empty() ? info.workingDir : childInfo.workingDir;
                    info.iconPath = childInfo.iconPath.empty() ? info.iconPath : childInfo.iconPath;
                    info.iconIndex = childInfo.iconIndex;
                    info.showCmd = childInfo.showCmd;
                    info.description = childInfo.description.empty() ? info.description : childInfo.description;
                    info.targetExists = childInfo.targetExists;
                    info.fullTarget = info.targetPath;
                    if (!info.arguments.empty()) {
                        info.fullTarget += L" ";
                        info.fullTarget += info.arguments;
                    }
                    info.isLnkChain = true;
                    info.warnings.insert(info.warnings.end(), childInfo.warnings.begin(), childInfo.warnings.end());
                }
            }
        }

        if (!info.targetPath.empty() && info.targetExists) {
            info.targetFileExt = GetFileExtLower(info.targetPath);
            info.isTargetPE = IsPEFile(info.targetPath);
            if (info.isTargetPE || IsExecutableExtension(info.targetFileExt)) {
                info.hasValidSignature = VerifyDigitalSignature(info.targetPath);
            }
        }

        // 解析附加数据块（二进制）
        ParseLnkExtraData(expandedPath, info);

        info.success = true;
        ret = true;

    } while (false);

    if (pPersistFile) pPersistFile->Release();
    if (pShellLink) pShellLink->Release();
    CoUninitialize();

    return ret;
}

// 命令行参数分词检测
void AnalyzeArguments(const std::wstring& args, std::vector<std::wstring>& tokens, std::vector<std::wstring>& warnings) {
    std::wstring current;
    bool inQuotes = false;
    for (size_t i = 0; i < args.length(); ++i) {
        wchar_t c = args[i];
        if (c == L'"') {
            inQuotes = !inQuotes;
            current += c;
        } else if (std::iswspace(c) && !inQuotes) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty()) tokens.push_back(current);

    for (auto& tok : tokens) {
        tok = TrimQuotesAndSpaces(tok);
    }

    std::vector<std::pair<std::wregex, int>> patterns = {
        { std::wregex(LR"(-e(?:ncod(?:edcommand)?)?\s+)", std::regex::icase), 20 },
        { std::wregex(LR"((invoke-expression|iex|downloadstring|net\.webclient|start-process))", std::regex::icase), 25 },
        { std::wregex(LR"((cmd\s*/\s*c|powershell|wscript|cscript|rundll32|regsvr32|mshta|msiexec|certutil|bitsadmin))", std::regex::icase), 20 },
        { std::wregex(LR"(-windowstyle\s+hidden)", std::regex::icase), 15 },
        { std::wregex(LR"(-w\s+hidden)", std::regex::icase), 15 },
        { std::wregex(LR"(-exec\s+(bypass|unrestricted))", std::regex::icase), 20 },
        { std::wregex(LR"(-sta|-nop|-noprofile)", std::regex::icase), 10 },
        { std::wregex(LR"(http[s]?://\S+)", std::regex::icase), 25 },
        { std::wregex(LR"(\d+\.\d+\.\d+\.\d+)", std::regex::icase), 20 }
    };

    for (const auto& tok : tokens) {
        if (tok.empty()) continue;
        for (const auto& pat : patterns) {
            if (std::regex_search(tok, pat.first)) {
                warnings.push_back(L"Command line argument contains suspicious pattern: " + tok);
                break;
            }
        }
        if (tok.length() > 20 && IsBase64String(tok)) {
            warnings.push_back(L"Suspected Base64 encoded argument: " + tok.substr(0, 30) + L"...");
        }
    }
}

//图标完整性检测
void CheckIconIntegrity(const LnkInfo& info, std::vector<std::wstring>& warnings) {
    if (info.iconPath.empty() || info.targetPath.empty()) return;
    std::wstring iconLower = info.iconPath;
    std::transform(iconLower.begin(), iconLower.end(), iconLower.begin(), ::towlower);
    std::wstring targetLower = info.targetPath;
    std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::towlower);
    if (iconLower != targetLower) {
        warnings.push_back(L"Icon path does not match target path, possible masquerading");
        if (iconLower.find(L"shell32.dll") != std::wstring::npos ||
            iconLower.find(L"imageres.dll") != std::wstring::npos) {
            warnings.push_back(L"Icon points to system DLL but index may be abnormal");
        }
    }
}

//主要检测函数
bool CheckLnkSuspiciousEnhanced(const LnkInfo& info, int& score, std::wstring& reason) {
    score = 0;
    std::vector<std::wstring> warnings;
    std::map<std::wstring, int> weightMap = {
        {L"Target path is empty", 10},
        {L"Target file does not exist", 10},
        {L"Command line argument contains suspicious pattern", 20},
        {L"Suspected Base64 encoded argument", 20},
        {L"Icon path does not match target path, possible masquerading", 15},
        {L"Icon points to system DLL but index may be abnormal", 5},
        {L"Working directory is in sensitive location (Temp/Downloads/ProgramData/Public/AppData)", 10},
        {L"Target is in temp or downloads directory", 10},
        {L"Target filename appears randomly generated", 5},
        {L"Show window as hidden", 15},
        {L"Show window as minimized", 10},
        {L"Target is script file", 15},
        {L"Target has executable extension but is not a PE file, possible伪装", 10},
        {L"Target file does not have valid digital signature", 10},
        {L"LNK file has hidden attribute", 10},
        {L"LNK file has system attribute", 10},
        {L"Modified time is earlier than creation time", 5},
        {L"Creation time is close to current time", 5},
        {L"LNK chain", 5},
        {L"Working directory does not match target directory", 5},
        // 权重
        {L"Target is remote/network path (\\ or http)", 15},
        {L"Target points to WebDAV or OneDrive folder", 10},
        {L"Icon spoofing: suspicious icon index or PE icon file", 15},
        {L"System icon used with script target, possible phishing", 20}
    };

    if (info.targetPath.empty()) {
        warnings.push_back(L"Target path is empty");
    } else if (!info.targetExists) {
        warnings.push_back(L"Target file does not exist");
    }

    if (!info.arguments.empty()) {
        std::vector<std::wstring> tokens;
        AnalyzeArguments(info.arguments, tokens, warnings);
    }

    CheckIconIntegrity(info, warnings);

    if (!info.workingDir.empty()) {
        std::wstring workLower = info.workingDir;
        std::transform(workLower.begin(), workLower.end(), workLower.begin(), ::towlower);
        if (workLower.find(L"\\temp\\") != std::wstring::npos ||
            workLower.find(L"\\downloads\\") != std::wstring::npos ||
            workLower.find(L"%temp%") != std::wstring::npos ||
            workLower.find(L"\\programdata\\") != std::wstring::npos ||
            workLower.find(L"\\users\\public\\") != std::wstring::npos ||
            workLower.find(L"\\appdata\\") != std::wstring::npos) {
            warnings.push_back(L"Working directory is in sensitive location (Temp/Downloads/ProgramData/Public/AppData)");
        }
    }

    if (!info.targetPath.empty()) {
        std::wstring targetLower = info.targetPath;
        std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::towlower);
        bool inTempOrDownloads = (targetLower.find(L"\\temp\\") != std::wstring::npos ||
                                  targetLower.find(L"\\downloads\\") != std::wstring::npos ||
                                  targetLower.find(L"\\appdata\\local\\temp\\") != std::wstring::npos);
        if (inTempOrDownloads) {
            warnings.push_back(L"Target is in temp or downloads directory");
        }
        size_t pos = targetLower.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            std::wstring fname = targetLower.substr(pos + 1);
            size_t len = fname.length();
            if (len > 10) {
                bool hasDigit = false, hasAlpha = false;
                for (wchar_t ch : fname) {
                    if (iswdigit(ch)) hasDigit = true;
                    if (iswalpha(ch)) hasAlpha = true;
                }
                if (hasDigit && hasAlpha) {
                    warnings.push_back(L"Target filename appears randomly generated");
                }
            }
        }
        if (!info.workingDir.empty()) {
            std::wstring targetDir = targetLower.substr(0, targetLower.find_last_of(L"\\/"));
            std::wstring workLower = info.workingDir;
            std::transform(workLower.begin(), workLower.end(), workLower.begin(), ::towlower);
            if (targetDir != workLower && targetDir.find(workLower) == std::wstring::npos) {
                warnings.push_back(L"Working directory does not match target directory");
            }
        }
    }

    if (info.showCmd == SW_HIDE) {
        warnings.push_back(L"Show window as hidden");
    } else if (info.showCmd == SW_SHOWMINIMIZED || info.showCmd == SW_SHOWMINNOACTIVE) {
        warnings.push_back(L"Show window as minimized");
    }

    if (!info.targetPath.empty() && info.targetExists) {
        if (IsScriptExtension(info.targetFileExt)) {
            warnings.push_back(L"Target is script file (" + info.targetFileExt + L")");
        }
        if (IsExecutableExtension(info.targetFileExt) && !info.isTargetPE) {
            warnings.push_back(L"Target has executable extension but is not a PE file, possible伪装");
        }
        if (info.isTargetPE || IsExecutableExtension(info.targetFileExt)) {
            if (!info.hasValidSignature) {
                warnings.push_back(L"Target file does not have valid digital signature");
            }
        }
    }

    if (info.lnkFileAttributes & FILE_ATTRIBUTE_HIDDEN)
        warnings.push_back(L"LNK file has hidden attribute");
    if (info.lnkFileAttributes & FILE_ATTRIBUTE_SYSTEM)
        warnings.push_back(L"LNK file has system attribute");

    if (info.lnkCreationTime.dwLowDateTime != 0 && info.lnkLastWriteTime.dwLowDateTime != 0) {
        ULARGE_INTEGER create, write;
        create.LowPart = info.lnkCreationTime.dwLowDateTime;
        create.HighPart = info.lnkCreationTime.dwHighDateTime;
        write.LowPart = info.lnkLastWriteTime.dwLowDateTime;
        write.HighPart = info.lnkLastWriteTime.dwHighDateTime;
        if (write.QuadPart < create.QuadPart) {
            warnings.push_back(L"Modified time is earlier than creation time");
        }
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER now64;
        now64.LowPart = now.dwLowDateTime;
        now64.HighPart = now.dwHighDateTime;
        if (create.QuadPart > now64.QuadPart - 864000000000LL) {
            warnings.push_back(L"Creation time is close to current time");
        }
    }

    if (info.isLnkChain) {
        warnings.push_back(L"LNK chain (depth " + std::to_wstring(info.chainDepth) + L")");
    }
    // 远程路径检测
    if (!info.targetPath.empty()) {
        std::wstring targetLower = info.targetPath;
        std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::towlower);
        if (targetLower.find(L"\\\\") == 0 || targetLower.find(L"http://") == 0 || targetLower.find(L"https://") == 0) {
            warnings.push_back(L"Target is remote/network path (\\ or http)");
        }
        if (targetLower.find(L"\\onedrive\\") != std::wstring::npos ||
            targetLower.find(L"\\webdav\\") != std::wstring::npos) {
            warnings.push_back(L"Target points to WebDAV or OneDrive folder");
        }
    }

    // 图标伪装检测
    if (!info.iconPath.empty()) {
        std::wstring iconLower = info.iconPath;
        std::transform(iconLower.begin(), iconLower.end(), iconLower.begin(), ::towlower);
        std::wstring iconExt = GetFileExtLower(info.iconPath);
        bool isIconSpoof = false;
        bool isSystemIconWithScript = false;

        // 检查图标文件是否为 PE 且扩展名异常，或索引过大
        if (PathFileExistsW(info.iconPath.c_str())) {
            if (IsPEFile(info.iconPath)) {
                // 扩展名不是常见 PE 扩展名，或索引大于正常范围
                if (iconExt != L".exe" && iconExt != L".dll" && iconExt != L".cpl" && iconExt != L".scr") {
                    isIconSpoof = true;
                } else if (info.iconIndex > 100) {
                    isIconSpoof = true;
                }
            }
        }

        // 系统图标库 + 脚本目标
        bool isSystemIconLib = (iconLower.find(L"shell32.dll") != std::wstring::npos ||
                                iconLower.find(L"imageres.dll") != std::wstring::npos ||
                                iconLower.find(L"comctl32.dll") != std::wstring::npos);
        if (isSystemIconLib && !info.targetPath.empty() && info.targetExists) {
            std::wstring targetExt = GetFileExtLower(info.targetPath);
            if (IsScriptExtension(targetExt)) {
                isSystemIconWithScript = true;
            }
        }

        if (isIconSpoof) {
            warnings.push_back(L"Icon spoofing: suspicious icon index or PE icon file");
        }
        if (isSystemIconWithScript) {
            warnings.push_back(L"System icon used with script target, possible phishing");
        }
    }

    // 累积分值
    for (const auto& w : warnings) {
        auto it = weightMap.find(w);
        if (it != weightMap.end()) {
            score += it->second;
        } else {
            score += 8;
        }
    }
    if (score > 100) score = 100;

    if (!warnings.empty()) {
        reason = L"Detected suspicious features (score " + std::to_wstring(score) + L"):\n";
        for (const auto& w : warnings) {
            reason += L"  - " + w + L"\n";
        }
        return true;
    }
    return false;
}

//主函数
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    if (argc < 2) {
        printf("Usage: %s <shortcut path>\n", argv[0]);
        return 1;
    }
    if(argc>2){
        if(strcmp(argv[2], "--withoutUi")==0){
            withUi=0;
            std::cout << "running without Ui" << std::endl;}
        else if(strcmp(argv[2], "--onlywithUi")==0){
            withUi=2;
            std::cout << "running with any Ui" << std::endl;}
        else{
            withUi=1;
            std::cout << "running with Ui" << std::endl;
        }
    }
    else{withUi=1;}
    strcpy(filepath,argv[1]);
    std::wstring lnkPath;
    int len = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, nullptr, 0);
    if (len > 1) {
        lnkPath.resize(len - 1);
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, &lnkPath[0], len);
    }

    LnkInfo info;
    if (!GetLnkInfoEnhanced(lnkPath, info)) {
        printf("Failed to parse shortcut.\n");
        return 1;
    }

    printf("=== LNK Analysis Result (Enhanced) ===\n");
    printf("Original path: %ls\n", info.originalPath.c_str());
    printf("Target path: %ls\n", info.targetPath.c_str());
    if (info.hasSecondaryTarget) {
        printf("Secondary target (from IDList): %ls\n", info.secondaryTargetPath.c_str());
    }
    if (info.hasEnvironmentBlock) {
        printf("Environment variable target: %ls\n", info.extraEnvTarget.c_str());
    }
    if (info.hasSpecialFolderBlock) {
        printf("Special folder target: %ls\n", info.specialFolderTarget.c_str());
    }
    printf("Command line arguments: %ls\n", info.arguments.c_str());
    printf("Working directory: %ls\n", info.workingDir.c_str());
    printf("Icon path: %ls (index %d)\n", info.iconPath.c_str(), info.iconIndex);
    printf("Show window mode: %d %s\n", info.showCmd,
           info.showCmd == SW_HIDE ? "(hidden)" :
           info.showCmd == SW_SHOWMINIMIZED ? "(minimized)" : "");
    printf("Description: %ls\n", info.description.c_str());
    printf("Target file exists: %s\n", info.targetExists ? "Yes" : "No");
    printf("Target file signature valid: %s\n", info.hasValidSignature ? "Yes" : "No/Unknown");
    printf("Target file is PE: %s\n", info.isTargetPE ? "Yes" : "No");
    printf("LNK chain depth: %d\n", info.chainDepth);

    int score = 0;
    std::wstring reason;
    if (CheckLnkSuspiciousEnhanced(info, score, reason)) {
        printf("\n[WARNING] This LNK has high risk!\n");
        printf("%ls\n", reason.c_str());
        if (score >= 50) {
            printf("Risk level: High\n");
        } else if (score >= 25) {
            printf("Risk level: Medium\n");
        } else {
            printf("Risk level: Low\n");
        }
    } else {
        printf("\nNo obvious malicious modifications detected.\n");
    }
    if (score >= 50 && withUi==2){
        MessagetoControlCenter_by_Lnkanalyzer message = {};
        lstrcpyA(message.type, "Fileanalyzer");
        message.WindowType=2;
        lstrcpyA(message.path, filepath);
        message.score=score;
        lstrcpyA(message.details, "");
        std::thread server(ClientThread_to_ControlCenter, &message);
        server.join();
    }
    else if (withUi==1){
        MessagetoControlCenter_by_Lnkanalyzer message = {};
        lstrcpyA(message.type, "Fileanalyzer");
        message.WindowType=4;
        lstrcpyA(message.path, filepath);
        message.score=score;
        lstrcpyA(message.details, "");
        std::thread server(ClientThread_to_ControlCenter, &message);
        server.join();
    }
    return 0;
}