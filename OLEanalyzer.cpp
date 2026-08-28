/*
OLEanalyzer.cpp
分析层

分析OLE2文件，评估潜在风险

命令行参数：
argv[0] --- OLEanalyzer.exe
argv[1] --- 需要分析的ole2文件路径
argv[2] --- 可选参数，"--withoutUi"表示不弹窗，"--onlywithUi"表示仅高危弹窗，其他情况默认弹窗+分析

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\OLEanalyzer.cpp" -o "%ExecutablePath%\OLEanalyzer.exe" -lole32 -loleaut32 -luuid -lshlwapi -mwindows

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
#include <objbase.h>
#include <ole2.h>
#include <objidl.h>
#include <random>
#include <chrono>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_OLEanalyzer"

#pragma pack(push, 1)
struct MessageToControlCenter {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
#pragma pack(pop)
#define PIPE_MESSAGE_SIZE sizeof(MessageToControlCenter)

HANDLE ConnectToPipe(const wchar_t* pipeName) {
    while (true) {
        if (WaitNamedPipeW(pipeName, 1000)) {
            HANDLE hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE,
                                       0, NULL, OPEN_EXISTING, 0, NULL);
            if (hPipe != INVALID_HANDLE_VALUE) {
                std::cout << "Success connecting to pipe" << std::endl;
                return hPipe;
            }
        }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PIPE_BUSY) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        } else {
            std::cerr << "Pipe error, code: " << err << std::endl;
            return INVALID_HANDLE_VALUE;
        }
    }
}

void ClientThread_ToControlCenter(MessageToControlCenter* msg) {
    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to connect to pipe" << std::endl;
        return;
    }
    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
        std::cerr << "Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}


struct OfficeDocInfo {
    std::wstring filePath;
    bool isOLE = false;
    bool hasMacro = false;
    std::wstring macroCode;
    std::vector<std::wstring> embeddedObjectNames; // 原始名称（OLE 专用）
    std::vector<std::wstring> extractedFiles;      // 提取的 PE/脚本文件路径
    std::vector<std::wstring> warnings;
    int riskScore = 0;
    bool success = false;
};

std::wstring Trim(const std::wstring& s) {
    size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return L"";
    size_t end = s.find_last_not_of(L" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::wstring ExpandEnv(const std::wstring& input) {
    if (input.empty()) return input;
    wchar_t buffer[32767] = {0};
    DWORD size = ExpandEnvironmentStringsW(input.c_str(), buffer, _countof(buffer));
    if (size == 0 || size > _countof(buffer)) return input;
    return std::wstring(buffer);
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

// 获取当前程序所在目录
std::wstring GetAppDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L'\\');
    if (pos != std::wstring::npos)
        return fullPath.substr(0, pos);
    return L"";
}

// 在程序所在路径的 .\Temp\ 下创建唯一临时子目录
std::wstring CreateTempDirectoryInAppPath() {
    std::wstring appDir = GetAppDirectory();
    if (appDir.empty()) return L"";

    std::wstring tempDir = appDir + L"\\Temp";
    // 确保 Temp 目录存在
    if (!CreateDirectoryW(tempDir.c_str(), NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            std::wcerr << L"Failed to create Temp directory" << std::endl;
            return L"";
        }
    }

    // 创建唯一子目录（时间戳 + 随机数兜底）
    std::wstring subDir = tempDir + L"\\MalOffice_" +
        std::to_wstring(std::chrono::steady_clock::now().time_since_epoch().count());
    if (!CreateDirectoryW(subDir.c_str(), NULL)) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        subDir = tempDir + L"\\MalOffice_" + std::to_wstring(dis(gen));
        if (!CreateDirectoryW(subDir.c_str(), NULL)) {
            std::wcerr << L"Failed to create unique temp subdirectory" << std::endl;
            return L"";
        }
    }
    return subDir;
}

// 递归删除目录
bool DeleteDirectory(const std::wstring& path) {
    std::wstring search = path + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return false;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring fullPath = path + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteDirectory(fullPath);
            RemoveDirectoryW(fullPath.c_str());
        } else {
            DeleteFileW(fullPath.c_str());
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    RemoveDirectoryW(path.c_str());
    return true;
}

// 递归搜索文件（支持通配符）
void SearchFilesRecursive(const std::wstring& dir, const std::wstring& pattern, std::vector<std::wstring>& outFiles) {
    std::wstring search = dir + L"\\" + pattern;
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            outFiles.push_back(dir + L"\\" + fd.cFileName);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    // 递归子目录
    search = dir + L"\\*";
    hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::wstring subDir = dir + L"\\" + fd.cFileName;
                SearchFilesRecursive(subDir, pattern, outFiles);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

// 读取流到字符串
bool ReadStreamToString(IStream* pStream, std::string& out) {
    STATSTG stat;
    if (FAILED(pStream->Stat(&stat, STATFLAG_NONAME))) return false;
    ULONG size = stat.cbSize.LowPart;
    if (size == 0) return true;
    char* buffer = new char[size + 1];
    ULONG read = 0;
    HRESULT hr = pStream->Read(buffer, size, &read);
    if (FAILED(hr) || read != size) {
        delete[] buffer;
        return false;
    }
    buffer[size] = '\0';
    out.assign(buffer, size);
    delete[] buffer;
    return true;
}

//OLE 宏提取（适用于 vbaProject.bin 或 OLE 文档）
bool ExtractMacroCodeFromOleStorage(IStorage* pStorage, std::wstring& code) {
    IStorage* pVbaStorage = nullptr;
    HRESULT hr = pStorage->OpenStorage(L"VBA", nullptr, STGM_READ | STGM_SHARE_EXCLUSIVE,
                                       nullptr, 0, &pVbaStorage);
    if (FAILED(hr)) return false;

    IEnumSTATSTG* pEnum = nullptr;
    hr = pVbaStorage->EnumElements(0, nullptr, 0, &pEnum);
    if (FAILED(hr)) {
        pVbaStorage->Release();
        return false;
    }

    STATSTG stat;
    ULONG fetched;
    bool found = false;
    while (pEnum->Next(1, &stat, &fetched) == S_OK) {
        if (stat.type == STGTY_STREAM) {
            std::wstring name = stat.pwcsName;
            if (name.find(L"Module") != std::wstring::npos ||
                name.find(L"This") != std::wstring::npos ||
                name.find(L"Class") != std::wstring::npos) {
                if (name == L"_VBA_PROJECT" || name == L"dir") {
                    CoTaskMemFree(stat.pwcsName);
                    continue;
                }
                IStream* pStream = nullptr;
                hr = pVbaStorage->OpenStream(name.c_str(), nullptr, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &pStream);
                if (SUCCEEDED(hr)) {
                    std::string ansi;
                    if (ReadStreamToString(pStream, ansi)) {
                        int wlen = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, nullptr, 0);
                        if (wlen > 0) {
                            std::wstring wstr(wlen - 1, L'\0');
                            MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, &wstr[0], wlen);
                            code += L"\n--- Module: " + name + L" ---\n";
                            code += wstr;
                            found = true;
                        }
                    }
                    pStream->Release();
                }
            }
        }
        CoTaskMemFree(stat.pwcsName);
    }
    pEnum->Release();
    pVbaStorage->Release();
    return found;
}

// 针对单独文件的封装
bool ExtractMacroCodeFromOleFile(const std::wstring& oleFilePath, std::wstring& code) {
    IStorage* pStorage = nullptr;
    HRESULT hr = StgOpenStorage(oleFilePath.c_str(), NULL, STGM_READ | STGM_SHARE_EXCLUSIVE,
                                NULL, 0, &pStorage);
    if (FAILED(hr) || !pStorage) return false;
    bool ret = ExtractMacroCodeFromOleStorage(pStorage, code);
    pStorage->Release();
    return ret;
}

//宏代码分析
void AnalyzeMacroCode(const std::wstring& code, std::vector<std::wstring>& warnings) {
    std::vector<std::pair<std::wregex, int>> patterns = {
        { std::wregex(LR"(CreateObject\s*\(\s*[\"']WScript\.Shell[\"']\s*\))", std::regex::icase), 25 },
        { std::wregex(LR"(CreateObject\s*\(\s*[\"']Shell\.Application[\"']\s*\))", std::regex::icase), 25 },
        { std::wregex(LR"(CreateObject\s*\(\s*[\"']MSXML2\.XMLHTTP[\"']\s*\))", std::regex::icase), 20 },
        { std::wregex(LR"(Shell\s*\(\s*[\"']cmd\.exe[\"']\s*\))", std::regex::icase), 20 },
        { std::wregex(LR"(Shell\s*\(\s*[\"']powershell\.exe[\"']\s*\))", std::regex::icase), 20 },
        { std::wregex(LR"(Run\s*\(\s*[\"']\s*cmd\.exe)", std::regex::icase), 15 },
        { std::wregex(LR"(Run\s*\(\s*[\"']\s*powershell)", std::regex::icase), 15 },
        { std::wregex(LR"(WScript\.Shell)", std::regex::icase), 20 },
        { std::wregex(LR"(Exec\s*\(\s*[\"']\s*(cmd|powershell|wscript|cscript))", std::regex::icase), 20 },
        { std::wregex(LR"(http[s]?://\S+)", std::regex::icase), 20 },
        { std::wregex(LR"(\d+\.\d+\.\d+\.\d+)", std::regex::icase), 15 },
        { std::wregex(LR"(Base64\s*\(|FromBase64String)", std::regex::icase), 20 },
        { std::wregex(LR"(Auto_Open|AutoExec|Document_Open|Workbook_Open|SlideShow_Start)", std::regex::icase), 20 },
        { std::wregex(LR"(Sub\s+AutoExec\(\)|Sub\s+AutoOpen\(\))", std::regex::icase), 20 },
        { std::wregex(LR"(RegExp|VBScript)", std::regex::icase), 10 },
        { std::wregex(LR"(\\\.\\\\|\\\\|net\s+use|wmic\s+process)", std::regex::icase), 15 }
    };

    std::wistringstream iss(code);
    std::wstring line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        for (const auto& pat : patterns) {
            if (std::regex_search(line, pat.first)) {
                warnings.push_back(L"Suspicious macro code: " + Trim(line));
                break;
            }
        }
        if (line.length() > 20 && IsBase64String(line)) {
            warnings.push_back(L"Suspected Base64 encoded string in macro: " + line.substr(0, 30) + L"...");
        }
        if (line.length() > 50) {
            int spaceCount = 0;
            for (wchar_t ch : line) if (ch == L' ') spaceCount++;
            if (spaceCount > line.length() / 2) {
                warnings.push_back(L"Macro code appears heavily obfuscated: " + line.substr(0, 40) + L"...");
            }
        }
    }
}

//文件类型检测
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

bool IsScriptFile(const std::wstring& path) {
    std::wstring ext = path;
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    size_t pos = ext.find_last_of(L'.');
    if (pos == std::wstring::npos) return false;
    std::wstring extOnly = ext.substr(pos);
    static std::set<std::wstring> scriptExts = { L".ps1", L".vbs", L".js", L".cmd", L".bat", L".jar", L".hta", L".py" };
    return scriptExts.find(extOnly) != scriptExts.end();
}

//调用外部分析器（异步）
void InvokeExternalAnalyzer(const std::wstring& filePath, const std::wstring& analyzerName) {
    std::thread([filePath, analyzerName]() {
        std::wstring cmd = analyzerName + L" \"" + filePath + L"\"";
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            std::wcerr << L"Failed to launch " << analyzerName << L" for " << filePath << std::endl;
        }
    }).detach();
}

//处理 ZIP 文档（使用外部传入的临时目录）
bool AnalyzeZipDocument(const std::wstring& zipPath, OfficeDocInfo& info, const std::wstring& tempDir) {
    if (tempDir.empty()) {
        info.warnings.push_back(L"Invalid temporary directory");
        return false;
    }

    // 复制为 .zip 扩展名（解决 Expand-Archive 扩展名限制）
    std::wstring zipCopy = tempDir + L"\\temp.zip";
    if (!CopyFileW(zipPath.c_str(), zipCopy.c_str(), FALSE)) {
        info.warnings.push_back(L"Failed to copy file to .zip extension");
        return false;
    }

    // PowerShell 解压
    std::wstring psCmd = L"powershell -Command \"Expand-Archive -LiteralPath '" + zipCopy + L"' -DestinationPath '" + tempDir + L"' -Force\"";
    std::wcout << L"Extracting ZIP to " << tempDir << L" ..." << std::endl;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, (LPWSTR)psCmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        info.warnings.push_back(L"Failed to start PowerShell for ZIP extraction");
        DeleteFileW(zipCopy.c_str());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteFileW(zipCopy.c_str());  // 删除临时 zip 副本

    // 递归搜索 vbaProject.bin 和嵌入对象文件
    std::vector<std::wstring> vbaProjectFiles;
    SearchFilesRecursive(tempDir, L"vbaProject.bin", vbaProjectFiles);
    std::vector<std::wstring> embeddedFiles;
    SearchFilesRecursive(tempDir, L"*.bin", embeddedFiles);
    SearchFilesRecursive(tempDir, L"*.ole", embeddedFiles);
    SearchFilesRecursive(tempDir, L"*.dat", embeddedFiles);

    // 过滤掉 vbaProject.bin（已单独处理）
    auto it = std::remove_if(embeddedFiles.begin(), embeddedFiles.end(),
        [&](const std::wstring& f) { return std::find(vbaProjectFiles.begin(), vbaProjectFiles.end(), f) != vbaProjectFiles.end(); });
    embeddedFiles.erase(it, embeddedFiles.end());

    // 分析 vbaProject.bin
    bool hasMacro = false;
    for (const auto& vbaPath : vbaProjectFiles) {
        std::wstring code;
        if (ExtractMacroCodeFromOleFile(vbaPath, code)) {
            hasMacro = true;
            info.macroCode += code;
            AnalyzeMacroCode(code, info.warnings);
        }
    }
    info.hasMacro = hasMacro;

    // 处理嵌入文件（PE/脚本检测）
    for (const auto& file : embeddedFiles) {
        if (IsPEFile(file)) {
            info.warnings.push_back(L"Embedded PE file found: " + file);
            info.extractedFiles.push_back(file);
        } else if (IsScriptFile(file)) {
            info.warnings.push_back(L"Embedded script file found: " + file);
            info.extractedFiles.push_back(file);
        } else {
            // 尝试作为 OLE 存储打开，检查 CONTENTS 流
            IStorage* pStore = nullptr;
            if (SUCCEEDED(StgOpenStorage(file.c_str(), NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, NULL, 0, &pStore))) {
                IStream* pStream = nullptr;
                if (SUCCEEDED(pStore->OpenStream(L"CONTENTS", nullptr, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &pStream))) {
                    BYTE header[10] = {0};
                    ULONG read = 0;
                    if (SUCCEEDED(pStream->Read(header, sizeof(header), &read)) && read >= 4) {
                        if (header[0] == 'M' && header[1] == 'Z') {
                            info.warnings.push_back(L"Embedded OLE object contains PE: " + file);
                            info.extractedFiles.push_back(file);
                        } else if (header[0] == '#' && header[1] == '!') {
                            info.warnings.push_back(L"Embedded OLE object contains script: " + file);
                            info.extractedFiles.push_back(file);
                        }
                    }
                    pStream->Release();
                }
                pStore->Release();
            }
        }
    }

    // 调用外部分析器
    for (const auto& file : info.extractedFiles) {
        if (IsPEFile(file))
            InvokeExternalAnalyzer(file, L"PEanalyzer.exe");
        else if (IsScriptFile(file) || !info.warnings.empty())
            InvokeExternalAnalyzer(file, L"CMDanalyzer.exe");
    }

    info.success = true;
    return true;
}

//分析 OLE 文档
bool AnalyzeOleDocument(const std::wstring& filePath, OfficeDocInfo& info) {
    IStorage* pStorage = nullptr;
    HRESULT hr = StgOpenStorage(filePath.c_str(), NULL, STGM_READ | STGM_SHARE_EXCLUSIVE,
                                NULL, 0, &pStorage);
    if (FAILED(hr) || !pStorage) {
        info.warnings.push_back(L"Failed to open OLE storage");
        return false;
    }

    // 提取宏
    std::wstring code;
    if (ExtractMacroCodeFromOleStorage(pStorage, code)) {
        info.hasMacro = true;
        info.macroCode = code;
        AnalyzeMacroCode(code, info.warnings);
    }

    // 检测嵌入对象（枚举存储）
    IEnumSTATSTG* pEnumStore = nullptr;
    hr = pStorage->EnumElements(0, nullptr, 0, &pEnumStore);
    if (SUCCEEDED(hr)) {
        STATSTG stat;
        ULONG fetched;
        while (pEnumStore->Next(1, &stat, &fetched) == S_OK) {
            if (stat.type == STGTY_STORAGE) {
                std::wstring name = stat.pwcsName;
                if (name.find(L"Object") != std::wstring::npos || name.find(L"Ole") != std::wstring::npos) {
                    info.embeddedObjectNames.push_back(name);
                    IStorage* pObjStore = nullptr;
                    if (SUCCEEDED(pStorage->OpenStorage(name.c_str(), nullptr, STGM_READ | STGM_SHARE_EXCLUSIVE, nullptr, 0, &pObjStore))) {
                        IStream* pStream = nullptr;
                        if (SUCCEEDED(pObjStore->OpenStream(L"CONTENTS", nullptr, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &pStream))) {
                            BYTE header[10] = {0};
                            ULONG read = 0;
                            if (SUCCEEDED(pStream->Read(header, sizeof(header), &read)) && read >= 4) {
                                if (header[0] == 'M' && header[1] == 'Z') {
                                    info.warnings.push_back(L"Embedded object contains PE: " + name);
                                } else if (header[0] == '#' && header[1] == '!') {
                                    info.warnings.push_back(L"Embedded object contains script: " + name);
                                }
                            }
                            pStream->Release();
                        }
                        pObjStore->Release();
                    }
                }
            }
            CoTaskMemFree(stat.pwcsName);
        }
        pEnumStore->Release();
    }

    pStorage->Release();
    info.success = true;
    return true;
}

// 风险评分
void CalculateRiskScore(OfficeDocInfo& info) {
    int score = 0;
    std::map<std::wstring, int> weightMap = {
        {L"Contains macro code", 10},
        {L"Suspicious macro code: CreateObject(\"WScript.Shell\")", 25},
        {L"Suspicious macro code: CreateObject(\"Shell.Application\")", 25},
        {L"Suspicious macro code: Shell(\"cmd.exe\")", 20},
        {L"Suspicious macro code: Shell(\"powershell.exe\")", 20},
        {L"Suspicious macro code: Run(\"cmd.exe\")", 15},
        {L"Suspicious macro code: Run(\"powershell\")", 15},
        {L"Suspicious macro code: WScript.Shell", 20},
        {L"Suspicious macro code: Exec(\"cmd\")", 20},
        {L"Suspicious macro code: URL detected", 20},
        {L"Suspicious macro code: IP address", 15},
        {L"Suspicious macro code: Base64", 20},
        {L"Suspicious macro code: Auto_Open/AutoExec", 20},
        {L"Suspicious macro code: Obfuscated", 15},
        {L"Embedded object contains executable (PE)", 30},
        {L"Embedded object contains script", 25},
        {L"Macro code appears heavily obfuscated", 20},
        {L"Embedded PE file found", 30},
        {L"Embedded script file found", 25},
        {L"Embedded OLE object contains PE", 30}
    };

    for (const auto& w : info.warnings) {
        auto it = weightMap.find(w);
        if (it != weightMap.end()) {
            score += it->second;
        } else {
            for (const auto& pair : weightMap) {
                if (w.find(pair.first) != std::wstring::npos) {
                    score += pair.second;
                    break;
                }
            }
        }
    }
    info.riskScore = (score > 100) ? 100 : score;
}

//主函数
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc < 2) {
        printf("Usage: %s <document path>\n", argv[0]);
        return 1;
    }

    int withUi = 1;
    char filepath[32768] = {0};
    strcpy_s(filepath, argv[1]);
    if (argc > 2 && strcmp(argv[2], "--withoutUi") == 0) {
        withUi = 0;
        std::cout << "Running without UI" << std::endl;
    } else if (argc > 2 && strcmp(argv[2], "--onlywithUi") == 0) {
        withUi = 2;
        std::cout << "Running only with UI (high risk only)" << std::endl;
    }

    int len = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, nullptr, 0);
    std::wstring wPath;
    if (len > 1) {
        wPath.resize(len - 1);
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, &wPath[0], len);
    } else {
        printf("Invalid path\n");
        return 1;
    }

    // 读取文件签名判断类型
    HANDLE hFile = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Cannot open file\n");
        return 1;
    }
    BYTE sig[8] = {0};
    DWORD read = 0;
    if (!ReadFile(hFile, sig, sizeof(sig), &read, NULL) || read < 8) {
        CloseHandle(hFile);
        printf("Cannot read file signature\n");
        return 1;
    }
    CloseHandle(hFile);

    bool isOLE = false, isZIP = false;
    if (sig[0] == 0xD0 && sig[1] == 0xCF && sig[2] == 0x11 && sig[3] == 0xE0 &&
        sig[4] == 0xA1 && sig[5] == 0xB1 && sig[6] == 0x1A && sig[7] == 0xE1) {
        isOLE = true;
    } else if (sig[0] == 0x50 && sig[1] == 0x4B && (sig[2] == 0x03 || sig[2] == 0x05 || sig[2] == 0x07)) {
        isZIP = true;
    } else {
        printf("Unsupported file format\n");
        return 1;
    }

    OfficeDocInfo info;
    info.filePath = wPath;
    info.isOLE = isOLE;
    bool analysisOk = false;

    if (isOLE) {
        analysisOk = AnalyzeOleDocument(wPath, info);
    } else if (isZIP) {
    std::wstring tempDir = CreateTempDirectoryInAppPath();
    if (tempDir.empty()) {
        printf("Failed to create temporary directory\n");
        return 1;
    }

    // 在临时目录下创建 _filepath_.txt，写入原文件绝对路径
    std::wstring pathFile = tempDir + L"\\_filepath_.txt";
    HANDLE hFile = CreateFileW(pathFile.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        // 写入内容为原文件路径，结尾加换行符（可选）
        std::wstring content = wPath ;
        WriteFile(hFile, content.c_str(),
                  static_cast<DWORD>(content.size() * sizeof(wchar_t)),
                  &written, NULL);
        CloseHandle(hFile);
    } else {
        // 写入失败仅作提示，不影响后续分析
        std::wcerr << L"Warning: Failed to create _filepath_.txt" << std::endl;
    }

    analysisOk = AnalyzeZipDocument(wPath, info, tempDir);
    DeleteDirectory(tempDir);
    }

    if (!analysisOk) {
        printf("Analysis failed.\n");
        return 1;
    }

    CalculateRiskScore(info);

    printf("=== Office Document Analysis Result ===\n");
    printf("File path: %ls\n", info.filePath.c_str());
    printf("File type: %ls\n", info.isOLE ? L"OLE Compound Document" : L"ZIP Container");
    printf("Has macro: %s\n", info.hasMacro ? "Yes" : "No");
    if (info.hasMacro) {
        printf("Macro code length: %zu characters\n", info.macroCode.length());
        printf("Macro snippet: %ls...\n", info.macroCode.substr(0, 200).c_str());
    }
    printf("Embedded objects found: %zu\n", info.embeddedObjectNames.size());
    for (const auto& name : info.embeddedObjectNames) {
        printf("  - %ls\n", name.c_str());
    }
    printf("Extracted suspicious files: %zu\n", info.extractedFiles.size());
    for (const auto& f : info.extractedFiles) {
        printf("  - %ls\n", f.c_str());
    }
    printf("Risk Score: %d\n", info.riskScore);

    if (info.warnings.empty()) {
        printf("\nNo obvious malicious signs detected.\n");
    } else {
        printf("\n[WARNING] Suspicious features:\n");
        for (const auto& w : info.warnings) {
            printf("  - %ls\n", w.c_str());
        }
        if (info.riskScore >= 50) printf("Risk level: High\n");
        else if (info.riskScore >= 25) printf("Risk level: Medium\n");
        else printf("Risk level: Low\n");
    }

    if (withUi == 1 || (withUi == 2 && info.riskScore >= 50)) {
        MessageToControlCenter message = {};
        lstrcpyA(message.type, "Fileanalyzer");
        if(withUi==2){message.WindowType = 2;}
        else{message.WindowType = 4;}
        lstrcpyA(message.path, filepath);
        message.score = info.riskScore;
        std::string details;
        for (const auto& w : info.warnings) {
            std::string narrow;
            int wnlen = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (wnlen > 0) {
                narrow.resize(wnlen - 1);
                WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, &narrow[0], wnlen, nullptr, nullptr);
                details += "- " + narrow + "\n";
            }
        }
        lstrcpyA(message.details, details.c_str());
        std::thread server(ClientThread_ToControlCenter, &message);
        server.join();
    }

    return 0;
}