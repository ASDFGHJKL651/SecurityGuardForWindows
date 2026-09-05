/*
PDFanalyzer.cpp
分析层

分析PDF文件，评估潜在风险

命令行参数：
argv[0] --- PDFanalyzer.exe
argv[1] --- 需要分析的.pdf文件路径
argv[2] --- 可选参数，"--withoutUi"表示不弹窗，"--onlywithUi"表示仅高危弹窗，其他情况默认弹窗+分析

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\PDFanalyzer.cpp" -o "%ExecutablePath%\PDFanalyzer.exe" -mwindows

运行权限：管理员权限
*/
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <comdef.h>
#include <psapi.h>          // 内存监控
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
#include <sstream>
#include <thread>
#include <chrono>
#include <random>
#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")     // 内存信息

//  管道通信 
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_PDFanalyzer"

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

//  安全阈值 
const int MAX_OBJECT_COUNT = 10000;                 // 对象数量上限
const int MAX_DICT_DEPTH = 20;                     // 字典嵌套深度上限
const size_t MAX_STREAM_LENGTH = 10 * 1024 * 1024; // 10MB
const size_t MAX_MEMORY_WORKINGSET_MB = 200;       // 工作集内存上限 200MB
const size_t MAX_ARRAY_BUFFER_MB = 100;            // ArrayBuffer 大小上限 100MB
const size_t MAX_SPECIAL_KEY_LEN = 32;             // /U 或 /O 键值长度上限

//  全局变量（用于内存监控） 
bool g_memoryExceeded = false;
size_t g_processedObjects = 0;

//  辅助函数（原有，略作调整） 
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

std::wstring GetAppDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L'\\');
    if (pos != std::wstring::npos)
        return fullPath.substr(0, pos);
    return L"";
}

std::wstring CreateTempDirectoryInAppPath() {
    std::wstring appDir = GetAppDirectory();
    if (appDir.empty()) return L"";

    std::wstring tempDir = appDir + L"\\Temp";
    if (!CreateDirectoryW(tempDir.c_str(), NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            std::wcerr << L"Failed to create Temp directory" << std::endl;
            return L"";
        }
    }

    std::wstring subDir = tempDir + L"\\PDFAnalyzer_" +
        std::to_wstring(std::chrono::steady_clock::now().time_since_epoch().count());
    if (!CreateDirectoryW(subDir.c_str(), NULL)) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        subDir = tempDir + L"\\PDFAnalyzer_" + std::to_wstring(dis(gen));
        if (!CreateDirectoryW(subDir.c_str(), NULL)) {
            std::wcerr << L"Failed to create unique temp subdirectory" << std::endl;
            return L"";
        }
    }
    return subDir;
}

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

//  文件类型检测 
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

//  调用外部分析器 
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

//  管道客户端 
HANDLE ConnectToPipe(const wchar_t* pipeName) {
    while (true) {
        if (WaitNamedPipeW(pipeName, 1000)) {
            HANDLE hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE,
                                       0, NULL, OPEN_EXISTING, 0, NULL);
            if (hPipe != INVALID_HANDLE_VALUE) {
                std::wcout << L"Success connecting to pipe" << std::endl;
                return hPipe;
            }
        }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PIPE_BUSY) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        } else {
            std::wcerr << L"Pipe error, code: " << err << std::endl;
            return INVALID_HANDLE_VALUE;
        }
    }
}

void ClientThread_ToControlCenter(MessageToControlCenter* msg) {
    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to connect to pipe" << std::endl;
        return;
    }
    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
        std::wcerr << L"Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}

//  PDF 文档信息结构 
struct PDFDocInfo {
    std::wstring filePath;
    bool isPDF = false;
    bool hasJavaScript = false;
    bool hasAutoAction = false;
    bool hasEmbeddedFile = false;
    std::vector<std::wstring> extractedFiles;
    std::vector<std::wstring> warnings;
    int riskScore = 0;
    bool success = false;
    std::wstring jsCode;
    std::vector<std::wstring> embeddedObjectNames;
    bool hasEncryption = false;          // 加密标记
    bool hasJBIG2Decode = false;         // JBIG2过滤器
};

//  扩展的解析函数（支持深度限制） 
// 提取对象中的字典，同时限制嵌套深度
std::string ExtractDict(const std::string& objData, size_t startPos, int& depth, bool& depthExceeded) {
    size_t pos = objData.find("<<", startPos);
    if (pos == std::string::npos) return "";
    int currentDepth = 0;
    size_t endPos = pos;
    for (size_t i = pos; i < objData.size(); ++i) {
        if (objData[i] == '<' && i+1 < objData.size() && objData[i+1] == '<') {
            currentDepth++;
            i++;
            if (currentDepth > MAX_DICT_DEPTH) {
                depthExceeded = true;
                return "";
            }
        } else if (objData[i] == '>' && i+1 < objData.size() && objData[i+1] == '>') {
            currentDepth--;
            i++;
            if (currentDepth == 0) {
                endPos = i+1;
                break;
            }
        }
    }
    if (currentDepth != 0) return "";
    depth = std::max(depth, currentDepth);
    return objData.substr(pos, endPos - pos);
}

// 在字典中查找键（忽略大小写）
bool DictHasKey(const std::string& dict, const std::string& key) {
    std::string search = "/" + key;
    size_t pos = dict.find(search);
    if (pos == std::string::npos) return false;
    size_t next = pos + search.size();
    if (next < dict.size() && (isalnum(dict[next]) || dict[next] == '_')) {
        return false;
    }
    return true;
}

// 从字典中提取键对应的值（字符串形式）
std::string GetDictValue(const std::string& dict, const std::string& key) {
    std::string search = "/" + key;
    size_t pos = dict.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    while (pos < dict.size() && isspace(dict[pos])) pos++;
    size_t start = pos;
    while (pos < dict.size() && !isspace(dict[pos]) && dict[pos] != '/' && dict[pos] != '[' && dict[pos] != '(') pos++;
    return dict.substr(start, pos - start);
}

// 提取流内容（在 "stream" 和 "endstream" 之间）
std::string ExtractStream(const std::string& objData, size_t streamPos) {
    size_t pos = objData.find("stream", streamPos);
    if (pos == std::string::npos) return "";
    pos += 6;
    while (pos < objData.size() && (objData[pos] == '\r' || objData[pos] == '\n')) pos++;
    size_t endPos = objData.find("endstream", pos);
    if (endPos == std::string::npos) return "";
    return objData.substr(pos, endPos - pos);
}

// 从字符串中提取对象编号（例如 "123 0 obj" 返回 123）
int ExtractObjectNumber(const std::string& objStart) {
    size_t pos = objStart.find("obj");
    if (pos == std::string::npos) return -1;
    // 向前找到数字
    size_t start = pos;
    while (start > 0 && isdigit(objStart[start-1])) start--;
    if (start == pos) return -1;
    std::string numStr = objStart.substr(start, pos - start - 1);
    // 去除空格
    numStr.erase(0, numStr.find_first_not_of(" \t"));
    numStr.erase(numStr.find_last_not_of(" \t") + 1);
    if (numStr.empty()) return -1;
    return std::stoi(numStr);
}

// 检查字符串是否为数字
bool IsNumber(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) if (!isdigit(c)) return false;
    return true;
}

// 解析单个对象
void ParseObject(const std::string& objData, PDFDocInfo& info, const std::wstring& tempDir,
                 std::set<int>& visitedObjects, bool& stopParsing) {
    if (stopParsing) return;

    // 提取对象编号并检查重复引用
    int objNum = ExtractObjectNumber(objData);
    if (objNum != -1) {
        if (visitedObjects.find(objNum) != visitedObjects.end()) {
            info.warnings.push_back(L"循环引用检测：对象 " + std::to_wstring(objNum) + L" 重复出现");
            return; // 跳过重复对象
        }
        visitedObjects.insert(objNum);
    }

    // 提取字典，带深度限制
    int depth = 0;
    bool depthExceeded = false;
    std::string dict = ExtractDict(objData, 0, depth, depthExceeded);
    if (depthExceeded) {
        info.warnings.push_back(L"字典嵌套深度超过 " + std::to_wstring(MAX_DICT_DEPTH) + L" 层，疑似畸形结构");
        return; // 不继续解析此对象
    }
    if (dict.empty()) return;

    // 检测加密标记
    if (DictHasKey(dict, "Encrypt")) {
        info.hasEncryption = true;
        info.warnings.push_back(L"发现 /Encrypt 字典，内容加密，静态解析可能不完整");
    }

    // 检测漏洞利用模式：/U 或 /O 异常长度，JBIG2Decode
    if (DictHasKey(dict, "U")) {
        std::string uVal = GetDictValue(dict, "U");
        if (uVal.size() > MAX_SPECIAL_KEY_LEN) {
            info.warnings.push_back(L"/U 键值长度异常 (" + std::to_wstring(uVal.size()) + L")，可能与 CVE-2010-2883 相关");
        }
    }
    if (DictHasKey(dict, "O")) {
        std::string oVal = GetDictValue(dict, "O");
        if (oVal.size() > MAX_SPECIAL_KEY_LEN) {
            info.warnings.push_back(L"/O 键值长度异常 (" + std::to_wstring(oVal.size()) + L")，可能与 CVE-2010-2883 相关");
        }
    }

    // 检查过滤器
    if (DictHasKey(dict, "Filter")) {
        std::string filter = GetDictValue(dict, "Filter");
        if (filter.find("/JBIG2Decode") != std::string::npos) {
            info.hasJBIG2Decode = true;
            info.warnings.push_back(L"包含 JBIG2Decode 过滤器，常与内存损坏漏洞 (CVE-2010-2883) 相关");
        }
        // 检测压缩流膨胀风险 (FlateDecode)
        if (filter.find("/FlateDecode") != std::string::npos || filter.find("/Flate") != std::string::npos) {
            // 获取 /Length 声明
            std::string lengthStr = GetDictValue(dict, "Length");
            size_t declaredLen = 0;
            if (!lengthStr.empty() && IsNumber(lengthStr)) {
                declaredLen = std::stoull(lengthStr);
            }
            // 获取实际流大小
            size_t streamPos = objData.find("stream");
            size_t actualLen = 0;
            if (streamPos != std::string::npos) {
                std::string streamData = ExtractStream(objData, streamPos);
                actualLen = streamData.size();
            }
            // 检查声明长度是否超过阈值
            if (declaredLen > MAX_STREAM_LENGTH) {
                info.warnings.push_back(L"声明流长度 (" + std::to_wstring(declaredLen) + L" 字节) 超过 10MB，可能导致内存异常分配");
            }
            // 检查膨胀风险：声明长度远大于实际长度（例如 >100倍）
            if (declaredLen > 0 && actualLen > 0 && declaredLen / actualLen > 100) {
                info.warnings.push_back(L"压缩流膨胀风险：声明长度 (" + std::to_wstring(declaredLen) +
                                        L") 远大于实际压缩大小 (" + std::to_wstring(actualLen) + L")，可能为 Zip Bomb");
            }
        }
    }

    // 检测自动动作和JavaScript（原有逻辑）
    bool hasJS = false;
    bool hasAuto = false;
    bool hasEmbed = false;
    std::string jsValue;
    std::string embeddedStream;

    if (DictHasKey(dict, "JavaScript") || DictHasKey(dict, "JS")) {
        hasJS = true;
        std::string val = GetDictValue(dict, "JavaScript");
        if (val.empty()) val = GetDictValue(dict, "JS");
        if (!val.empty()) {
            jsValue = val;
        }
    }

    if (DictHasKey(dict, "OpenAction") || DictHasKey(dict, "AA")) {
        hasAuto = true;
    }

    if (DictHasKey(dict, "EmbeddedFile")) {
        hasEmbed = true;
    }

    bool needStream = hasJS || hasAuto || hasEmbed;

    if (needStream) {
        size_t streamPos = objData.find("stream");
        if (streamPos != std::string::npos) {
            std::string streamData = ExtractStream(objData, streamPos);
            if (!streamData.empty()) {
                // 处理 JavaScript
                if (hasJS) {
                    info.hasJavaScript = true;
                    info.jsCode += L"[JavaScript] ";
                    int wlen = MultiByteToWideChar(CP_ACP, 0, streamData.c_str(), -1, nullptr, 0);
                    if (wlen > 0) {
                        std::wstring wstr(wlen - 1, L'\0');
                        MultiByteToWideChar(CP_ACP, 0, streamData.c_str(), -1, &wstr[0], wlen);
                        info.jsCode += wstr;
                        info.jsCode += L"\n";

                        //识别 JavaScript 内存耗尽代码
                        std::wstring jsCode = wstr;
                        // 匹配 new ArrayBuffer(数字) 或 new Uint8Array(数字)
                        std::wregex arrayPattern(LR"(new\s+(?:ArrayBuffer|Uint8Array)\s*\(\s*(\d+)\s*\))", std::regex::icase);
                        std::wsmatch match;
                        std::wstring::const_iterator start = jsCode.cbegin();
                        while (std::regex_search(start, jsCode.cend(), match, arrayPattern)) {
                            if (match.size() > 1) {
                                std::wstring numStr = match[1].str();
                                try {
                                    size_t num = std::stoull(numStr);
                                    if (num > MAX_ARRAY_BUFFER_MB * 1024 * 1024) {
                                        info.warnings.push_back(L"JavaScript 分配超大数据缓冲区 (" + numStr + L" 字节)，可能耗尽内存");
                                    }
                                } catch (...) {}
                            }
                            start = match.suffix().first;
                        }
                        // 检测循环创建对象或字符串连接
                        if (std::regex_search(jsCode, std::wregex(L"(new\\s+\\w+\\s*\\([^)]*\\)\\s*;){5,}", std::regex::icase)) ||
                            std::regex_search(jsCode, std::wregex(L"(\\+=.*;){5,}", std::regex::icase))) {
                            info.warnings.push_back(L"JavaScript 包含大量循环创建对象或字符串连接，可能导致内存耗尽");
                        }

                        // 保存JS文件
                        std::wstring jsFile = tempDir + L"\\js_" + std::to_wstring(GetTickCount()) + L".js";
                        HANDLE hJs = CreateFileW(jsFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hJs != INVALID_HANDLE_VALUE) {
                            DWORD written;
                            WriteFile(hJs, streamData.c_str(), (DWORD)streamData.size(), &written, NULL);
                            CloseHandle(hJs);
                            info.extractedFiles.push_back(jsFile);
                            info.embeddedObjectNames.push_back(L"JavaScript");
                        }
                    }
                }

                // 处理嵌入文件
                if (hasEmbed) {
                    info.hasEmbeddedFile = true;
                    std::string fname = GetDictValue(dict, "F");
                    if (fname.empty()) fname = GetDictValue(dict, "UF");
                    if (fname.empty()) fname = "embedded.dat";
                    std::wstring wfname;
                    int wlen = MultiByteToWideChar(CP_ACP, 0, fname.c_str(), -1, nullptr, 0);
                    if (wlen > 0) {
                        wfname.resize(wlen - 1);
                        MultiByteToWideChar(CP_ACP, 0, fname.c_str(), -1, &wfname[0], wlen);
                    } else {
                        wfname = L"embedded.dat";
                    }
                    std::replace(wfname.begin(), wfname.end(), L'/', L'_');
                    std::replace(wfname.begin(), wfname.end(), L'\\', L'_');
                    std::wstring embedPath = tempDir + L"\\" + wfname;
                    HANDLE hEmbed = CreateFileW(embedPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hEmbed != INVALID_HANDLE_VALUE) {
                        DWORD written;
                        WriteFile(hEmbed, streamData.c_str(), (DWORD)streamData.size(), &written, NULL);
                        CloseHandle(hEmbed);
                        info.extractedFiles.push_back(embedPath);
                        info.embeddedObjectNames.push_back(wfname);
                    }
                }

                // 原有模式匹配（未变）
                std::wstring wstream;
                int wlen = MultiByteToWideChar(CP_ACP, 0, streamData.c_str(), -1, nullptr, 0);
                if (wlen > 0) {
                    wstream.resize(wlen - 1);
                    MultiByteToWideChar(CP_ACP, 0, streamData.c_str(), -1, &wstream[0], wlen);
                }
                std::vector<std::pair<std::wregex, std::wstring>> patterns = {
                    { std::wregex(LR"(CreateObject\s*\(\s*[\"']WScript\.Shell[\"']\s*\))", std::regex::icase), L"Suspicious CreateObject(WScript.Shell)" },
                    { std::wregex(LR"(Shell\s*\(\s*[\"']cmd\.exe[\"']\s*\))", std::regex::icase), L"Suspicious Shell(cmd.exe)" },
                    { std::wregex(LR"(Shell\s*\(\s*[\"']powershell\.exe[\"']\s*\))", std::regex::icase), L"Suspicious Shell(powershell.exe)" },
                    { std::wregex(LR"(Run\s*\(\s*[\"']\s*cmd\.exe)", std::regex::icase), L"Suspicious Run(cmd.exe)" },
                    { std::wregex(LR"(Run\s*\(\s*[\"']\s*powershell)", std::regex::icase), L"Suspicious Run(powershell)" },
                    { std::wregex(LR"(WScript\.Shell)", std::regex::icase), L"Contains WScript.Shell" },
                    { std::wregex(LR"(Exec\s*\(\s*[\"']\s*(cmd|powershell|wscript|cscript))", std::regex::icase), L"Suspicious Exec(cmd/powershell/...)" },
                    { std::wregex(LR"(http[s]?://\S+)", std::regex::icase), L"URL detected" },
                    { std::wregex(LR"(\d+\.\d+\.\d+\.\d+)", std::regex::icase), L"IP address detected" },
                    { std::wregex(LR"(Base64\s*\(|FromBase64String)", std::regex::icase), L"Base64 usage" },
                    { std::wregex(LR"(eval\s*\()", std::regex::icase), L"eval() usage" },
                    { std::wregex(LR"(new\s+ActiveXObject)", std::regex::icase), L"ActiveXObject creation" },
                };
                for (const auto& pat : patterns) {
                    if (std::regex_search(wstream, pat.first)) {
                        info.warnings.push_back(pat.second);
                    }
                }
                if (wstream.length() > 20 && IsBase64String(wstream.substr(0, 100))) {
                    info.warnings.push_back(L"Suspected Base64 encoded data in stream");
                }
            }
        }
    }

    if (hasAuto) {
        info.hasAutoAction = true;
        info.warnings.push_back(L"Contains automatic action (/OpenAction or /AA)");
    }
}

//  主解析函数（使用内存映射文件） 
bool ParsePDF(const std::wstring& pdfPath, PDFDocInfo& info, const std::wstring& tempDir) {
    HANDLE hFile = CreateFileW(pdfPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        info.warnings.push_back(L"Cannot open file");
        return false;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart == 0) {
        CloseHandle(hFile);
        info.warnings.push_back(L"Invalid file size");
        return false;
    }
    DWORD fileSize = liSize.LowPart; // 仅处理小于4GB的文件

    // 创建文件映射
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        info.warnings.push_back(L"Failed to create file mapping");
        return false;
    }

    LPVOID pView = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pView) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        info.warnings.push_back(L"Failed to map view of file");
        return false;
    }

    // 复制数据到 std::string（一次复制，避免额外 vector）
    std::string data(static_cast<const char*>(pView), fileSize);

    UnmapViewOfFile(pView);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    // 检查头部
    if (data.size() < 8 || memcmp(data.data(), "%PDF-", 5) != 0) {
        info.warnings.push_back(L"Not a valid PDF file (header missing)");
        return false;
    }
    info.isPDF = true;

    // 准备解析
    size_t pos = 0;
    g_processedObjects = 0;
    bool stopParsing = false;
    std::set<int> visitedObjects; // 已访问对象编号

    while (!stopParsing) {
        size_t objPos = data.find("obj", pos);
        if (objPos == std::string::npos) break;
        size_t endPos = data.find("endobj", objPos);
        if (endPos == std::string::npos) break;
        std::string objData = data.substr(objPos, endPos - objPos + 6);

        // 对象计数
        g_processedObjects++;
        if (g_processedObjects > MAX_OBJECT_COUNT) {
            info.warnings.push_back(L"对象数量超过 " + std::to_wstring(MAX_OBJECT_COUNT) + L"，疑似堆喷射或拒绝服务攻击，停止解析");
            break;
        }

        // 解析对象
        ParseObject(objData, info, tempDir, visitedObjects, stopParsing);

        // 定期检查内存使用
        if (g_processedObjects % 10 == 0) {
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
                SIZE_T workingSetMB = pmc.WorkingSetSize / (1024 * 1024);
                if (workingSetMB > MAX_MEMORY_WORKINGSET_MB) {
                    info.warnings.push_back(L"工作集内存超过 " + std::to_wstring(MAX_MEMORY_WORKINGSET_MB) +
                                            L" MB，疑似内存耗尽攻击，中止解析");
                    stopParsing = true;
                    break;
                }
            }
        }

        pos = endPos + 6;
    }

    info.success = true;
    return true;
}

//  风险评分（增加新警告权重） 
void CalculateRiskScore(PDFDocInfo& info) {
    int score = 0;
    std::map<std::wstring, int> weightMap = {
        {L"Contains JavaScript", 30},
        {L"Contains automatic action (/OpenAction or /AA)", 25},
        {L"Suspicious CreateObject(WScript.Shell)", 25},
        {L"Suspicious Shell(cmd.exe)", 20},
        {L"Suspicious Shell(powershell.exe)", 20},
        {L"Suspicious Run(cmd.exe)", 15},
        {L"Suspicious Run(powershell)", 15},
        {L"Contains WScript.Shell", 20},
        {L"Suspicious Exec(cmd/powershell/...)", 20},
        {L"URL detected", 15},
        {L"IP address detected", 10},
        {L"Base64 usage", 15},
        {L"eval() usage", 20},
        {L"ActiveXObject creation", 20},
        {L"Contains embedded file", 30},
        {L"Suspected Base64 encoded data in stream", 15},
        {L"循环引用检测", 20},
        {L"字典嵌套深度超过", 25},
        {L"声明流长度超过 10MB", 30},
        {L"压缩流膨胀风险", 40},
        {L"包含 JBIG2Decode 过滤器", 35},
        {L"/U 键值长度异常", 30},
        {L"/O 键值长度异常", 30},
        {L"发现 /Encrypt 字典", 20},
        {L"JavaScript 分配超大数据缓冲区", 40},
        {L"JavaScript 包含大量循环创建对象或字符串连接", 35},
        {L"对象数量超过", 25},
        {L"工作集内存超过", 45},
        {L"Embedded PE file found", 30},
        {L"Embedded script file found", 25},
    };

    for (const auto& file : info.extractedFiles) {
        if (IsPEFile(file)) {
            info.warnings.push_back(L"Embedded PE file found: " + file);
            weightMap[L"Embedded PE file found"] = 30;
        } else if (IsScriptFile(file)) {
            info.warnings.push_back(L"Embedded script file found: " + file);
            weightMap[L"Embedded script file found"] = 25;
        }
    }

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

//  主函数 
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc < 2) {
        printf("Usage: %s <PDF file path> [--withoutUi] [--onlywithUi]\n", argv[0]);
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

    if (GetFileAttributesW(wPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("File does not exist\n");
        return 1;
    }

    std::wstring tempDir = CreateTempDirectoryInAppPath();
    if (tempDir.empty()) {
        printf("Failed to create temporary directory\n");
        return 1;
    }

    // 写入文件路径信息
    std::wstring pathFile = tempDir + L"\\_filepath_.txt";
    HANDLE hFile = CreateFileW(pathFile.c_str(), GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        std::wstring content = wPath + L"\r\n";
        WriteFile(hFile, content.c_str(),
                static_cast<DWORD>(content.size() * sizeof(wchar_t)),
                &written, NULL);
        CloseHandle(hFile);
    } else {
        std::wcerr << L"Warning: Failed to create _filepath_.txt" << std::endl;
    }

    PDFDocInfo info;
    info.filePath = wPath;
    bool parseOk = ParsePDF(wPath, info, tempDir);

    for (const auto& file : info.extractedFiles) {
        InvokeExternalAnalyzer(file, L"Fileanalyzer.exe");
    }

    CalculateRiskScore(info);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    DeleteDirectory(tempDir);

    printf("=== PDF Document Analysis Result ===\n");
    printf("File path: %ls\n", info.filePath.c_str());
    printf("Is PDF: %s\n", info.isPDF ? "Yes" : "No");
    printf("Has JavaScript: %s\n", info.hasJavaScript ? "Yes" : "No");
    printf("Has automatic action: %s\n", info.hasAutoAction ? "Yes" : "No");
    printf("Has embedded file: %s\n", info.hasEmbeddedFile ? "Yes" : "No");
    printf("Has encryption: %s\n", info.hasEncryption ? "Yes" : "No");
    printf("Has JBIG2Decode: %s\n", info.hasJBIG2Decode ? "Yes" : "No");
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
        lstrcpyA(message.type, "PDFAnalyzer");
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
        if (info.hasJavaScript) {
            details += "- JavaScript found\n";
        }
        lstrcpyA(message.details, details.c_str());
        std::thread server(ClientThread_ToControlCenter, &message);
        server.join();
    }

    return 0;
}