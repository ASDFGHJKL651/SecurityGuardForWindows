/*
TraverseAllFiles.cpp
分析层

在WinPE分析文件类型，路由至对应分析器（PEanalyzer_forWinPE、CMDanalyzer_forWinPE）

g++编译:
cd %g++Path%
g++ -fdiagnostics-color=always -g "%SourceCodePath%\TraverseAllFiles.cpp" -o "%ExecutableForWinPEPath%\TraverseAllFiles.exe"

运行权限：管理员权限
*/
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <locale>
#include <map>

#include <windows.h>
#include <shlwapi.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "shlwapi.lib")

#define MAX_DEPTH 1048576

// 自定义实现 PathFindExtensionW 功能
const wchar_t* myPathFindExtensionW(const wchar_t* pszPath) {
    if (!pszPath) return nullptr;
    const wchar_t* pLastDot = nullptr;
    const wchar_t* p = pszPath;
    while (*p) {
        if (*p == L'.') {
            pLastDot = p;
        } else if (*p == L'\\' || *p == L'/') {
            pLastDot = nullptr;
        }
        p++;
    }
    if (pLastDot) return pLastDot;
    return p;
}

// 自定义实现 PathIsRelativeW 功能
BOOL myPathIsRelativeW(LPCWSTR pszPath) {
    if (!pszPath) return FALSE;
    if (pszPath[0] == L'.' && 
        (pszPath[1] == L'\0' || pszPath[1] == L'\\' || pszPath[1] == L'/' ||
         (pszPath[1] == L'.' && (pszPath[2] == L'\0' || pszPath[2] == L'\\' || pszPath[2] == L'/')))) {
        return TRUE;
    }
    if (pszPath[0] == L'\\' && pszPath[1] != L'\\') {
        return TRUE;
    }
    return FALSE;
}

// 自定义实现 PathIsUNCW 功能
BOOL myPathIsUNCW(LPCWSTR pszPath) {
    if (!pszPath) return FALSE;
    if (pszPath[0] == L'\\' && pszPath[1] == L'\\') {
        return TRUE;
    }
    return FALSE;
}

// 将字符串转为小写
std::wstring toLower(const std::wstring& str) {
    std::wstring result = str;
    for (auto& c : result) {
        if (c >= L'A' && c <= L'Z') {
            c = c - L'A' + L'a';
        }
    }
    return result;
}

// 检查是否为可执行文件扩展名（保留原函数，后续用于分类）
bool isExecutableExtension(const std::wstring& path) {
    const wchar_t* ext = myPathFindExtensionW(path.c_str());
    if (!ext) return false;
    std::wstring extStr(ext);
    extStr = toLower(extStr);
    return extStr == L".exe" || extStr == L".dll" || extStr == L".sys" || extStr == L".cmd" || extStr == L".bat" || extStr == L".ps1";
}

// 获取文件扩展名（小写）
std::wstring getExtensionLower(const std::wstring& path) {
    const wchar_t* ext = myPathFindExtensionW(path.c_str());
    if (!ext) return L"";
    std::wstring extStr(ext);
    return toLower(extStr);
}

// 启动分析器进程
bool LaunchAnalyzer(const std::wstring& filePath) {
    std::wstring ext = getExtensionLower(filePath);
    std::wstring analyzerExe;
    if (ext == L".exe" || ext == L".dll" || ext == L".sys") {
        analyzerExe = L".\\PEanalyzer_forWinPE.exe";
    } else if (ext == L".bat" || ext == L".cmd" || ext == L".ps1") {
        analyzerExe = L".\\CMDanalyzer_forWinPE.exe";
    } else {
        // 理论上不会走到这里，因为调用前已筛选
        return false;
    }

    // 构造命令行：分析器路径 + 带引号的文件路径
    std::wstring cmdLine = L"\"" + analyzerExe + L"\" \"" + filePath + L"\"";

    // 创建进程
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    // 让分析器在后台运行，不显示窗口
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    // CreateProcess 的 lpCommandLine 必须可修改，所以用 vector<wchar_t>
    std::vector<wchar_t> cmdBuffer(cmdLine.begin(), cmdLine.end());
    cmdBuffer.push_back(L'\0');

    BOOL success = CreateProcessW(
        nullptr,                  // 不指定可执行文件路径，从命令行解析
        cmdBuffer.data(),         // 命令行
        nullptr, nullptr,         // 安全和继承
        FALSE,                    // 不继承句柄
        CREATE_NO_WINDOW,         // 不创建窗口（对控制台程序也有效）
        nullptr, nullptr,         // 环境变量和当前目录
        &si, &pi
    );

    if (success) {
        // 关闭进程和线程句柄，避免资源泄漏（子进程将独立运行）
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        // 可输出调试信息
        // std::wcout << L"已启动分析器: " << cmdLine << std::endl;
        return true;
    } else {
        DWORD err = GetLastError();
        std::wcerr << L"启动分析器失败 (错误码: " << err << L")，文件: " << filePath << std::endl;
        return false;
    }
}

// 递归扫描目录（修改：对可执行文件启动分析器）
void scanDirectory(const std::wstring& rootPath, int currentDepth) {
    if (currentDepth > MAX_DEPTH) {
        std::wcerr << L"警告：达到最大递归深度，跳过目录: " << rootPath << std::endl;
        return;
    }

    std::wstring searchPath = rootPath;
    if (searchPath.back() != L'\\' && searchPath.back() != L'/') {
        searchPath += L"\\";
    }
    searchPath += L"*";

    std::unique_ptr<WIN32_FIND_DATAW> findDataPtr(new WIN32_FIND_DATAW);
    WIN32_FIND_DATAW* findData = findDataPtr.get();

    HANDLE hFind = FindFirstFileW(searchPath.c_str(), findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
            std::wcerr << L"警告：拒绝访问 " << rootPath << std::endl;
        }
        return;
    }

    do {
        if (wcscmp(findData->cFileName, L".") == 0 || wcscmp(findData->cFileName, L"..") == 0) {
            continue;
        }

        std::wstring fullPath = rootPath;
        if (fullPath.back() != L'\\') {
            fullPath += L"\\";
        }
        fullPath += findData->cFileName;

        if (myPathIsRelativeW(fullPath.c_str()) || myPathIsUNCW(fullPath.c_str())) {
            continue;
        }

        if (findData->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            continue;
        }

        if (findData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scanDirectory(fullPath, currentDepth + 1);
        } else {
            // 只处理目标扩展名的文件
            if (isExecutableExtension(fullPath)) {
                // 获取规范化路径（可选，但保留原代码）
                wchar_t normalizedPath[MAX_PATH];
                DWORD length = GetFullPathNameW(fullPath.c_str(), MAX_PATH, normalizedPath, nullptr);
                if (length > 0 && length < MAX_PATH) {
                    // 启动对应的分析器
                    LaunchAnalyzer(normalizedPath);
                } else {
                    std::wcerr << L"警告：无法规范化路径 " << fullPath << std::endl;
                }
            }
        }
    } while (FindNextFileW(hFind, findData));

    DWORD lastError = GetLastError();
    FindClose(hFind);

    if (lastError != ERROR_NO_MORE_FILES) {
        if (lastError == ERROR_ACCESS_DENIED || lastError == ERROR_SHARING_VIOLATION) {
            std::wcerr << L"警告：拒绝访问 " << rootPath << std::endl;
        }
    }
}

int main(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    std::locale::global(std::locale(""));

    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (drives & (1UL << i)) {
            wchar_t driveLetter = L'A' + i;
            std::wstring driveRoot = std::wstring(1, driveLetter) + L":\\";

            UINT driveType = GetDriveTypeW(driveRoot.c_str());
            if (driveType == DRIVE_FIXED) {
                DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
                BOOL ready = GetDiskFreeSpaceW(
                    driveRoot.c_str(),
                    &sectorsPerCluster,
                    &bytesPerSector,
                    &numberOfFreeClusters,
                    &totalNumberOfClusters
                );

                if (ready) {
                    scanDirectory(driveRoot, 0);
                } else {
                    DWORD error = GetLastError();
                    if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
                        std::wcerr << L"警告：拒绝访问 " << driveRoot << std::endl;
                    }
                }
            }
        }
    }

    return EXIT_SUCCESS;
}