/*
ZIPanalyzer.cpp
分析层

解压压缩文件至临时目录，调用Fileanalyzer分析文件

g++编译:
cd %g++Path%
g++ -fdiagnostics-color=always -g "%SourceCodePath%\ZIPanalyzer.cpp" -o "%ExecutablePath%\ZIPanalyzer.exe" -mconsole -municode -mwindows

运行权限：管理员权限
*/
#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <random>
#include <chrono>
#include <thread>
#include <memory>
#include <map>
#include <set>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

//  辅助函数 

// 去除字符串首尾空白
wstring Trim(const wstring& s) {
    size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == wstring::npos) return L"";
    size_t end = s.find_last_not_of(L" \t\r\n");
    return s.substr(start, end - start + 1);
}

// 获取当前程序所在目录（不含末尾反斜杠）
wstring GetAppDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L'\\');
    if (pos != wstring::npos)
        return fullPath.substr(0, pos);
    return L"";
}

// 在程序所在路径的 .\Temp\ 下创建唯一临时子目录
wstring CreateTempDirectoryInAppPath() {
    wstring appDir = GetAppDirectory();
    if (appDir.empty()) return L"";

    wstring tempDir = appDir + L"\\Temp";
    // 确保 Temp 目录存在
    if (!CreateDirectoryW(tempDir.c_str(), NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            wcerr << L"Failed to create Temp directory" << endl;
            return L"";
        }
    }

    // 创建唯一子目录（时间戳 + 随机数兜底）
    wstring subDir = tempDir + L"\\MalContainer_" +
        to_wstring(chrono::steady_clock::now().time_since_epoch().count());
    if (!CreateDirectoryW(subDir.c_str(), NULL)) {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(1000, 9999);
        subDir = tempDir + L"\\MalContainer_" + to_wstring(dis(gen));
        if (!CreateDirectoryW(subDir.c_str(), NULL)) {
            wcerr << L"Failed to create unique temp subdirectory" << endl;
            return L"";
        }
    }
    return subDir;
}

// 递归删除目录
bool DeleteDirectory(const wstring& path) {
    wstring search = path + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return false;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        wstring fullPath = path + L"\\" + fd.cFileName;
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
void SearchFilesRecursive(const wstring& dir, const wstring& pattern, vector<wstring>& outFiles) {
    wstring search = dir + L"\\" + pattern;
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
                wstring subDir = dir + L"\\" + fd.cFileName;
                SearchFilesRecursive(subDir, pattern, outFiles);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

//  解压 ZIP（使用 PowerShell） 
bool ExtractZip(const wstring& zipPath, const wstring& destDir) {
    // 复制为 .zip 扩展名（解决 Expand-Archive 对扩展名的要求）
    wstring zipCopy = destDir + L"\\temp.zip";
    if (!CopyFileW(zipPath.c_str(), zipCopy.c_str(), FALSE)) {
        wcerr << L"Failed to copy file to .zip extension" << endl;
        return false;
    }

    // PowerShell 解压命令
    wstring psCmd = L"powershell -Command \"Expand-Archive -LiteralPath '" + zipCopy + L"' -DestinationPath '" + destDir + L"' -Force\"";
    wcout << L"Extracting ZIP to " << destDir << L" ..." << endl;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, (LPWSTR)psCmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        wcerr << L"Failed to start PowerShell for ZIP extraction" << endl;
        DeleteFileW(zipCopy.c_str());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 30000); // 等待解压完成，最多30秒
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteFileW(zipCopy.c_str());  // 删除临时 zip 副本
    return true;
}

// 解压非ZIP格式（使用 7z.exe） 
bool ExtractWith7z(const wstring& archivePath, const wstring& destDir, const wstring& sevenZipPath) {
    // 构建命令行：7z x "archive" -o"destDir" -y
    wstring cmdLine = L"\"" + sevenZipPath + L"\" x \"" + archivePath + L"\" -o\"" + destDir + L"\" -y";
    wcout << L"Extracting with 7z: " << cmdLine << endl;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        wcerr << L"Failed to start 7z.exe" << endl;
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE); // 等待执行完成
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0) {
        wcerr << L"7z.exe returned error code: " << exitCode << endl;
        return false;
    }
    return true;
}

//  调用 fileanalyzer.exe 分析单个文件 
bool AnalyzeFileWithExternal(const wstring& filePath, const wstring& extraArg) {
    wstring appDir = GetAppDirectory();
    wstring analyzerPath = appDir + L"\\fileanalyzer.exe";
    // 检查 fileanalyzer.exe 是否存在
    if (GetFileAttributesW(analyzerPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wcerr << L"fileanalyzer.exe not found in " << appDir << endl;
        return false;
    }

    // 构建命令行：fileanalyzer.exe "文件路径" [extraArg]
    wstring cmdLine = L"\"" + analyzerPath + L"\" \"" + filePath + L"\"";
    if (!extraArg.empty()) {
        cmdLine += L" " + extraArg;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        wcerr << L"Failed to launch fileanalyzer for " << filePath << endl;
        return false;
    }
    // 等待分析进程结束（确保临时目录不会被占用）
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

//  主函数 
int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc < 2) {
        wcout << L"Usage: " << argv[0] << L" <container_path> [--withoutUi|--onlywithUi]" << endl;
        wcout << L"  container_path: 压缩文件路径（支持ZIP，其他格式需7z.exe支持）" << endl;
        wcout << L"  --withoutUi  : 传递给 fileanalyzer.exe 的参数（默认）" << endl;
        wcout << L"  --onlywithUi : 传递给 fileanalyzer.exe 的参数" << endl;
        return 1;
    }

    wstring containerPath = argv[1];
    wstring extraArg = L""; // 默认
    if (argc >= 3) {
        wstring arg = argv[2];
        if (arg == L"--withoutUi" || arg == L"--onlywithUi") {
            extraArg = arg;
        } else {
            wcerr << L"Invalid argument: " << arg << endl;
            return 1;
        }
    }

    // 检查文件是否存在
    if (GetFileAttributesW(containerPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wcerr << L"File not found: " << containerPath << endl;
        return 1;
    }

    // 读取文件签名判断类型
    HANDLE hFile = CreateFileW(containerPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wcerr << L"Cannot open file" << endl;
        return 1;
    }
    BYTE sig[8] = {0};
    DWORD read = 0;
    if (!ReadFile(hFile, sig, sizeof(sig), &read, NULL) || read < 8) {
        CloseHandle(hFile);
        wcerr << L"Cannot read file signature" << endl;
        return 1;
    }
    CloseHandle(hFile);

    bool isZIP = false;
    // ZIP 签名：PK\x03\x04, PK\x05\x06, PK\x07\x08
    if (sig[0] == 0x50 && sig[1] == 0x4B && (sig[2] == 0x03 || sig[2] == 0x05 || sig[2] == 0x07)) {
        isZIP = true;
    } else {
        // 仅作提示，不退出，继续尝试用7z
        if (sig[0] == '7' && sig[1] == 'z' && sig[2] == 0xBC && sig[3] == 0xAF && sig[4] == 0x27 && sig[5] == 0x1C) {
            wcout << L"Detected 7z format, will use 7z.exe for extraction." << endl;
        } else if (sig[0] == 'R' && sig[1] == 'a' && sig[2] == 'r' && sig[3] == '!' && sig[4] == 0x1A && sig[5] == 0x07) {
            wcout << L"Detected RAR format, will use 7z.exe for extraction." << endl;
        } else {
            wcout << L"Unknown format, will try 7z.exe." << endl;
        }
    }

    // 创建临时目录
    wstring tempDir = CreateTempDirectoryInAppPath();
    if (tempDir.empty()) {
        wcerr << L"Failed to create temporary directory" << endl;
        return 1;
    }
    wcout << L"Temporary directory: " << tempDir << endl;

    // 在临时目录下创建 _filepath_.txt 写入原文件绝对路径
    wstring pathFile = tempDir + L"\\_filepath_.txt";
    HANDLE hFile_ = CreateFileW(pathFile.c_str(), GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile_ != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        wstring content = containerPath + L"\r\n";
        WriteFile(hFile_, content.c_str(),
                static_cast<DWORD>(content.size() * sizeof(wchar_t)),
                &written, NULL);
        CloseHandle(hFile_);
    } else {
        wcerr << L"Warning: Failed to create _filepath_.txt" << endl;
    }

    //  解压部分（根据格式选择方法） 
    bool extractOk = false;
    if (isZIP) {
        extractOk = ExtractZip(containerPath, tempDir);
    } else {
        // 非ZIP格式：尝试调用7z.exe
        wstring appDir = GetAppDirectory();
        wstring sevenZipPath = appDir + L"\\7-zip\\7z.exe";
        if (GetFileAttributesW(sevenZipPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            wcerr << L"7z.exe not found in " << appDir << L"\\7-zip\\" << endl;
            wcerr << L"Cannot extract non-ZIP archive." << endl;
            DeleteDirectory(tempDir);
            return 1;
        }
        extractOk = ExtractWith7z(containerPath, tempDir, sevenZipPath);
    }

    if (!extractOk) {
        wcerr << L"Failed to extract archive." << endl;
        DeleteDirectory(tempDir);
        return 1;
    }

    // 遍历解压后的所有文件（不包括目录）
    vector<wstring> allFiles;
    SearchFilesRecursive(tempDir, L"*", allFiles);

    wcout << L"Found " << allFiles.size() << L" files/directories in archive." << endl;

    // 对每个文件调用 fileanalyzer.exe
    int analyzedCount = 0;
    for (const auto& file : allFiles) {
        // 跳过目录
        if (GetFileAttributesW(file.c_str()) & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        wcout << L"Analyzing: " << file << endl;
        if (AnalyzeFileWithExternal(file, extraArg)) {
            analyzedCount++;
        } else {
            wcerr << L"Failed to analyze " << file << endl;
        }
    }

    wcout << L"Analyzed " << analyzedCount << L" files." << endl;
    Sleep(500);
    // 删除临时目录
    if (!DeleteDirectory(tempDir)) {
        wcerr << L"Failed to delete temporary directory: " << tempDir << endl;
        // 尝试强制删除（可能被占用，但退出后系统会清理）
    } else {
        wcout << L"Temporary directory deleted." << endl;
    }

    wcout << L"Container analysis completed." << endl;
    return 0;
}