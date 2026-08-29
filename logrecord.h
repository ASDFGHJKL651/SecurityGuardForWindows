/* 
logrecord.h
记录日志
*/
#pragma once

#include <windows.h>
#include <string>
#include <cstdio>
#include <cstring>

namespace LogRecord {

    // 获取当前可执行文件所在目录（宽字符）
    inline std::wstring GetExeDirectory() {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t* lastSlash = wcsrchr(exePath, L'\\');
        if (lastSlash) {
            *lastSlash = L'\0';
        }
        return std::wstring(exePath);
    }

    // 递归创建目录（宽字符路径）
    inline bool CreateDirectories(const std::wstring& path) {
        if (path.empty()) return true;

        DWORD attr = GetFileAttributesW(path.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return true;
        }

        size_t pos = path.find_last_of(L'\\');
        if (pos != std::wstring::npos) {
            std::wstring parent = path.substr(0, pos);
            if (!CreateDirectories(parent)) return false;
        }

        if (CreateDirectoryW(path.c_str(), nullptr)) {
            return true;
        } else {
            // 若已存在且为目录，也视为成功
            DWORD err = GetLastError();
            if (err == ERROR_ALREADY_EXISTS) {
                attr = GetFileAttributesW(path.c_str());
                return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
            }
            return false;
        }
    }

    /**
     * 写入日志到文件（UTF‑8 编码）
     * @param logPath  日志文件路径（宽字符，相对路径以程序所在目录为基准）
     * @param logType  日志类型，如 "[ERROR]" （UTF‑8 编码，通常为 ASCII）
     * @param module   记录日志的模块，如 "[User_UI.exe]" （UTF‑8 编码）
     * @param detail   日志详情（UTF‑8 编码）
     * @return 成功返回 true，否则 false
     */
    inline bool WriteLog(const wchar_t* logPath, const char* logType,
                         const char* module, const char* detail) {
        if (!logPath || !logType || !module || !detail) return false;

        // 1. 获取程序所在目录
        std::wstring exeDir = GetExeDirectory();
        if (exeDir.empty()) return false;

        // 2. 拼接完整路径
        std::wstring fullPath;
        bool isAbsolute = false;
        // 检测是否为绝对路径（盘符: 或 \\ 开头）
        if (wcslen(logPath) >= 2 && logPath[1] == L':') {
            isAbsolute = true;
        } else if (logPath[0] == L'\\' || logPath[0] == L'/') {
            isAbsolute = true;
        }

        if (isAbsolute) {
            fullPath = logPath;
        } else {
            fullPath = exeDir + L"\\" + logPath;
        }

        // 统一斜杠为反斜杠
        for (auto& ch : fullPath) {
            if (ch == L'/') ch = L'\\';
        }

        // 3. 创建目录（提取目录部分）
        size_t lastSlash = fullPath.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            std::wstring dir = fullPath.substr(0, lastSlash);
            if (!CreateDirectories(dir)) {
                return false;
            }
        }

        // 4. 打开文件（追加模式，不存在则创建）
        HANDLE hFile = CreateFileW(
            fullPath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        SetFilePointer(hFile, 0, nullptr, FILE_END);

        // 5. 获取当前时间（精确到 0.01 秒）
        SYSTEMTIME st;
        GetLocalTime(&st);
        char timeBuf[64];
        sprintf_s(timeBuf, sizeof(timeBuf),
                  "[%04d-%02d-%02d %02d:%02d:%02d.%02d]",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond,
                  st.wMilliseconds / 10);

        // 6. 构建日志行（UTF‑8 编码）
        std::string line;
        line.reserve(strlen(logType) + strlen(timeBuf) + strlen(module) + strlen(detail) + 10);
        line += logType;
        line += " ";
        line += timeBuf;
        line += " ";
        line += module;
        line += " ";
        line += detail;
        line += "\r\n";

        // 7. 写入文件
        DWORD bytesWritten;
        BOOL result = WriteFile(hFile, line.c_str(),
                                static_cast<DWORD>(line.size()),
                                &bytesWritten, nullptr);
        CloseHandle(hFile);

        return (result != 0 && bytesWritten == line.size());
    }

} // namespace LogRecord