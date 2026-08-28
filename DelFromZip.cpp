/*
DelFromZip.cpp
响应层

从压缩存档文件中删除文件

命令行参数：
argv[0] --- DelFromZip.exe
argv[1] --- 需要删除的文件路径（绝对路径）

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\DelFromZip.cpp" -o "%ExecutablePath%\DelFromZip.exe" -mconsole -municode -mwindows

运行权限：管理员权限
*/
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <windows.h>
#include <unordered_map>
#include <cstring>

namespace fs = std::filesystem;

//格式检测（魔数优先）
struct Magic {
    const char* data;
    size_t len;
    const wchar_t* format;
};

static const Magic MAGICS[] = {
    {"\x50\x4B\x03\x04",         4, L"zip"},
    {"\x37\x7A\xBC\xAF\x27\x1C", 6, L"7z"},
    {"\x52\x61\x72\x21\x1A\x07", 7, L"rar"},
    {"\x1F\x8B",                 2, L"gzip"},
    {"\x42\x5A\x68",             3, L"bzip2"},
    {"\xFD\x37\x7A\x58\x5A\x00", 6, L"xz"},
    {"\x4D\x53\x57\x49\x4D\x00\x00\x00", 8, L"wim"},
    {"\x4D\x53\x43\x46",         4, L"cab"},
    {"\x60\xEA",                 2, L"arj"},
};

std::wstring detect_format(const fs::path& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return L"unknown";
    char buffer[16] = {0};
    file.read(buffer, sizeof(buffer));
    size_t read = file.gcount();

    for (const auto& m : MAGICS) {
        if (read >= m.len && memcmp(buffer, m.data, m.len) == 0)
            return m.format;
    }

    std::wstring ext = filepath.extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    static const std::unordered_map<std::wstring, std::wstring> EXT_MAP = {
        {L".zip", L"zip"}, {L".7z", L"7z"}, {L".rar", L"rar"},
        {L".gz", L"gzip"}, {L".bz2", L"bzip2"}, {L".xz", L"xz"},
        {L".tar", L"tar"}, {L".wim", L"wim"}, {L".cab", L"cab"},
        {L".arj", L"arj"}, {L".lzh", L"lzh"}, {L".iso", L"iso"},
        {L".chm", L"chm"}, {L".cpio", L"cpio"}
    };
    auto it = EXT_MAP.find(ext);
    return (it != EXT_MAP.end()) ? it->second : L"unknown";
}

bool is_archive_file(const fs::path& filepath) {
    return detect_format(filepath) != L"unknown";
}

//辅助函数
fs::path create_temp_directory(const fs::path& base) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::wstring name = L"Temp_" + std::to_wstring(now) + L"_" + std::to_wstring(dis(gen));
    fs::path dir = base / name;
    fs::create_directories(dir);
    return dir;
}

fs::path get_7z_path() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    fs::path exeDir = fs::path(exePath).parent_path();
    fs::path sevenZip = exeDir / L"7-zip" / L"7z.exe";
    if (!fs::exists(sevenZip)) {
        std::wcerr << L"7z.exe not found at: " << sevenZip.wstring() << L"\n";
        return L"";
    }
    return sevenZip;
}

//执行 7z（使用 CreateProcess）
bool run_7z(const std::wstring& cmdLine) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdBuffer(cmdLine.size() + 1);
    wcscpy_s(cmdBuffer.data(), cmdBuffer.size(), cmdLine.c_str());

    BOOL success = CreateProcessW(
        NULL,
        cmdBuffer.data(),
        NULL, NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );

    if (!success) {
        DWORD err = GetLastError();
        std::wcerr << L"CreateProcess failed, error code: " << err << L"\n";
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0) {
        std::wcerr << L"7z exited with code " << exitCode << L"\n";
        return false;
    }
    return true;
}

bool unzip(const fs::path& zip_file, const fs::path& dest_dir) {
    fs::path sevenZip = get_7z_path();
    if (sevenZip.empty()) return false;

    // 确保目标目录存在（7z 会自动创建，但提前创建更稳妥）
    fs::create_directories(dest_dir);

    std::wstring cmdLine = L"\"" + sevenZip.wstring() + L"\" x \"" +
                           zip_file.wstring() + L"\" -o\"" +
                           dest_dir.wstring() + L"\" -y";
    if (!run_7z(cmdLine))
        return false;

    // 解压后验证目标目录是否存在
    return fs::exists(dest_dir) && fs::is_directory(dest_dir);
}

bool compress(const fs::path& source_dir, const fs::path& dest_file, const std::wstring& format) {
    fs::path sevenZip = get_7z_path();
    if (sevenZip.empty()) return false;

    std::wstring src = source_dir.wstring() + L"\\*";
    std::wstring cmdLine = L"\"" + sevenZip.wstring() + L"\" a -t" +
                           format + L" \"" + dest_file.wstring() +
                           L"\" \"" + src + L"\" -mx=9 -y";
    return run_7z(cmdLine);
}

//原子替换
bool move_replace(const fs::path& src, const fs::path& dst) {
    return MoveFileExW(src.c_str(), dst.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) != 0;
}

//递归展开嵌套归档
fs::path expand_fully(const fs::path& dir, const fs::path& temp_base) {
    fs::path current = dir;
    while (true) {
        std::vector<fs::path> files;
        for (auto& entry : fs::directory_iterator(current)) {
            if (fs::is_regular_file(entry.path()))
                files.push_back(entry.path());
        }
        // 若不是只有一个文件，或该文件不是归档，则停止展开
        if (files.size() != 1 || !is_archive_file(files[0]))
            break;

        fs::path single = files[0];
        fs::path new_temp = create_temp_directory(temp_base);

        if (!unzip(single, new_temp)) {
            std::wcerr << L"Failed to expand nested archive: " << single.wstring() << L"\n";
            // 解压失败，不删除原目录，直接返回原目录（可能不完整，但至少存在）
            return current;
        }

        // 删除旧目录，替换为新目录
        std::error_code ec;
        fs::remove_all(current, ec);
        if (ec) {
            std::wcerr << L"Warning: cannot remove old temp dir " << current.wstring()
                       << L", error: " << ec.message().c_str() << L"\n";
            // 若删除失败，仍尝试使用新目录，但旧目录残留可能干扰
        }
        current = new_temp;
    }
    return current;
}

//主程序
int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        std::wcerr << L"Usage: " << argv[0] << L" <full_path_to_file_inside_archive>\n";
        return 1;
    }

    fs::path input_path = argv[1];
    if (!input_path.is_absolute()) {
        input_path = fs::absolute(input_path);
    }

    fs::path root = input_path.root_path();
    std::vector<std::wstring> components;
    for (auto it = input_path.begin(); it != input_path.end(); ++it) {
        if (*it == root) continue;
        components.push_back(it->wstring());
    }
    if (components.empty()) {
        std::wcerr << L"Invalid path\n";
        return 1;
    }

    fs::path temp_base = fs::current_path() / L"Temp";
    fs::create_directories(temp_base);

    struct Record {
        fs::path temp_dir;
        fs::path original_path;
        std::wstring format;
    };
    std::vector<Record> records;
    bool has_archive = false;
    fs::path current_path = root;

    for (size_t i = 0; i < components.size(); ++i) {
        const std::wstring& comp = components[i];
        fs::path target = current_path / comp;

        if (!fs::exists(target)) {
            std::wcerr << L"Path does not exist: " << target.wstring() << L'\n';
            return 1;
        }

        if (fs::is_directory(target)) {
            current_path = target;
        }
        else if (fs::is_regular_file(target)) {
            std::wstring fmt = detect_format(target);
            if (fmt != L"unknown") {
                has_archive = true;
                fs::path original_path = target;
                fs::path temp_dir = create_temp_directory(temp_base);

                if (!unzip(target, temp_dir)) {
                    std::wcerr << L"Failed to unzip: " << target.wstring() << L'\n';
                    return 1;
                }

                fs::path final_dir = expand_fully(temp_dir, temp_base);
                // 检查 final_dir 是否存在（expand_fully 可能返回不存在的路径？）
                if (!fs::exists(final_dir) || !fs::is_directory(final_dir)) {
                    std::wcerr << L"After expansion, directory does not exist: " << final_dir.wstring() << L'\n';
                    return 1;
                }

                records.push_back({ final_dir, original_path, fmt });
                current_path = final_dir;
            }
            else {
                if (i == components.size() - 1 && has_archive) {
                    fs::remove(target);
                    break;
                }
                else if (i == components.size() - 1) {
                    return 0;   // 无归档文件，无需操作
                }
                else {
                    std::wcerr << L"Invalid path: non-archive file in the middle\n";
                    return 1;
                }
            }
        }
        else {
            std::wcerr << L"Invalid file type: " << target.wstring() << L'\n';
            return 1;
        }
    }

    // 逆序压缩
    for (auto it = records.rbegin(); it != records.rend(); ++it) {
        std::wstring compress_format = it->format;
        if (compress_format != L"7z" && compress_format != L"zip" &&
            compress_format != L"tar" && compress_format != L"wim") {
            compress_format = L"zip";
        }

        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(1000, 9999);
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        fs::path temp_zip = temp_base /
            (L"TempArc_" + std::to_wstring(now) + L"_" + std::to_wstring(dis(gen)) +
             (compress_format == L"zip" ? L".zip" : L"." + compress_format));

        if (!compress(it->temp_dir, temp_zip, compress_format)) {
            std::wcerr << L"Failed to compress to temporary file: " << temp_zip.wstring() << L'\n';
            fs::remove(temp_zip);
            return 1;
        }

        if (!move_replace(temp_zip, it->original_path)) {
            DWORD err = GetLastError();
            std::wcerr << L"Failed to replace file " << it->original_path.wstring()
                       << L" (error code: " << err << L")\n";
            fs::remove(temp_zip);
            return 1;
        }
    }

    // 清理临时目录
    for (const auto& rec : records) {
        std::error_code ec;
        fs::remove_all(rec.temp_dir, ec);
        if (ec) {
            std::wcerr << L"Warning: could not remove temp dir: " << rec.temp_dir.wstring() << L'\n';
        }
    }

    std::wcout << L"Operation completed successfully.\n";
    return 0;
}