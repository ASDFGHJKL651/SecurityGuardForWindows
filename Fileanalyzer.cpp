/*
Fileanalyzer.cpp
分析层

分析文件类型，路由至对应分析器（PEanalyzer、CMDanalyzer、LNKanalyzer、OLEanalyzer、PDFanalyzer、ZIPanalyzer等）

命令行参数：
argv[0] --- Fileanalyzer.exe
argv[1] --- 需要分析的文件路径
argv[2] --- 可选参数，"--withoutUi"表示不弹窗，"--onlywithUi"表示仅高危弹窗，其他情况默认弹窗+分析

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\Fileanalyzer.cpp" -o "%ExecutablePath%\Fileanalyzer.exe" -mwindows

运行权限：管理员权限
*/
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <algorithm>
#include <cctype>
#include <vector>
#include <cstring>
#include <windows.h> 
#include <cmath>    

int withUi = 1;           // 默认开启UI

//辅助函数
std::string toLower(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower;
}

std::string getExtension(const std::string& filepath) {
    size_t pos = filepath.find_last_of('.');
    if (pos == std::string::npos) return "";
    return toLower(filepath.substr(pos + 1));
}

//安全的子进程调用
void callAnalyzer(const std::string& exePath, const std::string& filepath, const std::string& extraArgs) {
    std::string cmdLine = "\"" + exePath + "\" \"" + filepath + "\"";
    if (!extraArgs.empty()) {
        cmdLine += " " + extraArgs;
    }

    std::vector<char> cmdBuffer(cmdLine.begin(), cmdLine.end());
    cmdBuffer.push_back('\0');

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessA(
        NULL,
        cmdBuffer.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        DWORD err = GetLastError();
        std::cerr << "Failed to launch " << exePath << " (error code: " << err << ")" << std::endl;
        return;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        if (exitCode != 0) {
            std::cerr << "Warning: " << exePath << " returned " << exitCode << std::endl;
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

//魔数检测
bool isPEFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    unsigned char buffer[0x40] = {0};
    file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
    if (file.gcount() < 2) return false;

    if (buffer[0] != 0x4D || buffer[1] != 0x5A) return false;

    std::uint32_t peOffset = 0;
    if (file.gcount() >= 0x3C + 4) {
        peOffset = *reinterpret_cast<std::uint32_t*>(&buffer[0x3C]);
    } else {
        file.seekg(0x3C);
        file.read(reinterpret_cast<char*>(&peOffset), sizeof(peOffset));
        if (!file) return false;
    }

    file.seekg(peOffset);
    char peSig[4] = {0};
    file.read(peSig, 4);
    return (file.gcount() == 4 && peSig[0] == 'P' && peSig[1] == 'E' &&
            peSig[2] == '\0' && peSig[3] == '\0');
}

bool isLNKFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    unsigned char header[4] = {0};
    file.read(reinterpret_cast<char*>(header), 4);
    return (file.gcount() == 4 && header[0] == 0x4C && header[1] == 0x00 &&
            header[2] == 0x00 && header[3] == 0x00);
}

bool isOLE2File(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    unsigned char magic[4] = {0};
    file.read(reinterpret_cast<char*>(magic), 4);
    return (file.gcount() == 4 &&
            magic[0] == 0xD0 && magic[1] == 0xCF &&
            magic[2] == 0x11 && magic[3] == 0xE0);
}

bool isPDFFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    unsigned char magic[4] = {0};
    file.read(reinterpret_cast<char*>(magic), 4);
    return (file.gcount() == 4 &&
            magic[0] == '%' && magic[1] == 'P' &&
            magic[2] == 'D' && magic[3] == 'F');
}

// 扩展/重命名：ZIP 及相关归档/镜像格式检测
bool isZIPFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    // 1. 魔数检测（优先)
    // 定义结构：偏移、字节序列、长度
    struct Magic {
        size_t offset;
        const unsigned char* data;
        size_t len;
    };

    // 常用魔数（偏移 0 或特定位置）
    static const unsigned char zip_magic[]    = {0x50, 0x4B, 0x03, 0x04}; // ZIP
    static const unsigned char zip_empty[]   = {0x50, 0x4B, 0x05, 0x06}; // ZIP empty
    static const unsigned char zip_spanned[] = {0x50, 0x4B, 0x07, 0x08}; // ZIP spanned
    static const unsigned char sevenz_magic[] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
    static const unsigned char xz_magic[]    = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
    static const unsigned char bz2_magic[]   = {0x42, 0x5A, 0x68};
    static const unsigned char gz_magic[]    = {0x1F, 0x8B};
    static const unsigned char rar_magic[]   = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
    static const unsigned char rar5_magic[]  = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};
    static const unsigned char cab_magic[]   = {0x4D, 0x53, 0x43, 0x46};
    static const unsigned char chm_magic[]   = {0x49, 0x54, 0x53, 0x46};
    static const unsigned char wim_magic[]   = {0x4D, 0x53, 0x57, 0x49, 0x4D}; // "MSWIM"
    static const unsigned char cpio_magic[]  = {0x30, 0x37, 0x30, 0x37, 0x30, 0x37}; // "070707"
    static const unsigned char cramfs_magic[] = {0x28, 0xCD, 0x3D, 0x45}; // 小端
    static const unsigned char qcow2_magic[] = {0x51, 0x46, 0x49, 0xFB}; // "QFI\xfb"
    static const unsigned char rpm_magic[]   = {0xED, 0xAB, 0xEE, 0xDB};
    static const unsigned char squashfs_magic[] = {0x73, 0x71, 0x73, 0x68}; // "sqsh"
    static const unsigned char squashfs_magic_be[] = {0x68, 0x73, 0x71, 0x73}; // "hsqs"
    static const unsigned char xar_magic[]   = {0x78, 0x61, 0x72, 0x21}; // "xar!"
    static const unsigned char z_magic[]     = {0x1F, 0x9D}; // compress
    static const unsigned char vhd_magic[]   = {0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78}; // "conectix"
    static const unsigned char vhdx_magic[]  = {0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65}; // "vhdxfile"
    static const unsigned char vmdk_magic[]  = {0x4B, 0x44, 0x4D, 0x56}; // "KDMV"
    static const unsigned char vdi_magic[]   = {0x3C, 0x00, 0x01, 0x0A}; // VDI header start
    static const unsigned char nsis_magic[]  = {0x4E, 0x53, 0x49, 0x53}; // "NSIS"
    static const unsigned char lzh_magic[]   = {0x2D, 0x6C, 0x68}; // "-lh" (部分匹配)

    std::vector<Magic> magics = {
        {0, zip_magic, 4},
        {0, zip_empty, 4},
        {0, zip_spanned, 4},
        {0, sevenz_magic, 6},
        {0, xz_magic, 6},
        {0, bz2_magic, 3},
        {0, gz_magic, 2},
        {0, rar_magic, 7},
        {0, rar5_magic, 8},
        {0, cab_magic, 4},
        {0, chm_magic, 4},
        {0, wim_magic, 5},
        {0, cpio_magic, 6},
        {0, cramfs_magic, 4},
        {0, qcow2_magic, 4},
        {0, rpm_magic, 4},
        {0, squashfs_magic, 4},
        {0, squashfs_magic_be, 4},
        {0, xar_magic, 4},
        {0, z_magic, 2},
        {0, vhd_magic, 8},
        {0, vhdx_magic, 8},
        {0, vmdk_magic, 4},
        {0, vdi_magic, 4},
        {0, nsis_magic, 4},
        {0, lzh_magic, 3} // 仅前缀匹配 "-lh"
    };

    // 特殊偏移的魔数（如 ISO）
    static const unsigned char iso_magic[] = {0x43, 0x44, 0x30, 0x30, 0x31}; // "CD001"
    magics.push_back({0x8001, iso_magic, 5}); // 常见偏移
    magics.push_back({0x8000, iso_magic, 5}); // 备选偏移

    // 检查每个魔数
    for (const auto& m : magics) {
        file.seekg(m.offset, std::ios::beg);
        if (!file) continue;
        unsigned char buffer[16];
        file.read(reinterpret_cast<char*>(buffer), m.len);
        if (file.gcount() == static_cast<std::streamsize>(m.len)) {
            if (std::memcmp(buffer, m.data, m.len) == 0) {
                return true;
            }
        }
    }

    //2. 扩展名回退（无固定魔数的格式）
    std::string ext = getExtension(filepath);
    static const std::vector<std::string> archiveExts = {
        // 压缩/归档
        "zip", "7z", "xz", "bz2", "gz", "tar", "tgz", "tbz2", "tz", "wim", "rar",
        "cab", "chm", "cpio", "cramfs", "dmg", "lzh", "lzma", "nsis", "qcow2",
        "rpm", "squashfs", "udf", "vdi", "vhd", "vhdx", "vmdk", "xar", "z",
        // 磁盘镜像（部分）
        "iso", "img", "vhd", "vmdk", "vdi", "qcow2", "dmg", "raw", "qcow", "vhdx",
        // 其他列出的格式（无魔数或复杂）
        "apfs", "ar", "arj", "cramfs", "ext", "fat", "gpt", "hfs", "ihex",
        "mbr", "mssi", "ntfs", "uefi"
    };
    if (std::find(archiveExts.begin(), archiveExts.end(), ext) != archiveExts.end()) {
        return true;
    }

    return false;
}

//已知非可执行二进制（文档、媒体等）
bool isKnownNonExecutableBinary(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    std::string ext = getExtension(filepath);
    static const std::vector<std::string> nonExecExts = {
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf",
        "pdf", "txt", "log", "csv", "xml", "json", "yaml", "yml",
        "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "ico", "cur", "webp",
        "svg", "psd", "ai", "eps",
        "mp3", "wav", "wma", "aac", "flac", "ogg", "m4a", "mid", "midi",
        "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm", "m4v", "3gp",
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "z", "arj", "lzh", "cab", "iso",
        "db", "sqlite", "sqlite3", "mdb", "accdb"
    };
    if (std::find(nonExecExts.begin(), nonExecExts.end(), ext) != nonExecExts.end())
        return true;

    unsigned char header[64] = {0};
    file.read(reinterpret_cast<char*>(header), sizeof(header));
    std::streamsize len = file.gcount();

    static const std::vector<std::pair<const unsigned char*, size_t>> magicList = {
        { (const unsigned char*)"\xFF\xD8\xFF", 3 },
        { (const unsigned char*)"\x89\x50\x4E\x47", 4 },
        { (const unsigned char*)"\x47\x49\x46\x38", 4 },
        { (const unsigned char*)"\x42\x4D", 2 },
        { (const unsigned char*)"\x49\x49\x2A\x00", 4 },
        { (const unsigned char*)"\x4D\x4D\x00\x2A", 4 },
        { (const unsigned char*)"\x00\x00\x01\x00", 4 },
        { (const unsigned char*)"\x00\x00\x02\x00", 4 },
        { (const unsigned char*)"\x52\x49\x46\x46", 4 },
        { (const unsigned char*)"\x49\x44\x33", 3 },
        { (const unsigned char*)"\x66\x4C\x61\x43", 4 },
        { (const unsigned char*)"\x4F\x67\x67\x53", 4 },
        { (const unsigned char*)"\x52\x61\x72\x21", 4 },
        { (const unsigned char*)"\x37\x7A\xBC\xAF", 4 },
        { (const unsigned char*)"\x1F\x8B", 2 },
        { (const unsigned char*)"\x42\x5A\x68", 3 },
        { (const unsigned char*)"\xFD\x37\x7A\x58\x5A\x00", 6 },
        { (const unsigned char*)"\x4D\x53\x43\x46", 4 },
        { (const unsigned char*)"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00", 16 },
        { (const unsigned char*)"\x1A\x45\xDF\xA3", 4 },
        { (const unsigned char*)"\x46\x4C\x56", 3 },
        { (const unsigned char*)"\x46\x57\x53", 3 },
        { (const unsigned char*)"\x43\x57\x53", 3 },
        { (const unsigned char*)"\xD7\xCD\xC6\x9A", 4 },
        { (const unsigned char*)"\x01\x00\x00\x00", 4 }
    };

    for (const auto& magic : magicList) {
        if (len >= static_cast<std::streamsize>(magic.second)) {
            if (std::memcmp(header, magic.first, magic.second) == 0) {
                return true;
            }
        }
    }

    return false;
}

//二进制检测（空字节）
bool isBinaryFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    const size_t BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE] = {0};
    file.read(buffer, BUFFER_SIZE);
    std::streamsize bytesRead = file.gcount();
    if (bytesRead <= 0) return false;

    for (std::streamsize i = 0; i < bytesRead; ++i) {
        if (buffer[i] == '\0') return true;
    }
    return false;
}

//熵值和可打印字符比例辅助判断
void computeEntropyAndPrintable(const std::string& filepath, double& entropy, double& printableRatio) {
    entropy = 0.0;
    printableRatio = 0.0;
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return;

    const size_t BUFFER_SIZE = 4096;
    unsigned char buffer[BUFFER_SIZE] = {0};
    file.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
    std::streamsize bytesRead = file.gcount();
    if (bytesRead <= 0) return;

    long long freq[256] = {0};
    long long printableCount = 0;
    for (std::streamsize i = 0; i < bytesRead; ++i) {
        unsigned char c = buffer[i];
        freq[c]++;
        if (std::isprint(c) || c == '\n' || c == '\r' || c == '\t') {
            printableCount++;
        }
    }

    double total = static_cast<double>(bytesRead);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = freq[i] / total;
            entropy -= p * log2(p);
        }
    }

    printableRatio = static_cast<double>(printableCount) / total;
}

//主程序
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file_path>" << std::endl;
        return 1;
    }

    withUi = 1;
    if (argc > 2) {
        if (strcmp(argv[2], "--withoutUi") == 0) {
            withUi = 0;
            std::cout << "running without Ui" << std::endl;
        } else if (strcmp(argv[2], "--onlywithUi") == 0) {
            withUi = 2;
            std::cout << "running with any Ui" << std::endl;
        } else {
            withUi = 1;
            std::cout << "running with Ui" << std::endl;
        }
    }

    std::string directory;
    std::string path_ = argv[0];
    size_t lastBackslash = path_.find_last_of("\\");
    if (lastBackslash != std::string::npos) {
        directory = path_.substr(0, lastBackslash);
    } else {
        directory = ".";
    }

    std::string filepath = argv[1];

    //1. PE 可执行文件
    if (isPEFile(filepath)) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\PEanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\PEanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\PEanalyzer.exe", filepath, "");
        }
        return 0;
    }

    //2. LNK 快捷方式
    if (isLNKFile(filepath)) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\LNKanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\LNKanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\LNKanalyzer.exe", filepath, "");
        }
        return 0;
    }

    //3. 根据扩展名明确分类（批处理、DOS 等）
    std::string ext = getExtension(filepath);
    if ((ext == "bat" || ext == "cmd" || ext == "ps1") && !isBinaryFile(filepath)) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\CMDanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\CMDanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\CMDanalyzer.exe", filepath, "");
        }
        return 0;
    }
    if ((ext == "com" || ext == "cdf-ms" || ext == "man") && isBinaryFile(filepath)) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\DOSanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\DOSanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\DOSanalyzer.exe", filepath, "");
        }
        return 0;
    }

    //4. OLE2 复合文档（.doc, .xls, .ppt, .msi 等)
    if (isOLE2File(filepath)) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\OLEanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\OLEanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\OLEanalyzer.exe", filepath, "");
        }
        return 0;
    }

    //5. PDF 文件
    if (isPDFFile(filepath)) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\PDFanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\PDFanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\PDFanalyzer.exe", filepath, "");
        }
        return 0;
    }

    //6. Office Open XML（基于 ZIP 的特殊处理）
    if (isZIPFile(filepath) && (ext == "docx" || ext == "xlsx" || ext == "pptx" ||
                                ext == "docm" || ext == "xlsm" || ext == "pptm")) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\OLEanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\OLEanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\OLEanalyzer.exe", filepath, "");
        }
        return 0;
    }

    // 7. 其他 ZIP/归档/磁盘镜像（均由 ZIPanalyzer 处理）
    if (isZIPFile(filepath)) {
        if (withUi == 0) {
            callAnalyzer(directory + "\\ZIPanalyzer.exe", filepath, "--withoutUi");
        } else if (withUi == 2) {
            callAnalyzer(directory + "\\ZIPanalyzer.exe", filepath, "--onlywithUi");
        } else {
            callAnalyzer(directory + "\\ZIPanalyzer.exe", filepath, "");
        }
        return 0;
    }

    // 8. 对于剩余文件，当 withUi==1 时使用熵值+可打印比辅助判断
    if (withUi == 1) {
        double entropy = 0.0, printableRatio = 0.0;
        computeEntropyAndPrintable(filepath, entropy, printableRatio);

        bool callDOS = false;
        bool extTrusted = !ext.empty() && (ext == "txt" || ext == "log" || ext == "csv" ||
                                            ext == "xml" || ext == "json" || ext == "yml" ||
                                            ext == "yaml" || ext == "bat" || ext == "cmd" ||
                                            ext == "ps1" || ext == "com" || ext == "cdf-ms" ||
                                            ext == "man");
        if (!extTrusted) {
            if (entropy > 7.0 && printableRatio < 0.3) {
                callDOS = true;
            } else if (entropy < 4.0 && printableRatio > 0.7) {
                callDOS = false;
            } else {
                callDOS = isBinaryFile(filepath);
            }
        } else {
            callDOS = isBinaryFile(filepath);
        }

        // if (callDOS) callAnalyzer(...);
        // else callAnalyzer(...);
        return 0;
    }

    //9. 跳过已知非可执行二进制 
    if (isKnownNonExecutableBinary(filepath)) {
        std::cerr << "Skipped known non-executable file: " << filepath << std::endl;
        return 1;
    }

    //10. 完全未知类型
    return 1;
}