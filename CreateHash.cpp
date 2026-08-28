//CreateHash.cpp
#include "Common.h"
#include <iomanip>

int main() {
    std::string exeDir = GetExeDirectory();
    std::string parentDir = GetParentDirectory(exeDir);

    // 所有需要校验的文件名
    std::vector<std::string> keys = {
        "CMDanalyzer", "ControlCenter", "DelFromZip", "Fileanalyzer",
        "FileSystemMonitor", "Installation_steps", "isol", "Lnkanalyzer",
        "MemoryGuard", "OLEanalyzer", "PDFanalyzer", "PEanalyzer",
        "RegistryMonitor", "SandBox", "SystemService", "taskscheduler",
        "User_UI", "ZIPanalyzer","NetworkGuard",
        "libgcc_s_seh-1.dll", "libmcfgthread-2.dll", "libstdc++-6.dll"
    };

    nlohmann::json j;
    for (const auto& key : keys) {
        std::string filename = key;
        if (key.length() < 4 || key.substr(key.length() - 4) != ".dll") {
            filename += ".exe";
        }
        std::string fullPath = parentDir + filename;
        auto hashBytes = Sha256File(fullPath);
        if (hashBytes.empty()) {
            std::cerr << "Warning: cannot hash " << fullPath << ", skipping." << std::endl;
            continue;
        }
        j[key] = BytesToHex(hashBytes);
        std::cout << fullPath << " hashed successfully" << std::endl;
    }

    if (j.empty()) {
        std::cerr << "Error: no files hashed successfully!" << std::endl;
        return 1;
    }

    std::string jsonStr = j.dump(4);
    std::vector<BYTE> plaintext(jsonStr.begin(), jsonStr.end());
    std::vector<BYTE> key = DeriveKey("P@aS7sw4&OR7d");
    std::vector<BYTE> encrypted = AesEncrypt(plaintext, key);
    if (encrypted.empty()) {
        std::cerr << "Encryption failed!" << std::endl;
        return 1;
    }

    // 创建 Configuration 目录并写入加密文件
    std::string configDir = exeDir + "Configuration\\";
    if (!CreateDirectoryA(configDir.c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            std::cerr << "Cannot create directory " << configDir << " (error " << GetLastError() << ")" << std::endl;
            return 1;
        }
    }
    std::string filePath = configDir + "HashValue.json";
    std::ofstream out(filePath, std::ios::binary);
    if (!out) {
        std::cerr << "Cannot write to " << filePath << std::endl;
        return 1;
    }
    out.write((char*)encrypted.data(), encrypted.size());
    out.close();

    std::cout << "HashValue.json generated successfully (" << encrypted.size() << " bytes)." << std::endl;
    return 0;
}