// CreateHash.cpp
// 生成所有待保护文件的 HMAC-SHA256 哈希，并加密存储为 HashValue.json
// 使用新的安全加密头文件（AES-256-CBC + HMAC + PBKDF2）
#include "AES-256-CBCEncryptionCommon.h"
#include <iomanip>
#include <iostream>

int main() {
    std::string exeDir = GetExeDirectory();
    std::string parentDir = GetParentDirectory(exeDir);

    // 所有需要校验的文件名（不含扩展名，DLL 带 .dll）
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
        // 若不以 .dll 结尾，则加上 .exe
        if (key.length() < 4 || key.substr(key.length() - 4) != ".dll") {
            filename += ".exe";
        }
        std::string fullPath = parentDir + filename;
        auto hashBytes = Sha256File(fullPath);   // 现为 HMAC-SHA256
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

    // 将 JSON 转为字节
    std::string jsonStr = j.dump(4);
    std::vector<BYTE> plaintext(jsonStr.begin(), jsonStr.end());

    // 使用固定的强密码（实际生产中应通过安全方式获取）
    std::string password = "G7#kLp$2Qr!vX9&mN4@zRw^5YcB*eH3";
    std::vector<BYTE> key(password.begin(), password.end());
    std::cout << "Password length: " << password.size() << " bytes." << std::endl;

    // 加密（新函数自动生成盐、IV 和 HMAC）
    std::vector<BYTE> encrypted = AesEncrypt(plaintext, key);

    // 清除敏感数据
    SecureZeroString(password);
    SecureZeroVector(key);
    SecureZeroVector(plaintext);

    if (encrypted.empty()) {
        std::cerr << "Encryption failed! Please check the diagnostic messages above." << std::endl;
        return 1;
    }

    // 创建 Configuration 目录
    std::string configDir = exeDir + "Configuration\\";
    if (!CreateDirectoryA(configDir.c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            std::cerr << "Cannot create directory " << configDir << " (error " << GetLastError() << ")" << std::endl;
            return 1;
        }
    }

    // 写入加密文件
    std::string filePath = configDir + "HashValue.json";
    std::ofstream out(filePath, std::ios::binary);
    if (!out) {
        std::cerr << "Cannot write to " << filePath << std::endl;
        return 1;
    }
    out.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    out.close();

    std::cout << "HashValue.json generated successfully (" << encrypted.size() << " bytes)." << std::endl;
    return 0;
}