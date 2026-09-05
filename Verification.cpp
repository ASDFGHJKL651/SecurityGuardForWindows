/*
Verification.cpp

开机以管理员权限自启动，校验程序哈希值（HMAC-SHA256），
若哈希不匹配则从 BackUp 目录恢复，然后启动所有校验通过的可执行文件。

编译命令（示例）：
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\Verification.cpp" -o "%Executable%\Verification\Verification.exe" -lbcrypt -lstdc++fs -static-libgcc -static-libstdc++
运行需要管理员权限。
*/
#include "AES-256-CBCEncryptionCommon.h"
#include <filesystem>
#include <iomanip>
#include <iostream>

// 校验并尝试恢复文件
bool VerifyAndReplace(const std::string& filePath, const std::string& backupPath,
                      const std::string& expectedHex, bool isDll) {
    auto hashBytes = Sha256File(filePath);
    std::string currentHex = BytesToHex(hashBytes);
    if (currentHex == expectedHex) {
        return true; // 哈希一致
    }

    // 哈希不一致，尝试从备份恢复
    if (!std::filesystem::exists(backupPath)) {
        std::cerr << "Backup not found: " << backupPath << std::endl;
        return false;
    }

    try {
        std::filesystem::copy_file(backupPath, filePath,
                                   std::filesystem::copy_options::overwrite_existing);
    } catch (const std::exception& e) {
        std::cerr << "Copy failed: " << e.what() << std::endl;
        return false;
    }

    // 重新校验恢复后的文件
    auto newHash = Sha256File(filePath);
    std::string newHex = BytesToHex(newHash);
    return (newHex == expectedHex);
}

int main() {
    std::string exeDir = GetExeDirectory();
    std::string parentDir = GetParentDirectory(exeDir);
    std::string configPath = exeDir + "Configuration\\HashValue.json";

    // 读取加密的哈希文件
    std::ifstream in(configPath, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open " << configPath << std::endl;
        return 1;
    }
    std::vector<BYTE> encrypted((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    in.close();
    std::cout << "Read encrypted file size: " << encrypted.size() << " bytes." << std::endl;

    // 解密（使用同一密码）
    std::string password = "G7#kLp$2Qr!vX9&mN4@zRw^5YcB*eH3";
    std::vector<BYTE> key(password.begin(), password.end());
    std::vector<BYTE> plainBytes = AesDecrypt(encrypted, key);

    // 清除密码和密钥
    SecureZeroString(password);
    SecureZeroVector(key);

    if (plainBytes.empty()) {
        std::cerr << "Decryption failed! Check diagnostic messages." << std::endl;
        return 1;
    }
    std::cout << "Decrypted size: " << plainBytes.size() << " bytes." << std::endl;

    // 转换为 JSON 字符串（新加密不会产生无用的尾随零，直接转换）
    std::string jsonStr(plainBytes.begin(), plainBytes.end());
    SecureZeroVector(plainBytes); // 清除明文

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(jsonStr);
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return 1;
    }

    // 1. 先校验所有 DLL，若失败则退出
    for (auto& [key, hashHex] : j.items()) {
        bool isDll = (key.length() >= 4 && key.substr(key.length() - 4) == ".dll");
        if (!isDll) continue;

        std::string filePath = parentDir + key;
        std::string backupPath = parentDir + "BackUp\\" + key;
        if (!VerifyAndReplace(filePath, backupPath, hashHex, true)) {
            std::cerr << "DLL verification failed for " << key << ", exiting." << std::endl;
            return 1;
        }
    }

    // 2. 校验所有 EXE 并启动它们（即使某个 EXE 无法恢复也继续执行其他）
    for (auto& [key, hashHex] : j.items()) {
        bool isDll = (key.length() >= 4 && key.substr(key.length() - 4) == ".dll");
        if (isDll) continue;

        std::string filename = key + ".exe";
        std::string filePath = parentDir + filename;
        std::string backupPath = parentDir + "BackUp\\" + filename;

        if (!VerifyAndReplace(filePath, backupPath, hashHex, false)) {
            std::cerr << "Skipping " << filename << " (hash mismatch after replacement)." << std::endl;
            continue;
        }

        // 启动进程
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::string cmdLine = "\"" + filePath + "\"";
        if (CreateProcessA(filePath.c_str(), (LPSTR)cmdLine.c_str(),
                           nullptr, nullptr, FALSE, 0, nullptr, parentDir.c_str(), &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            std::cout << "Started: " << filename << std::endl;
        } else {
            std::cerr << "Failed to start " << filename << " (error " << GetLastError() << ")" << std::endl;
        }
    }

    return 0;
}