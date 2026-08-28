/*
Verification.cpp

开机以管理员权限自启动，校验程序哈希值(SHA-256)，恢复被篡改的程序，启动校验通过的程序

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\Verification.cpp" -o "%Executable%\Verification\Verification.exe" -lbcrypt -lstdc++fs -static-libgcc -static-libstdc++

运行权限：管理员权限
*/
#include "Common.h"
#include <filesystem>
#include <iomanip>

bool VerifyAndReplace(const std::string& filePath, const std::string& backupPath,
                      const std::string& expectedHex, bool isDll) {
    auto hashBytes = Sha256File(filePath);
    std::string currentHex = BytesToHex(hashBytes);
    if (currentHex == expectedHex) {
        return true;
    }

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

    auto newHash = Sha256File(filePath);
    std::string newHex = BytesToHex(newHash);
    return (newHex == expectedHex);
}

int main() {
    std::string exeDir = GetExeDirectory();
    std::string parentDir = GetParentDirectory(exeDir);
    std::string configPath = exeDir + "Configuration\\HashValue.json";

    std::ifstream in(configPath, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open " << configPath << std::endl;
        return 1;
    }
    std::vector<BYTE> encrypted((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    in.close();
    std::cout << "Read encrypted file size: " << encrypted.size() << " bytes." << std::endl;

    std::vector<BYTE> key = DeriveKey("P@aS7sw4&OR7d");
    std::vector<BYTE> plainBytes = AesDecrypt(encrypted, key);
    if (plainBytes.empty()) {
        std::cerr << "Decryption failed!" << std::endl;
        return 1;
    }
    std::cout << "Decrypted size: " << plainBytes.size() << " bytes." << std::endl;

    std::cout << "First 20 bytes (hex): ";
    for (size_t i = 0; i < std::min<size_t>(20, plainBytes.size()); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)plainBytes[i] << " ";
    }
    std::cout << std::dec << std::endl;

    while (!plainBytes.empty() && plainBytes.back() == 0) {
        plainBytes.pop_back();
    }

    std::string jsonStr(plainBytes.begin(), plainBytes.end());
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(jsonStr);
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        std::cerr << "Raw string (first 100 chars): " << jsonStr.substr(0, 100) << std::endl;
        return 1;
    }

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