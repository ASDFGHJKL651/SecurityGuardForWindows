// Common.h
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <filesystem>
#include <cstring>
#include "nlohmann/json.hpp"

#pragma comment(lib, "bcrypt.lib")

// 确保链模式常量已定义
#ifndef BCRYPT_CHAIN_MODE
#define BCRYPT_CHAIN_MODE L"ChainingMode"
#endif
#ifndef BCRYPT_CHAIN_MODE_CBC
#define BCRYPT_CHAIN_MODE_CBC L"CBC"
#endif

//辅助错误打印
inline void PrintBcryptError(const char* func, NTSTATUS status) {
    std::cerr << "[BCrypt] " << func << " failed with status: 0x"
              << std::hex << status << std::dec << std::endl;
}

//路径工具
inline std::string GetExeDirectory() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string exePath(path);
    size_t pos = exePath.find_last_of("\\/");
    if (pos != std::string::npos) {
        return exePath.substr(0, pos + 1);
    }
    return "";
}

inline std::string GetParentDirectory(const std::string& dir) {
    std::string parent = dir;
    if (!parent.empty() && parent.back() == '\\') parent.pop_back();
    size_t pos = parent.find_last_of("\\/");
    if (pos != std::string::npos) {
        return parent.substr(0, pos + 1);
    }
    return "";
}

//十六进制转换
inline std::string BytesToHex(const std::vector<BYTE>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (BYTE b : bytes) {
        oss << std::setw(2) << (int)b;
    }
    return oss.str();
}

inline std::vector<BYTE> HexToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        BYTE b = (BYTE)strtol(byteStr.c_str(), nullptr, 16);
        bytes.push_back(b);
    }
    return bytes;
}

//SHA-256 文件哈希
inline std::vector<BYTE> Sha256File(const std::string& filePath) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != 0) {
        PrintBcryptError("BCryptOpenAlgorithmProvider (SHA256)", status);
        return {};
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (status != 0) {
        PrintBcryptError("BCryptCreateHash", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Sha256File: cannot open " << filePath << std::endl;
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        BCryptHashData(hHash, (BYTE*)buffer, (ULONG)file.gcount(), 0);
    }
    if (file.gcount() > 0) {
        BCryptHashData(hHash, (BYTE*)buffer, (ULONG)file.gcount(), 0);
    }
    file.close();

    std::vector<BYTE> hash(32);
    status = BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);
    if (status != 0) {
        PrintBcryptError("BCryptFinishHash", status);
        hash.clear();
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

//AES-256-CBC 加解密（强制 CBC）
inline std::vector<BYTE> DeriveKey(const std::string& password) {
    std::vector<BYTE> key(32, 0);
    size_t len = password.length();
    if (len > 32) len = 32;
    memcpy(key.data(), password.c_str(), len);
    return key;
}

// 设置 CBC 模式，失败则打印调试信息并返回 false
inline bool SetCbcMode(BCRYPT_ALG_HANDLE hAlg) {
    NTSTATUS status = BCryptSetProperty(hAlg, BCRYPT_CHAIN_MODE,
                                        (BYTE*)BCRYPT_CHAIN_MODE_CBC,
                                        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status == 0) return true;

    // 获取当前模式辅助诊断
    wchar_t currentMode[64] = {0};
    DWORD size = sizeof(currentMode);
    NTSTATUS getStatus = BCryptGetProperty(hAlg, BCRYPT_CHAIN_MODE,
                                           (BYTE*)currentMode, size, &size, 0);
    if (getStatus == 0) {
        std::wcerr << L"Current chain mode: " << currentMode << std::endl;
    } else {
        PrintBcryptError("BCryptGetProperty", getStatus);
    }
    PrintBcryptError("BCryptSetProperty (CBC)", status);
    return false;
}

inline std::vector<BYTE> AesEncrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& key) {
    if (plaintext.empty()) {
        std::cerr << "AesEncrypt: plaintext is empty!" << std::endl;
        return {};
    }
    if (key.size() != 32) {
        std::cerr << "AesEncrypt: key size must be 32 bytes (got " << key.size() << ")" << std::endl;
        return {};
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) {
        PrintBcryptError("BCryptOpenAlgorithmProvider (AES)", status);
        return {};
    }

    if (!SetCbcMode(hAlg)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<BYTE> iv(16);
    status = BCryptGenRandom(nullptr, iv.data(), (ULONG)iv.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        PrintBcryptError("BCryptGenRandom", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    //复制一份原始 IV，用于调用加密
    std::vector<BYTE> ivForEncrypt = iv;

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (BYTE*)key.data(), (ULONG)key.size(), 0);
    if (status != 0) {
        PrintBcryptError("BCryptGenerateSymmetricKey", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    DWORD cipherLen = 0;
    status = BCryptEncrypt(hKey, (BYTE*)plaintext.data(), (ULONG)plaintext.size(), nullptr,
                           ivForEncrypt.data(), (ULONG)ivForEncrypt.size(), nullptr, 0, &cipherLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        PrintBcryptError("BCryptEncrypt (size query)", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<BYTE> ciphertext(cipherLen);
    // 再次使用原始 IV
    ivForEncrypt = iv;  // 重新置为原始 IV
    status = BCryptEncrypt(hKey, (BYTE*)plaintext.data(), (ULONG)plaintext.size(), nullptr,
                           ivForEncrypt.data(), (ULONG)ivForEncrypt.size(),
                           ciphertext.data(), cipherLen, &cipherLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        PrintBcryptError("BCryptEncrypt (final)", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    ciphertext.resize(cipherLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // 拼接时使用原始 IV（未被修改的 iv）
    std::vector<BYTE> result;
    result.reserve(iv.size() + ciphertext.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

inline std::vector<BYTE> AesDecrypt(const std::vector<BYTE>& cipherWithIV, const std::vector<BYTE>& key) {
    if (cipherWithIV.size() < 16) {
        std::cerr << "AesDecrypt: ciphertext too short (no IV)" << std::endl;
        return {};
    }
    if (key.size() != 32) {
        std::cerr << "AesDecrypt: key size must be 32 bytes (got " << key.size() << ")" << std::endl;
        return {};
    }

    std::vector<BYTE> iv(cipherWithIV.begin(), cipherWithIV.begin() + 16);
    std::vector<BYTE> ciphertext(cipherWithIV.begin() + 16, cipherWithIV.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) {
        PrintBcryptError("BCryptOpenAlgorithmProvider (AES)", status);
        return {};
    }

    if (!SetCbcMode(hAlg)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (BYTE*)key.data(), (ULONG)key.size(), 0);
    if (status != 0) {
        PrintBcryptError("BCryptGenerateSymmetricKey", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    DWORD plainLen = 0;
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext.data(), (ULONG)ciphertext.size(), nullptr,
                           iv.data(), (ULONG)iv.size(), nullptr, 0, &plainLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        PrintBcryptError("BCryptDecrypt (size query)", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<BYTE> plaintext(plainLen);
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext.data(), (ULONG)ciphertext.size(), nullptr,
                           iv.data(), (ULONG)iv.size(), plaintext.data(), plainLen, &plainLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        PrintBcryptError("BCryptDecrypt (final)", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    plaintext.resize(plainLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return plaintext;
}