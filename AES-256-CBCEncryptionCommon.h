// AES-256-CBCEncryptionCommon.h
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
#include <limits>      // 用于 std::numeric_limits（手动 PBKDF2 可选）
#include "nlohmann/json.hpp"

#pragma comment(lib, "bcrypt.lib")

#ifndef BCRYPT_CHAIN_MODE
#define BCRYPT_CHAIN_MODE L"ChainingMode"
#endif
#ifndef BCRYPT_CHAIN_MODE_CBC
#define BCRYPT_CHAIN_MODE_CBC L"CBC"
#endif

// -------------------- 安全常量 --------------------
static const DWORD PBKDF2_ITERATIONS = 600000;
static const size_t SALT_SIZE = 16;
static const size_t IV_SIZE = 16;
static const size_t HMAC_SIZE = 32;
static const size_t AES_KEY_SIZE = 32;
static const size_t DERIVED_KEY_SIZE = 64;    // AES(32) + HMAC(32)

// -------------------- 安全辅助函数 --------------------
inline bool SecureCompare(const BYTE* a, const BYTE* b, size_t len) {
    BYTE result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return result == 0;
}

inline bool GenerateRandomBytes(BYTE* buffer, size_t size) {
    NTSTATUS status = BCryptGenRandom(nullptr, buffer, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        std::cerr << "[BCrypt] BCryptGenRandom failed with 0x" << std::hex << status << std::dec << std::endl;
        OutputDebugStringA("[BCrypt] BCryptGenRandom failed\n");
        return false;
    }
    return true;
}

inline void SecureZeroVector(std::vector<BYTE>& vec) {
    if (!vec.empty()) {
        SecureZeroMemory(vec.data(), vec.size());
        vec.clear();
    }
}

inline void SecureZeroString(std::string& str) {
    if (!str.empty()) {
        SecureZeroMemory(&str[0], str.size());
        str.clear();
    }
}

// -------------------- HMAC-SHA256 声明（供 PBKDF2 调用） --------------------
inline std::vector<BYTE> ComputeHMAC(const std::vector<BYTE>& key, const std::vector<BYTE>& data);

// -------------------- PBKDF2 手动实现（RFC 2898） --------------------
inline std::vector<BYTE> DeriveKeyPBKDF2(const std::string& password, const std::vector<BYTE>& salt, DWORD iterations) {
    std::vector<BYTE> derived(DERIVED_KEY_SIZE, 0);
    if (salt.size() != SALT_SIZE) {
        std::cerr << "[PBKDF2] Salt size must be 16 bytes (got " << salt.size() << ")" << std::endl;
        return {};
    }

    const size_t hLen = 32;                     // SHA-256 输出长度
    const size_t dkLen = DERIVED_KEY_SIZE;
    const size_t l = (dkLen + hLen - 1) / hLen; // 需要的块数

    std::vector<BYTE> passwordBytes(password.begin(), password.end());
    std::vector<BYTE> result;
    result.reserve(dkLen);

    for (size_t block = 1; block <= l; ++block) {
        // 构造数据：salt || 4字节大端块索引
        std::vector<BYTE> data;
        data.reserve(salt.size() + 4);
        data.insert(data.end(), salt.begin(), salt.end());
        data.push_back((BYTE)((block >> 24) & 0xFF));
        data.push_back((BYTE)((block >> 16) & 0xFF));
        data.push_back((BYTE)((block >> 8) & 0xFF));
        data.push_back((BYTE)(block & 0xFF));

        // U1 = HMAC(password, data)
        std::vector<BYTE> U = ComputeHMAC(passwordBytes, data);
        if (U.size() != hLen) {
            SecureZeroVector(passwordBytes);
            SecureZeroVector(data);
            SecureZeroVector(derived);
            return {};
        }
        std::vector<BYTE> T = U;  // 初始 T = U1

        // 迭代 iterations-1 次
        for (DWORD i = 1; i < iterations; ++i) {
            U = ComputeHMAC(passwordBytes, U);
            if (U.size() != hLen) {
                SecureZeroVector(passwordBytes);
                SecureZeroVector(data);
                SecureZeroVector(T);
                SecureZeroVector(derived);
                return {};
            }
            // XOR T ^= U
            for (size_t j = 0; j < hLen; ++j) {
                T[j] ^= U[j];
            }
        }
        result.insert(result.end(), T.begin(), T.end());

        // 清除当前块敏感数据
        SecureZeroVector(T);
        SecureZeroVector(U);
        SecureZeroVector(data);
    }

    // 截取所需长度（DERIVED_KEY_SIZE）
    if (result.size() > dkLen) {
        result.resize(dkLen);
    }
    std::copy(result.begin(), result.end(), derived.begin());
    SecureZeroVector(result);
    SecureZeroVector(passwordBytes);
    return derived;
}

// -------------------- HMAC-SHA256 计算（定义） --------------------
inline std::vector<BYTE> ComputeHMAC(const std::vector<BYTE>& key, const std::vector<BYTE>& data) {
    std::vector<BYTE> hmac(HMAC_SIZE, 0);
    if (key.empty() || data.empty()) {
        std::cerr << "[HMAC] Empty key or data" << std::endl;
        return {};
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) {
        std::cerr << "[HMAC] BCryptOpenAlgorithmProvider failed with 0x" << std::hex << status << std::dec << std::endl;
        return {};
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, (BYTE*)key.data(), (ULONG)key.size(), 0);
    if (status != 0) {
        std::cerr << "[HMAC] BCryptCreateHash failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    status = BCryptHashData(hHash, (BYTE*)data.data(), (ULONG)data.size(), 0);
    if (status != 0) {
        std::cerr << "[HMAC] BCryptHashData failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    status = BCryptFinishHash(hHash, hmac.data(), (ULONG)hmac.size(), 0);
    if (status != 0) {
        std::cerr << "[HMAC] BCryptFinishHash failed with 0x" << std::hex << status << std::dec << std::endl;
        hmac.clear();
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hmac;
}

// -------------------- AES-256-CBC 加解密（带 HMAC） --------------------
inline bool SetCbcMode(BCRYPT_ALG_HANDLE hAlg) {
    NTSTATUS status = BCryptSetProperty(hAlg, BCRYPT_CHAIN_MODE,
                                        (BYTE*)BCRYPT_CHAIN_MODE_CBC,
                                        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status == 0) return true;

    std::cerr << "[BCrypt] BCryptSetProperty (CBC) failed with 0x" << std::hex << status << std::dec << std::endl;
    return false;
}

inline std::vector<BYTE> AesEncrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& key) {
    if (key.empty()) {
        std::cerr << "[AesEncrypt] Empty password" << std::endl;
        return {};
    }
    std::string password(key.begin(), key.end());

    // 1. 生成盐
    std::vector<BYTE> salt(SALT_SIZE, 0);
    if (!GenerateRandomBytes(salt.data(), salt.size())) {
        SecureZeroString(password);
        return {};
    }

    // 2. PBKDF2 派生
    std::vector<BYTE> derived = DeriveKeyPBKDF2(password, salt, PBKDF2_ITERATIONS);
    SecureZeroString(password);
    if (derived.size() != DERIVED_KEY_SIZE) {
        std::cerr << "[AesEncrypt] DeriveKeyPBKDF2 returned wrong size" << std::endl;
        SecureZeroVector(derived);
        return {};
    }

    std::vector<BYTE> encKey(derived.begin(), derived.begin() + AES_KEY_SIZE);
    std::vector<BYTE> hmacKey(derived.begin() + AES_KEY_SIZE, derived.end());
    SecureZeroVector(derived);

    // 3. 生成 IV
    std::vector<BYTE> iv(IV_SIZE, 0);
    if (!GenerateRandomBytes(iv.data(), iv.size())) {
        SecureZeroVector(encKey);
        SecureZeroVector(hmacKey);
        return {};
    }

    // 4. AES 加密
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) {
        std::cerr << "[AesEncrypt] BCryptOpenAlgorithmProvider (AES) failed with 0x" << std::hex << status << std::dec << std::endl;
        SecureZeroVector(encKey);
        SecureZeroVector(hmacKey);
        SecureZeroVector(iv);
        return {};
    }
    if (!SetCbcMode(hAlg)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(hmacKey);
        SecureZeroVector(iv);
        return {};
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, encKey.data(), (ULONG)encKey.size(), 0);
    if (status != 0) {
        std::cerr << "[AesEncrypt] BCryptGenerateSymmetricKey failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(hmacKey);
        SecureZeroVector(iv);
        return {};
    }

    DWORD cipherLen = 0;
    std::vector<BYTE> ivCopy = iv;
    status = BCryptEncrypt(hKey, (BYTE*)plaintext.data(), (ULONG)plaintext.size(), nullptr,
                           ivCopy.data(), (ULONG)ivCopy.size(), nullptr, 0, &cipherLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        std::cerr << "[AesEncrypt] BCryptEncrypt (size) failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(hmacKey);
        SecureZeroVector(iv);
        return {};
    }

    std::vector<BYTE> ciphertext(cipherLen);
    ivCopy = iv;
    status = BCryptEncrypt(hKey, (BYTE*)plaintext.data(), (ULONG)plaintext.size(), nullptr,
                           ivCopy.data(), (ULONG)ivCopy.size(),
                           ciphertext.data(), cipherLen, &cipherLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        std::cerr << "[AesEncrypt] BCryptEncrypt (final) failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(hmacKey);
        SecureZeroVector(iv);
        return {};
    }
    ciphertext.resize(cipherLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // 5. 计算 HMAC
    std::vector<BYTE> hmacData;
    hmacData.reserve(salt.size() + iv.size() + ciphertext.size());
    hmacData.insert(hmacData.end(), salt.begin(), salt.end());
    hmacData.insert(hmacData.end(), iv.begin(), iv.end());
    hmacData.insert(hmacData.end(), ciphertext.begin(), ciphertext.end());

    std::vector<BYTE> hmac = ComputeHMAC(hmacKey, hmacData);
    SecureZeroVector(hmacKey);

    if (hmac.size() != HMAC_SIZE) {
        std::cerr << "[AesEncrypt] ComputeHMAC returned wrong size" << std::endl;
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        SecureZeroVector(hmacData);
        return {};
    }

    // 6. 组装最终结果: salt + iv + ciphertext + hmac
    std::vector<BYTE> result;
    result.reserve(salt.size() + iv.size() + ciphertext.size() + hmac.size());
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), hmac.begin(), hmac.end());

    SecureZeroVector(encKey);
    SecureZeroVector(iv);
    SecureZeroVector(ciphertext);
    SecureZeroVector(hmacData);
    SecureZeroVector(hmac);
    SecureZeroVector(salt);

    return result;
}

inline std::vector<BYTE> AesDecrypt(const std::vector<BYTE>& cipherWithIV, const std::vector<BYTE>& key) {
    if (key.empty()) {
        std::cerr << "[AesDecrypt] Empty password" << std::endl;
        return {};
    }
    std::string password(key.begin(), key.end());

    if (cipherWithIV.size() < SALT_SIZE + IV_SIZE + HMAC_SIZE) {
        std::cerr << "[AesDecrypt] Input too short" << std::endl;
        SecureZeroString(password);
        return {};
    }

    std::vector<BYTE> salt(cipherWithIV.begin(), cipherWithIV.begin() + SALT_SIZE);
    std::vector<BYTE> iv(cipherWithIV.begin() + SALT_SIZE, cipherWithIV.begin() + SALT_SIZE + IV_SIZE);
    size_t dataLen = cipherWithIV.size() - SALT_SIZE - IV_SIZE - HMAC_SIZE;
    std::vector<BYTE> ciphertext(cipherWithIV.begin() + SALT_SIZE + IV_SIZE,
                                 cipherWithIV.begin() + SALT_SIZE + IV_SIZE + dataLen);
    std::vector<BYTE> expectedHmac(cipherWithIV.end() - HMAC_SIZE, cipherWithIV.end());

    // PBKDF2
    std::vector<BYTE> derived = DeriveKeyPBKDF2(password, salt, PBKDF2_ITERATIONS);
    SecureZeroString(password);
    if (derived.size() != DERIVED_KEY_SIZE) {
        std::cerr << "[AesDecrypt] DeriveKeyPBKDF2 returned wrong size" << std::endl;
        SecureZeroVector(derived);
        return {};
    }

    std::vector<BYTE> encKey(derived.begin(), derived.begin() + AES_KEY_SIZE);
    std::vector<BYTE> hmacKey(derived.begin() + AES_KEY_SIZE, derived.end());
    SecureZeroVector(derived);

    // HMAC 验证
    std::vector<BYTE> hmacData;
    hmacData.reserve(salt.size() + iv.size() + ciphertext.size());
    hmacData.insert(hmacData.end(), salt.begin(), salt.end());
    hmacData.insert(hmacData.end(), iv.begin(), iv.end());
    hmacData.insert(hmacData.end(), ciphertext.begin(), ciphertext.end());

    std::vector<BYTE> actualHmac = ComputeHMAC(hmacKey, hmacData);
    SecureZeroVector(hmacKey);
    SecureZeroVector(hmacData);

    if (actualHmac.size() != HMAC_SIZE) {
        std::cerr << "[AesDecrypt] ComputeHMAC failed" << std::endl;
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        SecureZeroVector(expectedHmac);
        return {};
    }

    if (!SecureCompare(actualHmac.data(), expectedHmac.data(), HMAC_SIZE)) {
        std::cerr << "[AesDecrypt] HMAC verification failed" << std::endl;
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        SecureZeroVector(expectedHmac);
        SecureZeroVector(actualHmac);
        return {};
    }

    SecureZeroVector(expectedHmac);
    SecureZeroVector(actualHmac);

    // AES 解密
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) {
        std::cerr << "[AesDecrypt] BCryptOpenAlgorithmProvider (AES) failed with 0x" << std::hex << status << std::dec << std::endl;
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        return {};
    }
    if (!SetCbcMode(hAlg)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        return {};
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, encKey.data(), (ULONG)encKey.size(), 0);
    if (status != 0) {
        std::cerr << "[AesDecrypt] BCryptGenerateSymmetricKey failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        return {};
    }

    DWORD plainLen = 0;
    std::vector<BYTE> ivCopy = iv;
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext.data(), (ULONG)ciphertext.size(), nullptr,
                           ivCopy.data(), (ULONG)ivCopy.size(), nullptr, 0, &plainLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        std::cerr << "[AesDecrypt] BCryptDecrypt (size) failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        return {};
    }

    std::vector<BYTE> plaintext(plainLen);
    ivCopy = iv;
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext.data(), (ULONG)ciphertext.size(), nullptr,
                           ivCopy.data(), (ULONG)ivCopy.size(),
                           plaintext.data(), plainLen, &plainLen, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        std::cerr << "[AesDecrypt] BCryptDecrypt (final) failed with 0x" << std::hex << status << std::dec << std::endl;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroVector(encKey);
        SecureZeroVector(iv);
        SecureZeroVector(ciphertext);
        return {};
    }
    plaintext.resize(plainLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    SecureZeroVector(encKey);
    SecureZeroVector(iv);
    SecureZeroVector(ciphertext);
    SecureZeroVector(salt);

    return plaintext;
}

// -------------------- 文件完整性（HMAC-SHA256） --------------------
static const BYTE FILE_KEY_XOR[32] = {
    0x5A, 0x3F, 0x1C, 0x8E, 0x2B, 0x7D, 0x4E, 0x6A,
    0x9C, 0x2F, 0xD1, 0x3B, 0x7E, 0x5A, 0x1F, 0x4D,
    0x6B, 0x8A, 0x3C, 0x2E, 0x5F, 0x1D, 0x4A, 0x7B,
    0x9E, 0x3F, 0x2C, 0x5D, 0x1E, 0x4F, 0x8B, 0x6A
};
static const BYTE FILE_KEY_MASK[32] = {
    0x2B, 0x5E, 0x3D, 0xA9, 0x4C, 0x18, 0x6F, 0x0B,
    0xBF, 0x4D, 0xF0, 0x16, 0x5D, 0x3B, 0x7E, 0x2C,
    0x0A, 0xE9, 0x17, 0x4F, 0x3E, 0x7C, 0x2B, 0x5A,
    0xFD, 0x1E, 0x0F, 0x7E, 0x3F, 0x6E, 0xAA, 0x0B
};
inline void GetFileHmacKey(BYTE* key) {
    for (int i = 0; i < 32; ++i) {
        key[i] = FILE_KEY_XOR[i] ^ FILE_KEY_MASK[i];
    }
}

inline std::vector<BYTE> Sha256File(const std::string& filePath) {
    BYTE key[32];
    GetFileHmacKey(key);
    std::vector<BYTE> hmacKey(key, key + 32);
    SecureZeroMemory(key, sizeof(key));

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "[Sha256File] Cannot open " << filePath << std::endl;
        SecureZeroVector(hmacKey);
        return {};
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) {
        std::cerr << "[Sha256File] BCryptOpenAlgorithmProvider failed with 0x" << std::hex << status << std::dec << std::endl;
        SecureZeroVector(hmacKey);
        return {};
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, hmacKey.data(), (ULONG)hmacKey.size(), 0);
    SecureZeroVector(hmacKey);
    if (status != 0) {
        std::cerr << "[Sha256File] BCryptCreateHash failed with 0x" << std::hex << status << std::dec << std::endl;
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
        std::cerr << "[Sha256File] BCryptFinishHash failed with 0x" << std::hex << status << std::dec << std::endl;
        hash.clear();
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

// -------------------- 工具函数（保持兼容） --------------------
inline void PrintBcryptError(const char* func, NTSTATUS status) {
    std::cerr << "[BCrypt] " << func << " failed with 0x" << std::hex << status << std::dec << std::endl;
    OutputDebugStringA("[BCrypt] ");
    OutputDebugStringA(func);
    OutputDebugStringA(" failed\n");
}

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