/*
IsolationFolder.cpp

详见IsolationFoldermain.cpp
*/
#undef UNICODE
#undef _UNICODE
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <wincrypt.h>
#include "IsolationFolder.h"
#include <random>
#include <chrono>
#include <vector>
#include <fstream>
#include <iostream>

#define AES_BLOCK_SIZE 16   // AES 块大小为 16 字节

//AES 实现

SimpleAES::SimpleAES(const std::string& pwd)
    : password(pwd), hProv(NULL), hKey(NULL)
{
    init_crypto();
}

SimpleAES::~SimpleAES() {
    cleanup_crypto();
}

bool SimpleAES::init_crypto() {
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext 失败，错误码: " << GetLastError() << std::endl;
        return false;
    }

    HCRYPTHASH hHash = NULL;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash 失败，错误码: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        hProv = NULL;
        return false;
    }

    if (!CryptHashData(hHash, (const BYTE*)password.c_str(), (DWORD)password.length(), 0)) {
        std::cerr << "CryptHashData 失败，错误码: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        hProv = NULL;
        return false;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey 失败，错误码: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        hProv = NULL;
        return false;
    }

    CryptDestroyHash(hHash);
    return true;
}

void SimpleAES::cleanup_crypto() {
    if (hKey) {
        CryptDestroyKey(hKey);
        hKey = NULL;
    }
    if (hProv) {
        CryptReleaseContext(hProv, 0);
        hProv = NULL;
    }
}

bool SimpleAES::encrypt_file(const std::string& input_path, const std::string& output_path) {
    std::ifstream in(input_path, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "无法打开输入文件: " << input_path << std::endl;
        return false;
    }
    in.seekg(0, std::ios::end);
    size_t file_size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<BYTE> plaintext(file_size);
    in.read((char*)plaintext.data(), file_size);
    in.close();

    // 生成随机 IV
    BYTE iv[AES_BLOCK_SIZE];
    HCRYPTPROV hProvRand = NULL;
    if (!CryptAcquireContext(&hProvRand, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "无法获取随机数提供者，错误码: " << GetLastError() << std::endl;
        return false;
    }
    if (!CryptGenRandom(hProvRand, AES_BLOCK_SIZE, iv)) {
        std::cerr << "CryptGenRandom 失败，错误码: " << GetLastError() << std::endl;
        CryptReleaseContext(hProvRand, 0);
        return false;
    }
    CryptReleaseContext(hProvRand, 0);

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        std::cerr << "CryptSetKeyParam (IV) 失败，错误码: " << GetLastError() << std::endl;
        return false;
    }

    // 准备加密缓冲区：复制明文并预留填充空间
    DWORD data_len = (DWORD)file_size;
    DWORD buffer_len = data_len + AES_BLOCK_SIZE; // 足够容纳填充
    std::vector<BYTE> buffer(data_len);
    memcpy(buffer.data(), plaintext.data(), data_len);
    buffer.resize(buffer_len); // 扩展至 buffer_len

    if (!CryptEncrypt(hKey, NULL, TRUE, 0, buffer.data(), &data_len, buffer_len)) {
        std::cerr << "CryptEncrypt 失败，错误码: " << GetLastError() << std::endl;
        return false;
    }
    // 加密后 data_len 为实际密文长度
    buffer.resize(data_len);

    // 写入文件头部 + 密文
    std::ofstream out(output_path, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "无法创建输出文件: " << output_path << std::endl;
        return false;
    }

    out.write("ISOL", 4);
    out.write((char*)iv, AES_BLOCK_SIZE);
    uint64_t size64 = file_size;
    out.write((char*)&size64, sizeof(size64));
    uint32_t path_len = (uint32_t)input_path.length();
    out.write((char*)&path_len, sizeof(path_len));
    out.write(input_path.c_str(), path_len);
    out.write((char*)buffer.data(), buffer.size());
    out.close();

    return true;
}

bool SimpleAES::decrypt_file(const std::string& input_path, const std::string& output_path) {
    std::ifstream in(input_path, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "无法打开加密文件: " << input_path << std::endl;
        return false;
    }

    char magic[4];
    BYTE iv[AES_BLOCK_SIZE];
    uint64_t original_size;
    uint32_t path_len;

    in.read(magic, 4);
    if (strncmp(magic, "ISOL", 4) != 0) {
        std::cerr << "无效的加密文件格式" << std::endl;
        in.close();
        return false;
    }

    in.read((char*)iv, AES_BLOCK_SIZE);
    in.read((char*)&original_size, sizeof(original_size));
    in.read((char*)&path_len, sizeof(path_len));

    std::string original_path;
    if (path_len > 0) {
        std::vector<char> path_buf(path_len + 1, 0);
        in.read(path_buf.data(), path_len);
        original_path = path_buf.data();
    }

    // 读取密文
    in.seekg(0, std::ios::end);
    size_t total_size = in.tellg();
    in.seekg(4 + AES_BLOCK_SIZE + sizeof(original_size) + sizeof(path_len) + path_len, std::ios::beg);
    size_t cipher_len = total_size - (4 + AES_BLOCK_SIZE + sizeof(original_size) + sizeof(path_len) + path_len);
    std::vector<BYTE> ciphertext(cipher_len);
    in.read((char*)ciphertext.data(), cipher_len);
    in.close();

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        std::cerr << "CryptSetKeyParam (IV) 失败，错误码: " << GetLastError() << std::endl;
        return false;
    }

    // 解密：原地解密
    DWORD out_len = (DWORD)ciphertext.size();
    if (!CryptDecrypt(hKey, NULL, TRUE, 0, ciphertext.data(), &out_len)) {
        std::cerr << "CryptDecrypt 失败，错误码: " << GetLastError() << std::endl;
        return false;
    }
    // 解密后 out_len 为明文长度（应等于 original_size）
    ciphertext.resize(out_len);

    std::string dest_path = output_path;
    if (dest_path.empty()) {
        if (original_path.empty()) {
            std::cerr << "未指定目标路径且头部无原始路径" << std::endl;
            return false;
        }
        dest_path = original_path;
    }

    std::ofstream out(dest_path, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "无法创建解密文件: " << dest_path << std::endl;
        return false;
    }
    out.write((char*)ciphertext.data(), out_len);
    out.close();

    return true;
}

//IsolationFolder 实现

IsolationFolder::IsolationFolder(const std::string& path, const std::string& pwd)
    : folder_path(path), password(pwd), aes(pwd) {}

IsolationFolder::~IsolationFolder() {}

bool IsolationFolder::enable_privilege(const char* privilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result && GetLastError() == ERROR_SUCCESS;
}

bool IsolationFolder::take_ownership() {
    if (!enable_privilege(SE_TAKE_OWNERSHIP_NAME)) {
        std::cerr << "无法启用SeTakeOwnershipPrivilege，请以管理员身份运行" << std::endl;
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    PSID pSid = ((PTOKEN_USER)buffer.data())->User.Sid;

    if (SetNamedSecurityInfoA((LPSTR)folder_path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                              pSid, NULL, NULL, NULL) != ERROR_SUCCESS) {
        std::cerr << "设置所有者失败，错误码: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

bool IsolationFolder::set_folder_permissions() {
    if (!take_ownership()) {
        return false;
    }

    // 创建拒绝 Everyone 的 DACL
    EXPLICIT_ACCESS_A ea = {0};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPSTR)"EVERYONE";

    PACL pDACL = NULL;
    if (SetEntriesInAclA(1, &ea, NULL, &pDACL) != ERROR_SUCCESS) {
        std::cerr << "创建DACL失败" << std::endl;
        return false;
    }

    DWORD result = SetNamedSecurityInfoA((LPSTR)folder_path.c_str(), SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION,
                                         NULL, NULL, pDACL, NULL);

    LocalFree(pDACL);

    if (result != ERROR_SUCCESS) {
        std::cerr << "设置文件夹权限失败，错误码: " << result << std::endl;
        return false;
    }

    std::cout << "✓ 文件夹权限已锁定（拒绝所有用户访问）" << std::endl;
    return true;
}

bool IsolationFolder::restore_folder_permissions() {
    if (!take_ownership()) {
        return false;
    }

    EXPLICIT_ACCESS_A ea = {0};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPSTR)"CREATOR OWNER";

    PACL pDACL = NULL;
    if (SetEntriesInAclA(1, &ea, NULL, &pDACL) != ERROR_SUCCESS) {
        return false;
    }

    DWORD result = SetNamedSecurityInfoA((LPSTR)folder_path.c_str(), SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION,
                                         NULL, NULL, pDACL, NULL);

    LocalFree(pDACL);
    return result == ERROR_SUCCESS;
}

bool IsolationFolder::initialize() {
    if (CreateDirectoryA(folder_path.c_str(), NULL)) {
        std::cout << "✓ 创建隔离文件夹: " << folder_path << std::endl;
    } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "✓ 隔离文件夹已存在: " << folder_path << std::endl;
    } else {
        std::cerr << "创建文件夹失败，错误码: " << GetLastError() << std::endl;
        return false;
    }
    return set_folder_permissions();
}

bool IsolationFolder::add_file(const std::string& file_path) {
    size_t pos = file_path.find_last_of("\\/");
    std::string file_name = (pos == std::string::npos) ? file_path : file_path.substr(pos + 1);
    std::string encrypted_path = folder_path + "\\" + file_name + ".isol";

    if (!aes.encrypt_file(file_path, encrypted_path)) {
        std::cerr << "加密文件失败: " << file_path << std::endl;
        return false;
    }

    if (DeleteFileA(file_path.c_str())) {
        std::cout << "✓ 已移入隔离区: " << file_name << " (AES-256加密)" << std::endl;
    } else {
        std::cout << "✓ 已加密并复制到隔离区: " << file_name << " (原始文件未删除)" << std::endl;
    }
    return true;
}

bool IsolationFolder::extract_file(const std::string& file_name, const std::string& dest_path) {
    std::string encrypted_path = folder_path + "\\" + file_name;
    if (encrypted_path.find(".isol") == std::string::npos) {
        encrypted_path += ".isol";
    }

    if (GetFileAttributesA(encrypted_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "隔离区中不存在文件: " << file_name << std::endl;
        return false;
    }

    if (!aes.decrypt_file(encrypted_path, dest_path)) {
        std::cerr << "解密文件失败" << std::endl;
        return false;
    }

    if (DeleteFileA(encrypted_path.c_str())) {
        std::cout << "✓ 已从隔离区移出: " << file_name << std::endl;
    } else {
        std::cout << "✓ 已解密到目标位置 (隔离区文件保留)" << std::endl;
    }
    return true;
}

bool IsolationFolder::list_files() {
    std::string search_path = folder_path + "\\*.isol";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search_path.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cout << "隔离区为空" << std::endl;
        return true;
    }

    std::cout << "\n=== 隔离区文件列表 ===" << std::endl;
    int count = 0;
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string name = findData.cFileName;
            size_t pos = name.find(".isol");
            if (pos != std::string::npos) {
                name = name.substr(0, pos);
            }
            std::cout << "  " << ++count << ". " << name
                      << " (" << findData.nFileSizeLow << " bytes)" << std::endl;
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    std::cout << "共 " << count << " 个文件" << std::endl;
    return true;
}

bool IsolationFolder::delete_file(const std::string& file_name) {
    std::string path = folder_path + "\\" + file_name;
    if (path.find(".isol") == std::string::npos) {
        path += ".isol";
    }

    if (DeleteFileA(path.c_str())) {
        std::cout << "✓ 已从隔离区删除: " << file_name << std::endl;
        return true;
    } else {
        std::cerr << "删除失败，错误码: " << GetLastError() << std::endl;
        return false;
    }
}

bool IsolationFolder::cleanup() {
    return restore_folder_permissions();
}