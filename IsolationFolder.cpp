/*
IsolationFolder.cpp
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
#include <limits>

// 自定义文件头魔数
static const char MAGIC[] = "ISOL";
static const size_t MAGIC_LEN = 4;

// ------------------------------------------------------------------
// IsolationFolder 实现
// ------------------------------------------------------------------

IsolationFolder::IsolationFolder(const std::string& path, const std::string& pwd)
    : folder_path(path), password(pwd) {}

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
        std::cerr << "无法启用 SeTakeOwnershipPrivilege，请以管理员身份运行" << std::endl;
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

// 修复权限：只允许当前用户和 SYSTEM 完全控制，阻止继承
bool IsolationFolder::set_folder_permissions() {
    if (!take_ownership()) {
        return false;
    }

    // 获取当前用户 SID
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "无法获取进程令牌" << std::endl;
        return false;
    }
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(hToken);
        std::cerr << "无法获取用户 SID" << std::endl;
        return false;
    }
    CloseHandle(hToken);
    PSID pUserSid = ((PTOKEN_USER)buffer.data())->User.Sid;

    // 构造 ACL：允许当前用户完全控制（同时允许 SYSTEM，便于系统操作）
    EXPLICIT_ACCESS_A ea[2] = {0};
    // 当前用户
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = GRANT_ACCESS;
    ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPSTR)pUserSid;

    // SYSTEM
    BYTE systemSid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(systemSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &sidSize)) {
        std::cerr << "无法创建 SYSTEM SID" << std::endl;
        return false;
    }
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPSTR)systemSid;

    PACL pDACL = NULL;
    DWORD dwRes = SetEntriesInAclA(2, ea, NULL, &pDACL);
    if (dwRes != ERROR_SUCCESS) {
        std::cerr << "创建 DACL 失败，错误码: " << dwRes << std::endl;
        return false;
    }

    // 设置 DACL，并阻止继承（PROTECTED_DACL_SECURITY_INFORMATION）
    DWORD result = SetNamedSecurityInfoA((LPSTR)folder_path.c_str(), SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                         NULL, NULL, pDACL, NULL);

    LocalFree(pDACL);

    if (result != ERROR_SUCCESS) {
        std::cerr << "设置文件夹权限失败，错误码: " << result << std::endl;
        return false;
    }

    std::cout << "✓ 文件夹权限已锁定（仅允许当前用户和 SYSTEM 访问）" << std::endl;
    return true;
}

// 恢复权限：移除自定义 DACL，即允许所有人访问（NULL DACL）
bool IsolationFolder::restore_folder_permissions() {
    if (!take_ownership()) {
        return false;
    }

    // 传入 NULL 作为 DACL，表示删除自定义 ACL，让文件夹继承父目录权限
    DWORD result = SetNamedSecurityInfoA((LPSTR)folder_path.c_str(), SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION,
                                         NULL, NULL, NULL, NULL);

    if (result != ERROR_SUCCESS) {
        std::cerr << "恢复权限失败，错误码: " << result << std::endl;
        return false;
    }
    return true;
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
    // 读取原始文件
    std::ifstream in(file_path, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "无法打开文件: " << file_path << std::endl;
        return false;
    }
    in.seekg(0, std::ios::end);
    size_t file_size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<BYTE> plaintext(file_size);
    in.read((char*)plaintext.data(), file_size);
    in.close();

    // 加密（AesEncrypt 返回 salt+IV+ciphertext+HMAC）
    std::vector<BYTE> passwordBytes(password.begin(), password.end());
    std::vector<BYTE> encryptedData = AesEncrypt(plaintext, passwordBytes);
    SecureZeroVector(passwordBytes);
    if (encryptedData.empty()) {
        std::cerr << "加密失败" << std::endl;
        SecureZeroVector(plaintext);
        return false;
    }
    SecureZeroVector(plaintext);

    // 构造输出文件路径
    size_t pos = file_path.find_last_of("\\/");
    std::string file_name = (pos == std::string::npos) ? file_path : file_path.substr(pos + 1);
    std::string encrypted_path = folder_path + "\\" + file_name + ".isol";

    // 写自定义头部 + 加密数据
    std::ofstream out(encrypted_path, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "无法创建隔离文件: " << encrypted_path << std::endl;
        SecureZeroVector(encryptedData);
        return false;
    }

    // 写入魔数
    out.write(MAGIC, MAGIC_LEN);
    // 写入原始文件大小（uint64_t）
    uint64_t size64 = file_size;
    out.write((char*)&size64, sizeof(size64));
    // 写入原始路径长度和路径
    uint32_t path_len = (uint32_t)file_path.length();
    out.write((char*)&path_len, sizeof(path_len));
    out.write(file_path.c_str(), path_len);
    // 写入加密数据
    out.write((char*)encryptedData.data(), encryptedData.size());
    out.close();

    SecureZeroVector(encryptedData);

    // 删除原始文件（可选）
    if (DeleteFileA(file_path.c_str())) {
        std::cout << "✓ 已移入隔离区: " << file_name << " (AES-256-CBC + HMAC 加密)" << std::endl;
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

    // 读取文件头
    std::ifstream in(encrypted_path, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "无法打开隔离文件: " << encrypted_path << std::endl;
        return false;
    }

    char magic[MAGIC_LEN + 1] = {0};
    in.read(magic, MAGIC_LEN);
    if (strncmp(magic, MAGIC, MAGIC_LEN) != 0) {
        std::cerr << "无效的隔离文件格式" << std::endl;
        in.close();
        return false;
    }

    uint64_t original_size;
    in.read((char*)&original_size, sizeof(original_size));
    uint32_t path_len;
    in.read((char*)&path_len, sizeof(path_len));
    std::string original_path;
    if (path_len > 0) {
        std::vector<char> path_buf(path_len + 1, 0);
        in.read(path_buf.data(), path_len);
        original_path = path_buf.data();
    }

    // 读取剩余加密数据
    in.seekg(0, std::ios::end);
    size_t total_size = in.tellg();
    size_t header_size = MAGIC_LEN + sizeof(original_size) + sizeof(path_len) + path_len;
    size_t enc_len = total_size - header_size;
    in.seekg(header_size, std::ios::beg);
    std::vector<BYTE> encryptedData(enc_len);
    in.read((char*)encryptedData.data(), enc_len);
    in.close();

    // 解密
    std::vector<BYTE> passwordBytes(password.begin(), password.end());
    std::vector<BYTE> plaintext = AesDecrypt(encryptedData, passwordBytes);
    SecureZeroVector(passwordBytes);
    SecureZeroVector(encryptedData);

    if (plaintext.empty()) {
        std::cerr << "解密失败（可能是密码错误或文件损坏）" << std::endl;
        return false;
    }

    // 确定目标路径
    std::string dest = dest_path;
    if (dest.empty()) {
        if (original_path.empty()) {
            std::cerr << "未指定目标路径且头部无原始路径" << std::endl;
            SecureZeroVector(plaintext);
            return false;
        }
        dest = original_path;
    }

    // 写入明文
    std::ofstream out(dest, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "无法创建解密文件: " << dest << std::endl;
        SecureZeroVector(plaintext);
        return false;
    }
    out.write((char*)plaintext.data(), plaintext.size());
    out.close();
    SecureZeroVector(plaintext);

    // 删除隔离文件
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