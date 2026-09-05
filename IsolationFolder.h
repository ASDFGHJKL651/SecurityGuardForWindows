/*
IsolationFolder.h
*/
#ifndef ISOLATION_FOLDER_H
#define ISOLATION_FOLDER_H

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstring>
#include <iomanip>

#include "AES-256-CBCEncryptionCommon.h"   // 新的 AES 加密头文件

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")         // 已在 EncryptionCommon 中链接，但保留无妨

// 隔离文件夹管理类
class IsolationFolder {
private:
    std::string folder_path;
    std::string password;                  // 存储密码（明文，仅用于派生密钥）

    bool set_folder_permissions();
    bool restore_folder_permissions();
    bool take_ownership();
    bool enable_privilege(const char* privilege);

public:
    IsolationFolder(const std::string& path, const std::string& pwd);
    ~IsolationFolder();

    bool initialize();                             // 创建文件夹并锁定
    bool add_file(const std::string& file_path);   // 移入（加密）
    bool extract_file(const std::string& file_name, const std::string& dest_path = ""); // 移出（解密）
    bool list_files();                             // 列出
    bool delete_file(const std::string& file_name); // 删除
    bool cleanup();                                // 恢复权限
};

#endif