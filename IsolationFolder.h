/*
IsolationFolder.h

详见IsolationFoldermain.cpp
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

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib") 

// AES-256-CBC 加密类（使用 Windows CryptoAPI）
class SimpleAES {
private:
    std::string password;              // 保存密码以派生根密钥
    HCRYPTPROV hProv;                  // 加密服务提供者句柄
    HCRYPTKEY hKey;                    // AES 密钥句柄

    bool init_crypto();                // 初始化 CSP 并派生密钥
    void cleanup_crypto();             // 释放句柄

public:
    SimpleAES(const std::string& pwd);
    ~SimpleAES();

    bool encrypt_file(const std::string& input_path, const std::string& output_path);
    bool decrypt_file(const std::string& input_path, const std::string& output_path);
};

// 隔离文件夹管理类（接口不变）
class IsolationFolder {
private:
    std::string folder_path;
    std::string password;
    SimpleAES aes;

    bool set_folder_permissions();
    bool restore_folder_permissions();
    bool take_ownership();
    bool enable_privilege(const char* privilege);

public:
    IsolationFolder(const std::string& path, const std::string& pwd);
    ~IsolationFolder();

    bool initialize();                             // 创建文件夹并锁定
    bool add_file(const std::string& file_path);    // 移入（加密）
    bool extract_file(const std::string& file_name, const std::string& dest_path = ""); // 移出（解密），dest_path 为空则使用原路径
    bool list_files();                             // 列出
    bool delete_file(const std::string& file_name); // 删除
    bool cleanup();                                // 恢复权限
};

#endif
//g++ -std=c++11 -o D:\CPPFiles\SandBox\isol.exe D:\CPPFiles\SandBox\main.cpp D:\CPPFiles\SandBox\IsolationFolder.cpp -ladvapi32 -static