/*
IsolationFoldermain.cpp
响应层

加密并隔离恶意文件，防止被执行或篡改

命令行参数：
argv[0] --- Isol.exe
argv[1] --- 命令（init/add/extract/list/delete/cleanup）
argv[2] --- 文件夹路径
argv[3] --- 其他参数（根据命令不同而不同）init|list|cleanup: <密码|*>，add: <文件路径> <密码|*>，extract: <文件名> <目标路径|*> <密码|*>，delete: <文件名> <密码>

g++编译:
cd %g++Path%
g++ -std=c++11 -o "%ExecutablePath%\Isol.exe" "%SourceCodePath%\IsolationFoldermain.cpp" "%SourceCodePath%\IsolationFolder.cpp" -ladvapi32 -static -lbcrypt -lws2_32 -lshell32 -lshlwapi -lole32 -luser32 -mwindows

运行权限：管理员权限
*/
#undef UNICODE
#undef _UNICODE
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include "IsolationFolder.h"
#include <iostream>

// 默认硬编码密码
static const std::string DEFAULT_PASSWORD = "Kx9#mP2$vL7@nQ5&rT3!wY4*zC6^bA8";

void print_usage(const char* prog_name) {
    std::cout << "\n=== 恶意文件隔离工具 (AES-256-CBC + HMAC) ===\n"
              << "用法:\n"
              << "  " << prog_name << " init <文件夹路径|*> <密码|*>\n"
              << "      创建并锁定隔离文件夹（* 表示使用默认值）\n"
              << "  " << prog_name << " add <文件夹路径|*> <文件路径> <密码|*>\n"
              << "      将文件移入隔离区（加密）\n"
              << "  " << prog_name << " extract <文件夹路径|*> <文件名> <目标路径|*> <密码|*>\n"
              << "      从隔离区移出文件（解密），目标路径为 '*' 则自动还原到原始位置\n"
              << "  " << prog_name << " list <文件夹路径|*> <密码|*>\n"
              << "      列出隔离区所有文件\n"
              << "  " << prog_name << " delete <文件夹路径|*> <文件名> <密码|*>\n"
              << "      从隔离区删除文件\n"
              << "  " << prog_name << " cleanup <文件夹路径|*> <密码|*>\n"
              << "      恢复文件夹权限（谨慎使用）\n"
              << std::endl;
}

// 替换参数：若为 "*" 则替换为默认值
inline std::string replace_star(const std::string& arg, const std::string& default_val) {
    return (arg == "*") ? default_val : arg;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    // 检查管理员权限
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    if (!isAdmin) {
        std::cerr << "⚠ 警告：未以管理员身份运行，某些操作可能失败" << std::endl;
        std::cerr << "建议右键选择「以管理员身份运行」" << std::endl;
    }

    try {
        // 辅助 lambda：获取替换后的路径和密码
        // 默认路径
        std::string DEFAULT_PATH = GetExeDirectory();   // 来自 AES-256-CBCEncryptionCommon.h
        DEFAULT_PATH += "ISOL\\";  

        auto get_path_pwd = [&](int path_idx, int pwd_idx) -> std::pair<std::string, std::string> {
            std::string path = (argc > path_idx) ? argv[path_idx] : "";
            std::string pwd  = (argc > pwd_idx) ? argv[pwd_idx] : "";
            path = replace_star(path, DEFAULT_PATH);
            pwd  = replace_star(pwd, DEFAULT_PASSWORD);
            return {path, pwd};
        };

        if (cmd == "init" && argc == 4) {
            auto [path, pwd] = get_path_pwd(2, 3);
            IsolationFolder folder(path, pwd);
            if (folder.initialize()) {
                std::cout << "\n✓ 隔离文件夹初始化成功！（AES-256-CBC + HMAC 加密）" << std::endl;
            }
        }
        else if (cmd == "add" && argc == 5) {
            auto [path, pwd] = get_path_pwd(2, 4);
            IsolationFolder folder(path, pwd);
            folder.add_file(argv[3]);
        }
        else if (cmd == "extract" && argc == 6) {
            auto [path, pwd] = get_path_pwd(2, 5);
            IsolationFolder folder(path, pwd);
            std::string dest = argv[4];
            if (dest == "*") dest = "";   // 触发自动还原
            folder.extract_file(argv[3], dest);
        }
        else if (cmd == "list" && argc == 4) {
            auto [path, pwd] = get_path_pwd(2, 3);
            IsolationFolder folder(path, pwd);
            folder.list_files();
        }
        else if (cmd == "delete" && argc == 5) {
            auto [path, pwd] = get_path_pwd(2, 4);
            IsolationFolder folder(path, pwd);
            folder.delete_file(argv[3]);
        }
        else if (cmd == "cleanup" && argc == 4) {
            auto [path, pwd] = get_path_pwd(2, 3);
            IsolationFolder folder(path, pwd);
            if (folder.cleanup()) {
                std::cout << "✓ 文件夹权限已恢复（允许所有人访问）" << std::endl;
            }
        }
        else {
            print_usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}