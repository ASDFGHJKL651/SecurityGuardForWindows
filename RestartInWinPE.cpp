/*
RestartInWinPE.cpp

设置下次重启使用WinPE环境，应对RootKit攻击

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\RestartInWinPE.cpp" -o "%ExecutablePath%\RestartInWinPE.exe" -lshlwapi -static

运行权限：管理员权限
*/
#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <fstream>      // 用于读写 startnet.cmd
#include <sstream>
#include <ctime>

#pragma comment(lib, "shlwapi.lib")

//  通用函数 

// 执行命令（通过 cmd /c），返回退出码（用于简单命令）
int RunCommand(const std::string& cmd) {
    std::string commandLine = "cmd.exe /c " + cmd;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    std::vector<char> cmdBuffer(commandLine.begin(), commandLine.end());
    cmdBuffer.push_back('\0');

    if (!CreateProcessA(NULL, cmdBuffer.data(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exitCode);
}

// 执行命令并实时显示输出（直接启动程序，避免 cmd 解析）
int RunCommandWithOutput(const std::string& commandLine) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        std::cerr << "创建管道失败" << std::endl;
        return -1;
    }

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    std::vector<char> cmdBuffer(commandLine.begin(), commandLine.end());
    cmdBuffer.push_back('\0');

    BOOL success = CreateProcessA(NULL, cmdBuffer.data(), NULL, NULL,
                                  TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWritePipe);  // 父进程关闭写入端

    if (!success) {
        CloseHandle(hReadPipe);
        std::cerr << "启动进程失败，错误码：" << GetLastError() << std::endl;
        return -1;
    }

    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        std::cout << buffer;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
    return static_cast<int>(exitCode);
}

// 执行命令并捕获输出（用于 bcdedit /create）
std::string ExecCmd(const std::string& cmd) {
    char buffer[4096];
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}

//  系统检测 

bool IsUEFI() {
    FIRMWARE_TYPE ft;
    GetFirmwareType(&ft);
    return (ft == FirmwareTypeUefi);
}

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0,0,0,0,0,0, &adminsGroup)) {
        CheckTokenMembership(NULL, adminsGroup, &isAdmin);
        FreeSid(adminsGroup);
    }
    return isAdmin != FALSE;
}

//  文件注入 WinPE 

// 复制目录（使用 xcopy）
bool CopyDirectory(const std::string& src, const std::string& dst) {
    std::string cmd = "xcopy \"" + src + "\" \"" + dst + "\" /E /I /Y /Q";
    int ret = RunCommand(cmd);
    if (ret != 0) {
        std::cerr << "复制目录失败，命令：" << cmd << "，返回码：" << ret << std::endl;
        return false;
    }
    return true;
}

// 将源目录中的文件注入到 boot.wim 中，并设置自启动
bool InjectFilesIntoWIM(const std::string& wimPath, const std::string& sourceDir) {
    // 检查源目录
    if (!PathFileExistsA(sourceDir.c_str())) {
        std::cerr << "源目录不存在: " << sourceDir << std::endl;
        return false;
    }

    // 创建临时挂载点（使用固定名称，便于清理）
    const std::string mountDir = "C:\\WinPEMount";
    // 如果挂载点已存在，尝试删除（可能是上次残留）
    if (PathFileExistsA(mountDir.c_str())) {
        if (!RemoveDirectoryA(mountDir.c_str())) {
            std::cerr << "警告：挂载点已存在且无法删除，尝试继续..." << std::endl;
        }
    }
    if (!CreateDirectoryA(mountDir.c_str(), NULL)) {
        std::cerr << "创建挂载目录失败，错误码：" << GetLastError() << std::endl;
        return false;
    }

    // 1. 挂载 boot.wim（索引 1）
    std::cout << "正在挂载 boot.wim ..." << std::endl;
    std::string mountCmd = "dism /Mount-Image /ImageFile:\"" + wimPath + "\" /Index:1 /MountDir:\"" + mountDir + "\"";
    int ret = RunCommandWithOutput(mountCmd);
    if (ret != 0) {
        std::cerr << "挂载镜像失败，退出码：" << ret << std::endl;
        RemoveDirectoryA(mountDir.c_str());   // 清理
        return false;
    }

    // 2. 复制文件到 WinPE 的 System32\MyApp
    std::string destDir = mountDir + "\\Windows\\System32\\MyApp";
    std::cout << "正在复制文件到 " << destDir << " ..." << std::endl;
    if (!CopyDirectory(sourceDir, destDir)) {
        std::cerr << "复制文件失败，尝试卸载镜像..." << std::endl;
        // 卸载但不提交（放弃修改）
        std::string umountCmd = "dism /Unmount-Image /MountDir:\"" + mountDir + "\" /Discard";
        RunCommandWithOutput(umountCmd);
        RemoveDirectoryA(mountDir.c_str());
        return false;
    }

    // 3. 设置自启动：修改 startnet.cmd，追加一行启动命令
    std::string startnetPath = mountDir + "\\Windows\\System32\\startnet.cmd";
    std::cout << "正在设置自启动: " << startnetPath << std::endl;

    // 读取现有内容（如果存在）
    std::string existingContent;
    std::ifstream inFile(startnetPath.c_str());
    if (inFile.is_open()) {
        std::stringstream buffer;
        buffer << inFile.rdbuf();
        existingContent = buffer.str();
        inFile.close();
    }

    // 追加启动命令（确保换行）
    std::ofstream outFile(startnetPath.c_str(), std::ios::out | std::ios::trunc);
    if (!outFile.is_open()) {
        std::cerr << "无法创建/打开 startnet.cmd" << std::endl;
        // 卸载并丢弃修改
        std::string umountCmd = "dism /Unmount-Image /MountDir:\"" + mountDir + "\" /Discard";
        RunCommandWithOutput(umountCmd);
        RemoveDirectoryA(mountDir.c_str());
        return false;
    }
    // 写入原有内容（如果有）
    if (!existingContent.empty()) {
        outFile << existingContent;
        // 确保结尾有换行
        if (existingContent.back() != '\n')
            outFile << "\n";
    }
    // 追加启动命令（使用 start /b 在后台运行）
    outFile << "cd /d %SystemRoot%\\System32\\MyApp\n";
    outFile << "start /b traverseallfiles.exe\n";
    outFile.close();

    // 4. 卸载并提交修改
    std::cout << "正在提交修改并卸载镜像 ..." << std::endl;
    std::string commitCmd = "dism /Unmount-Image /MountDir:\"" + mountDir + "\" /Commit";
    ret = RunCommandWithOutput(commitCmd);
    if (ret != 0) {
        std::cerr << "卸载/提交镜像失败，退出码：" << ret << std::endl;
        // 尝试丢弃修改（可能已部分提交，但错误依然）
        std::string discardCmd = "dism /Unmount-Image /MountDir:\"" + mountDir + "\" /Discard";
        RunCommandWithOutput(discardCmd);
        RemoveDirectoryA(mountDir.c_str());
        return false;
    }

    // 5. 清理挂载目录
    RemoveDirectoryA(mountDir.c_str());
    std::cout << "文件注入完成。" << std::endl;
    return true;
}

//  主程序 

int main() {
    SetConsoleOutputCP(CP_UTF8);

    if (!IsAdmin()) {
        std::cerr << "错误：此程序需要管理员权限。请以管理员身份运行。" << std::endl;
        RunCommand("pause");
        return 1;
    }

    // 获取程序所在目录
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir(exePath);
    exeDir = exeDir.substr(0, exeDir.find_last_of("\\"));

    const std::string sevenZipPath = exeDir + "\\7-zip\\7z.exe";
    const std::string isoPath = exeDir + "\\WinPE\\WinPE.iso";
    const std::string extractDir = "C:\\WinPE";
    const std::string wimPath = extractDir + "\\sources\\boot.wim";
    const std::string sdiPath = extractDir + "\\boot\\boot.sdi";

    // 检查必要文件
    if (!PathFileExistsA(sevenZipPath.c_str())) {
        std::cerr << "错误：未找到 7z.exe，路径：" << sevenZipPath << std::endl;
        RunCommand("pause");
        return 1;
    }
    if (!PathFileExistsA(isoPath.c_str())) {
        std::cerr << "错误：未找到 WinPE.iso，路径：" << isoPath << std::endl;
        RunCommand("pause");
        return 1;
    }

    // 创建解压目录
    if (!CreateDirectoryA(extractDir.c_str(), NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            std::cerr << "警告：无法创建目录 " << extractDir << "，错误码：" << GetLastError() << std::endl;
        }
    }

    // 1. 解压 ISO
    std::cout << "正在解压 ISO ..." << std::endl;
    std::cout << "命令: \"" << sevenZipPath << "\" x \"" << isoPath << "\" -o" << extractDir << " -y" << std::endl;
    int ret = RunCommandWithOutput("\"" + sevenZipPath + "\" x \"" + isoPath + "\" -o" + extractDir + " -y");
    if (ret != 0) {
        std::cerr << "解压失败，退出码：" << ret << std::endl;
        std::cerr << "请手动执行上述命令以查看详细错误。" << std::endl;
        RunCommand("pause");
        return 1;
    }

    // 检查必要文件
    if (!PathFileExistsA(wimPath.c_str())) {
        std::cerr << "错误：未找到 " << wimPath << "，请确认 ISO 结构。" << std::endl;
        RunCommand("pause");
        return 1;
    }
    if (!PathFileExistsA(sdiPath.c_str())) {
        std::cerr << "错误：未找到 " << sdiPath << "，请确认 ISO 结构。" << std::endl;
        RunCommand("pause");
        return 1;
    }

    //  注入可执行文件到 WinPE 
    std::string execSrc = exeDir + "\\WinPE\\Executable";
    if (!PathFileExistsA(execSrc.c_str())) {
        std::cerr << "错误：未找到可执行文件源目录 " << execSrc << std::endl;
        RunCommand("pause");
        return 1;
    }
    std::cout << "\n开始注入可执行文件到 WinPE ..." << std::endl;
    if (!InjectFilesIntoWIM(wimPath, execSrc)) {
        std::cerr << "注入可执行文件失败，请检查 DISM 是否可用。" << std::endl;
        RunCommand("pause");
        return 1;
    }

    // 2. 配置 BCD
    std::cout << "\n正在配置 BCD 启动项 ..." << std::endl;

    std::string cmdRamdisk = "bcdedit /create /d \"WinPE\" /application osloader";
    std::string output = ExecCmd(cmdRamdisk);
    size_t start = output.find('{');
    size_t end = output.find('}', start);
    if (start == std::string::npos || end == std::string::npos) {
        std::cerr << "创建启动项失败，输出：" << output << std::endl;
        RunCommand("pause");
        return 1;
    }
    std::string guid = output.substr(start, end - start + 1);
    std::cout << "创建 GUID: " << guid << std::endl;

    auto SetBcd = [&](const std::string& param) -> int {
        std::string cmd = "bcdedit /set " + guid + " " + param;
        int code = RunCommand(cmd);
        if (code != 0) {
            std::cerr << "警告：bcdedit /set 失败，命令：" << cmd << "，返回码：" << code << std::endl;
        }
        return code;
    };

    std::string driveLetter = extractDir.substr(0, 2);
    std::string pathWithoutDrive = extractDir.substr(3);
    std::string wimRelative = pathWithoutDrive + "\\sources\\boot.wim";
    std::string device = "ramdisk=[" + driveLetter + "]" + wimRelative + ",{ramdiskoptions}";

    SetBcd("device " + device);
    SetBcd("osdevice " + device);

    std::string bootPath = IsUEFI() ? "\\Windows\\System32\\winload.efi" : "\\Windows\\System32\\winload.exe";
    SetBcd("path " + bootPath);
    SetBcd("systemroot \\Windows");
    SetBcd("detecthal yes");
    SetBcd("winpe yes");

    std::string sdiDevice = "partition=" + driveLetter;
    RunCommand("bcdedit /set {ramdiskoptions} ramdisksdidevice " + sdiDevice);
    std::string sdiPathFull = pathWithoutDrive + "\\boot\\boot.sdi";
    RunCommand("bcdedit /set {ramdiskoptions} ramdisksdipath " + sdiPathFull);

    RunCommand("bcdedit /default " + guid);

    std::cout << "\n当前 BCD 默认启动项：" << std::endl;
    RunCommand("bcdedit /enum | findstr \"default\"");

    std::cout << "\n操作完成！重启计算机将自动进入 WinPE，且 traverseallfiles.exe 将自动以管理员权限运行。\n";
    RunCommand("pause");
    return 0;
}