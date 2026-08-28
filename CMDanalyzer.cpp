/*
CMDanalyzer.cpp
分析层

分析CMD/PowerShell脚本，评估恶意代码

命令行参数：
argv[0] --- CMDanalyzer.exe
argv[1] --- 需要分析的CMD/PowerShell脚本路径
argv[2] --- 可选参数，"--withoutUi"表示不弹窗，"--onlywithUi"表示仅高危弹窗，其他情况默认弹窗+分析
argv[3] --- 可选参数，"--XML"表示输出XML格式结果

g++编译:
cd %g++Path%
g++ -fdiagnostics-color=always -g "%SourceCodePath%\CMDanalyzer.cpp" -o "%ExecutablePath%\CMDanalyzer.exe" -mwindows

运行权限：管理员权限
*/
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <unordered_map>
#include <unordered_set>
#include <cmath>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <memory>
#include <filesystem>
#include <iomanip>
#include <chrono>
#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif
#include <thread>

namespace fs = std::filesystem;

int withUi;
char filepath[32768];

#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_CMDanalyzer"
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_CMDanalyzer"

#pragma pack(push, 1)
struct MessagetoControlCenter_by_CMDanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
#pragma pack(pop)

#define PIPE_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_CMDanalyzer)

HANDLE ConnectToPipe(const wchar_t* pipeName) {
    while (true) {
        if (WaitNamedPipeW(pipeName, 1000)) {
            SetConsoleOutputCP(CP_ACP);
            SetConsoleCP(CP_ACP);
            HANDLE hPipe = CreateFileW(
                pipeName,
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL
            );
            if (hPipe != INVALID_HANDLE_VALUE) {
                std::cout << "Success connecting to pipe" << std::endl;
                return hPipe;
            }
        }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            std::cout << "Waiting for server to create pipe" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        } else if (err == ERROR_PIPE_BUSY) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        } else {
            std::cerr << "Connecting to pipe encountered an unknown error, code: " << err << std::endl;
            return INVALID_HANDLE_VALUE;
        }
    }
}

void ClientThread_to_ControlCenter(MessagetoControlCenter_by_CMDanalyzer* msg) {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Process CMDAndPowerShell: Always failed to connect to pipe, exiting send thread" << std::endl;
        return;
    }

    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
        std::cerr << "Process A: Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}
//辅助函数
static inline std::string toLower(const std::string& s) {
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return res;
}

static inline std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static double calculateEntropy(const std::string& s) {
    if (s.empty()) return 0.0;
    std::unordered_map<char, int> freq;
    for (char c : s) freq[c]++;
    double entropy = 0.0;
    for (const auto& p : freq) {
        double prob = static_cast<double>(p.second) / s.length();
        entropy -= prob * std::log2(prob);
    }
    return entropy;
}

static std::string base64Decode(const std::string& encoded) {
    static const std::string b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    std::vector<int> vals;
    for (char c : encoded) {
        if (c == '=') break;
        size_t pos = b64chars.find(c);
        if (pos == std::string::npos) continue;
        vals.push_back(static_cast<int>(pos));
    }
    for (size_t i = 0; i + 3 < vals.size(); i += 4) {
        uint32_t chunk = (vals[i] << 18) | (vals[i+1] << 12) | (vals[i+2] << 6) | vals[i+3];
        decoded.push_back((chunk >> 16) & 0xFF);
        decoded.push_back((chunk >> 8) & 0xFF);
        decoded.push_back(chunk & 0xFF);
    }
    size_t rem = vals.size() % 4;
    if (rem == 2) {
        uint32_t chunk = (vals[vals.size()-2] << 18) | (vals[vals.size()-1] << 12);
        decoded.push_back((chunk >> 16) & 0xFF);
    } else if (rem == 3) {
        uint32_t chunk = (vals[vals.size()-3] << 18) | (vals[vals.size()-2] << 12) | (vals[vals.size()-1] << 6);
        decoded.push_back((chunk >> 16) & 0xFF);
        decoded.push_back((chunk >> 8) & 0xFF);
    }
    return decoded;
}

static std::string hexDecode(const std::string& hex) {
    std::string decoded;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        char c = static_cast<char>(std::stoi(byte, nullptr, 16));
        decoded.push_back(c);
    }
    return decoded;
}

//变量展开
class VariableExpander {
private:
    std::unordered_map<std::string, std::string> variables;
    bool delayedExpansion = false;
    const int maxExpandDepth = 5;   // 递归展开最大层数

    // 移除 ^ 转义链（包括 ^ 后接数字）
    static std::string removeCaretEscapes(const std::string& s) {
        std::string result;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '^' && i + 1 < s.size() && s[i+1] != '\n' && s[i+1] != '\r') {
                // 跳过 ^ 及其后一个字符
                ++i;
            } else {
                result.push_back(s[i]);
            }
        }
        return result;
    }

    std::string getVariableValue(const std::string& var) {
        auto it = variables.find(var);
        if (it != variables.end()) return it->second;
        return "";
    }

    // 递归展开变量，%var% 、 %var:~offset,len% 和 !var!
    std::string expandVariablesRecursive(const std::string& line, int depth) {
        if (depth > maxExpandDepth) return line;
        std::string result = line;
        bool changed = false;

        // 1. 展开 %var%
        std::regex percentPattern(R"(%([a-zA-Z_][a-zA-Z0-9_]*)%)");
        std::smatch m;
        std::string temp = result;
        while (std::regex_search(temp, m, percentPattern)) {
            std::string var = m[1];
            std::string val = getVariableValue(var);
            if (val.empty()) {
                val = "";   // 未定义则清除
            }
            // 替换第一次出现（但 regex_search 找第一个）
            size_t pos = temp.find(m.str());
            if (pos != std::string::npos) {
                temp.replace(pos, m.length(0), val);
                changed = true;
            } else break;
        }
        result = temp;

        // 2. 展开 %var:~offset,len%
        std::regex subPattern(R"(%([a-zA-Z_][a-zA-Z0-9_]*)~([^%]*)%)");
        temp = result;
        while (std::regex_search(temp, m, subPattern)) {
            std::string var = m[1];
            std::string spec = m[2];
            std::string val = getVariableValue(var);
            if (!val.empty()) {
                long long offset = 0, len = -1;
                std::string specStr = spec;
                size_t comma = specStr.find(',');
                if (comma != std::string::npos) {
                    try { offset = std::stoll(specStr.substr(0, comma)); } catch(...) { offset = 0; }
                    try { len = std::stoll(specStr.substr(comma+1)); } catch(...) { len = -1; }
                } else {
                    try { offset = std::stoll(specStr); } catch(...) { offset = 0; }
                    len = -1;
                }
                // 处理负偏移
                if (offset < 0) offset = val.size() + offset;
                if (offset < 0) offset = 0;
                if (len < 0) len = val.size() - offset;
                if (offset >= (long long)val.size()) {
                    val = "";
                } else {
                    if (offset + len > (long long)val.size()) len = val.size() - offset;
                    if (len < 0) len = 0;
                    val = val.substr(offset, len);
                }
            } else {
                val = "";
            }
            size_t pos = temp.find(m.str());
            if (pos != std::string::npos) {
                temp.replace(pos, m.length(0), val);
                changed = true;
            } else break;
        }
        result = temp;

        // 3. 展开延迟变量 !var!
        if (delayedExpansion) {
            std::regex delayedPattern(R"(!([a-zA-Z_][a-zA-Z0-9_]*)!)");
            temp = result;
            while (std::regex_search(temp, m, delayedPattern)) {
                std::string var = m[1];
                std::string val = getVariableValue(var);
                if (val.empty()) val = "";
                size_t pos = temp.find(m.str());
                if (pos != std::string::npos) {
                    temp.replace(pos, m.length(0), val);
                    changed = true;
                } else break;
            }
            result = temp;
        }

        // 如果发生了变化，递归继续展开（深度+1）
        if (changed) {
            return expandVariablesRecursive(result, depth + 1);
        }
        return result;
    }

public:
    void processSetCommand(const std::string& line) {
        // 匹配 set "var=..." 或 set var=...
        std::regex setPattern(R"(set\s+(?:".*?"\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*))", std::regex::icase);
        std::smatch m;
        if (std::regex_search(line, m, setPattern)) {
            std::string var = m[1];
            std::string val = trim(m[2]);
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                val = val.substr(1, val.size()-2);
            variables[var] = val;
        }
        if (std::regex_search(line, std::regex(R"(setlocal\s+enabledelayedexpansion)", std::regex::icase))) {
            delayedExpansion = true;
        } else if (std::regex_search(line, std::regex(R"(setlocal\s+disabledelayedexpansion)", std::regex::icase))) {
            delayedExpansion = false;
        }
    }

    std::string expandVariables(const std::string& line) {
        return expandVariablesRecursive(line, 0);
    }

    std::string expandFile(const std::string& content) {
        // 预处理：移除 ^ 转义链
        std::string preprocessed = removeCaretEscapes(content);

        std::istringstream iss(preprocessed);
        std::string line, expanded;
        while (std::getline(iss, line)) {
            std::string trimmed = trim(line);
            if (trimmed.empty()) {
                expanded += line + "\n";
                continue;
            }
            if (std::regex_search(trimmed, std::regex(R"(^(rem|::)\s*)", std::regex::icase))) {
                expanded += line + "\n";
                continue;
            }
            if (std::regex_search(trimmed, std::regex(R"(^set\s+)", std::regex::icase))) {
                processSetCommand(trimmed);
                std::string expandedLine = expandVariables(line);
                expanded += expandedLine + "\n";
                continue;
            }
            std::string expandedLine = expandVariables(line);
            expanded += expandedLine + "\n";
        }
        return expanded;
    }
};

//规则管理
struct MaliciousRule {
    std::string pattern;
    int weight;
    std::string description;
    std::string technique;
};

class RuleManager {
public:
    std::vector<MaliciousRule> rules;
    std::vector<MaliciousRule> whitelistRules;

    RuleManager() {
        initRules();
        initWhitelist();
    }

    void initRules() {
        rules.push_back({R"(powershell.*(?:-enc|-e|bypass|windowstyle| -Command))", 8, "PowerShell encoded or command execution", "T1059.003"});
        rules.push_back({R"(certutil.*-decode)", 7, "certutil decode and execute", "T1105"});
        rules.push_back({R"(bitsadmin.*/transfer)", 7, "bitsadmin download", "T1105"});
        rules.push_back({R"(mshta.*\.hta)", 6, "MSHTA execute HTA", "T1218.005"});
        rules.push_back({R"(wmic.*process.*call.*create)", 6, "WMIC create process", "T1047"});
        rules.push_back({R"(rundll32\.exe)", 5, "Rundll32 execute", "T1218.011"});
        rules.push_back({R"(regsvr32\.exe)", 5, "Regsvr32 execute", "T1218.010"});
        rules.push_back({R"(cscript.*\.vbs)", 5, "Cscript execute VBS", "T1059.005"});
        rules.push_back({R"(wscript.*\.vbs)", 5, "Wscript execute VBS", "T1059.005"});
        rules.push_back({R"(reg\s+(?:add|delete).*HKEY_(?:CURRENT_USER|LOCAL_MACHINE).*run)", 6, "Registry Run key modification", "T1547.001"});
        rules.push_back({R"(schtasks\s+/create)", 6, "Create scheduled task", "T1053.005"});
        rules.push_back({R"(sc\s+create)", 5, "Create service", "T1543.003"});
        rules.push_back({R"((?:copy|move|ren).*\\(?:system32|syswow64))", 4, "System directory file operation", "T1570"});
        rules.push_back({R"((?:type|more|findstr).*\.(?:txt|doc|docx|xls|xlsx|pdf|key|pem))", 4, "Sensitive file read", "T1005"});
        rules.push_back({R"(net\s+(?:user|localgroup|view|group))", 3, "Network information gathering", "T1069"});
        rules.push_back({R"(whoami|hostname|ipconfig|systeminfo)", 2, "System information query", "T1033"});
        rules.push_back({R"(del\s+/f\s+/q)", 7, "Force delete file", "T1485"});
        rules.push_back({R"(format\s+[a-z]:)", 8, "Format disk", "T1485"});
        rules.push_back({R"(rd\s+/s\s+/q)", 6, "Force delete directory", "T1485"});
        rules.push_back({R"(\^[a-zA-Z])", 2, "Caret escape obfuscation", "T1027"});
        rules.push_back({R"(set\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*.*%.*%.*%)", 3, "Environment variable concatenation obfuscation", "T1027"});
        rules.push_back({R"(for\s+/f.*in.*\(.*\)\s+do)", 3, "For /f command execution", "T1059.003"});
        rules.push_back({R"(cmd\s+/c\s+.*&&.*\|\|)", 4, "Cmd /c multi-command chaining", "T1059.003"});
        rules.push_back({R"(curl.*-o.*\.exe)", 6, "Curl download executable", "T1105"});
        rules.push_back({R"(wget.*-O.*\.exe)", 6, "Wget download executable", "T1105"});
        rules.push_back({R"(start\s+.*\.exe)", 2, "Start program", "T1059"});
        rules.push_back({R"(CreateObject\(\s*["'](?:WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject|ADODB\.Stream)["']\s*\))", 6, "Create dangerous COM object", "T1059.005"});
        rules.push_back({R"(GetObject\(\s*["']winmgmts:["']\s*\))", 5, "WMI query", "T1047"});

        // InstallUtil.exe
        rules.push_back({R"(installutil\.exe)", 6, "InstallUtil execute assembly", "T1218.004"});
        // regsvr32 /u /s /i: (SCT 下载执行)
        rules.push_back({R"(regsvr32.*/(?:u|s|i:))", 7, "Regsvr32 SCT download and execute", "T1218.010"});
        // msbuild.exe
        rules.push_back({R"(msbuild\.exe)", 6, "MSBuild execute inline C#", "T1127"});
        // csc.exe
        rules.push_back({R"(csc\.exe)", 5, "CSC compile C#", "T1127"});
        // rundll32.exe javascript:
        rules.push_back({R"(rundll32\.exe.*javascript:)", 7, "Rundll32 execute JavaScript", "T1218.011"});
        // wmic /node: (远程执行)
        rules.push_back({R"(wmic.*/node:)", 6, "WMIC remote execution", "T1047"});
        // schtasks /create /xml (任务计划导入)
        rules.push_back({R"(schtasks.*/create.*/xml)", 7, "Schtasks create from XML (persistence)", "T1053.005"});

        // Cobalt Strike, Mimikatz, PowerShell混淆, 注册表持久化 
        // Cobalt Strike Beacon 特征：$1 变量赋值包含 beacon 或 beacon.dll 引用
        rules.push_back({R"(\$1\s*=\s*[^;]*beacon)", 6, "Cobalt Strike Beacon variable pattern", "T1059.003"});
        rules.push_back({R"(beacon\.dll)", 6, "Cobalt Strike beacon.dll reference", "T1059.003"});
        // Mimikatz 典型命令
        rules.push_back({R"(sekurlsa::logonpasswords)", 8, "Mimikatz credential dumping", "T1003.001"});
        rules.push_back({R"(privilege::debug)", 7, "Mimikatz privilege escalation", "T1068"});
        // PowerShell 混淆：iex 配合 [System.Text.Encoding]::UTF8.GetString
        rules.push_back({R"(iex\s*\(.*\[System\.Text\.Encoding\]::UTF8\.GetString)", 8, "PowerShell encoded payload decoding (iex + UTF8.GetString)", "T1027"});
        // 注册表持久化：reg add 包含 run 或 services 路径
        rules.push_back({R"(reg\s+add\s+.*\\(?:run|services)\\)", 6, "Registry persistence via run or services", "T1547.001"});
    }

    void initWhitelist() {
        whitelistRules.push_back({R"(certutil.*-hashfile)", 0, "certutil compute hash", ""});
        whitelistRules.push_back({R"(certutil.*-ping)", 0, "certutil network test", ""});
        whitelistRules.push_back({R"(ipconfig /all)", 0, "IP configuration query", ""});
        whitelistRules.push_back({R"(ping -n 1)", 0, "Ping test", ""});
        whitelistRules.push_back({R"(systeminfo)", 0, "System info", ""});
        whitelistRules.push_back({R"(tasklist)", 0, "Process list", ""});
        whitelistRules.push_back({R"(dir /b)", 0, "Directory list", ""});
    }

    // 逐行检查是否匹配白名单
    bool isLineWhitelisted(const std::string& line) const {
        std::string lower = toLower(line);
        for (const auto& w : whitelistRules) {
            try {
                std::regex re(w.pattern, std::regex::icase);
                if (std::regex_search(lower, re)) return true;
            } catch (...) {}
        }
        return false;
    }

    // 对非白名单行进行规则匹配
    std::vector<std::tuple<std::string, int, std::string>> scanLines(const std::vector<std::string>& lines) const {
        std::vector<std::tuple<std::string, int, std::string>> findings;
        for (const auto& line : lines) {
            if (isLineWhitelisted(line)) continue;
            std::string lowerLine = toLower(line);
            for (const auto& rule : rules) {
                try {
                    std::regex re(rule.pattern, std::regex::icase);
                    if (std::regex_search(lowerLine, re)) {
                        findings.emplace_back(rule.description, rule.weight, rule.technique);
                    }
                } catch (...) {}
            }
        }
        return findings;
    }
};

//高级混淆检测
class AdvancedObfuscationDetector {
public:
    struct Result {
        bool hasNullByte = false;
        bool hasNestedCall = false;
        bool hasForLoopObfuscation = false;
        int score = 0;
        std::string restoredCommand;
    };

    Result detectAndRestore(const std::string& content) {
        Result res;
        std::string work = content;
        if (work.find('\x00') != std::string::npos) {
            res.hasNullByte = true;
            res.score += 3;
            work.erase(std::remove(work.begin(), work.end(), '\x00'), work.end());
        }
        std::regex callPattern(R"(call\s+(set|cmd|powershell|certutil|bitsadmin))", std::regex::icase);
        std::smatch m;
        if (std::regex_search(work, m, callPattern)) {
            res.hasNestedCall = true;
            res.score += 2;
        }
        std::regex forPattern(R"(for\s+/f.*in.*\(.*\)\s+do)", std::regex::icase);
        if (std::regex_search(work, forPattern)) {
            res.hasForLoopObfuscation = true;
            res.score += 2;
        }
        std::regex caretPattern(R"(\^([a-zA-Z]))");
        std::string restored = std::regex_replace(work, caretPattern, "$1");
        std::regex loneCaret(R"(\^)");
        restored = std::regex_replace(restored, loneCaret, "");
        std::regex extraSpaces(R"(\s+)");
        restored = std::regex_replace(restored, extraSpaces, " ");
        res.restoredCommand = trim(restored);
        return res;
    }
};

//编码载荷扫描
class AdvancedPayloadScanner {
public:
    struct Result {
        bool hasBase64 = false;
        bool hasHex = false;
        bool hasUTF16 = false;
        bool hasDeflate = false;
        bool hasSegmentedBase64 = false;
        int score = 0;
        std::vector<std::string> decodedPayloads;
    };

    Result scan(const std::string& content) {
        Result res;
        std::string work = content;

        // 分段 Base64
        std::regex setVarPattern(R"(set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([A-Za-z0-9+/]+={0,2}))", std::regex::icase);
        std::smatch m;
        std::vector<std::pair<std::string, std::string>> segments;
        std::string temp = work;
        while (std::regex_search(temp, m, setVarPattern)) {
            std::string val = m[2];
            if (val.length() > 20) segments.emplace_back(m[1], val);
            temp = m.suffix();
        }
        if (segments.size() >= 2) {
            std::string concat;
            for (const auto& seg : segments) concat += seg.second;
            std::regex base64Full(R"(^[A-Za-z0-9+/]+=*$)");
            if (std::regex_match(concat, base64Full) && concat.length() % 4 == 0) {
                res.hasSegmentedBase64 = true;
                res.score += 4;
                std::string decoded = base64Decode(concat);
                if (!decoded.empty()) res.decodedPayloads.push_back(decoded);
            }
        }

        // 标准 Base64 - 增加熵和可打印性过滤
        std::regex base64Pattern(R"([A-Za-z0-9+/]{50,}={0,2})");
        temp = work;
        while (std::regex_search(temp, m, base64Pattern)) {
            std::string match = m.str();
            if (match.length() >= 50 && calculateEntropy(match) <= 7.5) {
                std::string decoded = base64Decode(match);
                int printable = 0;
                for (char c : decoded) if (std::isprint(static_cast<unsigned char>(c))) printable++;
                if (!decoded.empty() && (printable * 1.0 / decoded.length()) >= 0.3) {
                    res.hasBase64 = true;
                    res.score += 3;
                    res.decodedPayloads.push_back(decoded.substr(0, 200));
                }
            }
            temp = m.suffix();
        }

        // Hex
        std::regex hexPattern(R"([0-9A-Fa-f]{100,})");
        temp = work;
        while (std::regex_search(temp, m, hexPattern)) {
            std::string hexStr = m.str();
            if (hexStr.length() % 2 == 0) {
                res.hasHex = true;
                res.score += 2;
                std::string decoded = hexDecode(hexStr);
                if (!decoded.empty()) res.decodedPayloads.push_back(decoded.substr(0, 200));
            }
            temp = m.suffix();
        }

        // UTF-16
        int nullCount = 0;
        for (char c : work) if (c == '\x00') nullCount++;
        if (nullCount > 20 && work.length() % 2 == 0) {
            res.hasUTF16 = true;
            res.score += 3;
            std::string utf16clean;
            for (size_t i = 0; i < work.length(); i += 2) {
                if (work[i] != '\x00') utf16clean.push_back(work[i]);
            }
            if (!utf16clean.empty()) res.decodedPayloads.push_back(utf16clean.substr(0, 200));
        }

        // Deflate
        if (work.find("\x78\x9C") != std::string::npos || work.find("\x78\xDA") != std::string::npos) {
            res.hasDeflate = true;
            res.score += 4;
        } else if (work.length() > 100 && calculateEntropy(work) > 6.0) {
            res.score += 1;
        }

        return res;
    }
};

//威胁情报（哈希、签名）
class ThreatIntelligence {
public:
    struct HashInfo { std::string md5; std::string sha256; };

    static HashInfo computeHashes(const std::string& filePath) {
        HashInfo info;
#ifdef _WIN32
        std::string cmd = "certutil -hashfile \"" + filePath + "\" MD5";
        std::string result = execCommand(cmd);
        std::regex md5Regex(R"(([0-9a-fA-F]{32}))");
        std::smatch m;
        if (std::regex_search(result, m, md5Regex)) info.md5 = m[1];
        cmd = "certutil -hashfile \"" + filePath + "\" SHA256";
        result = execCommand(cmd);
        if (std::regex_search(result, m, md5Regex)) info.sha256 = m[1];
#endif
        return info;
    }

    static bool hasValidSignature(const std::string& filePath) {
#ifdef _WIN32
        // 不实现
        return false;
#endif
        return false;
    }

private:
    static std::string execCommand(const std::string& cmd) {
        std::string result;
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return result;
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        _pclose(pipe);
        return result;
    }
};

//综合检测
class MaliciousBatDetectorEnhanced {
private:
    RuleManager ruleManager;
    AdvancedObfuscationDetector obfDetector;
    AdvancedPayloadScanner payloadScanner;
    VariableExpander varExpander;

    // 对解码后的 PowerShell 编码命令进行二次扫描和动态加分
    int scanPowerShellEncoded(const std::string& content, std::vector<std::string>& decodedPayloads) {
        int extraScore = 0;
        // 匹配 -enc, -e, -ec, -encodedCommand
        std::regex psEncRegex(R"(powershell\s+(?:-enc(?:odedCommand)?|-e|-ec)\s+([A-Za-z0-9+/]+={0,2}))", std::regex::icase);
        std::smatch m;
        std::string temp = content;
        while (std::regex_search(temp, m, psEncRegex)) {
            std::string base64 = m[1];
            // 补齐填充
            while (base64.size() % 4) base64 += '=';
            std::string decoded = base64Decode(base64);
            if (!decoded.empty()) {
                decodedPayloads.push_back(decoded);
                // 二次特征匹配
                std::string lowerDec = toLower(decoded);
                if (lowerDec.find("iex") != std::string::npos ||
                    lowerDec.find("downloadstring") != std::string::npos ||
                    lowerDec.find("invoke-cradle") != std::string::npos ||
                    lowerDec.find("new-object net.webclient") != std::string::npos ||
                    lowerDec.find("new-object system.net.webclient") != std::string::npos) {
                    extraScore += 4;
                }
                // 长度和熵动态加分
                double ent = calculateEntropy(decoded);
                if (decoded.length() > 500 && ent > 6.0) {
                    extraScore += 5;
                } else if (decoded.length() > 200 && ent > 5.5) {
                    extraScore += 2;
                }
                // 对解码内容进行规则扫描（半权重）
                std::vector<std::string> decLines;
                std::istringstream iss(decoded);
                std::string line;
                while (std::getline(iss, line)) {
                    std::string clean = trim(line);
                    if (!clean.empty()) decLines.push_back(clean);
                }
                auto findings = ruleManager.scanLines(decLines);
                for (const auto& [desc, weight, tech] : findings) {
                    extraScore += weight / 2;
                }
            }
            temp = m.suffix();
        }
        return extraScore;
    }

public:
    struct Report {
        std::string filePath;
        size_t fileSize = 0;
        int totalScore = 0;
        double confidence = 0.0;
        std::string riskLevel;
        std::vector<std::string> findings;
        std::vector<std::string> dangerousCommands;
        std::vector<std::string> techniques;
        std::vector<std::string> suspiciousTools;
        std::vector<std::string> decodedPayloads;
        ThreatIntelligence::HashInfo hashInfo;
        bool hasValidSignature = false;
        std::string expandedContent;
    };

    Report analyze(const std::string& filePath) {
        Report report;
        report.filePath = filePath;

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            report.findings.push_back("Unable to open file");
            return report;
        }
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        report.fileSize = content.size();
        file.close();

        if (content.empty()) {
            report.riskLevel = "SAFE";
            return report;
        }

        // 1. 变量展开（内部包含 ^ 转义移除和递归展开）
        std::string expanded = varExpander.expandFile(content);
        report.expandedContent = expanded;

        // 2. 混淆检测
        auto obfResult = obfDetector.detectAndRestore(content);
        report.totalScore += obfResult.score;
        if (obfResult.hasNullByte) report.findings.push_back("Detected null byte insertion obfuscation");
        if (obfResult.hasNestedCall) report.findings.push_back("Detected call nesting obfuscation");
        if (obfResult.hasForLoopObfuscation) report.findings.push_back("Detected for /f loop obfuscation");

        // 3. 将展开内容按行分割，清理空白
        std::vector<std::string> lines;
        std::istringstream iss(expanded);
        std::string line;
        while (std::getline(iss, line)) {
            std::string clean = std::regex_replace(line, std::regex(R"(\s+)"), " ");
            clean = trim(clean);
            if (!clean.empty()) lines.push_back(clean);
        }

        // 4. 逐行规则扫描（白名单自动跳过）
        auto findings = ruleManager.scanLines(lines);
        for (const auto& [desc, weight, tech] : findings) {
            report.totalScore += weight;
            report.dangerousCommands.push_back(desc);
            if (!tech.empty()) report.techniques.push_back(tech);
        }

        // 5. 编码载荷检测
        auto payloadRes = payloadScanner.scan(expanded);
        report.totalScore += payloadRes.score;
        if (payloadRes.hasBase64) report.findings.push_back("Detected Base64 encoded payload");
        if (payloadRes.hasSegmentedBase64) report.findings.push_back("Detected segmented Base64 concatenation");
        if (payloadRes.hasHex) report.findings.push_back("Detected Hex encoded payload");
        if (payloadRes.hasUTF16) report.findings.push_back("Detected UTF-16 encoded data");
        if (payloadRes.hasDeflate) report.findings.push_back("Detected Deflate compressed data");
        for (const auto& dec : payloadRes.decodedPayloads) {
            report.decodedPayloads.push_back(dec);
            // 对解码内容二次扫描
            std::vector<std::string> decLines = { dec };
            auto subFindings = ruleManager.scanLines(decLines);
            for (const auto& [desc, weight, tech] : subFindings) {
                report.totalScore += weight / 2;
                report.dangerousCommands.push_back("[Decoded] " + desc);
            }
        }

        // 6. 高危工具调用统计
        std::unordered_set<std::string> tools = {
            "powershell", "pwsh", "certutil", "bitsadmin", "mshta",
            "wmic", "rundll32", "regsvr32", "cscript", "wscript",
            "net", "netsh", "schtasks", "sc", "taskkill", "curl", "wget",
            "installutil", "msbuild", "csc"
        };
        std::unordered_set<std::string> foundTools;
        for (const auto& line : lines) {
            std::string lower = toLower(line);
            for (const auto& tool : tools) {
                std::string pattern = "(?:^|[\\s&|;(),]\\s*)" + tool + "\\b";
                try {
                    std::regex re(pattern, std::regex::icase);
                    if (std::regex_search(lower, re)) {
                        foundTools.insert(tool);
                    }
                } catch (...) {}
            }
        }
        report.suspiciousTools.assign(foundTools.begin(), foundTools.end());
        int toolCount = report.suspiciousTools.size();
        report.totalScore += toolCount * 2;

        // 7. 联动加分：工具≥5加10分，下载+执行组合加8分
        if (toolCount >= 5) report.totalScore += 10;
        bool hasDownload = false, hasExecute = false;
        for (const auto& cmd : report.dangerousCommands) {
            if (cmd.find("download") != std::string::npos || cmd.find("bitsadmin") != std::string::npos) hasDownload = true;
            if (cmd.find("execute") != std::string::npos || cmd.find("PowerShell") != std::string::npos) hasExecute = true;
        }
        if (hasDownload && hasExecute) report.totalScore += 8;

        // 8. 威胁情报（哈希、签名）
        report.hashInfo = ThreatIntelligence::computeHashes(filePath);
        report.hasValidSignature = ThreatIntelligence::hasValidSignature(filePath);
        if (!report.hashInfo.md5.empty()) {
            report.findings.push_back("MD5: " + report.hashInfo.md5);
        }
        if (report.hasValidSignature) {
            report.findings.push_back("File has valid digital signature (may be system file)");
            report.totalScore -= 10;
        }

        // 9. 文件大小调整（超大文件降权）
        if (report.fileSize > 1024 * 1024) report.totalScore = static_cast<int>(report.totalScore * 0.8);

        //PowerShell 编码命令深度扫描
        int psExtra = scanPowerShellEncoded(expanded, report.decodedPayloads);
        report.totalScore += psExtra;
        if (psExtra > 0) report.findings.push_back("PowerShell encoded command detected and decoded (extra score)");

        // 10. 最终评分、置信度、风险等级
        report.totalScore = std::max(0, report.totalScore);
        double rawConfidence = static_cast<double>(report.totalScore) / 120.0; // 最大120分
        report.confidence = std::min(1.0, rawConfidence);

        if (report.totalScore < 10) report.riskLevel = "SAFE";
        else if (report.totalScore < 25) report.riskLevel = "SUSPICIOUS";
        else report.riskLevel = "MALICIOUS";
        if (report.totalScore >= 25 && withUi==2){
            MessagetoControlCenter_by_CMDanalyzer message = {};
            lstrcpyA(message.type, "Fileanalyzer");
            message.WindowType=2;
            lstrcpyA(message.path, filepath);
            message.score=report.totalScore;
            lstrcpyA(message.details, "");
            std::thread server(ClientThread_to_ControlCenter, &message);
            server.join();
        }
        else if (withUi==1){
            MessagetoControlCenter_by_CMDanalyzer message = {};
            lstrcpyA(message.type, "Fileanalyzer");
            message.WindowType=4;
            lstrcpyA(message.path, filepath);
            message.score=report.totalScore;
            lstrcpyA(message.details, "");
            std::thread server(ClientThread_to_ControlCenter, &message);
            server.join();
        }
        // 11. 摘要信息
        if (report.riskLevel == "MALICIOUS") report.findings.push_back("Detected high-risk malicious command features");
        if (!report.techniques.empty()) {
            std::string techs;
            for (const auto& t : report.techniques) techs += t + " ";
            report.findings.push_back("Associated ATT&CK Techniques: " + techs);
        }
        if (!report.decodedPayloads.empty()) report.findings.push_back("Found decoded payload (may contain hidden commands)");

        return report;
    }

    void printReport(const Report& report) const {
        std::cout << "\n========== Malicious Batch File Detection Report (Enhanced v2.2) ==========\n";
        std::cout << "File Path: " << report.filePath << "\n";
        std::cout << "File Size: " << report.fileSize << " bytes\n";
        std::cout << "Risk Level: " << report.riskLevel << "\n";
        std::cout << "Confidence Score: " << std::fixed << std::setprecision(2) << report.confidence << "\n";
        std::cout << "Total Score: " << report.totalScore << "\n";
        if (!report.hashInfo.md5.empty()) std::cout << "MD5: " << report.hashInfo.md5 << "\n";
        if (!report.hashInfo.sha256.empty()) std::cout << "SHA256: " << report.hashInfo.sha256 << "\n";
        std::cout << "Digital Signature Valid: " << (report.hasValidSignature ? "Yes" : "No") << "\n";

        if (!report.dangerousCommands.empty()) {
            std::cout << "\n[!] Dangerous Command Features:\n";
            for (const auto& cmd : report.dangerousCommands) std::cout << "  - " << cmd << "\n";
        }
        if (!report.suspiciousTools.empty()) {
            std::cout << "\n[!] Called High-Risk System Tools:\n";
            for (const auto& tool : report.suspiciousTools) std::cout << "  - " << tool << "\n";
        }
        if (!report.techniques.empty()) {
            std::cout << "\n[+] Associated ATT&CK Techniques:\n";
            for (const auto& t : report.techniques) std::cout << "  - " << t << "\n";
        }
        if (!report.decodedPayloads.empty()) {
            std::cout << "\n[!] Decoded Payload Samples (first 200 chars):\n";
            for (const auto& pl : report.decodedPayloads) std::cout << "  - " << pl << "\n";
        }
        if (!report.findings.empty()) {
            std::cout << "\n[+] Detection Summary:\n";
            for (const auto& f : report.findings) std::cout << "  - " << f << "\n";
        } else {
            std::cout << "\nNo obvious malicious features found.\n";
        }
        std::cout << "======================================================\n";
    }
};

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " <target.bat|target.cmd> [--withoutUi|--onlywithUi]\n";
    std::cout << "Example: " << progName << " C:\\suspicious\\malware.bat\n";
}

std::string sanitizeFileName(const std::string& path) {
    std::string result = path;
    const std::string illegalChars = "\\/:*?\"<>|";
    for (char& c : result) {
        if (illegalChars.find(c) != std::string::npos) {
            c = '_';
        }
    }
    return result;
}

// 转义XML特殊字符
std::string escapeXML(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result += c;
        }
    }
    return result;
}

int main(int argc, char* argv[]) {
    std::cout << "MaliciousBatDetector_Enhanced v2.2 - Enhanced Batch Malicious Command Detection Tool\n";
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    // 解析第3个参数（UI模式）
    if (argc > 2) {
        if (strcmp(argv[2], "--withoutUi") == 0) {
            withUi = 0;
            std::cout << "running without Ui" << std::endl;
        } else if (strcmp(argv[2], "--onlywithUi") == 0) {
            withUi = 2;
            std::cout << "running with any Ui" << std::endl;
        } else {
            withUi = 1;
            std::cout << "running with Ui" << std::endl;
        }
    } else {
        withUi = 1;
    }

    // 解析第4个参数（是否生成XML）
    bool writeXML = false;
    if (argc >= 4 && strcmp(argv[3], "--XML") == 0) {
        writeXML = true;
        std::cout << "XML output enabled" << std::endl;
    }

    strcpy(filepath, argv[1]);
    std::string targetFile = argv[1];

    MaliciousBatDetectorEnhanced detector;
    auto report = detector.analyze(targetFile);
    if (report.filePath.empty()) {
        std::cerr << "Error: Unable to analyze file (file may not exist or cannot be read)\n";
        return 1;
    }
    detector.printReport(report);

    //写入XML报告
    if (writeXML) {
        // 创建 Logs 目录
        fs::path logDir = fs::current_path() / "Logs";
        try {
            fs::create_directories(logDir);
        } catch (const std::exception& e) {
            std::cerr << "Failed to create Logs directory: " << e.what() << std::endl;
            return 1;
        }

        // 清理文件名并构建XML路径
        std::string baseName = sanitizeFileName(targetFile);
        fs::path xmlPath = logDir / (baseName + ".xml");

        std::ofstream xmlFile(xmlPath);
        if (!xmlFile.is_open()) {
            std::cerr << "Failed to open XML file for writing: " << xmlPath << std::endl;
            return 1;
        }

        // 写入XML内容
        xmlFile << "<analysis>\n";
        xmlFile << "  <score>" << report.totalScore << "</score>\n";
        xmlFile << "  <Details>\n";

        // 写入列表项
        auto writeList = [&](const std::string& tag, const std::vector<std::string>& items) {
            if (!items.empty()) {
                xmlFile << "    <" << tag << ">\n";
                for (const auto& item : items) {
                    xmlFile << "      <Item>" << escapeXML(item) << "</Item>\n";
                }
                xmlFile << "    </" << tag << ">\n";
            }
        };

        writeList("DangerousCommands", report.dangerousCommands);
        writeList("SuspiciousTools", report.suspiciousTools);
        writeList("Techniques", report.techniques);
        writeList("DecodedPayloads", report.decodedPayloads);
        writeList("Findings", report.findings);

        xmlFile << "  </Details>\n";
        xmlFile << "</analysis>\n";
        xmlFile.close();

        std::cout << "XML report written to: " << xmlPath << std::endl;
    }

    return 0;
}