/*
NetworkGuard.cpp

端点层+分析层

检测并分析网络流量，识别恶意连接和可疑域名

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\NetWorkGuard.cpp" -o "%ExecutablePath%\NetWorkGuard.exe" -lws2_32 -liphlpapi -lfwpuclnt -lpsapi -lole32 -lwintrust -lcrypt32 -std=c++11 -Wno-write-strings -mwindows

运行权限：管理员权限
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>  
#include <iphlpapi.h>
#include <fwpmu.h>   
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cmath>       
#include <vector>
#include <string>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <exception>
#include <excpt.h>    
#include <iostream>
#include <algorithm>
#include <cctype>
#include <wintrust.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <atomic> 
#include <winternl.h>
#include "shutdown_handler.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define MAX_PACKET_SIZE 65535
#define PIPE_TO_CONTROLCENTER_NG L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_NetworkGuard"
#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_NetworkGuard"

struct CommandFromUser_UI {
    int command;   // 1 = 退出
};

std::atomic<bool> g_bExit{false};
HANDLE g_hExitEvent = nullptr;

#pragma pack(push, 1)
struct MessagetoControlCenter_by_NetworkGuard {
    char type[64];
    UINT8  protocol;
    UINT32 localAddr;      // 网络字节序
    UINT16 localPort;      // 主机字节序
    UINT32 remoteAddr;     // 网络字节序
    UINT16 remotePort;     // 主机字节序
    DWORD  pid;
    wchar_t processPath[MAX_PATH];
    char   ip[64];         // 远程 IP 字符串（如 "192.168.1.1"）
    char   domain[256];    // 域名（HTTP Host / DNS 域名 / TLS SNI）
};
#pragma pack(pop)
#define NG_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_NetworkGuard)

// 协议常量
#define ETH_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

bool GetLocalIPs();
bool IsLocalIP(in_addr ip);
DWORD GetProcessIDByTCP(in_addr srcIP, u_short srcPort, in_addr dstIP, u_short dstPort);
DWORD GetProcessIDByUDP(in_addr srcIP, u_short srcPort);
bool ParseDNSQuery(const unsigned char* data, int len, std::string& domain, u_short& qtype);
bool ParseTLSClientHello(const unsigned char* data, int len, std::string& sni);
bool VerifyDigitalSignature(const std::wstring& path);
void ProcessPacket(const unsigned char* packet, int len); 

// WFP GUID 定义（省略，保持与原来相同）
GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = 
    {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
GUID FWPM_CONDITION_ALE_PROCESS_ID = 
    {0x0de0b250, 0xa3d7, 0x4e10, {0x9a, 0x2c, 0x92, 0x89, 0xad, 0x07, 0xae, 0x63}};
GUID FWPM_CONDITION_IP_PROTOCOL = 
    {0x3971ef2b, 0x623e, 0x4f9a, {0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}};
GUID FWPM_CONDITION_IP_LOCAL_ADDRESS = 
    {0xd9ee00de, 0xc1ef, 0x4617, {0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}};
GUID FWPM_CONDITION_IP_LOCAL_PORT = 
    {0x0c1ba1af, 0x5765, 0x453f, {0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}};
GUID FWPM_CONDITION_IP_REMOTE_ADDRESS = 
    {0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};
GUID FWPM_CONDITION_IP_REMOTE_PORT = 
    {0xc35a604d, 0xd22b, 0x4e1a, {0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}};
GUID FWPM_SUBLAYER_UNIVERSAL = 
    {0x1f05f9d0, 0x6cfb, 0x4b5b, {0xb2, 0x53, 0xd7, 0x5c, 0x8c, 0xfa, 0xc1, 0xbb}};
GUID FWPM_CONDITION_ALE_APP_ID = 
    {0x2b821975, 0x5bf3, 0x49ef, {0xbf, 0xd3, 0xdb, 0x5a, 0xe9, 0xfa, 0x9e, 0x6d}};

//威胁情报与黑白名单
// 黑名单：IP（支持CIDR）、域名（精确及通配符）
struct CIDRBlock {
    in_addr prefix;
    UINT8 mask;
    bool isIPv4;
};
std::vector<CIDRBlock> g_blacklistCIDR;
std::unordered_set<std::string> g_blacklistExactDomains;
std::unordered_set<std::string> g_blacklistWildcardDomainsReversed; // 反转后前缀（如 "com.example."）

// 白名单：精确域名和通配符
std::unordered_set<std::string> g_whitelistExactDomains;
std::unordered_set<std::string> g_whitelistWildcardDomainsReversed;

// 高风险 TLD
std::unordered_set<std::string> g_highRiskTLD = { ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".cc", ".pw", ".biz" };

// 常见合法域名白名单（用于跳过DGA检测）
std::unordered_set<std::string> g_commonWhiteDomains = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "ytimg.com",
    "microsoft.com", "windows.com", "live.com", "msdn.com",
    "apple.com", "icloud.com", "itunes.com",
    "amazon.com", "aws.amazon.com",
    "facebook.com", "twitter.com", "instagram.com",
    "github.com", "stackoverflow.com",
    "wikipedia.org", "wikimedia.org",
    "cloudflare.com", "cloudfront.net",
    "akamai.net", "akamaihd.net",
    "fastly.net", "cdn.net",
    "baidu.com", "qq.com", "sina.com.cn",
    "yahoo.com", "bing.com", "duckduckgo.com",
    "googlevideo.com",
    "doubleclick.net", "googleadservices.com"
};

// 常见英文单词列表（用于DGA评分）
const std::unordered_set<std::string> commonEnglishWords = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
    "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
    "people", "into", "year", "your", "good", "some", "could", "them", "see", "other",
    "than", "then", "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first", "well", "way",
    "even", "new", "want", "because", "any", "these", "give", "day", "most", "us"
};

// 常见双字母组合（英语高频）
const std::unordered_set<std::string> commonBigrams = {
    "th","he","in","en","an","re","on","at","nd","st","es","or","nt","er","ea","ti",
    "to","it","ou","ea","as","ha","ar","is","ng","se","me","de","un","ed","le","ve",
    "al","of","ne","ro","ri","ra","li","ll","ce","co","hi","mo","ma","vi","ic","ap",
    "ca","ac","lo","bo","ba","ex","pa","tu","no","mi","si","na","ta","et","ty","ni",
    "sa","la","ve","re","ea","em","hi","lo","an","so","do","ja","os","ru","ul","pu",
    "um","ro","ho","we","be","fo","ur","di","wa","or","da","en","su","ic","me","at",
    "wo","go","ov","te","sa","ne","ra","ss","ti","ci","ec","if"
};

//WFP
HANDLE g_engineHandle = NULL;
bool g_wfpInitialized = false;

// 命名管道句柄
HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;

// 本机 IP 列表
std::vector<in_addr> g_localIPs;

//进程信息缓存
struct ProcessInfo {
    std::string path;
    bool trusted;          // 系统路径或数字签名可信
    bool isBrowser;        // 是否为浏览器进程
    bool isSystemService;  // 是否为系统服务
    std::chrono::steady_clock::time_point cacheTime;
};
std::unordered_map<DWORD, ProcessInfo> g_processCache;
std::mutex g_processCacheMutex;

//DNS 统计
struct DNSStats {
    std::set<std::string> uniqueDomains;
    int totalQueries;
    std::chrono::steady_clock::time_point startTime;
    // 平均域名长度累加
    double totalDomainLength;
};
std::unordered_map<DWORD, DNSStats> g_dnsStats;
std::mutex g_dnsMutex;

//流量统计（目标IP/域名）
struct FlowStats {
    std::chrono::steady_clock::time_point startTime;
    int count;
    size_t totalBytes;
};
std::unordered_map<std::string, FlowStats> g_flowStats;
std::mutex g_flowMutex;

//TLS指纹库
std::unordered_set<std::string> g_maliciousTLSFingerprints; // 存储MD5或SHA1哈希

// 辅助函数声明
bool IsIPInCIDR(const in_addr& ip, const CIDRBlock& cidr);
bool IsIPBlacklisted(const char* ip);
bool IsDomainBlacklisted(const char* domain);
bool IsDomainWhitelisted(const char* domain);
bool IsHighRiskTLD(const char* domain);
bool IsCommonDomain(const char* domain);
double CalcEntropy(const char* str);
bool IsDgaDomain(const char* domain, const std::string& processPath);
std::string GetProcessPath(DWORD pid);
std::string GetProcessInfoAndTrust(DWORD pid, bool& trusted, bool& isBrowser, bool& isSystemService);
DWORD GetParentPID(DWORD pid);

bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed, error: " << GetLastError() << std::endl;
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        std::cerr << "LookupPrivilegeValueW failed, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_SUCCESS) {
        std::cout << "SeDebugPrivilege enabled successfully." << std::endl;
        CloseHandle(hToken);
        return true;
    } else {
        std::cerr << "SeDebugPrivilege not enabled, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }
}

bool SetProcessCritical(bool bSet) {
    // 首次调用时加载函数指针
    if (g_pRtlSetProcessIsCritical == nullptr) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            g_pRtlSetProcessIsCritical = (RtlSetProcessIsCritical_t)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
        }
        if (g_pRtlSetProcessIsCritical == nullptr) {
            std::cerr << "[Critical] RtlSetProcessIsCritical not available." << std::endl;
            return false;
        }
    }

    NTSTATUS status = g_pRtlSetProcessIsCritical(bSet ? TRUE : FALSE, NULL, FALSE);
    if (status == 0) {
        std::cout << "[Critical] Process " << (bSet ? "set" : "unset") << " as system critical." << std::endl;
        return true;
    } else {
        std::cerr << "[Critical] " << (bSet ? "Set" : "Unset") << " failed, status: 0x" << std::hex << status << std::endl;
        return false;
    }
}

template<typename Func>
bool RetryOperation(Func func, const char* name, int maxRetries = 10, int delaySec = 5) {
    for (int attempt = 1; attempt <= maxRetries; ++attempt) {
        if (func()) {
            printf("[DEBUG] %s succeeded.\n", name);
            return true;
        }
        if (attempt < maxRetries) {
            printf("[WARNING] %s failed (attempt %d/%d), retrying in %d seconds...\n",
                   name, attempt, maxRetries, delaySec);
            std::this_thread::sleep_for(std::chrono::seconds(delaySec));
        } else {
            printf("[ERROR] %s failed after %d retries.\n", name, maxRetries);
        }
    }
    return false;
}


//黑白名单加载与初始化
bool LoadMaliciousList(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return false;
    char line[256];
    int ipCount = 0, domainCount = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len-1] == '\r') line[--len] = '\0';
        if (len == 0) continue;
        bool isIP = true;
        for (char* p = line; *p; ++p) {
            if (!(*p >= '0' && *p <= '9') && *p != '.' && *p != '/') {
                isIP = false;
                break;
            }
        }
        if (isIP) {
            // 检查是否为CIDR
            char* slash = strchr(line, '/');
            if (slash) {
                *slash = '\0';
                in_addr addr;
                if (inet_pton(AF_INET, line, &addr) == 1) {
                    int mask = atoi(slash+1);
                    if (mask >= 0 && mask <= 32) {
                        CIDRBlock cidr;
                        cidr.prefix = addr;
                        cidr.mask = (UINT8)mask;
                        g_blacklistCIDR.push_back(cidr);
                        ipCount++;
                    }
                }
            } else {
                // 精确IP（暂时不加入CIDR，用哈希集合更快）
                // 为了兼容，保留精确IP在CIDR中也能处理，但使用CIDR匹配时把掩码设为32
                in_addr addr;
                if (inet_pton(AF_INET, line, &addr) == 1) {
                    CIDRBlock cidr;
                    cidr.prefix = addr;
                    cidr.mask = 32;
                    g_blacklistCIDR.push_back(cidr);
                    ipCount++;
                }
            }
        } else {
            // 域名
            std::string domain(line);
            // 通配符
            if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
                std::string suffix = domain.substr(2);
                std::reverse(suffix.begin(), suffix.end());
                suffix += ".";  // 反转后以"."结尾方便查找前缀
                g_blacklistWildcardDomainsReversed.insert(suffix);
            } else {
                g_blacklistExactDomains.insert(domain);
            }
            domainCount++;
        }
    }
    fclose(f);
    printf("[DEBUG] Loaded %d IPs/CIDR and %d domains from %s\n", ipCount, domainCount, filename);
    return true;
}

bool LoadWhitelist(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return false;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len-1] == '\r') line[--len] = '\0';
        if (len == 0) continue;
        std::string domain(line);
        if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
            std::string suffix = domain.substr(2);
            std::reverse(suffix.begin(), suffix.end());
            suffix += ".";
            g_whitelistWildcardDomainsReversed.insert(suffix);
        } else {
            g_whitelistExactDomains.insert(domain);
        }
    }
    fclose(f);
    printf("[DEBUG] Loaded whitelist from %s\n", filename);
    return true;
}

bool LoadMaliciousTLSFingerprints(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return false;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len-1] == '\r') line[--len] = '\0';
        if (len == 0) continue;
        g_maliciousTLSFingerprints.insert(std::string(line));
    }
    fclose(f);
    printf("[DEBUG] Loaded %zu TLS fingerprints from %s\n", g_maliciousTLSFingerprints.size(), filename);
    return true;
}

// 匹配函数
bool IsIPInCIDR(const in_addr& ip, const CIDRBlock& cidr) {
    uint32_t ipaddr = ntohl(ip.S_un.S_addr);
    uint32_t prefix = ntohl(cidr.prefix.S_un.S_addr);
    uint32_t mask = (cidr.mask == 0) ? 0 : (0xFFFFFFFF << (32 - cidr.mask));
    return (ipaddr & mask) == (prefix & mask);
}

bool IsIPBlacklisted(const char* ip) {
    in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return false;
    for (auto& cidr : g_blacklistCIDR) {
        if (IsIPInCIDR(addr, cidr)) return true;
    }
    return false;
}

bool IsDomainBlacklisted(const char* domain) {
    std::string d(domain);
    // 精确匹配
    if (g_blacklistExactDomains.find(d) != g_blacklistExactDomains.end()) return true;
    // 通配符匹配：反转后查找前缀
    std::string rev = d;
    std::reverse(rev.begin(), rev.end());
    rev += ".";
    for (const auto& prefix : g_blacklistWildcardDomainsReversed) {
        if (rev.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}

bool IsDomainWhitelisted(const char* domain) {
    std::string d(domain);
    if (g_whitelistExactDomains.find(d) != g_whitelistExactDomains.end()) return true;
    std::string rev = d;
    std::reverse(rev.begin(), rev.end());
    rev += ".";
    for (const auto& prefix : g_whitelistWildcardDomainsReversed) {
        if (rev.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}

bool IsHighRiskTLD(const char* domain) {
    std::string d(domain);
    size_t dot = d.rfind('.');
    if (dot == std::string::npos) return false;
    std::string tld = d.substr(dot);
    std::transform(tld.begin(), tld.end(), tld.begin(), ::tolower);
    return g_highRiskTLD.find(tld) != g_highRiskTLD.end();
}

bool IsCommonDomain(const char* domain) {
    std::string d(domain);
    return g_commonWhiteDomains.find(d) != g_commonWhiteDomains.end();
}

//DGA 检测 
double CalcEntropy(const char* str) {
    int len = strlen(str);
    if (len == 0) return 0;
    int freq[256] = {0};
    for (int i = 0; i < len; ++i) freq[(unsigned char)str[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

double CalculateBigramScore(const char* domain) {
    int len = strlen(domain);
    if (len < 2) return 0.0;
    int rareCount = 0;
    int total = 0;
    for (int i = 0; i < len - 1; ++i) {
        char bigram[3] = {domain[i], domain[i+1], 0};
        std::string bg = bigram;
        std::transform(bg.begin(), bg.end(), bg.begin(), ::tolower);
        if (commonBigrams.find(bg) == commonBigrams.end()) {
            rareCount++;
        }
        total++;
    }
    return (double)rareCount / total; // 比例越高越可疑
}

double VowelConsonantRatio(const char* domain) {
    int vowels = 0, consonants = 0;
    for (int i = 0; domain[i]; ++i) {
        char c = tolower(domain[i]);
        if (c >= 'a' && c <= 'z') {
            if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u')
                vowels++;
            else
                consonants++;
        }
    }
    if (consonants == 0) return 0.0;
    return (double)vowels / consonants; // 合法域名通常更均衡，DGA辅音密集 => 比例偏低
}

bool ContainsEnglishWord(const char* domain) {
    std::string d(domain);
    std::transform(d.begin(), d.end(), d.begin(), ::tolower);
    // 简单检查是否包含常见单词（至少3个字母）
    for (const auto& word : commonEnglishWords) {
        if (word.size() >= 3 && d.find(word) != std::string::npos) {
            return true;
        }
    }
    return false;
}

int DgaScore(const char* domain, const std::string& processPath) {
    // 返回一个分数，分数越高越可疑
    int score = 0;
    int len = strlen(domain);
    // 1. 长度
    if (len > 25) score += 10;
    else if (len > 20) score += 5;
    // 2. 熵
    double ent = CalcEntropy(domain);
    if (ent > 7.0) score += 15;
    else if (ent > 6.5) score += 8;
    // 3. 双字母罕见比例
    double bigramScore = CalculateBigramScore(domain);
    if (bigramScore > 0.5) score += 12;
    else if (bigramScore > 0.3) score += 6;
    // 4. 元音/辅音比例
    double vc = VowelConsonantRatio(domain);
    if (vc < 0.2) score += 10;
    else if (vc < 0.4) score += 5;
    // 5. TLD 高风险
    if (IsHighRiskTLD(domain)) score += 10;
    // 6. 是否包含常见单词（减分）
    if (ContainsEnglishWord(domain)) score -= 15;
    // 7. 是否为常见白名单（直接0分）
    if (IsCommonDomain(domain)) return 0;
    // 8. 进程调整：浏览器进程降低敏感度
    if (processPath.find("chrome") != std::string::npos ||
        processPath.find("firefox") != std::string::npos ||
        processPath.find("iexplore") != std::string::npos ||
        processPath.find("edge") != std::string::npos) {
        score -= 10;
    }
    // 系统服务也降低
    if (processPath.find("svchost") != std::string::npos ||
        processPath.find("services") != std::string::npos) {
        score -= 8;
    }
    return score;
}

bool IsDgaDomain(const char* domain, const std::string& processPath) {
    // 先检查白名单
    if (IsDomainWhitelisted(domain)) return false;
    if (IsCommonDomain(domain)) return false;
    int score = DgaScore(domain, processPath);
    // 动态阈值：默认阈值30，可根据进程调整
    int threshold = 30;
    if (processPath.find("chrome") != std::string::npos ||
        processPath.find("firefox") != std::string::npos ||
        processPath.find("edge") != std::string::npos) {
        threshold = 40; // 浏览器放宽
    } else if (processPath.find("svchost") != std::string::npos) {
        threshold = 35;
    }
    return score >= threshold;
}

//TLS指纹提取（类JA3
std::string ComputeJA3FromClientHello(const unsigned char* data, int len) {
    // 实现类似JA3，提取版本、加密套件、扩展、椭圆曲线、EC点格式
    if (len < 43) return "";
    if (data[0] != 0x16) return ""; 
    int pos = 5;
    if (pos + 4 > len) return "";
    if (data[pos] != 0x01) return ""; 
    pos += 4; 
    // 提取版本
    if (pos + 2 > len) return "";
    uint16_t version = ntohs(*(uint16_t*)(data + pos));
    pos += 2;
    // 跳过随机数
    if (pos + 32 > len) return "";
    pos += 32;

    if (pos + 1 > len) return "";
    uint8_t sidLen = data[pos++];
    if (pos + sidLen > len) return "";
    pos += sidLen;

    if (pos + 2 > len) return "";
    uint16_t cipherLen = ntohs(*(uint16_t*)(data + pos));
    pos += 2;
    if (pos + cipherLen > len) return "";
    std::vector<uint16_t> ciphers;
    for (int i = 0; i < cipherLen; i += 2) {
        if (pos + 2 > len) break;
        uint16_t c = ntohs(*(uint16_t*)(data + pos));
        ciphers.push_back(c);
        pos += 2;
    }

    if (pos + 1 > len) return "";
    uint8_t compLen = data[pos++];
    if (pos + compLen > len) return "";
    pos += compLen;

    if (pos + 2 > len) return "";
    uint16_t extLen = ntohs(*(uint16_t*)(data + pos));
    pos += 2;
    if (pos + extLen > len) return "";
    int end = pos + extLen;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> ellipticCurves;
    std::vector<uint8_t> ecPointFormats;
    while (pos + 4 <= end) {
        uint16_t extType = ntohs(*(uint16_t*)(data + pos));
        uint16_t extDataLen = ntohs(*(uint16_t*)(data + pos + 2));
        pos += 4;
        if (pos + extDataLen > end) break;
        extensions.push_back(extType);
        if (extType == 10) { // supported_groups (elliptic curves)
            if (extDataLen >= 2) {
                uint16_t groupLen = ntohs(*(uint16_t*)(data + pos));
                pos += 2;
                for (int i = 0; i < groupLen; i += 2) {
                    if (pos + 2 > end) break;
                    uint16_t curve = ntohs(*(uint16_t*)(data + pos));
                    ellipticCurves.push_back(curve);
                    pos += 2;
                }
            }
        } else if (extType == 11) { // ec_point_formats
            if (extDataLen >= 1) {
                uint8_t formatLen = data[pos++];
                for (int i = 0; i < formatLen; ++i) {
                    if (pos + 1 > end) break;
                    ecPointFormats.push_back(data[pos++]);
                }
            }
        } else {
            pos += extDataLen;
        }
    }
    // 构建JA3字符串: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    std::stringstream ss;
    ss << std::hex << version;
    ss << ",";
    for (size_t i = 0; i < ciphers.size(); ++i) {
        if (i > 0) ss << "-";
        ss << std::hex << ciphers[i];
    }
    ss << ",";
    for (size_t i = 0; i < extensions.size(); ++i) {
        if (i > 0) ss << "-";
        ss << std::hex << extensions[i];
    }
    ss << ",";
    for (size_t i = 0; i < ellipticCurves.size(); ++i) {
        if (i > 0) ss << "-";
        ss << std::hex << ellipticCurves[i];
    }
    ss << ",";
    for (size_t i = 0; i < ecPointFormats.size(); ++i) {
        if (i > 0) ss << "-";
        ss << std::hex << (int)ecPointFormats[i];
    }
    std::string ja3str = ss.str();
    // 计算MD5
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 16;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "";
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!CryptHashData(hHash, (BYTE*)ja3str.c_str(), ja3str.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    char hex[33];
    for (int i = 0; i < 16; ++i) sprintf(hex + i*2, "%02x", rgbHash[i]);
    return std::string(hex, 32);
}

bool IsMaliciousTLSFingerprint(const std::string& fp) {
    return g_maliciousTLSFingerprints.find(fp) != g_maliciousTLSFingerprints.end();
}

//HTTP检测
bool IsHTTPMethod(const unsigned char* data, int len) {
    if (len < 4) return false;
    if (memcmp(data, "GET ", 4) == 0 ||
        memcmp(data, "POST", 4) == 0 ||
        memcmp(data, "PUT ", 4) == 0 ||
        memcmp(data, "HEAD", 4) == 0 ||
        memcmp(data, "DELE", 4) == 0 ||
        memcmp(data, "PATCH",5) == 0 ||
        memcmp(data, "OPTIONS",7) == 0 ||
        memcmp(data, "CONNECT",7) == 0) {
        return true;
    }
    return false;
}

bool ParseHTTPEnhanced(const unsigned char* data, int len, std::string& host, std::string& uri,
                       std::string& ua, bool& hasAccept, bool& hasAcceptLang) {
    std::string payload((char*)data, len);
    size_t lineEnd = payload.find("\r\n");
    if (lineEnd == std::string::npos) return false;
    std::string firstLine = payload.substr(0, lineEnd);
    size_t firstSpace = firstLine.find(' ');
    if (firstSpace == std::string::npos) return false;
    size_t secondSpace = firstLine.find(' ', firstSpace+1);
    if (secondSpace == std::string::npos) return false;
    uri = firstLine.substr(firstSpace+1, secondSpace-firstSpace-1);
    // 提取headers
    size_t hostPos = payload.find("\r\nHost: ");
    if (hostPos == std::string::npos) hostPos = payload.find("\r\nhost: ");
    if (hostPos != std::string::npos) {
        hostPos += 8;
        size_t end = payload.find("\r\n", hostPos);
        if (end != std::string::npos) {
            host = payload.substr(hostPos, end-hostPos);
            size_t colon = host.find(':');
            if (colon != std::string::npos) host = host.substr(0, colon);
        }
    }
    size_t uaPos = payload.find("\r\nUser-Agent: ");
    if (uaPos == std::string::npos) uaPos = payload.find("\r\nuser-agent: ");
    if (uaPos != std::string::npos) {
        uaPos += 15;
        size_t end = payload.find("\r\n", uaPos);
        if (end != std::string::npos) ua = payload.substr(uaPos, end-uaPos);
    }
    hasAccept = (payload.find("\r\nAccept: ") != std::string::npos ||
                 payload.find("\r\naccept: ") != std::string::npos);
    hasAcceptLang = (payload.find("\r\nAccept-Language: ") != std::string::npos ||
                     payload.find("\r\naccept-language: ") != std::string::npos);
    return !host.empty() || !uri.empty();
}

bool IsMaliciousURI(const std::string& uri) {
    static const std::vector<std::string> maliciousPaths = {
        "/update.exe", "/gateway", "/connect", "/bot", "/cmd", "/control",
        "/c2", "/payload", "/shell", "/backdoor"
    };
    std::string lower = uri;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& path : maliciousPaths) {
        if (lower.find(path) != std::string::npos) return true;
    }
    return false;
}

int HTTPAnomalyScore(const std::string& ua, bool hasAccept, bool hasAcceptLang,
                     const std::string& uri, const std::string& processPath) {
    int score = 0;
    // User-Agent 异常
    if (ua.empty()) score += 10;
    else if (ua.length() < 10 || ua.length() > 300) score += 8;
    else {
        // 检查是否包含常见浏览器标识，但进程是浏览器则不匹配
        bool isBrowser = (processPath.find("chrome") != std::string::npos ||
                          processPath.find("firefox") != std::string::npos ||
                          processPath.find("edge") != std::string::npos);
        if (isBrowser) {
            if (ua.find("Chrome") == std::string::npos &&
                ua.find("Firefox") == std::string::npos &&
                ua.find("Edge") == std::string::npos &&
                ua.find("Safari") == std::string::npos) {
                score += 15; // 浏览器进程但UA不像浏览器
            }
        }
    }
    // 缺少常见头部
    if (!hasAccept) score += 5;
    if (!hasAcceptLang) score += 3;
    // 恶意URI
    if (IsMaliciousURI(uri)) score += 15;
    return score;
}

//DNS异常检测
bool IsSystemServiceProcess(const std::string& path) {
    std::string p = path;
    std::transform(p.begin(), p.end(), p.begin(), ::tolower);
    return (p.find("svchost") != std::string::npos ||
            p.find("services") != std::string::npos ||
            p.find("lsass") != std::string::npos ||
            p.find("csrss") != std::string::npos ||
            p.find("winlogon") != std::string::npos);
}

bool IsBrowserProcess(const std::string& path) {
    std::string p = path;
    std::transform(p.begin(), p.end(), p.begin(), ::tolower);
    return (p.find("chrome") != std::string::npos ||
            p.find("firefox") != std::string::npos ||
            p.find("iexplore") != std::string::npos ||
            p.find("edge") != std::string::npos ||
            p.find("opera") != std::string::npos);
}

bool CheckDNSAnomaly(DWORD pid, const std::string& domain, const std::string& processPath) {
    // 白名单域名不统计
    if (IsDomainWhitelisted(domain.c_str())) return false;
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_dnsMutex);
    auto it = g_dnsStats.find(pid);
    if (it == g_dnsStats.end()) {
        DNSStats stats;
        stats.uniqueDomains.insert(domain);
        stats.totalQueries = 1;
        stats.totalDomainLength = domain.length();
        stats.startTime = now;
        g_dnsStats[pid] = stats;
        return false;
    }
    DNSStats& stats = it->second;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - stats.startTime).count();
    if (elapsed >= 60) {
        stats.uniqueDomains.clear();
        stats.totalQueries = 0;
        stats.totalDomainLength = 0;
        stats.startTime = now;
    }
    stats.uniqueDomains.insert(domain);
    stats.totalQueries++;
    stats.totalDomainLength += domain.length();

    // 动态阈值
    int maxUnique = 50, maxQueries = 100;
    bool isBrowser = IsBrowserProcess(processPath);
    bool isSys = IsSystemServiceProcess(processPath);
    if (isBrowser) {
        maxUnique = 80;
        maxQueries = 150;
    } else if (isSys) {
        maxUnique = 60;
        maxQueries = 120;
    }
    bool anomaly = (stats.uniqueDomains.size() > (size_t)maxUnique || stats.totalQueries > maxQueries);
    // 平均长度异常
    double avgLen = stats.totalDomainLength / stats.totalQueries;
    if (avgLen > 30) anomaly = true;
    if (anomaly) {
        printf("[DEBUG] DNS anomaly detected for PID %u: unique=%zu, total=%d, avgLen=%.2f\n",
               pid, stats.uniqueDomains.size(), stats.totalQueries, avgLen);
    }
    return anomaly;
}

// 进程可信度评估
bool VerifyDigitalSignature(const std::wstring& path) {
    // 在函数内部定义静态 GUID，确保可取地址
    static GUID verifyGuid = 
        {0x00AAC56B, 0xCD44, 0x11d0, {0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}};

    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA wtd = {0};
    wtd.cbStruct = sizeof(WINTRUST_DATA);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.hWVTStateData = NULL;
    wtd.pwszURLReference = NULL;
    wtd.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(NULL, &verifyGuid, &wtd);
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &verifyGuid, &wtd);
    return (status == ERROR_SUCCESS);
}

std::string GetProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "";
    char path[MAX_PATH];
    DWORD size = sizeof(path);
    if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return std::string(path);
    }
    CloseHandle(hProcess);
    return "";
}

DWORD GetParentPID(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return pe.th32ParentProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

ProcessInfo GetProcessInfo(DWORD pid) {
    std::lock_guard<std::mutex> lock(g_processCacheMutex);
    auto it = g_processCache.find(pid);
    auto now = std::chrono::steady_clock::now();
    if (it != g_processCache.end()) {
        // 缓存30秒
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.cacheTime).count();
        if (age < 30) return it->second;
    }
    ProcessInfo info;
    info.path = GetProcessPath(pid);
    info.trusted = false;
    info.isBrowser = false;
    info.isSystemService = false;
    if (!info.path.empty()) {
        // 系统路径可信
        std::string lower = info.path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("c:\\windows\\system32") == 0 ||
            lower.find("c:\\windows\\syswow64") == 0) {
            info.trusted = true;
        }
        // 数字签名验证
        if (!info.trusted) {
            int wlen = MultiByteToWideChar(CP_ACP, 0, info.path.c_str(), -1, NULL, 0);
            if (wlen > 0) {
                std::wstring wpath(wlen, L'\0');
                MultiByteToWideChar(CP_ACP, 0, info.path.c_str(), -1, &wpath[0], wlen);
                wpath.resize(wlen - 1);
                if (VerifyDigitalSignature(wpath)) {
                    info.trusted = true;
                }
            }
        }
        // 识别进程类型
        info.isBrowser = IsBrowserProcess(info.path);
        info.isSystemService = IsSystemServiceProcess(info.path);
        // 父进程判断：如果父进程是explorer或services，也可调整
        DWORD parent = GetParentPID(pid);
        if (parent) {
            std::string parentPath = GetProcessPath(parent);
            if (!parentPath.empty()) {
                std::string pp = parentPath;
                std::transform(pp.begin(), pp.end(), pp.begin(), ::tolower);
                if (pp.find("explorer.exe") != std::string::npos ||
                    pp.find("services.exe") != std::string::npos) {
                    // 如果父进程可信，子进程不一定可信
                }
            }
        }
    }
    info.cacheTime = now;
    g_processCache[pid] = info;
    return info;
}

//流量统计
void UpdateFlowStats(const std::string& target, size_t bytes) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_flowMutex);
    auto it = g_flowStats.find(target);
    if (it == g_flowStats.end()) {
        FlowStats fs;
        fs.startTime = now;
        fs.count = 1;
        fs.totalBytes = bytes;
        g_flowStats[target] = fs;
    } else {
        FlowStats& fs = it->second;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - fs.startTime).count();
        if (elapsed >= 60) {
            fs.startTime = now;
            fs.count = 1;
            fs.totalBytes = bytes;
        } else {
            fs.count++;
            fs.totalBytes += bytes;
        }
    }
}

bool CheckFlowAnomaly(const std::string& target, size_t bytes) {
    // 检查某个目标是否高频小包
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_flowMutex);
    auto it = g_flowStats.find(target);
    if (it == g_flowStats.end()) return false;
    FlowStats& fs = it->second;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - fs.startTime).count();
    if (elapsed >= 60) return false;
    // 如果60秒内连接次数>50且每次平均字节<200，则可疑
    if (fs.count > 50 && fs.totalBytes / fs.count < 200) {
        return true;
    }
    return false;
}

void CleanupFlowStats() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_flowMutex);
    for (auto it = g_flowStats.begin(); it != g_flowStats.end(); ) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.startTime).count();
        if (elapsed > 120) it = g_flowStats.erase(it);
        else ++it;
    }
}

//发送告警
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

void SendAlertThread_NG(MessagetoControlCenter_by_NetworkGuard* msg) {
    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NG);
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        if (!WriteFile(hPipe, msg, NG_MESSAGE_SIZE, &bytesWritten, NULL) ||
            bytesWritten != NG_MESSAGE_SIZE) {
            printf("[ERROR] WriteFile to pipe failed\n");
        }
        CloseHandle(hPipe);
    }
    delete msg;
}

void SendAlertAsync_NG(const MessagetoControlCenter_by_NetworkGuard* msg) {
    MessagetoControlCenter_by_NetworkGuard* copy = new MessagetoControlCenter_by_NetworkGuard;
    memcpy(copy, msg, NG_MESSAGE_SIZE);
    std::thread t(SendAlertThread_NG, copy);
    t.detach();
}

void SendAlert(DWORD pid, const std::string& processPath, const std::string& target,
               const std::string& type, int threatScore, const std::string& detail,
               UINT8 protocol, in_addr srcIP, u_short srcPort,
               in_addr dstIP, u_short dstPort,
               const std::string& ipStr, const std::string& domainStr) {
    int wlen = MultiByteToWideChar(CP_ACP, 0, processPath.c_str(), -1, NULL, 0);
    if (wlen == 0) return;
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, processPath.c_str(), -1, &wpath[0], wlen);
    wpath.resize(wlen - 1);

    MessagetoControlCenter_by_NetworkGuard msg = {};
    snprintf(msg.type, sizeof(msg.type), "%s", type.c_str());
    msg.protocol = protocol;
    msg.localAddr = srcIP.S_un.S_addr;
    msg.localPort = srcPort;
    msg.remoteAddr = dstIP.S_un.S_addr;
    msg.remotePort = dstPort;
    msg.pid = pid;
    wcsncpy_s(msg.processPath, wpath.c_str(), _TRUNCATE);
    strncpy_s(msg.ip, ipStr.c_str(), _TRUNCATE);
    strncpy_s(msg.domain, domainStr.c_str(), _TRUNCATE);

    SendAlertAsync_NG(&msg);
}

void ServerThread_from_User_UI() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (!g_bExit.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_FROM_CONTROLCENTER_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(CommandFromUser_UI),
            sizeof(CommandFromUser_UI),
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "[ERROR] CreateNamedPipe failed, error: " << GetLastError() << std::endl;
            break;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::cerr << "[ERROR] ConnectNamedPipe failed, error: " << GetLastError() << std::endl;
            CloseHandle(hPipe);
            continue;
        }

        std::cout << "[DEBUG] Control client connected." << std::endl;

        CommandFromUser_UI msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            if (msg.command == 1) {   // 退出命令
                std::cout << "[INFO] Received exit command, shutting down..." << std::endl;
                g_bExit.store(true);
                if (g_hExitEvent) SetEvent(g_hExitEvent);
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                break;
            }
        }

        if (hPipe != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }
}

//原始套接字捕获
void ProcessPacket(const unsigned char* packet, int len);

void CaptureLoop() {
    const int MAX_RETRIES = 10;
    const int RETRY_DELAY_SEC = 5;

    for (int attempt = 1; attempt <= MAX_RETRIES; ++attempt) {
        SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (rawSocket == INVALID_SOCKET) {
            printf("[WARNING] socket creation failed (attempt %d/%d), error: %d\n",
                   attempt, MAX_RETRIES, WSAGetLastError());
            if (attempt < MAX_RETRIES) {
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                continue;
            }
            printf("[ERROR] socket creation failed after %d retries, capture thread exits.\n", MAX_RETRIES);
            return;
        }

        // 尝试绑定到第一个本地 IP
        bool bound = false;
        sockaddr_in local;
        local.sin_family = AF_INET;
        local.sin_port = 0;
        for (auto& ip : g_localIPs) {
            local.sin_addr = ip;
            if (bind(rawSocket, (sockaddr*)&local, sizeof(local)) == 0) {
                bound = true;
                printf("[DEBUG] Bound to IP: %s\n", inet_ntoa(ip));
                break;
            }
        }
        if (!bound) {
            printf("[WARNING] bind failed (attempt %d/%d)\n", attempt, MAX_RETRIES);
            closesocket(rawSocket);
            if (attempt < MAX_RETRIES) {
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                continue;
            }
            printf("[ERROR] bind failed after %d retries, capture thread exits.\n", MAX_RETRIES);
            return;
        }

        // 设置 SIO_RCVALL
        DWORD dwBytesReturned = 0;
        DWORD dwRcvAll = RCVALL_ON;
        if (WSAIoctl(rawSocket, SIO_RCVALL, &dwRcvAll, sizeof(dwRcvAll),
                     NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
            printf("[WARNING] WSAIoctl SIO_RCVALL failed (attempt %d/%d), error: %d\n",
                   attempt, MAX_RETRIES, WSAGetLastError());
            closesocket(rawSocket);
            if (attempt < MAX_RETRIES) {
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                continue;
            }
            printf("[ERROR] WSAIoctl failed after %d retries, capture thread exits.\n", MAX_RETRIES);
            return;
        }

        // 成功，进入主捕获循环
                // 设置接收超时 1 秒，避免永久阻塞
        int timeout = 1000; // 毫秒
        if (setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
            printf("[WARNING] setsockopt SO_RCVTIMEO failed, error: %d\n", WSAGetLastError());
        }

        printf("[DEBUG] Packet capture started successfully.\n");
        unsigned char buffer[MAX_PACKET_SIZE];
        sockaddr_in from;
        int fromLen = sizeof(from);

        while (!g_bExit.load()) {
            int recvLen = recvfrom(rawSocket, (char*)buffer, sizeof(buffer), 0,
                                   (sockaddr*)&from, &fromLen);
            if (recvLen > 0) {
                try {
                    ProcessPacket(buffer, recvLen);
                } catch (...) {
                    // 异常处理
                }
            } else if (recvLen == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAETIMEDOUT) {
                    // 超时，继续循环检查退出标志
                } else if (err == WSAENOTSOCK || err == WSAEINTR) {
                    // 套接字被关闭或中断，退出
                    printf("[DEBUG] Socket error, exiting capture loop.\n");
                    break;
                } else {
                    printf("[WARNING] recvfrom error: %d\n", err);
                }
            }

            // 检查 ESC 键退出（保留原有功能）
            if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
                printf("[DEBUG] ESC pressed, exiting capture loop.\n");
                g_bExit.store(true);
                break;
            }

            static int cnt = 0;
            if (++cnt % 1000 == 0) CleanupFlowStats();
        }

        // 退出前关闭
        WSAIoctl(rawSocket, SIO_RCVALL, &dwRcvAll, sizeof(dwRcvAll),
                 NULL, 0, &dwBytesReturned, NULL, NULL);
        closesocket(rawSocket);
        printf("[DEBUG] Capture loop exited.\n");
        return; // 正常退出
    }
}

//包处理主函数
void ProcessPacket(const unsigned char* packet, int len) {
    static int packetCount = 0;
    packetCount++;
    if (packetCount % 1000 == 0) {
        printf("[DEBUG] Processed %d packets so far.\n", packetCount);
    }

    try {
        struct ip_header {
            unsigned char ver_ihl;
            unsigned char tos;
            unsigned short total_len;
            unsigned short id;
            unsigned short frag_off;
            unsigned char ttl;
            unsigned char protocol;
            unsigned short checksum;
            unsigned int src_addr;
            unsigned int dst_addr;
        };
        if (len < sizeof(ip_header)) return;
        ip_header* ip = (ip_header*)packet;
        if ((ip->ver_ihl >> 4) != 4) return;
        int ipHeaderLen = (ip->ver_ihl & 0xF) * 4;
        if (len < ipHeaderLen + 20) return;
        unsigned char* payload = (unsigned char*)packet + ipHeaderLen;
        int payloadLen = len - ipHeaderLen;

        in_addr srcIP, dstIP;
        srcIP.S_un.S_addr = ip->src_addr;
        dstIP.S_un.S_addr = ip->dst_addr;

        if (!IsLocalIP(srcIP)) return;

        char srcStr[32], dstStr[32];
        sprintf_s(srcStr, sizeof(srcStr), "%u.%u.%u.%u", (srcIP.S_un.S_addr & 0xFF), ((srcIP.S_un.S_addr >> 8) & 0xFF), ((srcIP.S_un.S_addr >> 16) & 0xFF), ((srcIP.S_un.S_addr >> 24) & 0xFF));
        sprintf_s(dstStr, sizeof(dstStr), "%u.%u.%u.%u", (dstIP.S_un.S_addr & 0xFF), ((dstIP.S_un.S_addr >> 8) & 0xFF), ((dstIP.S_un.S_addr >> 16) & 0xFF), ((dstIP.S_un.S_addr >> 24) & 0xFF));

        // 处理TCP
        if (ip->protocol == IPPROTO_TCP) {
            struct tcp_header {
                unsigned short src_port;
                unsigned short dst_port;
                unsigned int seq;
                unsigned int ack;
                unsigned char reserved_flags;
                unsigned char flags;
                unsigned short window;
                unsigned short checksum;
                unsigned short urgent;
            };
            if (payloadLen < sizeof(tcp_header)) return;
            tcp_header* tcp = (tcp_header*)payload;
            u_short srcPort = ntohs(tcp->src_port);
            u_short dstPort = ntohs(tcp->dst_port);
            int tcpHeaderLen = ((tcp->reserved_flags >> 4) & 0xF) * 4;
            if (tcpHeaderLen < 20 || tcpHeaderLen > payloadLen) return;
            unsigned char* data = payload + tcpHeaderLen;
            int dataLen = payloadLen - tcpHeaderLen;
            if (dataLen <= 0) return;

            printf("[DEBUG] TCP packet %s:%u -> %s:%u len=%d\n", srcStr, srcPort, dstStr, dstPort, dataLen);

            DWORD pid = GetProcessIDByTCP(srcIP, srcPort, dstIP, dstPort);
            if (pid == 0) return;
            ProcessInfo pInfo = GetProcessInfo(pid);
            if (pInfo.path.empty()) return;
            std::string processPath = pInfo.path;
            printf("[DEBUG] PID=%u, Path=%s\n", pid, processPath.c_str());

            char dstIpStr[32];
            sprintf_s(dstIpStr, sizeof(dstIpStr), "%u.%u.%u.%u",
                      (dstIP.S_un.S_addr & 0xFF),
                      ((dstIP.S_un.S_addr >> 8) & 0xFF),
                      ((dstIP.S_un.S_addr >> 16) & 0xFF),
                      ((dstIP.S_un.S_addr >> 24) & 0xFF));

            // 如果进程可信（系统路径或数字签名），可放宽检测
            if (pInfo.trusted) {
                // 仍然检测黑名单，但DGA和异常行为可跳过或降低
            }

            // 黑名单IP检测
            if (IsIPBlacklisted(dstIpStr)) {
                printf("[DEBUG] IP blacklisted: %s\n", dstIpStr);
                SendAlert(pid, processPath, dstIpStr, "IP_Blacklist", 100, "IP blacklisted",
                          ip->protocol, srcIP, srcPort, dstIP, dstPort,
                          dstIpStr, "");
                return;
            }

            // 流量统计特征（对目标IP）
            UpdateFlowStats(dstIpStr, dataLen);
            if (CheckFlowAnomaly(dstIpStr, dataLen)) {
                SendAlert(pid, processPath, dstIpStr, "Flow_Anomaly", 60, "High frequency small packets",
                          ip->protocol, srcIP, srcPort, dstIP, dstPort,
                          dstIpStr, "");
                return;
            }

            // 尝试HTTP解析（不限于特定端口）
            bool isHTTP = IsHTTPMethod(data, dataLen);
            if (isHTTP) {
                std::string host, uri, ua;
                bool hasAccept, hasAcceptLang;
                if (ParseHTTPEnhanced(data, dataLen, host, uri, ua, hasAccept, hasAcceptLang)) {
                    if (!host.empty()) {
                        printf("[DEBUG] HTTP Host: %s\n", host.c_str());
                        // 白名单检查
                        if (IsDomainWhitelisted(host.c_str())) {
                            // 放行
                            return;
                        }
                        if (IsDomainBlacklisted(host.c_str())) {
                            printf("[DEBUG] Domain blacklisted: %s\n", host.c_str());
                            SendAlert(pid, processPath, host, "Domain_Blacklist", 100, "Domain blacklisted",
                                      ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                      dstIpStr, host);
                            return;
                        }
                        // DGA检测
                        if (IsDgaDomain(host.c_str(), processPath)) {
                            printf("[DEBUG] DGA detected: %s\n", host.c_str());
                            SendAlert(pid, processPath, host, "DGA", 80, "DGA detected",
                                      ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                      dstIpStr, host);
                            return;
                        }
                        // HTTP异常检测
                        int httpScore = HTTPAnomalyScore(ua, hasAccept, hasAcceptLang, uri, processPath);
                        if (httpScore >= 25) {
                            printf("[DEBUG] HTTP anomaly detected: score=%d\n", httpScore);
                            SendAlert(pid, processPath, host, "HTTP_Anomaly", httpScore, "HTTP anomaly",
                                      ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                      dstIpStr, host);
                            return;
                        }
                    }
                }
            } else if (dstPort == 443) {
                // TLS Client Hello
                std::string sni;
                if (ParseTLSClientHello(data, dataLen, sni)) {
                    if (!sni.empty()) {
                        printf("[DEBUG] TLS SNI: %s\n", sni.c_str());
                        if (IsDomainWhitelisted(sni.c_str())) {
                            // 放行
                            return;
                        }
                        if (IsDomainBlacklisted(sni.c_str())) {
                            printf("[DEBUG] Domain blacklisted (SNI): %s\n", sni.c_str());
                            SendAlert(pid, processPath, sni, "Domain_Blacklist", 100, "Domain blacklisted",
                                      ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                      dstIpStr, sni);
                            return;
                        }
                        if (IsDgaDomain(sni.c_str(), processPath)) {
                            printf("[DEBUG] DGA detected (SNI): %s\n", sni.c_str());
                            SendAlert(pid, processPath, sni, "DGA", 80, "DGA detected",
                                      ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                      dstIpStr, sni);
                            return;
                        }
                    }
                    // TLS指纹检测
                    std::string ja3 = ComputeJA3FromClientHello(data, dataLen);
                    if (!ja3.empty() && IsMaliciousTLSFingerprint(ja3)) {
                        printf("[DEBUG] Malicious TLS fingerprint: %s\n", ja3.c_str());
                        SendAlert(pid, processPath, sni.empty() ? dstIpStr : sni, "Malicious_TLS", 90, "Malicious TLS fingerprint",
                                  ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                  dstIpStr, sni);
                        return;
                    }
                }
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udp_header {
                unsigned short src_port;
                unsigned short dst_port;
                unsigned short length;
                unsigned short checksum;
            };
            if (payloadLen < sizeof(udp_header)) return;
            udp_header* udp = (udp_header*)payload;
            u_short srcPort = ntohs(udp->src_port);
            u_short dstPort = ntohs(udp->dst_port);
            if (dstPort != 53) return;
            unsigned char* data = payload + 8;
            int dataLen = payloadLen - 8;
            if (dataLen < 12) return;

            printf("[DEBUG] UDP DNS packet %s:%u -> %s:%u\n", srcStr, srcPort, dstStr, dstPort);

            DWORD pid = GetProcessIDByUDP(srcIP, srcPort);
            if (pid == 0) return;
            ProcessInfo pInfo = GetProcessInfo(pid);
            if (pInfo.path.empty()) return;
            std::string processPath = pInfo.path;
            printf("[DEBUG] PID=%u, Path=%s\n", pid, processPath.c_str());

            std::string domain;
            u_short qtype;
            if (ParseDNSQuery(data, dataLen, domain, qtype)) {
                if (!domain.empty()) {
                    printf("[DEBUG] DNS Query: %s (type %u)\n", domain.c_str(), qtype);
                    // 白名单优先
                    if (IsDomainWhitelisted(domain.c_str())) {
                        return;
                    }
                    if (IsDomainBlacklisted(domain.c_str())) {
                        printf("[DEBUG] Domain blacklisted (DNS): %s\n", domain.c_str());
                        SendAlert(pid, processPath, domain, "Domain_Blacklist", 100, "Domain blacklisted",
                                  ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                  dstStr, domain);
                        return;
                    }
                    if (IsDgaDomain(domain.c_str(), processPath)) {
                        printf("[DEBUG] DGA detected (DNS): %s\n", domain.c_str());
                        SendAlert(pid, processPath, domain, "DGA", 80, "DGA detected",
                                  ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                  dstStr, domain);
                        return;
                    }
                    if (CheckDNSAnomaly(pid, domain, processPath)) {
                        SendAlert(pid, processPath, domain, "DNS_Anomaly", 70, "Abnormal DNS behavior",
                                  ip->protocol, srcIP, srcPort, dstIP, dstPort,
                                  dstStr, domain);
                        return;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        printf("[ERROR] ProcessPacket exception: %s, GetLastError=%lu\n", e.what(), GetLastError());
    } catch (...) {
        printf("[ERROR] ProcessPacket unknown exception, GetLastError=%lu\n", GetLastError());
    }
}

//WFP 函数（保留但不使用）
bool InitWFP() {
    DWORD ret = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_engineHandle);
    if (ret != ERROR_SUCCESS) {
        printf("[ERROR] FwpmEngineOpen0 failed: %d\n", ret);
        return false;
    }
    g_wfpInitialized = true;
    printf("[DEBUG] WFP initialized successfully. Engine handle: %p\n", g_engineHandle);
    return true;
}

void CleanupWFP() {
    if (g_engineHandle) {
        FwpmEngineClose0(g_engineHandle);
        g_engineHandle = NULL;
    }
    g_wfpInitialized = false;
    printf("[DEBUG] WFP cleaned up.\n");
}

// 辅助函数（获取本地IP等）
bool GetLocalIPs() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) return false;
    struct hostent* he = gethostbyname(hostname);
    if (!he) return false;
    printf("[DEBUG] Local IPs:\n");
    for (int i = 0; he->h_addr_list[i] != NULL; ++i) {
        in_addr addr;
        memcpy(&addr, he->h_addr_list[i], sizeof(in_addr));
        if (addr.S_un.S_addr != htonl(INADDR_LOOPBACK)) {
            g_localIPs.push_back(addr);
            printf("  %s\n", inet_ntoa(addr));
        }
    }
    return !g_localIPs.empty();
}

bool IsLocalIP(in_addr ip) {
    for (auto& local : g_localIPs)
        if (local.S_un.S_addr == ip.S_un.S_addr) return true;
    return false;
}

DWORD GetProcessIDByTCP(in_addr srcIP, u_short srcPort, in_addr dstIP, u_short dstPort) {
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRet = GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwRet != ERROR_INSUFFICIENT_BUFFER) return 0;
    pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
    if (!pTcpTable) return 0;
    dwRet = GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwRet != NO_ERROR) { free(pTcpTable); return 0; }
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
        MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
        in_addr localAddr, remoteAddr;
        localAddr.S_un.S_addr = row.dwLocalAddr;
        remoteAddr.S_un.S_addr = row.dwRemoteAddr;
        u_short localPort = ntohs((u_short)row.dwLocalPort);
        u_short remotePort = ntohs((u_short)row.dwRemotePort);
        if (localAddr.S_un.S_addr == srcIP.S_un.S_addr &&
            localPort == srcPort &&
            remoteAddr.S_un.S_addr == dstIP.S_un.S_addr &&
            remotePort == dstPort) {
            DWORD pid = row.dwOwningPid;
            free(pTcpTable);
            return pid;
        }
    }
    free(pTcpTable);
    return 0;
}

DWORD GetProcessIDByUDP(in_addr srcIP, u_short srcPort) {
    PMIB_UDPTABLE_OWNER_PID pUdpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRet = GetExtendedUdpTable(NULL, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (dwRet != ERROR_INSUFFICIENT_BUFFER) return 0;
    pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
    if (!pUdpTable) return 0;
    dwRet = GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (dwRet != NO_ERROR) { free(pUdpTable); return 0; }
    for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i) {
        MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];
        in_addr localAddr;
        localAddr.S_un.S_addr = row.dwLocalAddr;
        u_short localPort = ntohs((u_short)row.dwLocalPort);
        if (localAddr.S_un.S_addr == srcIP.S_un.S_addr &&
            localPort == srcPort) {
            DWORD pid = row.dwOwningPid;
            free(pUdpTable);
            return pid;
        }
    }
    free(pUdpTable);
    return 0;
}

bool ParseDNSQuery(const unsigned char* data, int len, std::string& domain, u_short& qtype) {
    if (len < 12) return false;
    u_short qdcount = ntohs(*(u_short*)(data + 4));
    if (qdcount == 0) return false;
    int pos = 12;
    domain.clear();
    while (pos < len) {
        unsigned char labelLen = data[pos++];
        if (labelLen == 0) break;
        if (labelLen & 0xC0) { pos++; break; }
        if (pos + labelLen > len) return false;
        if (!domain.empty()) domain += ".";
        domain.append((char*)data + pos, labelLen);
        pos += labelLen;
    }
    if (domain.empty()) return false;
    if (pos + 4 > len) return false;
    qtype = ntohs(*(u_short*)(data + pos));
    return true;
}

bool ParseTLSClientHello(const unsigned char* data, int len, std::string& sni) {
    if (len < 5) return false;
    if (data[0] != 0x16) return false;
    int pos = 5;
    if (pos + 4 > len) return false;
    if (data[pos] != 0x01) return false;
    pos += 4;
    if (pos + 35 > len) return false;
    pos += 2 + 32;
    unsigned char sidLen = data[pos++];
    if (pos + sidLen > len) return false;
    pos += sidLen;
    if (pos + 2 > len) return false;
    u_short cipherLen = ntohs(*(u_short*)(data + pos));
    pos += 2;
    if (pos + cipherLen > len) return false;
    pos += cipherLen;
    if (pos + 1 > len) return false;
    unsigned char compLen = data[pos++];
    if (pos + compLen > len) return false;
    pos += compLen;
    if (pos + 2 > len) return false;
    u_short extLen = ntohs(*(u_short*)(data + pos));
    pos += 2;
    if (pos + extLen > len) return false;
    int end = pos + extLen;

    while (pos + 4 <= end) {
        u_short extType = ntohs(*(u_short*)(data + pos));
        u_short extDataLen = ntohs(*(u_short*)(data + pos + 2));
        pos += 4;
        if (pos + extDataLen > end) break;
        if (extType == 0) {
            if (pos + 2 > end) break;
            u_short nameListLen = ntohs(*(u_short*)(data + pos));
            pos += 2;
            if (pos + nameListLen > end) break;
            int nameEnd = pos + nameListLen;
            while (pos + 1 <= nameEnd) {
                unsigned char nameType = data[pos++];
                if (pos + 2 > nameEnd) break;
                u_short nameLen = ntohs(*(u_short*)(data + pos));
                pos += 2;
                if (pos + nameLen > nameEnd) break;
                if (nameType == 0) {
                    sni.assign((char*)data + pos, nameLen);
                    return true;
                }
                pos += nameLen;
            }
        } else {
            pos += extDataLen;
        }
    }
    return false;
}

// VEH 异常处理 
LONG WINAPI VectoredExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    printf("\n[FATAL] Unhandled SEH exception detected!\n");
    printf("  ExceptionCode: 0x%08X\n", pExceptionInfo->ExceptionRecord->ExceptionCode);
    printf("  ExceptionFlags: 0x%08X\n", pExceptionInfo->ExceptionRecord->ExceptionFlags);
    printf("  ExceptionAddress: %p\n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        printf("  Access violation %s at address %p\n",
               pExceptionInfo->ExceptionRecord->ExceptionInformation[0] ? "write" : "read",
               (void*)pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_SHUTDOWN_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT) {
        // 在系统强制终止前，立即解除关键状态
        SetProcessCritical(false);
        return TRUE;
    }
    return FALSE;
}

int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    PVOID vehHandle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    if (!vehHandle) {
        printf("[WARNING] AddVectoredExceptionHandler failed\n");
    }

    EnableDebugPrivilege();
    SetProcessCritical(true);
    InstallShutdownHandler();
    SetProcessShutdownParameters(0x100, 0);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    try {
        g_hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_hExitEvent) {
            printf("[ERROR] Failed to create exit event.\n");
            SetProcessCritical(false);
            return 1;
        }
        printf("[DEBUG] NetworkGuard started with debug output enabled.\n");
        WSADATA wsaData;
        if (!RetryOperation([]() -> bool {
                WSADATA wsaData;
                return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
            }, "WSAStartup")) {
                SetProcessCritical(false);
                return 1;  // 最终失败则退出
        }
        if (!RetryOperation([]() -> bool {
                return GetLocalIPs();
            }, "GetLocalIPs")) {
            WSACleanup();
            SetProcessCritical(false);
            return 1;
        }
        if (!LoadMaliciousList("malicious.txt")) {
            printf("[WARNING] Failed to load malicious.txt\n");
        }
        if (!LoadWhitelist("whitelist.txt")) {
            printf("[WARNING] Failed to load whitelist.txt\n");
        }
        if (!LoadMaliciousTLSFingerprints("tls_fingerprints.txt")) {
            printf("[WARNING] Failed to load tls_fingerprints.txt\n");
        }
        if (!InitWFP()) {
            printf("[WARNING] WFP init failed, blocking may not work.\n");
        }
        std::thread controlThread(ServerThread_from_User_UI);
        controlThread.detach();


        printf("[DEBUG] NetworkGuard main loop started. Press ESC to exit.\n");

        std::thread captureThread(CaptureLoop);
        captureThread.join();

        SetProcessCritical(false);
        CleanupWFP();
        if (g_pipeHandle != INVALID_HANDLE_VALUE) CloseHandle(g_pipeHandle);
        WSACleanup();
        printf("[DEBUG] NetworkGuard exited.\n");
    } catch (const std::exception& e) {
        printf("[ERROR] main exception: %s, GetLastError=%lu\n", e.what(), GetLastError());
        CleanupWFP();
        if (g_pipeHandle != INVALID_HANDLE_VALUE) CloseHandle(g_pipeHandle);
        WSACleanup();
    } catch (...) {
        printf("[ERROR] main unknown exception, GetLastError=%lu\n", GetLastError());
        CleanupWFP();
        if (g_pipeHandle != INVALID_HANDLE_VALUE) CloseHandle(g_pipeHandle);
        WSACleanup();
    }

    if (g_hExitEvent) {
        CloseHandle(g_hExitEvent);
        g_hExitEvent = nullptr;
    }
    if (vehHandle) {
        RemoveVectoredExceptionHandler(vehHandle);
    }
    return 0;
}