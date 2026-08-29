/*
User_UI.cpp
决策层+响应层

用户决策UI+用户决策响应+自动决策响应

window type:
0 --- 主窗口
1 --- MemoryGuard                  内存检测工具                       5s自动响应:终止进程
2 --- FileAnalyzer                 文件扫描工具(仅高危)                5s自动响应:加密隔离文件 AES-256
3 --- RegistryMonitor              注册表监控工具                     5s自动响应:恢复注册表值
4 --- FileAnalyzer                 文件扫描工具(所有,用户右键菜单扫描)  无自动响应
5 --- SystemService/Taskscheduler  系统服务/计划任务监控工具           5s自动响应:禁用服务/任务
6 --- NetworkGuard                 网络监控工具                       5s自动响应:5元组 阻止连接

g++编译:
cd %g++Path%
g++ -fdiagnostics-color=always -g "%SourceCodePath%\User_UI.cpp" -o "%ExecutablePath%\User_UI.exe" -mwindows -municode -lwbemuuid -loleaut32 -ladvapi32 -luuid -ltaskschd -lws2_32 -liphlpapi -lfwpuclnt -lpsapi -lole32 -lcomdlg32 -lshell32 -std=c++11 -Wno-write-strings

运行权限：管理员权限
*/
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <cstdlib>
#include <windows.h>
#include <shellapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <fstream>
#include <unordered_map>          // 用于决策缓存和弹窗缓存
#include <unordered_set>          // 用于信任路径集合
#include <cctype>                 // 用于 std::towlower
#include <algorithm>
#include <winsvc.h>               // 服务管理
#include <taskschd.h>             // 任务计划
#include <comdef.h>               // COM 辅助
#include <fwpmu.h>          // WFP 用户态 API
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>        
#include <iphlpapi.h>   
#include <psapi.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cmath>       // for log2
#include <set>
#include <mutex>
#include <sstream>
#include <exception>
#include <excpt.h>     // for VEH
#include <tlhelp32.h> 
#include <winternl.h>
#include <commdlg.h>   
#include <shlobj.h>    
#include "logrecord.h"
#pragma comment(lib, "fwpuclnt.lib")

#include "nlohmann/json.hpp"

// 按钮 ID（按类型分配）
#define IDC_BUTTON_ALLOW        1001
#define IDC_BUTTON_RESTRICT     1002
#define IDC_BUTTON_BLOCK        1003
#define IDC_BUTTON_TRUST        1004
#define IDC_BUTTON_UNTRUST      1005
#define IDC_BUTTON_QUARANTINE   1006
#define IDC_BUTTON_DELETE       1007
#define IDC_BUTTON_TRUST_       1008
#define IDC_BUTTON_UNTRUST_     1009
#define IDC_EXIT_BUTTON         1010
#define IDC_BUTTON_DISABLE      1011
#define IDC_BUTTON_DELETE_TASK  1012
#define IDC_BUTTON_ALLOW_CONN  1013
#define IDC_BLOCK_CONN         1014
#define IDC_BUTTON_ADD_FILE         1015
#define IDC_BUTTON_ADD_FOLDER       1016
#define IDC_BUTTON_EDIT_MALICIOUS  1017
#define IDC_BUTTON_EDIT_WHITELIST  1018
#define IDC_BUTTON_EDIT_TLS        1019
#define IDC_BUTTON_RESTORE_ISOL   1020 
#define IDC_PROC_STATIC_BASE  2000
#define IDC_PROC_BUTTON_BASE  2100
#define IDC_EXTRA_STATIC     (IDC_PROC_STATIC_BASE + SUB_PROCESS_COUNT)   // 2006
#define IDC_EXTRA_BUTTON     (IDC_PROC_BUTTON_BASE + SUB_PROCESS_COUNT)   // 2106

#define WM_TRAYICON             (WM_APP + 1)
#define WM_CREATE_ALERT         (WM_APP + 2) 
UINT WM_TASKBARCREATED = RegisterWindowMessage(L"TaskbarCreated");

// 基准尺寸（逻辑像素，96 DPI 下）
#define BASE_WIDTH  800
#define BASE_HEIGHT 600

// 控件基准大小（96 DPI 下）
#define TEXT_WIDTH  400
#define TEXT_HEIGHT 50
#define BUTTON_WIDTH  100
#define BUTTON_HEIGHT 30
#define GAP 20
#define WINDOW_COUNT 1          // 只保留主窗口，其余动态创建

#define PIPE_TO_ControlCenter_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_USERUI"
#define PIPE_FROM_ControlCenter_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_USERUI"
#define PIPE_TO_SystemService_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_SystemService"
#define PIPE_TO_TaskScheduler_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_TaskScheduler"
#define PIPE_TO_MemoryGuard_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_MemoryGuard"
#define PIPE_TO_RegistryMonitor_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_RegistryMonitor"
#define PIPE_TO_NetworkGuard_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_NetworkGuard"
#define PIPE_TO_FileSystemMonitor_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_FileSystemMonitor"

GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = 
    {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
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

// 全局数据
HWND g_hWnds[WINDOW_COUNT] = { NULL };
BOOL g_bTrayCreated = FALSE;
NOTIFYICONDATA nid = {};
HANDLE g_engineHandle = NULL;
bool g_wfpInitialized = false;

// 用于过滤自身
wchar_t g_selfPath[MAX_PATH] = { 0 };
DWORD g_selfPid = 0;

// 白名单全局变量
std::vector<std::wstring> g_whitelist;
std::unordered_set<std::wstring> g_trustedFolders;

// 决策缓存：路径(小写) -> (按钮ID, 时间戳)
std::unordered_map<std::wstring, std::pair<int, std::chrono::steady_clock::time_point>> g_decisionCache;
const int CACHE_EXPIRY_SECONDS = 120;

// 弹窗缓存：路径(小写) -> 最后弹窗时间（仅用于类型2和4）
std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> g_alertCache;

//  注册表弹窗缓存（类型3，30秒内不重复弹窗） 
std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> g_regAlertCache;
const int REG_ALERT_CACHE_EXPIRY_SECONDS = 30;   // 30秒

// 信任路径集合（永久有效，本次运行期间不弹窗）
std::unordered_set<std::wstring> g_trustedPaths;

// 动态基础目录（存放程序所在路径）
std::wstring g_baseDir;

HBRUSH g_hWhiteBrush = NULL;

const wchar_t* g_extraProcessNames[] = {
    L"Fileanalyzer.exe",
    L"PEanalyzer.exe",
    L"CMDanalyzer.exe",
    L"Lnkanalyzer.exe",
    L"PDFanalyzer.exe",
    L"OLEanalyzer.exe",
    L"ZIPanalyzer.exe",
    L"DelFromZip.exe",
    L"7z.exe",
    L"isol.exe"
};
const int EXTRA_PROCESS_COUNT = sizeof(g_extraProcessNames) / sizeof(g_extraProcessNames[0]);

// 用于计算额外进程 CPU 的历史数据缓存
std::unordered_map<DWORD, ULONGLONG> g_extraProcKernel;
std::unordered_map<DWORD, ULONGLONG> g_extraProcUser;
ULONGLONG g_lastExtraSysTime = 0;

// 每个窗口的实例数据
struct WindowData {
    int windowType;                 // 0:主窗口，1:告警（含PID），2:告警（无PID），3:注册表，4:其他（无PID），5:服务/任务
    int pid;
    wchar_t path[32768];
    wchar_t details[32768];
    int score;
    BYTE key[32768]=""; 
    BYTE oldvalue[32768]="";
    DWORD oldvalue_len=0;
    BYTE newvalue[32768]="";
    DWORD newvalue_len=0;
    BYTE valuetype[256]="";
    HWND hButton0, hButton1, hButton2, hExitButton;
    UINT uDpi;
    int defaultAction;            // 超时默认操作按钮ID
    UINT_PTR timerId;             // 定时器句柄
    UINT8  protocol=0;
    UINT32 localAddr=0;      // 网络字节序
    UINT16 localPort=0;      // 主机字节序
    UINT32 remoteAddr=0;     // 网络字节序
    UINT16 remotePort=0;     // 主机字节序
    char   ip[64]="";         // 远程 IP 字符串（如 "192.168.1.1"）
    char   domain[256]="";  
    struct ProcessInfo {
        HWND hStatic;                  // 显示文本的静态控件
        HWND hButton;                  // “退出/启动”按钮
        DWORD pid;                     // 当前进程ID，0表示不存在
        double cpuUsage;               // CPU 使用率（%）
        double memMB;                  // 内存占用（MB）
        ULONGLONG lastKernelTime;      // 上次内核时间（用于CPU计算）
        ULONGLONG lastUserTime;        // 上次用户时间
        ULONGLONG lastSysTime;         // 上次系统总时间
    };
    ProcessInfo procInfo[6];   
    HWND hExtraStatic;          // 汇总静态控件
    HWND hExtraButton;          // 退出按钮
    double extraCpuSum;         // 汇总 CPU
    double extraMemSum;
    HWND hAddFileButton;        // “添加文件白名单”按钮
    HWND hAddFolderButton;      // “添加文件夹白名单”按钮
    HWND hEditMalicious;
    HWND hEditWhitelist;
    HWND hEditTLS;
    HWND hRestoreIsolButton;
};

#pragma pack(push, 1)
struct MessageFromControlCenter {
    int WindowType=-1;
    int PID=-1;
    wchar_t path[32768]=L"";
    wchar_t details[32768]=L"";
    int score=0;
    BYTE key[32768]=""; 
    BYTE oldvalue[32768]="";
    DWORD oldvalue_len=0;
    BYTE newvalue[32768]="";
    DWORD newvalue_len=0;
    BYTE valuetype[256]="";
    UINT8  protocol=0;
    UINT32 localAddr=0;      // 网络字节序
    UINT16 localPort=0;      // 主机字节序
    UINT32 remoteAddr=0;     // 网络字节序
    UINT16 remotePort=0;     // 主机字节序
    char   ip[64]="";         // 远程 IP 字符串（如 "192.168.1.1"）
    char   domain[256]="";   
};
struct CommandToEndpointLevel{
    int command;
};
#pragma pack(pop)
#define BUFFER_SIZE_FROMCONTROLCENTER sizeof(MessageFromControlCenter)
#define BUFFER_SIZE_TOEndpointLevel sizeof(CommandToEndpointLevel)

const wchar_t* g_subProcessNames[] = {
    L"FileSystemMonitor.exe",
    L"MemoryGuard.exe",
    L"NetWorkGuard.exe",
    L"RegistryMonitor.exe",
    L"SystemService.exe",
    L"TaskScheduler.exe"
};
const int SUB_PROCESS_COUNT = 6;
const wchar_t* g_pipeNamesToSubProcess[] = {
    PIPE_TO_FileSystemMonitor_NAME,
    PIPE_TO_MemoryGuard_NAME,
    PIPE_TO_NetworkGuard_NAME,
    PIPE_TO_RegistryMonitor_NAME,
    PIPE_TO_SystemService_NAME,
    PIPE_TO_TaskScheduler_NAME
};


// 函数声明
HWND CreateAlertWindow(const MessageFromControlCenter& data);
void LoadWhitelist();
std::wstring ToLower(const std::wstring& str);
void CleanExpiredCache();
void CleanExpiredAlertCache();      // 清理过期的弹窗缓存
void ApplyDecision(int buttonId, const std::wstring& path, int pid);
void AddToHighTrustWhiteList(const std::wstring& filePath);
//  服务/任务操作辅助函数 
bool DisableService(const std::wstring& serviceName);
bool DeleteServiceByName(const std::wstring& serviceName);
bool DisableTask(const std::wstring& taskPath);
bool DeleteTaskByName(const std::wstring& taskPath);
bool IsService(const std::wstring& name);
bool IsTask(const std::wstring& path);
static std::string WideToUtf8(const std::wstring& wstr);

// 将路径添加到 HighTrustWhiteList.json 的指定数组（"Files" 或 "Paths"）
void AddPathToHighTrustList(const std::wstring& path, bool isFolder) {
    if (path.empty()) return;

    std::wstring jsonPathW = g_baseDir + L"\\WhiteList\\HighTrustWhiteList.json";
    std::string jsonPath = WideToUtf8(jsonPathW);

    nlohmann::json j;
    std::ifstream in(jsonPath);
    if (in.is_open()) {
        try { in >> j; } catch (...) { j = nlohmann::json::object(); }
        in.close();
    } else {
        j = nlohmann::json::object();
    }

    std::string pathUtf8 = WideToUtf8(path);
    if (pathUtf8.empty()) return;
    std::string lowerPath = pathUtf8;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    const char* arrayName = isFolder ? "Paths" : "Files";
    if (!j.contains(arrayName) || !j[arrayName].is_array()) {
        j[arrayName] = nlohmann::json::array();
    }

    // 去重（忽略大小写）
    bool exists = false;
    for (auto& item : j[arrayName]) {
        if (item.is_string()) {
            std::string existing = item.get<std::string>();
            std::transform(existing.begin(), existing.end(), existing.begin(), ::tolower);
            if (existing == lowerPath) {
                exists = true;
                break;
            }
        }
    }
    if (!exists) {
        j[arrayName].push_back(pathUtf8);
    }

    // 写回文件
    std::ofstream out(jsonPath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (out.is_open()) {
        std::string content = j.dump(4);
        out.write(content.c_str(), content.size());
        out.close();
    }
}

bool InitWFP() {
    DWORD ret = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_engineHandle);
    if (ret != ERROR_SUCCESS) {
        printf("[ERROR] FwpmEngineOpen0 failed: %d\n", ret);
        char logs[64];
        sprintf_s(logs,sizeof(logs),"FwpmEngineOpen0 failed: %d",ret);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }
    g_wfpInitialized = true;
    printf("[DEBUG] WFP initialized successfully. Engine handle: %p\n", g_engineHandle);
    LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","WFP initialized successfully");
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

bool AddBlockRuleFor5Tuple(in_addr srcIP, u_short srcPort, in_addr dstIP, u_short dstPort, u_char protocol) {
    if (!g_wfpInitialized) return false;

    FWPM_FILTER0 filter = {0};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = {0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};   // 使用默认子层，避免注册问题
    filter.displayData.name = L"NetworkGuard Block Rule (5-tuple)";
    filter.displayData.description = L"Block by 5-tuple";
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_EMPTY;            // 必须为空

    // 准备条件数组（5个条件）
    FWPM_FILTER_CONDITION0 conds[5];
    int idx = 0;

    // 1) 协议
    conds[idx].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[idx].matchType = FWP_MATCH_EQUAL;
    conds[idx].conditionValue.type = FWP_UINT8;
    conds[idx].conditionValue.uint8 = (UINT8)protocol;
    idx++;

    // 2) 本地地址
    conds[idx].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
    conds[idx].matchType = FWP_MATCH_EQUAL;
    conds[idx].conditionValue.type = FWP_UINT32;
    conds[idx].conditionValue.uint32 = srcIP.S_un.S_addr;
    idx++;

    // 3) 本地端口
    conds[idx].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    conds[idx].matchType = FWP_MATCH_EQUAL;
    conds[idx].conditionValue.type = FWP_UINT16;
    conds[idx].conditionValue.uint16 = srcPort;
    idx++;

    // 4) 远程地址
    conds[idx].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[idx].matchType = FWP_MATCH_EQUAL;
    conds[idx].conditionValue.type = FWP_UINT32;
    conds[idx].conditionValue.uint32 = dstIP.S_un.S_addr;
    idx++;

    // 5) 远程端口
    conds[idx].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[idx].matchType = FWP_MATCH_EQUAL;
    conds[idx].conditionValue.type = FWP_UINT16;
    conds[idx].conditionValue.uint16 = dstPort;
    idx++;

    filter.filterCondition = conds;
    filter.numFilterConditions = idx;

    UINT64 filterId = 0;
    DWORD ret = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &filterId);
    if (ret != ERROR_SUCCESS) {
        printf("[ERROR] FwpmFilterAdd0 (5-tuple) failed: %d (0x%08X)\n", ret, ret);
        char logs[64];
        sprintf_s(logs,sizeof(logs),"FwpmFilterAdd0 (5-tuple) failed: %d (0x%08X)",ret,ret);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }

    char srcStr[32], dstStr[32];
    sprintf_s(srcStr, sizeof(srcStr), "%u.%u.%u.%u", 
              (srcIP.S_un.S_addr & 0xFF), ((srcIP.S_un.S_addr >> 8) & 0xFF),
              ((srcIP.S_un.S_addr >> 16) & 0xFF), ((srcIP.S_un.S_addr >> 24) & 0xFF));
    sprintf_s(dstStr, sizeof(dstStr), "%u.%u.%u.%u",
              (dstIP.S_un.S_addr & 0xFF), ((dstIP.S_un.S_addr >> 8) & 0xFF),
              ((dstIP.S_un.S_addr >> 16) & 0xFF), ((dstIP.S_un.S_addr >> 24) & 0xFF));
    printf("[DEBUG] Block rule added for 5-tuple: %s:%u -> %s:%u proto=%u, filterId=%llu\n",
           srcStr, srcPort, dstStr, dstPort, protocol, filterId);
    char logs[128];
    sprintf_s(logs,sizeof(logs),"Block rule added for 5-tuple: %s:%u -> %s:%u proto=%u, filterId=%llu",srcStr, srcPort, dstStr, dstPort, protocol, filterId);
    LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]",logs);
    return true;
}

//  权限、进程控制、管道等原有函数 
bool EnableDebugPrivilege() {
    HANDLE hToken;
    char logs[64];
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed, error: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"OpenProcessToken failed, error: %d",GetLastError());
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        std::cerr << "LookupPrivilegeValueW failed, error: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"LookupPrivilegeValueW failed, error: %d",GetLastError());
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed, error: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"AdjustTokenPrivileges failed, error: %d",GetLastError());
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_SUCCESS) {
        std::cout << "SeDebugPrivilege enabled successfully." << std::endl;
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","SeDebugPrivilege enabled successfully.");
        CloseHandle(hToken);
        CloseHandle(hToken);
        return true;
    } else {
        std::cerr << "SeDebugPrivilege not enabled, error: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"SeDebugPrivilege not enabled, error: %d",GetLastError());
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        CloseHandle(hToken);
        return false;
    }
}

typedef NTSTATUS (NTAPI *RtlSetProcessIsCritical_t)(BOOLEAN, BOOLEAN*, BOOLEAN);
static RtlSetProcessIsCritical_t g_pRtlSetProcessIsCritical = nullptr;

bool SetProcessCritical(bool bSet) {
    // 首次调用时加载函数指针
    char logs[128];
    if (g_pRtlSetProcessIsCritical == nullptr) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            g_pRtlSetProcessIsCritical = (RtlSetProcessIsCritical_t)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
        }
        if (g_pRtlSetProcessIsCritical == nullptr) {
            std::cerr << "[Critical] RtlSetProcessIsCritical not available." << std::endl;
            LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]","RtlSetProcessIsCritical not available.");
            return false;
        }
    }

    NTSTATUS status = g_pRtlSetProcessIsCritical(bSet ? TRUE : FALSE, NULL, FALSE);
    if (status == 0) {
        std::cout << "[Critical] Process " << (bSet ? "set" : "unset") << " as system critical." << std::endl;
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","Process set/unset as system critical");
        return true;
    } else {
        std::cerr << "[Critical] " << (bSet ? "Set" : "Unset") << " failed, status: 0x" << std::hex << status << std::endl;
        sprintf_s(logs,sizeof(logs),"Set/Unset  failed, status: 0x%x",status);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }
}

typedef LONG (NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);

bool SuspendProcess(DWORD pid) {
    char logs[64];
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed, error code: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"OpenProcess failed, error code:%d",GetLastError());
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }

    NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");

    if (pfnNtSuspendProcess == NULL) {
        std::cerr << "Failed to get NtSuspendProcess function address" << std::endl;
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]","Failed to get NtSuspendProcess function address");
        CloseHandle(hProcess);
        return false;
    }

    LONG status = pfnNtSuspendProcess(hProcess);
    CloseHandle(hProcess);

    if (status == 0) {
        std::cout << "Successfully suspended process PID: " << pid << std::endl;
        sprintf_s(logs,sizeof(logs),"Successfully suspended process PID:%d",pid );
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]",logs);
        return true;
    } else {
        std::cerr << "NtSuspendProcess failed, status: " << status << std::endl;
        sprintf_s(logs,sizeof(logs),"NtSuspendProcess failed, status: %d",status);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }
}

typedef LONG (NTAPI *NtResumeProcess)(HANDLE ProcessHandle);

bool ResumeProcessByPID_NT(DWORD dwProcessID) {
    char logs[64];
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessID);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"OpenProcess failed. Error: %d",GetLastError() );
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");

    if (pfnNtResumeProcess == NULL) {
        std::cerr << "Failed to get NtResumeProcess address." << std::endl;
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]","Failed to get NtSuspendProcess function address");
        CloseHandle(hProcess);
        return false;
    }

    LONG status = pfnNtResumeProcess(hProcess);
    CloseHandle(hProcess);

    return status == 0;
}

bool KillProcess(DWORD processId) {
    char logs[64];
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed, error code: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"OpenProcess failed. Error: %d",GetLastError() );
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        return false;
    }

    BOOL result = TerminateProcess(hProcess, 0);
    if (result == 0) {
        std::cerr << "TerminateProcess failed, error code: " << GetLastError() << std::endl;
        sprintf_s(logs,sizeof(logs),"TerminateProcess failed, error code:%d",GetLastError() );
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    return true;
}

static HKEY GetRootKey(const std::string& rootStr) {
    if (rootStr == "HKEY_LOCAL_MACHINE" || rootStr == "HKLM")
        return HKEY_LOCAL_MACHINE;
    if (rootStr == "HKEY_CURRENT_USER" || rootStr == "HKCU")
        return HKEY_CURRENT_USER;
    if (rootStr == "HKEY_CLASSES_ROOT" || rootStr == "HKCR")
        return HKEY_CLASSES_ROOT;
    if (rootStr == "HKEY_USERS" || rootStr == "HKU")
        return HKEY_USERS;
    if (rootStr == "HKEY_CURRENT_CONFIG" || rootStr == "HKCC")
        return HKEY_CURRENT_CONFIG;
    return nullptr;  // 未知根键
}

// 设置注册表值
DWORD ParseRegType(BYTE* lpType) {
    if (!lpType) return REG_NONE;
    // 先尝试作为 DWORD 读取（常见于二进制传输）
    DWORD dwType = *reinterpret_cast<DWORD*>(lpType);
    // 常见合法类型：REG_SZ(1), REG_EXPAND_SZ(2), REG_BINARY(3), REG_DWORD(4), REG_MULTI_SZ(7), REG_QWORD(11)
    if (dwType == 1 || dwType == 2 || dwType == 3 || dwType == 4 || dwType == 7 || dwType == 11) {
        return dwType;
    }
    // 否则尝试作为字符串解析（例如 "REG_SZ"）
    const char* pszType = reinterpret_cast<const char*>(lpType);
    if (_stricmp(pszType, "REG_SZ") == 0) return REG_SZ;
    if (_stricmp(pszType, "REG_EXPAND_SZ") == 0) return REG_EXPAND_SZ;
    if (_stricmp(pszType, "REG_BINARY") == 0) return REG_BINARY;
    if (_stricmp(pszType, "REG_DWORD") == 0) return REG_DWORD;
    if (_stricmp(pszType, "REG_MULTI_SZ") == 0) return REG_MULTI_SZ;
    if (_stricmp(pszType, "REG_QWORD") == 0) return REG_QWORD;
    return REG_NONE;  // 无法识别
}

static std::wstring Utf8ToWide(const char* utf8) {
    if (!utf8 || !*utf8) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &wstr[0], len);
    wstr.pop_back(); // 移除末尾的 L'\0'
    return wstr;
}

// 将宽字符串转换为 UTF‑8 窄字符串
static std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string utf8(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &utf8[0], len, nullptr, nullptr);
    utf8.pop_back(); // 移除末尾的 '\0'
    return utf8;
}

// 获取根键句柄（宽字符，不区分大小写）
static HKEY GetRootKeyW(const std::wstring& rootStr) {
    std::wstring upper = rootStr;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);
    if (upper == L"HKEY_LOCAL_MACHINE" || upper == L"HKLM")
        return HKEY_LOCAL_MACHINE;
    if (upper == L"HKEY_CURRENT_USER" || upper == L"HKCU")
        return HKEY_CURRENT_USER;
    if (upper == L"HKEY_CLASSES_ROOT" || upper == L"HKCR")
        return HKEY_CLASSES_ROOT;
    if (upper == L"HKEY_USERS" || upper == L"HKU")
        return HKEY_USERS;
    if (upper == L"HKEY_CURRENT_CONFIG" || upper == L"HKCC")
        return HKEY_CURRENT_CONFIG;
    return nullptr;
}

 //修正 SetRegistryValue 函数
LONG SetRegistryValue(
    BYTE* lpFullPath,
    BYTE* lpType,
    BYTE* lpData,
    DWORD cbData
) {
    if (!lpFullPath || !lpType || !lpData) return ERROR_INVALID_PARAMETER;

    DWORD regType = ParseRegType(lpType);
    if (regType == REG_NONE) return ERROR_INVALID_PARAMETER;

    // 转为宽字符串（UTF-8）
    std::wstring fullPath = Utf8ToWide((char*)lpFullPath);
    if (fullPath.empty()) return ERROR_INVALID_PARAMETER;

    // 去除首尾空格
    size_t start = fullPath.find_first_not_of(L" \t");
    if (start == std::wstring::npos) return ERROR_INVALID_PARAMETER;
    size_t end = fullPath.find_last_not_of(L" \t");
    fullPath = fullPath.substr(start, end - start + 1);

    // 合并连续反斜杠
    std::wstring normalized;
    for (size_t i = 0; i < fullPath.size(); ++i) {
        if (fullPath[i] == L'\\') {
            normalized += L'\\';
            while (i + 1 < fullPath.size() && fullPath[i + 1] == L'\\') i++;
        } else {
            normalized += fullPath[i];
        }
    }
    fullPath = normalized;

    // 定义已知根键（大小写不敏感）
    static const std::wstring rootKeys[] = {
        L"HKEY_LOCAL_MACHINE", L"HKLM",
        L"HKEY_CURRENT_USER", L"HKCU",
        L"HKEY_CLASSES_ROOT", L"HKCR",
        L"HKEY_USERS", L"HKU",
        L"HKEY_CURRENT_CONFIG", L"HKCC"
    };
    const int rootKeysCount = sizeof(rootKeys) / sizeof(rootKeys[0]);

    std::wstring rootStr, remaining;
    bool foundRoot = false;

    // 查找匹配的根键
    for (int i = 0; i < rootKeysCount; ++i) {
        const std::wstring& rk = rootKeys[i];
        if (_wcsnicmp(fullPath.c_str(), rk.c_str(), rk.length()) == 0) {
            rootStr = rk;  // 保留原始大小写（但后续不区分）
            remaining = fullPath.substr(rk.length());
            // 跳过可能存在的反斜杠
            if (!remaining.empty() && remaining[0] == L'\\') {
                remaining.erase(0, 1);
            }
            foundRoot = true;
            break;
        }
    }

    if (!foundRoot) {
        // 无法识别根键
        return ERROR_INVALID_PARAMETER;
    }

    // 如果剩余部分为空，则无子路径，返回错误
    if (remaining.empty()) {
        return ERROR_INVALID_PARAMETER;
    }

    // 分离子路径和值名（通过最后一个反斜杠）
    std::wstring subPath, valueName;
    size_t lastBackslash = remaining.find_last_of(L'\\');
    if (lastBackslash == std::wstring::npos) {
        // 没有反斜杠，则整个剩余部分作为子路径，值名为空（默认值）
        subPath = remaining;
        valueName = L"";
    } else {
        subPath = remaining.substr(0, lastBackslash);
        valueName = remaining.substr(lastBackslash + 1);
    }

    // 清洗子路径和值名（去除首尾空格和反斜杠）
    auto TrimPath = [](std::wstring& str) {
        size_t s = str.find_first_not_of(L" \t");
        if (s == std::wstring::npos) { str.clear(); return; }
        size_t e = str.find_last_not_of(L" \t");
        str = str.substr(s, e - s + 1);
        if (!str.empty() && str.front() == L'\\') str.erase(0, 1);
        if (!str.empty() && str.back() == L'\\') str.pop_back();
    };
    TrimPath(subPath);
    TrimPath(valueName);

    if (subPath.empty()) {
        return ERROR_INVALID_PARAMETER;
    }

    HKEY hRoot = GetRootKeyW(rootStr);
    if (!hRoot) return ERROR_INVALID_PARAMETER;

    HKEY hKey = nullptr;
    // 显式指定 64 位注册表视图
    DWORD dwAccess = KEY_SET_VALUE | KEY_QUERY_VALUE | 0x0100;

    // 尝试打开键
    LONG lResult = RegOpenKeyExW(hRoot, subPath.c_str(), 0, dwAccess, &hKey);

    // 若键不存在，则自动创建
    if (lResult == ERROR_FILE_NOT_FOUND) {
        DWORD dwDisposition;
        lResult = RegCreateKeyExW(hRoot, subPath.c_str(), 0, NULL,
                                  REG_OPTION_NON_VOLATILE, dwAccess, NULL,
                                  &hKey, &dwDisposition);
    }

    if (lResult != ERROR_SUCCESS) {
        if (hKey) RegCloseKey(hKey);
        return lResult;
    }

    // 设置值：若 valueName 为空，则传 NULL 表示默认值
    const wchar_t* lpValueName = valueName.empty() ? NULL : valueName.c_str();
    lResult = RegSetValueExW(hKey, lpValueName, 0, regType, lpData, cbData);
    RegCloseKey(hKey);
    if((int)lResult==0){LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","Set registry value successfully.");}
    else{
        char logs[64];
        sprintf_s(logs,sizeof(logs),"Failed to set registry value ,error: %x",lResult);
        LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]",logs);}
    return lResult;
}

HANDLE ConnectToPipe(const wchar_t* pipeName) {
    while (true) {
        if (WaitNamedPipe(pipeName, 1000)) {
            SetConsoleOutputCP(CP_ACP);
            SetConsoleCP(CP_ACP);
            HANDLE hPipe = CreateFile(
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
        }
        else if (err == ERROR_PIPE_BUSY) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        else {
            std::cerr << "Connecting to pipe encountered an unknown error, code: " << err << std::endl;
            return INVALID_HANDLE_VALUE;
        }
    }
}

void ServerThread_from_ControlCenter() {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    while (true) {
        HANDLE hPipe = CreateNamedPipe(
            PIPE_FROM_ControlCenter_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE_FROMCONTROLCENTER, BUFFER_SIZE_FROMCONTROLCENTER,
            0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateNamedPipe failed, error: " << GetLastError() << std::endl;
            break;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::cerr << "ConnectNamedPipe failed, error: " << GetLastError() << std::endl;
            CloseHandle(hPipe);
            continue;
        }

        std::cout << "Client connected." << std::endl;

        MessageFromControlCenter content;
        DWORD bytesRead;
        while (ReadFile(hPipe, &content, sizeof(content), &bytesRead, NULL) && bytesRead == sizeof(content)) {
            MessageFromControlCenter* pMsg = new MessageFromControlCenter(content);
            if (g_hWnds[0]) {
                PostMessage(g_hWnds[0], WM_CREATE_ALERT, 0, (LPARAM)pMsg);
            }
            else {
                delete pMsg;
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}


void ServerThread_To_EndpointLevel(const wchar_t* pipeName) {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    HANDLE hPipe = ConnectToPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Process User_UI: Always failed to connect to pipe, exiting send thread" << std::endl;
        return;
    }
    CommandToEndpointLevel message = {};
    message.command=1;// "退出"命令
    DWORD bytesWritten;
    if (!WriteFile(hPipe, &message, BUFFER_SIZE_TOEndpointLevel, &bytesWritten, NULL) || bytesWritten != BUFFER_SIZE_TOEndpointLevel) {
        std::cerr << "Process A: Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);

}

//  辅助函数 
std::wstring ToLower(const std::wstring& str) {
    std::wstring lower = str;
    for (auto& c : lower) c = std::towlower(c);
    return lower;
}

void CleanExpiredCache() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = g_decisionCache.begin(); it != g_decisionCache.end(); ) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.second).count() >= CACHE_EXPIRY_SECONDS) {
            it = g_decisionCache.erase(it);
        } else {
            ++it;
        }
    }
}

// 清理过期的弹窗缓存（类型2和4）
void CleanExpiredAlertCache() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = g_alertCache.begin(); it != g_alertCache.end(); ) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() >= CACHE_EXPIRY_SECONDS) {
            it = g_alertCache.erase(it);
        } else {
            ++it;
        }
    }
}

//  清理过期的注册表弹窗缓存（类型3） 
void CleanExpiredRegAlertCache() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = g_regAlertCache.begin(); it != g_regAlertCache.end(); ) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() >= REG_ALERT_CACHE_EXPIRY_SECONDS) {
            it = g_regAlertCache.erase(it);
        } else {
            ++it;
        }
    }
}

void ApplyDecision(int buttonId, const std::wstring& path, int pid) {
    // 对于类型2/4，信任/不信任不做操作，隔离/删除执行命令
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    switch (buttonId) {
        case IDC_BUTTON_TRUST:
        case IDC_BUTTON_UNTRUST:
            // 无操作（窗口会被销毁，进程可能仍挂起？原始行为不恢复，保持）
            break;
        case IDC_BUTTON_QUARANTINE: {
            // 使用动态路径
            std::wstring wcmd_isol = L"\"" + g_baseDir + L"\\isol.exe\"  add  \"" + g_baseDir + L"\\ISOL\"  \"" + path + L"\"  @pASs7W#Ord";
            wchar_t* cmd_isol_ = new wchar_t[wcslen(wcmd_isol.c_str()) + 1];
            lstrcpyW(cmd_isol_, wcmd_isol.c_str());
            CreateProcess(NULL, cmd_isol_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            break;
        }
        case IDC_BUTTON_DELETE: {
            std::wstring wcmd_del = L"cmd /c del /f /q /a \"" + path + L"\"";
            wchar_t* cmd_del_ = new wchar_t[wcslen(wcmd_del.c_str()) + 1];
            lstrcpyW(cmd_del_, wcmd_del.c_str());
            CreateProcess(NULL, cmd_del_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            break;
        }
        default:
            break;
    }
}

void UpdateProcessInfo(WindowData* pData) {
    if (!pData || pData->windowType != 0) return;

    FILETIME idleTime, kernelTime, userTime;
    GetSystemTimes(&idleTime, &kernelTime, &userTime);
    ULONGLONG sysKernel = ((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
    ULONGLONG sysUser   = ((ULONGLONG)userTime.dwHighDateTime   << 32) | userTime.dwLowDateTime;
    ULONGLONG sysTotal  = sysKernel + sysUser;

    ULONGLONG deltaSys = sysTotal - g_lastExtraSysTime;
    if (deltaSys == 0) deltaSys = 1;   // 避免除零
    g_lastExtraSysTime = sysTotal;

    // 重置额外进程汇总
    double extraCpuSum = 0.0;
    double extraMemSum = 0.0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return;
    }

    // 为每个目标进程名收集匹配的PID（可能有多个同名进程，仅取路径一致的第一个）
    std::vector<DWORD> foundPids[SUB_PROCESS_COUNT];
    do {
        for (int i = 0; i < SUB_PROCESS_COUNT; ++i) {
            if (_wcsicmp(pe.szExeFile, g_subProcessNames[i]) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProc) {
                    wchar_t fullPath[MAX_PATH];
                    DWORD size = MAX_PATH;
                    if (QueryFullProcessImageName(hProc, 0, fullPath, &size)) {
                        std::wstring expectedPath = g_baseDir + L"\\" + g_subProcessNames[i];
                        if (_wcsicmp(fullPath, expectedPath.c_str()) == 0) {
                            foundPids[i].push_back(pe.th32ProcessID);
                        }
                    }
                    CloseHandle(hProc);
                }
                break; // 只匹配一个进程名，继续下一个进程
            }
        }
        bool isExtra = false;
        for (int i = 0; i < EXTRA_PROCESS_COUNT; ++i) {
            if (_wcsicmp(pe.szExeFile, g_extraProcessNames[i]) == 0) {
                isExtra = true;
                break;
            }
        }
        if (isExtra) {
            DWORD pid = pe.th32ProcessID;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProc) {
                // 内存
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    extraMemSum += pmc.WorkingSetSize / (1024.0 * 1024.0);
                }

                // CPU
                FILETIME createTime, exitTime, procKernel, procUser;
                if (GetProcessTimes(hProc, &createTime, &exitTime, &procKernel, &procUser)) {
                    ULONGLONG kt = ((ULONGLONG)procKernel.dwHighDateTime << 32) | procKernel.dwLowDateTime;
                    ULONGLONG ut = ((ULONGLONG)procUser.dwHighDateTime   << 32) | procUser.dwLowDateTime;
                    auto itK = g_extraProcKernel.find(pid);
                    if (itK != g_extraProcKernel.end()) {
                        ULONGLONG prevK = itK->second;
                        ULONGLONG prevU = g_extraProcUser[pid];
                        ULONGLONG deltaProc = (kt + ut) - (prevK + prevU);
                        double cpu = (double)deltaProc / (double)deltaSys * 100.0;
                        if (cpu > 100.0) cpu = 100.0;   // 单进程限幅
                        extraCpuSum += cpu;
                    }
                    // 更新历史
                    g_extraProcKernel[pid] = kt;
                    g_extraProcUser[pid]   = ut;
                }
                CloseHandle(hProc);
            }
        }
    } while (Process32Next(hSnapshot, &pe));
    CloseHandle(hSnapshot);

    wchar_t displayExtra[256];
    swprintf_s(displayExtra, L"File system operation | PID: - | CPU: %.1f%% | Mem: %.1f MB",
               extraCpuSum, extraMemSum);
    SetWindowText(pData->hExtraStatic, displayExtra);
    // 按钮始终可用（无启动逻辑）
    EnableWindow(pData->hExtraButton, TRUE);

    // 更新每个进程的信息
    for (int i = 0; i < SUB_PROCESS_COUNT; ++i) {
        DWORD pid = 0;
        if (!foundPids[i].empty()) pid = foundPids[i][0];   // 取第一个匹配的进程

        wchar_t displayText[256];
        if (pid == 0) {
            // 进程不存在
            swprintf_s(displayText, L"%s | PID: - | CPU: - | Mem: -", g_subProcessNames[i]);
            SetWindowText(pData->procInfo[i].hStatic, displayText);
            SetWindowText(pData->procInfo[i].hButton, L"启动");
            EnableWindow(pData->procInfo[i].hButton, TRUE);
            pData->procInfo[i].pid = 0;
            pData->procInfo[i].cpuUsage = 0.0;
            pData->procInfo[i].memMB = 0.0;
            continue;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            // 打开失败，视为不存在
            swprintf_s(displayText, L"%s | PID: - | CPU: - | Mem: -", g_subProcessNames[i]);
            SetWindowText(pData->procInfo[i].hStatic, displayText);
            SetWindowText(pData->procInfo[i].hButton, L"启动");
            EnableWindow(pData->procInfo[i].hButton, TRUE);
            pData->procInfo[i].pid = 0;
            pData->procInfo[i].cpuUsage = 0.0;
            pData->procInfo[i].memMB = 0.0;
            continue;
        }

        // 获取内存（工作集）
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            pData->procInfo[i].memMB = pmc.WorkingSetSize / (1024.0 * 1024.0);
        } else {
            pData->procInfo[i].memMB = 0.0;
        }

        // 获取进程CPU时间
        FILETIME createTime, exitTime, procKernel, procUser;
        if (GetProcessTimes(hProcess, &createTime, &exitTime, &procKernel, &procUser)) {
            ULONGLONG kt = ((ULONGLONG)procKernel.dwHighDateTime << 32) | procKernel.dwLowDateTime;
            ULONGLONG ut = ((ULONGLONG)procUser.dwHighDateTime   << 32) | procUser.dwLowDateTime;
            ULONGLONG procTotal = kt + ut;

            if (pData->procInfo[i].lastSysTime != 0) {
                ULONGLONG deltaSys = sysTotal - pData->procInfo[i].lastSysTime;
                ULONGLONG deltaProc = procTotal - (pData->procInfo[i].lastKernelTime + pData->procInfo[i].lastUserTime);
                if (deltaSys > 0) {
                    double cpu = (double)deltaProc / (double)deltaSys * 100.0;
                    pData->procInfo[i].cpuUsage = (cpu > 100.0) ? 100.0 : cpu;
                } else {
                    pData->procInfo[i].cpuUsage = 0.0;
                }
            } else {
                pData->procInfo[i].cpuUsage = 0.0;
            }
            // 保存本次时间，用于下次计算
            pData->procInfo[i].lastKernelTime = kt;
            pData->procInfo[i].lastUserTime   = ut;
            pData->procInfo[i].lastSysTime    = sysTotal;
        } else {
            pData->procInfo[i].cpuUsage = 0.0;
        }

        CloseHandle(hProcess);

        // 更新显示文本
        swprintf_s(displayText, L"%s | PID: %lu | CPU: %.1f%% | Mem: %.1f MB",
                   g_subProcessNames[i], pid,
                   pData->procInfo[i].cpuUsage,
                   pData->procInfo[i].memMB);
        SetWindowText(pData->procInfo[i].hStatic, displayText);
        SetWindowText(pData->procInfo[i].hButton, L"退出");
        EnableWindow(pData->procInfo[i].hButton, TRUE);
        pData->procInfo[i].pid = pid;
    }
}

//  服务/任务操作实现 
bool DisableService(const std::wstring& serviceName) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }
    // 设置启动类型为禁用
    BOOL ok = ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                                  SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (ok) {
        // 尝试停止服务
        SERVICE_STATUS status;
        ControlService(hService, SERVICE_CONTROL_STOP, &status);
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    if(ok != 0){LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","Disable service successfully.");}
    else{LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]","Failed to disable service");}
    return ok != 0;
}

bool DeleteServiceByName(const std::wstring& serviceName) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), DELETE);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }
    BOOL ok = DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    if(ok != 0){LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","Delete service successfully.");}
    else{LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]","Failed to delete service");}
    return ok != 0;
}

// 判断是否为服务（尝试打开）
bool IsService(const std::wstring& name) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hService = OpenService(hSCM, name.c_str(), SERVICE_QUERY_STATUS);
    bool exists = (hService != NULL);
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return exists;
}

// 任务操作
bool IsTask(const std::wstring& path) {
    // 构建完整任务路径（以 "\" 开头）
    std::wstring fullPath = path;
    if (!fullPath.empty() && fullPath[0] != L'\\') {
        fullPath = L"\\" + fullPath;
    }

    HRESULT hr;
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return false;
    }
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return false;
    }
    IRegisteredTask* pTask = NULL;
    hr = pRootFolder->GetTask(_bstr_t(fullPath.c_str()), &pTask);
    bool exists = SUCCEEDED(hr) && (pTask != NULL);
    if (pTask) pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
    return exists;
}

//  修改 DisableTask 
bool DisableTask(const std::wstring& taskPath) {
    std::wstring fullPath = taskPath;
    if (!fullPath.empty() && fullPath[0] != L'\\') {
        fullPath = L"\\" + fullPath;
    }

    HRESULT hr;
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return false;
    }
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return false;
    }
    IRegisteredTask* pTask = NULL;
    hr = pRootFolder->GetTask(_bstr_t(fullPath.c_str()), &pTask);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return false;
    }
    hr = pTask->put_Enabled(VARIANT_FALSE);
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
    if(SUCCEEDED(hr)){LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","Disable task successfully.");}
    else{LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]","Failed to disable task");}
    return SUCCEEDED(hr);
}

//  修改 DeleteTaskByName 
bool DeleteTaskByName(const std::wstring& taskPath) {
    std::wstring fullPath = taskPath;
    if (!fullPath.empty() && fullPath[0] != L'\\') {
        fullPath = L"\\" + fullPath;
    }

    HRESULT hr;
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return false;
    }
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return false;
    }
    hr = pRootFolder->DeleteTask(_bstr_t(fullPath.c_str()), 0);
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
    if(SUCCEEDED(hr)){LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[INFO]","[User_UI]","Delete task successfully.");}
    else{LogRecord::WriteLog(L".\\Logs\\LogFiles\\User_UI.log","[ERROR]","[User_UI]","Failed to delete task");}
    return SUCCEEDED(hr);
}

void PerformExit() {
    // 1. 向 6 个子进程发送退出命令
    for (int i = 0; i < SUB_PROCESS_COUNT; ++i) {
        std::thread(ServerThread_To_EndpointLevel, g_pipeNamesToSubProcess[i]).detach();
    }
    // 2. 向 ControlCenter 发送退出命令
    std::thread(ServerThread_To_EndpointLevel, PIPE_TO_ControlCenter_NAME).detach();

    // 3. 杀死额外进程组（文件分析工具）
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (int i = 0; i < EXTRA_PROCESS_COUNT; ++i) {
                    if (_wcsicmp(pe.szExeFile, g_extraProcessNames[i]) == 0) {
                        KillProcess(pe.th32ProcessID);
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    // 4. 销毁所有窗口（退出自身）
    for (int i = 0; i < WINDOW_COUNT; i++) {
        if (g_hWnds[i]) DestroyWindow(g_hWnds[i]);
    }
}


//  窗口过程 
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    WindowData* pData = (WindowData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    if (msg == WM_TASKBARCREATED) {
        // 仅对主窗口（类型0）进行恢复
        if (pData && pData->windowType == 0) {
            // 先移除旧图标（可能无效，但可清理残留）
            Shell_NotifyIcon(NIM_DELETE, &nid);

            // 重新填充结构（确保 hWnd 和消息ID正确）
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
            wcscpy_s(nid.szTip, L"Security Guard For Windows\n你的设备受保护");

            // 重新添加
            if (Shell_NotifyIcon(NIM_ADD, &nid)) {
                g_bTrayCreated = TRUE;
            } else {
                g_bTrayCreated = FALSE;
            }
        }
        return 0;  // 消息已处理，不再向下传递
    }

    switch (msg) {
    case WM_CREATE: {
        LPVOID param = ((LPCREATESTRUCT)lParam)->lpCreateParams;
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;

        pData = new WindowData();
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pData);
        ZeroMemory(pData, sizeof(WindowData));

        if ((INT_PTR)param == 0) {
            //  主窗口 
            // 初始化进程信息控件
            for (int i = 0; i < SUB_PROCESS_COUNT; ++i) {
                ZeroMemory(&pData->procInfo[i], sizeof(WindowData::ProcessInfo));
                pData->procInfo[i].hStatic = CreateWindow(
                    L"STATIC", L"",
                    WS_CHILD | WS_VISIBLE | SS_LEFT,
                    0, 0, 0, 0,
                    hwnd, (HMENU)(IDC_PROC_STATIC_BASE + i), hInst, nullptr
                );
                pData->procInfo[i].hButton = CreateWindow(
                    L"BUTTON", L"启动",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)(IDC_PROC_BUTTON_BASE + i), hInst, nullptr
                );
            }
            pData->hExtraStatic = CreateWindow(
                L"STATIC", L"",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_EXTRA_STATIC, hInst, nullptr
            );
            pData->hExtraButton = CreateWindow(
                L"BUTTON", L"退出",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_EXTRA_BUTTON, hInst, nullptr
            );
            pData->hAddFileButton = CreateWindow(
                L"BUTTON", L"添加文件白名单",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_BUTTON_ADD_FILE, hInst, nullptr
            );
            // 创建“添加文件夹白名单”按钮
            pData->hAddFolderButton = CreateWindow(
                L"BUTTON", L"添加文件夹白名单",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_BUTTON_ADD_FOLDER, hInst, nullptr
            );
            pData->hEditMalicious = CreateWindow(
                L"BUTTON", L"修改IP/域名黑名单",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_BUTTON_EDIT_MALICIOUS, hInst, nullptr
            );
            pData->hEditWhitelist = CreateWindow(
                L"BUTTON", L"修改IP/域名白名单",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_BUTTON_EDIT_WHITELIST, hInst, nullptr
            );
            pData->hEditTLS = CreateWindow(
                L"BUTTON", L"修改TLS 指纹库黑名单",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_BUTTON_EDIT_TLS, hInst, nullptr
            );
            pData->hRestoreIsolButton = CreateWindow(
                L"BUTTON", L"还原隔离文件",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_BUTTON_RESTORE_ISOL, hInst, nullptr
            );
            // 退出按钮（原有）
            pData->hExitButton = CreateWindow(
                L"BUTTON", L"退出",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd, (HMENU)IDC_EXIT_BUTTON, hInst, nullptr
            );
            pData->hButton0 = pData->hButton1 = pData->hButton2 = NULL;

            // 启动定时器，每秒更新进程信息
            SetTimer(hwnd, 2, 1000, NULL);
        }
        else {
            MessageFromControlCenter* pMsg = (MessageFromControlCenter*)param;
            pData->windowType = pMsg->WindowType;
            pData->pid = pMsg->PID;
            wcscpy_s(pData->path, pMsg->path);
            wcscpy_s(pData->details, pMsg->details);
            pData->score = pMsg->score;
            memcpy(pData->key, pMsg->key, sizeof(pData->key));
            memcpy(pData->oldvalue, pMsg->oldvalue, sizeof(pData->oldvalue));
            memcpy(pData->newvalue, pMsg->newvalue, sizeof(pData->newvalue));
            memcpy(pData->valuetype, pMsg->valuetype, sizeof(pData->valuetype));
            pData->oldvalue_len = pMsg->oldvalue_len;
            pData->newvalue_len = pMsg->newvalue_len;
            pData->localAddr = pMsg->localAddr;
            pData->remoteAddr = pMsg->remoteAddr;
            pData->localPort = pMsg->localPort;
            pData->remotePort = pMsg->remotePort;
            pData->protocol = pMsg->protocol;
            strcpy_s(pData->ip, sizeof(pData->ip), pMsg->ip);
            strcpy_s(pData->domain, sizeof(pData->domain), pMsg->domain);
            if (pData->windowType == 1) {
                pData->hButton0 = CreateWindow(
                    L"BUTTON", L"允许",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_ALLOW, hInst, nullptr
                );
                pData->hButton1 = CreateWindow(
                    L"BUTTON", L"限制权限",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_RESTRICT, hInst, nullptr
                );
                pData->hButton2 = CreateWindow(
                    L"BUTTON", L"阻止",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_BLOCK, hInst, nullptr
                );
                pData->hExitButton = NULL;
            }
            else if (pData->windowType == 2 || pData->windowType == 4) {
                pData->hButton0 = CreateWindow(
                    L"BUTTON", L"信任",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_TRUST, hInst, nullptr
                );
                pData->hButton1 = CreateWindow(
                    L"BUTTON", L"允许",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_UNTRUST, hInst, nullptr
                );
                pData->hButton2 = CreateWindow(
                    L"BUTTON", L"隔离",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_QUARANTINE, hInst, nullptr
                );
                pData->hExitButton = CreateWindow(
                    L"BUTTON", L"删除",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_DELETE, hInst, nullptr
                );
            }
            else if (pData->windowType == 3) {
                pData->key[sizeof(pData->key) - 1] = '\0';
                pData->oldvalue[sizeof(pData->oldvalue) - 1] = '\0';
                pData->newvalue[sizeof(pData->newvalue) - 1] = '\0';
                pData->valuetype[sizeof(pData->valuetype) - 1] = '\0';
                ZeroMemory(pData->key, sizeof(pData->key));
                strcpy_s((char*)pData->key, sizeof(pData->key), (char*)pMsg->key);
                
                // 安全复制 valuetype
                ZeroMemory(pData->valuetype, sizeof(pData->valuetype));
                strcpy_s((char*)pData->valuetype, sizeof(pData->valuetype), (char*)pMsg->valuetype);
                
                // 复制 oldvalue 和 newvalue（二进制数据，按长度复制）
                if (pMsg->oldvalue_len > 0 && pMsg->oldvalue_len <= sizeof(pData->oldvalue)) {
                    memcpy(pData->oldvalue, pMsg->oldvalue, pMsg->oldvalue_len);
                    pData->oldvalue_len = pMsg->oldvalue_len;
                }
                if (pMsg->newvalue_len > 0 && pMsg->newvalue_len <= sizeof(pData->newvalue)) {
                    memcpy(pData->newvalue, pMsg->newvalue, pMsg->newvalue_len);
                    pData->newvalue_len = pMsg->newvalue_len;
                }
                pData->hButton0 = CreateWindow(
                    L"BUTTON", L"同意",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_TRUST_, hInst, nullptr
                );
                pData->hButton1 = CreateWindow(
                    L"BUTTON", L"拒绝",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_UNTRUST_, hInst, nullptr
                );
            }
            //  WindowType=5 服务/任务 
            else if (pData->windowType == 5) {
                pData->hButton0 = CreateWindow(
                    L"BUTTON", L"同意",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_TRUST, hInst, nullptr
                );
                pData->hButton1 = CreateWindow(
                    L"BUTTON", L"禁用服务/任务",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_DISABLE, hInst, nullptr
                );
                pData->hButton2 = CreateWindow(
                    L"BUTTON", L"删除服务/任务",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_DELETE_TASK, hInst, nullptr
                );
                pData->hExitButton = NULL;
            }
            else if (pData->windowType == 6) {
                pData->hButton0 = CreateWindow(
                    L"BUTTON", L"允许连接",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BUTTON_ALLOW_CONN, hInst, nullptr
                );
                pData->hButton1 = CreateWindow(
                    L"BUTTON", L"阻止连接",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 0, 0,
                    hwnd, (HMENU)IDC_BLOCK_CONN, hInst, nullptr
                );
                pData->hButton2 = NULL;
                pData->hExitButton = NULL;
            }
        }

        HDC hdc = GetDC(NULL);
        pData->uDpi = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(NULL, hdc);

        float scale = (float)pData->uDpi / 96.0f;
        // 根据窗口类型设置尺寸和位置
        if (pData->windowType == 1 || pData->windowType == 2 || pData->windowType == 3 || pData->windowType == 5 || pData->windowType == 6) {
            // 小型窗口：200x120逻辑像素，右下角
            int width = (int)(200 * scale);
            int height = (int)(120 * scale);
            int screenW = GetSystemMetrics(SM_CXSCREEN);
            int screenH = GetSystemMetrics(SM_CYSCREEN);
            int x = screenW - width - 0;  //设置为紧贴窗口右侧，根据实际调整（部分设备实际可能超出边框）
            int y = screenH - height - 0; //设置为紧贴窗口下侧，根据实际调整（部分设备实际可能超出边框）
            SetWindowPos(hwnd, NULL, x, y, width, height, SWP_NOZORDER);
            // 设置默认操作
            switch (pData->windowType) {
                case 1: pData->defaultAction = IDC_BUTTON_BLOCK; break;
                case 2: pData->defaultAction = IDC_BUTTON_QUARANTINE; break;
                case 3: pData->defaultAction = IDC_BUTTON_UNTRUST_; break;
                case 5: pData->defaultAction = IDC_BUTTON_DISABLE; break;
                case 6: pData->defaultAction = IDC_BLOCK_CONN; break;
            }
            // 启动定时器，5秒
            pData->timerId = SetTimer(hwnd, 1, 5000, NULL);
        } else {
            // 其他窗口（主窗口和类型4）保持原尺寸，位置默认
            SetWindowPos(hwnd, NULL, 0, 0,
                (int)(BASE_WIDTH * scale),
                (int)(BASE_HEIGHT * scale),
                SWP_NOMOVE | SWP_NOZORDER);
        }

        if (pData->windowType == 0) {
            nid.cbSize = sizeof(NOTIFYICONDATA);
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
            wcscpy_s(nid.szTip, L"Security Guard For Windows\n你的设备受保护");
            int retries = 0;
            const int MAX_RETRIES = 10; // 尝试 10 次，每次间隔 3000ms
            while (retries < MAX_RETRIES) {
                if (Shell_NotifyIcon(NIM_ADD, &nid)) {
                    g_bTrayCreated = TRUE;
                    break;
                }
                retries++;
                Sleep(3000);
            }
        }
        return 0;
    }

    case WM_SIZE: {
        if (!pData) return 0;
        RECT client;
        GetClientRect(hwnd, &client);
        int cx = client.right, cy = client.bottom;

        float scale = (float)pData->uDpi / 96.0f;
        int gap = (int)(GAP * scale);
        int rowHeight = (int)(30 * scale);
        int btnWidth = (int)(60 * scale);
        int leftMargin = (int)(10 * scale);
        int rightMargin = (int)(10 * scale);

        if (pData->windowType == 0) {
        // 布局进程监控行（6行）
            for (int i = 0; i < SUB_PROCESS_COUNT; ++i) {
                int y = (int)(10 * scale) + i * (rowHeight + gap);
                int staticWidth = cx - leftMargin - btnWidth - rightMargin;
                if (staticWidth < 50) staticWidth = 50;
                if (pData->procInfo[i].hStatic) {
                    SetWindowPos(pData->procInfo[i].hStatic, NULL,
                                leftMargin, y, staticWidth, rowHeight, SWP_NOZORDER);
                }
                if (pData->procInfo[i].hButton) {
                    SetWindowPos(pData->procInfo[i].hButton, NULL,
                                cx - rightMargin - btnWidth, y, btnWidth, rowHeight, SWP_NOZORDER);
                }
            }
            int extraIndex = SUB_PROCESS_COUNT;  // 索引 6
            int yExtra = (int)(10 * scale) + extraIndex * (rowHeight + gap);
            int staticWidthExtra = cx - leftMargin - btnWidth - rightMargin;
            if (staticWidthExtra < 50) staticWidthExtra = 50;
            if (pData->hExtraStatic) {
                SetWindowPos(pData->hExtraStatic, NULL,
                            leftMargin, yExtra, staticWidthExtra, rowHeight, SWP_NOZORDER);
            }
            if (pData->hExtraButton) {
                SetWindowPos(pData->hExtraButton, NULL,
                            cx - rightMargin - btnWidth, yExtra, btnWidth, rowHeight, SWP_NOZORDER);
            }
            int btnH = (int)(BUTTON_HEIGHT * scale);
            int gap = (int)(GAP * scale);
            int bottomMargin = (int)(10 * scale);
            int totalBtnHeight = 3 * btnH + 2 * gap;   // 三行按钮
            int startY = cy - bottomMargin - totalBtnHeight;

            // 第一行：添加文件/文件夹白名单（两个按钮并排）
            int btnW3 = (cx - 3 * gap) / 3;   // 三个按钮，两个间隙
            int y1 = startY;
            if (pData->hAddFileButton) {
                SetWindowPos(pData->hAddFileButton, NULL, gap, y1, btnW3, btnH, SWP_NOZORDER);
            }
            if (pData->hAddFolderButton) {
                SetWindowPos(pData->hAddFolderButton, NULL, gap + btnW3 + gap, y1, btnW3, btnH, SWP_NOZORDER);
            }
            if (pData->hRestoreIsolButton) {
                SetWindowPos(pData->hRestoreIsolButton, NULL, gap + 2 * (btnW3 + gap), y1, btnW3, btnH, SWP_NOZORDER);
            }

            // 第二行：三个编辑按钮平均分配宽度
            int y2 = y1 + btnH + gap;
            if (pData->hEditMalicious) {
                SetWindowPos(pData->hEditMalicious, NULL, gap, y2, btnW3, btnH, SWP_NOZORDER);
            }
            if (pData->hEditWhitelist) {
                SetWindowPos(pData->hEditWhitelist, NULL, gap + btnW3 + gap, y2, btnW3, btnH, SWP_NOZORDER);
            }
            if (pData->hEditTLS) {
                SetWindowPos(pData->hEditTLS, NULL, gap + 2 * (btnW3 + gap), y2, btnW3, btnH, SWP_NOZORDER);
            }

            // 第三行：退出按钮居中
            int btnWExit = (int)(BUTTON_WIDTH * scale);
            int y3 = y2 + btnH + gap;
            int xExit = (cx - btnWExit) / 2;
            if (pData->hExitButton) {
                SetWindowPos(pData->hExitButton, NULL, xExit, y3, btnWExit, btnH, SWP_NOZORDER);
            }
            return 0;  // 主窗口布局完成
        }
        int btnCount = 0;
        if (pData->hButton0) btnCount++;
        if (pData->hButton1) btnCount++;
        if (pData->hButton2) btnCount++;
        if (pData->hExitButton) btnCount++;

        if (btnCount == 0) return 0;

        // 按钮尺寸：小型窗口自适应宽度，其他固定
        int btnW, btnH;
        if (pData->windowType == 1 || pData->windowType == 2 || pData->windowType == 3 || pData->windowType == 5 || pData->windowType == 6) {
            // 小型窗口：按钮宽度自适应，高度固定为20逻辑像素
            btnW = (cx - gap * (btnCount - 1)) / btnCount;
            if (btnW < 30) btnW = 30; // 最小宽度
            btnH = (int)(20 * scale);
        } else {
            btnW = (int)(BUTTON_WIDTH * scale);
            btnH = (int)(BUTTON_HEIGHT * scale);
        }

        int totalW = btnW * btnCount + gap * (btnCount - 1);
        int startX = (cx - totalW) / 2;
        if (startX < 0) startX = 0;

        int btnY;
        if (pData->windowType == 0) {
            btnY = (cy - btnH) / 2;
            if (btnY < 0) btnY = 0;
        } else {
            btnY = cy - btnH - gap;
            if (btnY < 0) btnY = 0;
        }

        int curX = startX;
        if (pData->hButton0) {
            SetWindowPos(pData->hButton0, NULL, curX, btnY, btnW, btnH, SWP_NOZORDER);
            curX += btnW + gap;
        }
        if (pData->hButton1) {
            SetWindowPos(pData->hButton1, NULL, curX, btnY, btnW, btnH, SWP_NOZORDER);
            curX += btnW + gap;
        }
        if (pData->hButton2) {
            SetWindowPos(pData->hButton2, NULL, curX, btnY, btnW, btnH, SWP_NOZORDER);
            curX += btnW + gap;
        }
        if (pData->hExitButton) {
            SetWindowPos(pData->hExitButton, NULL, curX, btnY, btnW, btnH, SWP_NOZORDER);
            curX += btnW + gap;
        }

        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_PAINT: {
        if (!pData) return 0;
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        if (pData->windowType != 0) {
            RECT client;
            GetClientRect(hwnd, &client);
            int cx = client.right, cy = client.bottom;

            float scale = (float)pData->uDpi / 96.0f;
            int gap = (int)(GAP * scale);
            int btnH = (int)(BUTTON_HEIGHT * scale);

            wchar_t displayText[32768 + 50];
            if (pData->windowType == 1) {
                swprintf_s(displayText, L"Details: %s\nPID: %d\nPATH: %s\nscore: %d",
                           pData->details, pData->pid, pData->path, pData->score);
            } else if (pData->windowType == 2 || pData->windowType == 4) {
                swprintf_s(displayText, L"Details: %s\nPATH: %s\nscore: %d",
                           pData->details, pData->path, pData->score);
            } else if (pData->windowType == 3) {
                swprintf_s(displayText, L"\nRegistory Key: %hs\nDetails: %s\n",
                           reinterpret_cast<const char*>(pData->key), pData->newvalue);
            }
            //  类型5显示服务/任务信息 
            else if (pData->windowType == 5) {
                swprintf_s(displayText, L"服务/任务名: %s\n详情: %s",
                           pData->path, pData->details);
            }
            else if (pData->windowType == 6) {
                swprintf_s(displayText, L"连接信息:\nIP: %hs\nDomain: %hs",
                           pData->ip, pData->domain);
            }

            RECT rcAvail = { gap, gap, cx - gap, cy - btnH - 2 * gap };
            if (rcAvail.bottom <= rcAvail.top) rcAvail.bottom = rcAvail.top + 1;

            RECT rcCalc = rcAvail;
            rcCalc.bottom = rcCalc.top;
            DrawText(hdc, displayText, -1, &rcCalc,
                     DT_CALCRECT | DT_WORDBREAK | DT_CENTER);
            int textHeight = rcCalc.bottom - rcCalc.top;
            int availHeight = rcAvail.bottom - rcAvail.top;

            int offset = (availHeight - textHeight) / 2;
            if (offset < 0) offset = 0;

            RECT rcDraw = rcAvail;
            rcDraw.top += offset;
            rcDraw.bottom = rcDraw.top + textHeight;

            DrawText(hdc, displayText, -1, &rcDraw,
                     DT_CENTER | DT_WORDBREAK);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_GETMINMAXINFO: {
        if (!pData) return 0;
        float scale = (float)pData->uDpi / 96.0f;
        MINMAXINFO* pInfo = (MINMAXINFO*)lParam;
        pInfo->ptMinTrackSize.x = (int)(400 * scale);
        pInfo->ptMinTrackSize.y = (int)(300 * scale);
        return 0;
    }

    case WM_SYSCOMMAND: {
        if (wParam == SC_CLOSE) {
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    case WM_TRAYICON: {
        if (lParam == WM_LBUTTONUP) {
            for (int i = 0; i < WINDOW_COUNT; i++) {
                if (g_hWnds[i]) ShowWindow(g_hWnds[i], SW_SHOW);
            }
            SetForegroundWindow(g_hWnds[0]);
        }
        return 0;
    }

    case WM_CREATE_ALERT: {
        MessageFromControlCenter* pMsg = (MessageFromControlCenter*)lParam;
        if (pMsg) {
            // 过滤自身
            if (pMsg->PID == g_selfPid || _wcsicmp(pMsg->path, g_selfPath) == 0) {
                delete pMsg;
                return 0;
            }

            // 白名单过滤
            bool inWhitelist = false;
            for (const auto& wpath : g_whitelist) {
                if (_wcsicmp(pMsg->path, wpath.c_str()) == 0 && (int)pMsg->WindowType != 4) {
                    inWhitelist = true;
                    break;
                }
            }
            if (inWhitelist) {
                delete pMsg;
                return 0;
            }
            // 检查是否已被用户信任（本次运行永久有效）
            std::wstring lowerPath = ToLower(pMsg->path);
            if (pMsg->WindowType != 4){
                if (g_trustedPaths.find(lowerPath) != g_trustedPaths.end()) {
                    delete pMsg;
                    return 0;  // 信任路径不再弹窗
                }
            }
            // 针对类型2和4：先检查弹窗缓存，避免重复弹窗
            if (pMsg->WindowType == 2) {
                CleanExpiredAlertCache();  // 清理过期条目
                auto alertIt = g_alertCache.find(lowerPath);
                if (alertIt != g_alertCache.end()) {
                    // 两分钟内已经弹过窗，直接忽略（不挂起，不创建窗口）
                    delete pMsg;
                    return 0;
                }
                // 未弹过，记录本次弹窗时间
                g_alertCache[lowerPath] = std::chrono::steady_clock::now();

                // 然后检查决策缓存（用户之前的选择）
                CleanExpiredCache();
                auto decisionIt = g_decisionCache.find(lowerPath);
                if (decisionIt != g_decisionCache.end()) {
                    // 命中决策缓存，直接应用之前的决策，不挂起、不弹窗
                    ApplyDecision(decisionIt->second.first, pMsg->path, pMsg->PID);
                    delete pMsg;
                    return 0;
                }
                // 未命中决策缓存，继续正常流程（挂起、自动隔离、弹窗）
            }

            //  针对类型3（注册表）的30秒缓存过滤 
            if (pMsg->WindowType == 3) {
                CleanExpiredRegAlertCache();
                // 将 key（UTF-8字符串）转为宽字符串
                std::wstring regKey = Utf8ToWide(reinterpret_cast<const char*>(pMsg->key));
                if (!regKey.empty()) {
                    std::wstring lowerKey = ToLower(regKey);
                    auto it = g_regAlertCache.find(lowerKey);
                    if (it != g_regAlertCache.end()) {
                        // 30秒内已弹过窗，直接跳过（自动同意）
                        delete pMsg;
                        return 0;
                    }
                    // 未命中，记录本次弹窗时间
                    g_regAlertCache[lowerKey] = std::chrono::steady_clock::now();
                }
                // 注意：类型3不执行挂起和自动隔离，继续走正常流程（创建窗口）
            }

            //  类型5：不挂起，不隔离 
            if (pMsg->WindowType != 5) {
                // 挂起进程（对于类型1和3，也挂起；对于类型2/4，如果未命中缓存，则挂起）
                if(pMsg->WindowType == 1){
                    int PID_ = pMsg->PID;
                    DWORD PID = static_cast<DWORD>(PID_);
                    SuspendProcess(PID);
                }
                // 自动隔离（score>=300）
                if (int(pMsg->score) >= 300 && pMsg->WindowType==2) {
                    // 使用动态路径
                    STARTUPINFO si;
                    PROCESS_INFORMATION pi;

                    ZeroMemory(&si, sizeof(si));
                    si.cb = sizeof(si);
                    ZeroMemory(&pi, sizeof(pi));
                    // 注意：此处使用pData->path？但pData尚未创建，应使用pMsg->path
                    std::wstring wcmd_isol = L"\"" + g_baseDir + L"\\isol.exe\"  add  \"" + g_baseDir + L"\\ISOL\"  \"" + (wchar_t*)(pMsg->path) + L"\"  @pASs7W#Ord";
                    wchar_t* cmd_isol_ = new wchar_t[wcslen(wcmd_isol.c_str()) + 1];
                    lstrcpyW(cmd_isol_, wcmd_isol.c_str());
                    CreateProcess(NULL, cmd_isol_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                }
            }

            // 创建告警窗口
            HWND hwndAlert = CreateAlertWindow(*pMsg);
            if (hwndAlert) ShowWindow(hwndAlert, SW_SHOW);
            delete pMsg;
        }
        return 0;
    }

    case WM_TIMER: {
        if (wParam == 1) {
            WindowData* pDataLocal = (WindowData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            if (pDataLocal && pDataLocal->timerId != 0) {
                KillTimer(hwnd, pDataLocal->timerId);
                pDataLocal->timerId = 0;
                // 模拟点击默认按钮
                PostMessage(hwnd, WM_COMMAND, MAKEWPARAM(pDataLocal->defaultAction, 0), 0);
            }
        }
        else if (wParam == 2) {   // 主窗口进程更新
            if (pData && pData->windowType == 0) {
                UpdateProcessInfo(pData);
            }
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        WindowData* pData = (WindowData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
        if (pData && pData->windowType == 0) {
            int id = GetDlgCtrlID(hCtrl);
            if ((id >= IDC_PROC_STATIC_BASE && id < IDC_PROC_STATIC_BASE + SUB_PROCESS_COUNT)||
            (id == IDC_EXTRA_STATIC)) {
                SetTextColor(hdc, RGB(0, 0, 0));              // 黑色文字
                SetBkColor(hdc, RGB(255, 255, 255));          // 白色背景
                return (LRESULT)g_hWhiteBrush;
            }
        }
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    case WM_COMMAND: {
        WindowData* pData = (WindowData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
        if (!pData) return 0;

        // 用户点击按钮，取消定时器
        if (pData->timerId != 0) {
            KillTimer(hwnd, pData->timerId);
            pData->timerId = 0;
        }

        int btnId = LOWORD(wParam);
        // 处理子进程控制按钮
        if (btnId >= IDC_PROC_BUTTON_BASE && btnId < IDC_PROC_BUTTON_BASE + SUB_PROCESS_COUNT) {
            int idx = btnId - IDC_PROC_BUTTON_BASE;
            if (idx < 0 || idx >= SUB_PROCESS_COUNT) return 0;

            if (pData->procInfo[idx].pid != 0) {
                // 进程存在 → 发送退出命令
                std::thread([idx]() {
                    ServerThread_To_EndpointLevel(g_pipeNamesToSubProcess[idx]);
                }).detach();
            } else {
                // 进程不存在 → 启动进程
                std::wstring exePath = g_baseDir + L"\\" + g_subProcessNames[idx];
                STARTUPINFO si = { sizeof(si) };
                PROCESS_INFORMATION pi;
                if (CreateProcess(exePath.c_str(), NULL, NULL, NULL, FALSE,
                                CREATE_NO_WINDOW, NULL, g_baseDir.c_str(), &si, &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    // 可在此添加启动失败的处理（如日志或提示）
                }
            }
            return 0;  // 已处理，不再向下执行
        }

        int PID_ = pData->pid;
        DWORD PID = static_cast<DWORD>(PID_);
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        // 使用动态路径构建命令
        std::wstring wcmd_sandbox = g_baseDir + L"\\SandBox.exe \"" + (wchar_t*)(pData->path) + L"\"";
        std::wstring wcmd_isol = L"\"" + g_baseDir + L"\\isol.exe\"  add  \"" + g_baseDir + L"\\ISOL\"  \"" + (wchar_t*)(pData->path) + L"\"  @pASs7W#Ord";
        std::wstring wcmd_del = (std::wstring)L"cmd /c del /f /q /a \"" + (wchar_t*)(pData->path) + (std::wstring)L"\"";
        std::wstring wcmd_del_fromzip = L"\"" + g_baseDir + L"\\delfromzip.exe\"  \"" + (wchar_t*)(pData->path) + L"\"";
        wchar_t* cmd_sandbox_ = new wchar_t[wcslen(wcmd_sandbox.c_str()) + 1];
        wchar_t* cmd_isol_ = new wchar_t[wcslen(wcmd_isol.c_str()) + 1];
        wchar_t* cmd_del_ = new wchar_t[wcslen(wcmd_del.c_str()) + 1];
        wchar_t* cmd_del_fromzip_ = new wchar_t[wcslen(wcmd_del_fromzip.c_str()) + 1];
        lstrcpyW(cmd_sandbox_, wcmd_sandbox.c_str());
        lstrcpyW(cmd_isol_, wcmd_isol.c_str());
        lstrcpyW(cmd_del_, wcmd_del.c_str());
        lstrcpyW(cmd_del_fromzip_, wcmd_del_fromzip.c_str());
        // 若为类型2/4，在用户点击时记录选择（信任/不信任/隔离/删除）
        in_addr srcIP, dstIP;
        srcIP.S_un.S_addr = pData->localAddr;
        dstIP.S_un.S_addr = pData->remoteAddr;
        u_short srcPort = pData->localPort;
        u_short dstPort = pData->remotePort;
        u_char protocol = pData->protocol;
        if (pData->windowType == 2 || pData->windowType == 4) {
            int buttonId = LOWORD(wParam);
            if (buttonId == IDC_BUTTON_TRUST || buttonId == IDC_BUTTON_UNTRUST ||
                buttonId == IDC_BUTTON_QUARANTINE || buttonId == IDC_BUTTON_DELETE) {
                CleanExpiredCache();
                std::wstring lowerPath = ToLower(pData->path);
                auto now = std::chrono::steady_clock::now();
                g_decisionCache[lowerPath] = { buttonId, now };
                // 若为信任，额外记录到永久集合
                if (buttonId == IDC_BUTTON_TRUST) {
                    g_trustedPaths.insert(lowerPath);
                }
            }
        }

        switch (LOWORD(wParam)) {
            case IDC_BUTTON_ALLOW:
                ResumeProcessByPID_NT(PID);
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_RESTRICT:
                KillProcess(PID);
                CreateProcess(NULL, cmd_sandbox_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_BLOCK:
                KillProcess(PID);
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_TRUST:
                // 信任：将路径添加到高信任白名单（持久化）
                AddToHighTrustWhiteList(pData->path);
                // 同时更新内存缓存（永久有效）
                g_trustedPaths.insert(ToLower(pData->path));
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_UNTRUST:
                // 不信任：仅关闭窗口
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_QUARANTINE:
                CreateProcess(NULL, cmd_isol_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                CreateProcess(NULL, cmd_del_fromzip_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_DELETE:
                CreateProcess(NULL, cmd_del_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                CreateProcess(NULL, cmd_del_fromzip_, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_TRUST_:
                DestroyWindow(hwnd);
                break;
            case IDC_BUTTON_UNTRUST_:
                SetRegistryValue(pData->key, pData->valuetype, pData->oldvalue, pData->oldvalue_len);
                DestroyWindow(hwnd);
                break;
            //  新增服务/任务按钮处理 
            case IDC_BUTTON_DISABLE: {
                // 判断是服务还是任务，执行禁用
                std::wstring name = pData->path;
                bool success = false;
                if (IsService(name)) {
                    success = DisableService(name);
                } else if (IsTask(name)) {
                    success = DisableTask(name);
                }
                DestroyWindow(hwnd);
                break;
            }
            case IDC_BUTTON_DELETE_TASK: {
                std::wstring name = pData->path;
                bool success = false;
                if (IsService(name)) {
                    success = DeleteServiceByName(name);
                } else if (IsTask(name)) {
                    success = DeleteTaskByName(name);
                }
                DestroyWindow(hwnd);
                break;
            }
            case IDC_BUTTON_ALLOW_CONN: {
                // 允许连接的处理逻辑
                DestroyWindow(hwnd);
                break;
            }
            case IDC_BLOCK_CONN: {
                int success_;
                success_ = AddBlockRuleFor5Tuple(srcIP, srcPort, dstIP, dstPort, protocol);
                if (success_ == 0){std::cout << "AddBlockRuleFor5Tuple successfully\n";}
                DestroyWindow(hwnd);
                break;
            }
            case IDC_BUTTON_ADD_FILE: {
                OPENFILENAME ofn = { sizeof(OPENFILENAME) };
                wchar_t szFile[32768] = { 0 };
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
                ofn.lpstrFilter = L"所有文件\0*.*\0";
                ofn.Flags = OFN_ALLOWMULTISELECT | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
                if (GetOpenFileName(&ofn)) {
                    // 解析多选文件
                    wchar_t* p = szFile;
                    std::wstring dir = p;
                    p += wcslen(p) + 1;
                    if (*p == 0) {
                        // 单选
                        AddPathToHighTrustList(dir, false);
                    } else {
                        while (*p) {
                            std::wstring fullPath = dir + L"\\" + p;
                            AddPathToHighTrustList(fullPath, false);
                            p += wcslen(p) + 1;
                        }
                    }
                }
                break;
            }
            case IDC_BUTTON_ADD_FOLDER: {
                BROWSEINFO bi = { 0 };
                bi.hwndOwner = hwnd;
                bi.lpszTitle = L"请选择要添加的文件夹";
                bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
                LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
                if (pidl) {
                    wchar_t folderPath[MAX_PATH];
                    if (SHGetPathFromIDList(pidl, folderPath)) {
                        AddPathToHighTrustList(folderPath, true);
                    }
                    CoTaskMemFree(pidl);
                }
                break;
            }
            case IDC_BUTTON_EDIT_MALICIOUS: {
                std::wstring filePath = g_baseDir + L"\\WhiteList\\malicious.txt";
                ShellExecute(NULL, L"open", L"notepad.exe", filePath.c_str(), NULL, SW_SHOW);
                break;
            }
            case IDC_BUTTON_EDIT_WHITELIST: {
                std::wstring filePath = g_baseDir + L"\\WhiteList\\whitelist.txt";
                ShellExecute(NULL, L"open", L"notepad.exe", filePath.c_str(), NULL, SW_SHOW);
                break;
            }
            case IDC_BUTTON_EDIT_TLS: {
                std::wstring filePath = g_baseDir + L"\\WhiteList\\tls_fingerprints.txt";
                ShellExecute(NULL, L"open", L"notepad.exe", filePath.c_str(), NULL, SW_SHOW);
                break;
            }
            case IDC_BUTTON_RESTORE_ISOL: {
                // 弹出文件选择对话框，默认定位到 .\ISOL
                OPENFILENAME ofn = { sizeof(OPENFILENAME) };
                wchar_t szFile[MAX_PATH] = { 0 };
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"隔离文件 (*.isol)\0*.isol\0";
                ofn.lpstrInitialDir = (g_baseDir + L"\\ISOL").c_str();  // 初始目录
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;

                if (GetOpenFileName(&ofn)) {
                    std::wstring selectedFile = szFile;
                    // 提取文件名（不含路径）
                    size_t pos = selectedFile.find_last_of(L"\\");
                    std::wstring fileName = (pos != std::wstring::npos) ? selectedFile.substr(pos + 1) : selectedFile;
                    // 去除 .isol 后缀
                    std::wstring baseName = fileName;
                    size_t dotPos = baseName.find_last_of(L'.');
                    if (dotPos != std::wstring::npos && baseName.substr(dotPos) == L".isol") {
                        baseName = baseName.substr(0, dotPos);
                    }
                    // 构造命令行
                    std::wstring cmd = L"\"" + g_baseDir + L"\\isol.exe\" extract \"" + g_baseDir + L"\\ISOL\" \"" + baseName + L"\" * @pASs7W#Ord";
                    STARTUPINFO si = { sizeof(si) };
                    PROCESS_INFORMATION pi;
                    if (CreateProcess(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }
                }
                break;
            }
            case IDC_EXTRA_BUTTON: {
                // 杀死所有额外进程
                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnapshot != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32 pe;
                    pe.dwSize = sizeof(PROCESSENTRY32);
                    if (Process32First(hSnapshot, &pe)) {
                        do {
                            for (int i = 0; i < EXTRA_PROCESS_COUNT; ++i) {
                                if (_wcsicmp(pe.szExeFile, g_extraProcessNames[i]) == 0) {
                                    KillProcess(pe.th32ProcessID);
                                    break;
                                }
                            }
                        } while (Process32Next(hSnapshot, &pe));
                    }
                    CloseHandle(hSnapshot);
                }
                break;
            }
            case IDC_EXIT_BUTTON: {
                PerformExit();
            }
        }
        delete[] cmd_sandbox_;
        delete[] cmd_isol_;
        delete[] cmd_del_;
        delete[] cmd_del_fromzip_;
        return 0;
    }

    case WM_DESTROY: {
        // 取消定时器
        if (pData && pData->timerId != 0) {
            KillTimer(hwnd, pData->timerId);
            pData->timerId = 0;
        }

        int type = -1;
        if (pData) type = pData->windowType;

        for (int i = 0; i < WINDOW_COUNT; i++) {
            if (g_hWnds[i] == hwnd) {
                g_hWnds[i] = NULL;
                break;
            }
        }

        if (type == 0) {
            if (g_bTrayCreated) {
                KillTimer(hwnd, 2);
                if (g_hWhiteBrush) {
                    DeleteObject(g_hWhiteBrush);
                    g_hWhiteBrush = NULL;
                }
                Shell_NotifyIcon(NIM_DELETE, &nid);
                g_bTrayCreated = FALSE;
            }
            PostQuitMessage(0);
        }

        if (pData) {
            delete pData;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);
        }
        return 0;
    }

    case WM_QUERYENDSESSION:
        SetProcessCritical(false);
        PerformExit();
        return TRUE;

    case WM_ENDSESSION:
        if (wParam) {
            SetProcessCritical(false);
            // 会话确实正在结束，执行清理退出
            PerformExit();
            // 确保消息循环退出
            PostQuitMessage(0);
        }
        return 0;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

//  创建告警窗口 
HWND CreateAlertWindow(const MessageFromControlCenter& data) {
    const wchar_t CLASS_NAME[] = L"SampleClass";
    HINSTANCE hInst = GetModuleHandle(NULL);
    MessageFromControlCenter* pParam = new MessageFromControlCenter(data);
    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"Security Guard Alert", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, BASE_WIDTH, BASE_HEIGHT,
        nullptr, nullptr, hInst, (LPVOID)pParam
    );
    return hwnd;
}

void AddToHighTrustWhiteList(const std::wstring& filePath) {
    if (filePath.empty()) return;

    // 构建绝对路径（宽字符）
    std::wstring jsonPathW = g_baseDir + L"\\WhiteList\\HighTrustWhiteList.json";
    // 转换为 UTF‑8 窄字符串（用于 fstream）
    std::string jsonPath = WideToUtf8(jsonPathW);

    // 读取现有 JSON
    nlohmann::json j;
    std::ifstream in(jsonPath);
    if (in.is_open()) {
        try {
            in >> j;
        } catch (...) {
            j = nlohmann::json::object();
        }
        in.close();
    } else {
        j = nlohmann::json::object();
    }

    // 确保 Files 数组存在
    if (!j.contains("Files") || !j["Files"].is_array()) {
        j["Files"] = nlohmann::json::array();
    }

    // 将文件路径转为 UTF‑8 字符串用于存储
    std::string filePathUtf8 = WideToUtf8(filePath);
    if (filePathUtf8.empty()) return;

    // 检查是否已存在（忽略大小写）
    std::string lowerPath = filePathUtf8;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    bool exists = false;
    for (auto& item : j["Files"]) {
        if (item.is_string()) {
            std::string existing = item.get<std::string>();
            std::transform(existing.begin(), existing.end(), existing.begin(), ::tolower);
            if (existing == lowerPath) {
                exists = true;
                break;
            }
        }
    }

    if (!exists) {
        j["Files"].push_back(filePathUtf8);
    }

    // 写回文件（UTF-8 without BOM）
    std::ofstream out(jsonPath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (out.is_open()) {
        std::string content = j.dump(4); // 缩进4空格
        out.write(content.c_str(), content.size());
        out.close();
    }
}

//  加载白名单 
void LoadWhitelist() {
    std::ifstream f(".\\whitelist\\whitelist.json");
    if (!f.is_open()) {
        return;
    }
    try {
        nlohmann::json j = nlohmann::json::parse(f);
        if (j.contains("whitelist") && j["whitelist"].is_array()) {
            for (auto& item : j["whitelist"]) {
                std::string path_utf8 = item.get<std::string>();
                int len = MultiByteToWideChar(CP_UTF8, 0, path_utf8.c_str(), -1, NULL, 0);
                if (len > 0) {
                    std::wstring wpath(len, L'\0');
                    MultiByteToWideChar(CP_UTF8, 0, path_utf8.c_str(), -1, &wpath[0], len);
                    wpath.pop_back();
                    g_whitelist.push_back(wpath);
                }
            }
        }
    } catch (...) {
        // 忽略异常
    }
}

//  程序入口 
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow) {
    // 获取当前可执行文件所在目录并保存到全局变量
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    std::wstring fullPath(exePath);
    size_t pos = fullPath.find_last_of(L"\\");
    if (pos != std::wstring::npos) {
        g_baseDir = fullPath.substr(0, pos);
    } else {
        g_baseDir = L"."; // 如果找不到，使用当前目录
    }

    EnableDebugPrivilege();
    SetProcessCritical(true);
    SetProcessShutdownParameters(0x100, 0);
    g_hWhiteBrush = CreateSolidBrush(RGB(255, 255, 255));
    SetProcessDPIAware();
    const int MAX_RETRIES = 10;
    const int RETRY_INTERVAL_MS = 5000;
    bool wfpInitialized = false;
    for (int attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        if (InitWFP()) {
            wfpInitialized = true;
            break;
        }
        std::cout << "[WFP] InitWFP failed, retry in " << RETRY_INTERVAL_MS/1000 
                  << " seconds... (attempt " << (attempt + 1) << "/" << MAX_RETRIES << ")" << std::endl;
        Sleep(RETRY_INTERVAL_MS);
    }
    if (!wfpInitialized) {
        std::cout << "[WFP] InitWFP failed after " << MAX_RETRIES << " attempts. WFP features will be disabled." << std::endl;
    }
    GetModuleFileName(NULL, g_selfPath, MAX_PATH);
    g_selfPid = GetCurrentProcessId();

    LoadWhitelist();

    const wchar_t CLASS_NAME[] = L"SampleClass";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    HWND hwndMain = CreateWindowEx(
        0, CLASS_NAME, L"Security Guard For Windows", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, BASE_WIDTH, BASE_HEIGHT,
        nullptr, nullptr, hInstance, (LPVOID)0
    );
    g_hWnds[0] = hwndMain;
    ShowWindow(hwndMain, nCmdShow);

    std::thread pipeThread(ServerThread_from_ControlCenter);
    pipeThread.detach();

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    SetProcessCritical(false);
    if (g_bTrayCreated) {
        Shell_NotifyIcon(NIM_DELETE, &nid);
        g_bTrayCreated = FALSE;
    }

    return 0;
}