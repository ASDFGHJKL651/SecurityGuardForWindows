/*
MemoryGuard.cpp
端点层+分析层

监控内存中的可疑行为，评估潜在风险

g++编译:
cd %g++Path%
g++.exe -fdiagnostics-color=always -g "%SourceCodePath%\MemoryGuard.cpp" -o "%ExecutablePath%\MemoryGuard.exe" -lpsapi -lntdll -luser32 -lwintrust -lcrypt32 -liphlpapi -lws2_32 -static -std=c++11 -lpthread -ltdh -mwindows

运行权限：管理员权限
*/

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <io.h>
#include <fcntl.h>
#include <wchar.h>
#include <map>
#include <ctime>
#include <cstring>
#include <set>
#include <intrin.h>
#include <regex>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <winreg.h>
#include <iphlpapi.h>
#include <cmath>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <condition_variable>
#include <evntcons.h>
#include <evntrace.h>
#include <evntprov.h>
#include <tdh.h>
#include <unordered_map>
#include <ws2tcpip.h>     
#include <set> 
#include "nlohmann/json.hpp"
#include "shutdown_handler.h"

using json = nlohmann::json;

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "tdh.lib")

//补充缺失
#ifndef SystemModuleInformation
#define SystemModuleInformation 0x0B
#endif
#ifndef SystemCallInformation
#define SystemCallInformation 0x0C
#endif
#ifndef SystemProcessInformation
#define SystemProcessInformation 0x05
#endif
#ifndef SystemCodeIntegrityInformation
#define SystemCodeIntegrityInformation 0x67
#endif
#ifndef SystemKernelDebuggerInformation
#define SystemKernelDebuggerInformation 0x23
#endif

#ifndef _MEMORY_SECTION_NAME_DEFINED_
#define _MEMORY_SECTION_NAME_DEFINED_
typedef struct _MEMORY_SECTION_NAME {
    UNICODE_STRING SectionFileName;
} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;
#endif

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#define MemorySectionName 2
#define ThreadApcState 0x12
#define ThreadApcsPending 0x10
#define ProcessCommandLineInformation 60
#define ProcessImageFileName 27

#define SessionName L"MemoryGuardETWSession"

//信号量、LRU缓存、CPU跟踪
#include <queue>
#include <list>

//LRU 缓存模板
template<typename K, typename V>
class LRUCache {
public:
    LRUCache(size_t capacity) : m_capacity(capacity) {}
    void put(const K& key, const V& value) {
        auto it = m_map.find(key);
        if (it != m_map.end()) {
            m_list.splice(m_list.begin(), m_list, it->second);
            it->second->second = value;
            return;
        }
        if (m_list.size() >= m_capacity) {
            auto last = m_list.back();
            m_map.erase(last.first);
            m_list.pop_back();
        }
        m_list.emplace_front(key, value);
        m_map[key] = m_list.begin();
    }
    bool get(const K& key, V& value) {
        auto it = m_map.find(key);
        if (it == m_map.end()) return false;
        m_list.splice(m_list.begin(), m_list, it->second);
        value = it->second->second;
        return true;
    }
    size_t size() const { return m_list.size(); }
    void clear() { m_list.clear(); m_map.clear(); }
private:
    size_t m_capacity;
    std::list<std::pair<K, V>> m_list;
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> m_map;
};

//全局缓存定义
static LRUCache<std::wstring, uint32_t> g_ModuleHashCache(5000); // (模块路径, .text哈希)
static LRUCache<DWORD, std::map<std::wstring, uint32_t>> g_PidModuleHashCache(3000); // 每个进程的模块哈希缓存，实际每个进程内使用map，但这里只存整体？
// 实现为：每个进程独立LRU缓存，但总条目受控。
static std::map<DWORD, LRUCache<std::wstring, uint32_t>> g_PidModuleHashCacheMap;
static std::mutex g_HashCacheMutex;
static std::unordered_map<DWORD, ULONGLONG> g_LastEventTime;
static std::mutex g_LastEventTimeMutex;
static std::set<std::wstring> g_WhiteListFiles;          // 精确匹配的文件路径（小写）
static std::vector<std::wstring> g_WhiteListPaths;       // 目录路径（小写，以反斜杠结尾）
static std::mutex g_WhiteListMutex;
static std::thread g_WhiteListReloadThread;
static volatile bool g_StopWhiteListReload = false;

enum TrustLevel {
    TRUST_HIGH,
    TRUST_MEDIUM,
    TRUST_LOW
};

// 信任缓存
struct TrustEntryEx {
    TrustLevel level;
    FILETIME lastWrite;
    std::wstring signer;    // CN
    std::wstring thumbprint;
    FILETIME lastVerify;    // 上次验证时间
};
static LRUCache<std::wstring, TrustEntryEx> g_TrustCacheEx(2000);
static std::mutex g_TrustCacheExMutex;

// JIT进程集合
static std::set<DWORD> g_JITProcesses;
static std::mutex g_JITMutex;
static std::chrono::steady_clock::time_point g_JITLastUpdate = std::chrono::steady_clock::now();

// 内核调试标志
static bool g_KdDebuggerEnabled = false;

// 信号量：限制同时深度扫描数
class Semaphore {
public:
    Semaphore(int count) : m_count(count) {}
    void acquire() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this](){ return m_count > 0; });
        --m_count;
    }
    void release() {
        std::unique_lock<std::mutex> lock(m_mutex);
        ++m_count;
        m_cv.notify_one();
    }
private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    int m_count;
};
static Semaphore g_DeepScanSemaphore(3); // 最多3个深度扫描

// 进程CPU使用率跟踪
struct ProcessCPUInfo {
    FILETIME createTime;
    FILETIME kernelTime;
    FILETIME userTime;
    ULONGLONG totalTime;
    std::chrono::steady_clock::time_point lastUpdate;
};

struct WorkContext {
    DWORD pid;
    FILETIME eventTime;
};
static std::map<DWORD, ProcessCPUInfo> g_ProcessCPU;
static std::mutex g_CPUMutex;

// 系统CPU负载（近似）
static std::atomic<double> g_SystemCPUUsage(0.0);

// 清理线程
static std::thread g_CleanupThread;
static volatile bool g_StopCleanup = false;

// 定时器刷新信任缓存
static std::thread g_TrustRefreshThread;
static volatile bool g_StopTrustRefresh = false;

// 活动扫描频率控制
static volatile bool g_SkipActiveScan = false;

//全局变量
static std::map<DWORD, std::pair<FILETIME, std::chrono::steady_clock::time_point>> g_LastScanInfo;
static std::mutex g_LastScanMutex;
static const int COOLDOWN_SECONDS = 15;

static HANDLE g_hExitEvent = nullptr; 

struct PendingEvent {
    DWORD pid;
    FILETIME timestamp;
};
static std::map<DWORD, PendingEvent> g_PendingEvents;
static std::mutex g_PendingMutex;
static std::thread g_BatchThread;
static volatile bool g_StopBatch = false;

static const int BATCH_INTERVAL_EMPTY_MS = 1000;   // 空时1s
static const int BATCH_INTERVAL_NORMAL_MS = 400;
static const int BATCH_INTERVAL_BUSY_MS = 50;      // 队列>50时快速
static const size_t BATCH_BUSY_THRESHOLD = 50;     // 调整

#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_MemoryGuard"
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_MemoryGuard"

struct MessagetoControlCenter_by_MemoryGuard {
    char type[256];
    int PID;
    int ParentPID;
    char path[32768];
    int score;
};
struct CommandFromUser_UI {
    int command;   // 1 = 退出
};
#define PIPE_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_MemoryGuard)

static std::thread g_ControlPipeThread;  

// ScanResult 结构体
struct ScanResult {
    bool hasRWX;
    bool hasAnonExec;
    bool hasPEAnomaly;
    bool hasModuleInc;
    bool hasThreadOutOfModule;
    bool hasCodeWrite;
    bool hasCodeTamper;
    bool hasThreadContextAbnormal;
    bool hasReflectiveInjection;
    bool hasInlineHook;
    bool hasIATHook;
    bool hasReflectiveShellcode;
    bool hasInlineHookExt;
    bool hasIATHookEx;
    bool hasProcessHollow;
    bool hasThreadContextExAbnormal;
    bool hasAPCInjection;
    bool hasCodeSignFailed;
    bool hasSuspiciousCmdLine;
    bool hasScriptEngine;
    bool hasClrInNonManaged;
    bool hasProcessDoppelganging;
    bool hasPROPagate;
    bool hasCOMHijacking;
    bool hasDebuggerFlag;
    bool hasNtGlobalFlag;
    bool hasHeapFlags;
    bool hasSandboxStrings;
    bool hasPersistenceCmd;
    bool hasLateralMovement;
    bool hasNamedPipe;
    bool hasIOC_IP;
    bool hasIOC_Domain;
    bool hasIOC_Mutex;
    bool hasInvalidSignature;
    bool hasDynamicAPI;
    bool hasIDTHook;
    bool hasGDTOverride;
    bool hasKernelCallbackHook;
    bool hasHiddenDriver;

    bool hasAMSIBypass;
    bool hasDirectSyscall;
    bool hasDLLSideLoad;
    bool hasFilelessPE;
    bool hasThreadlessInjection;
    bool hasDoppelgangV2;

    bool hasSSDTHook;
    bool hasShadowSSDTHook;
    bool hasHiddenDriverEx;
    bool hasDKOMProcess;

    bool hasPersistenceCandidate;
    bool hasLateralCandidate;

    bool hasSyscallHook;
    bool hasC2Beacon;
    bool hasSuspiciousParent;

    DWORD ppid;
    FILETIME createTime;
    std::wstring imagePath;
    std::wstring commandLine;
    double baseScore;
    double finalScore;

    // 漏报率相关标志
    bool hasMsbuildCompile;
    bool hasRegsvr32Download;
    bool hasRundll32Suspicious;

    ScanResult()
        : hasRWX(false), hasAnonExec(false), hasPEAnomaly(false),
          hasModuleInc(false), hasThreadOutOfModule(false), hasCodeWrite(false),
          hasCodeTamper(false), hasThreadContextAbnormal(false),
          hasReflectiveInjection(false), hasInlineHook(false), hasIATHook(false),
          hasReflectiveShellcode(false), hasInlineHookExt(false), hasIATHookEx(false),
          hasProcessHollow(false), hasThreadContextExAbnormal(false),
          hasAPCInjection(false), hasCodeSignFailed(false), hasSuspiciousCmdLine(false),
          hasScriptEngine(false), hasClrInNonManaged(false),
          hasProcessDoppelganging(false), hasPROPagate(false), hasCOMHijacking(false),
          hasDebuggerFlag(false), hasNtGlobalFlag(false), hasHeapFlags(false),
          hasSandboxStrings(false), hasPersistenceCmd(false), hasLateralMovement(false),
          hasNamedPipe(false),
          hasIOC_IP(false), hasIOC_Domain(false), hasIOC_Mutex(false),
          hasInvalidSignature(false), hasDynamicAPI(false),
          hasIDTHook(false), hasGDTOverride(false), hasKernelCallbackHook(false), hasHiddenDriver(false),
          hasAMSIBypass(false), hasDirectSyscall(false), hasDLLSideLoad(false),
          hasFilelessPE(false), hasThreadlessInjection(false), hasDoppelgangV2(false),
          hasSSDTHook(false), hasShadowSSDTHook(false), hasHiddenDriverEx(false), hasDKOMProcess(false),
          hasPersistenceCandidate(false), hasLateralCandidate(false),
          hasSyscallHook(false), hasC2Beacon(false), hasSuspiciousParent(false),
          hasMsbuildCompile(false), hasRegsvr32Download(false), hasRundll32Suspicious(false),
          ppid(0), baseScore(0.0), finalScore(0.0) {
        createTime.dwLowDateTime = 0;
        createTime.dwHighDateTime = 0;
        imagePath = L"";
        commandLine = L"";
    }
};

static bool VerifySignatureEx(const wchar_t* filePath, bool& isSigned, bool& isExpired, bool& isSelfSigned);

// NT 函数指针声明
typedef NTSTATUS (WINAPI *NtQueryVirtualMemoryFunc)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    DWORD MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

typedef NTSTATUS (WINAPI *NtQueryInformationProcessFunc)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (WINAPI *NtQueryInformationThreadFunc)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (WINAPI *NtSuspendThreadFunc)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (WINAPI *NtResumeThreadFunc)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (WINAPI *NtQuerySystemInformationFunc)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (WINAPI *NtSystemDebugControlFunc)(
    ULONG Command,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnLength
);

// 内核内存读取结构 
#define SYSDBG_READ_VIRTUAL_MEMORY 1

typedef struct _SYSDBG_VIRTUAL_MEMORY {
    PVOID Address;
    PVOID Buffer;
    ULONG Length;
} SYSDBG_VIRTUAL_MEMORY, *PSYSDBG_VIRTUAL_MEMORY;

//内核模块信息
typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// 全局函数指针
static NtQueryVirtualMemoryFunc pNtQueryVirtualMemory = nullptr;
static NtQueryInformationProcessFunc pNtQueryInformationProcess = nullptr;
static NtQueryInformationThreadFunc pNtQueryInformationThread = nullptr;
static NtSuspendThreadFunc pNtSuspendThread = nullptr;
static NtResumeThreadFunc pNtResumeThread = nullptr;
static NtQuerySystemInformationFunc pNtQuerySystemInformation = nullptr;
static NtSystemDebugControlFunc pNtSystemDebugControl = nullptr;

static EVENT_TRACE_PROPERTIES* g_pProp = nullptr;

//内核模块缓存
struct KernelModuleInfo {
    uint64_t Base;
    uint64_t Size;
    std::string FullPath;
    std::string Name;
};
static std::vector<KernelModuleInfo> g_KernelModules;
static bool g_HasKernelModules = false;
static uint64_t g_NtosBase = 0;
static uint64_t g_NtosSize = 0;

static bool g_HVCIEnabled = false;
static bool g_PatchGuardActive = false;

//ETW 全局变量
static TRACEHANDLE g_SessionHandle = 0;
static TRACEHANDLE g_TraceHandle = 0;
static volatile bool g_StopRequested = false;
static const GUID KERNEL_PROCESS_GUID = {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
static const GUID KERNEL_IMAGE_GUID   = {0x2CB15D1D, 0x5FC1, 0x11D2, {0xAA, 0xE4, 0x00, 0xA0, 0xC9, 0x06, 0xEA, 0xCD}};
static const GUID KERNEL_THREAD_GUID  = {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID KERNEL_NETWORK_GUID = {0x7DD42A49, 0x5329, 0x4832, {0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}};

#define NET_EVENT_TCP_CONNECT_IPV4  12
#define NET_EVENT_UDP_CONNECT_IPV4  14

static const std::set<USHORT> g_LateralPorts = {
    445,   // SMB
    3389,  // RDP
    135,   // DCOM
    5985,  // WinRM
    22,    // SSH
    23,    // Telnet
    139,   // NetBIOS
    389,   // LDAP
    636    // LDAPS
};

static bool IsPrivateIP(DWORD ip) {
    BYTE a = (ip >> 0) & 0xFF;
    BYTE b = (ip >> 8) & 0xFF;
    // 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
    if (a == 10) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 127) return true;
    return false;
}

// 线程池
static PTP_POOL g_ThreadPool = nullptr;
static int g_MaxThreads = 2;

// 全局进程树
struct ProcessInfo {
    DWORD pid;
    DWORD ppid;
    FILETIME createTime;
    std::wstring imagePath;
    std::wstring commandLine;
    std::wstring processName;
    double baseScore;
    double finalScore;
    bool hasSuspiciousCmdLine;
    bool hasPersistenceCandidate;
    bool hasLateralCandidate;

    ProcessInfo()
        : pid(0), ppid(0), baseScore(0.0), finalScore(0.0),
          hasSuspiciousCmdLine(false), hasPersistenceCandidate(false), hasLateralCandidate(false) {
        createTime.dwLowDateTime = 0;
        createTime.dwHighDateTime = 0;
    }
};

static std::map<DWORD, ProcessInfo> g_ProcessMap;
static std::mutex g_ProcessMapMutex;

//时序关联与攻击链
enum EventType {
    EVT_PROCESS_CREATE,
    EVT_IMAGE_LOAD,
    EVT_EXTERNAL_CONNECT,
    EVT_MEMORY_ANOMALY
};

struct EventNode {
    EventType type;
    FILETIME timestamp;
    std::wstring detail;
    DWORD pid;
};

static std::map<DWORD, std::vector<EventNode>> g_Timeline;
static std::mutex g_TimelineMutex;

// 轻量扫描冷却
static std::map<DWORD, FILETIME> g_LastLightScanTime;
static std::mutex g_LightScanMutex;
static const int LIGHT_SCAN_COOLDOWN_SEC = 300;

// 恶意IP列表
static std::set<std::string> g_MaliciousIPs;
static std::mutex g_MaliciousIPsMutex;

// C2 信标
static std::map<DWORD, int> g_C2BeaconMap;
static std::mutex g_C2Mutex;
static std::thread g_NetworkThread;
static std::thread g_ActiveScanThread;

static std::map<DWORD, std::set<std::string>> g_ProcessConnIPs;          // 每个进程的远程IP集合（60秒窗口）
static std::map<DWORD, std::chrono::steady_clock::time_point> g_ProcessConnResetTime;
static std::mutex g_NetConnMutex;

static std::map<DWORD, std::wstring> g_ProcessNameCache;                // 进程名缓存
static std::mutex g_ProcNameCacheMutex;

// 网络告警标记（供 CheckProcess 使用）
static std::map<DWORD, bool> g_NetC2Flag;                               // 进程有C2连接
static std::map<DWORD, bool> g_NetLateralFlag;                          // 进程有横向移动
static std::map<DWORD, bool> g_NetScanFlag;                             // 进程有扫描行为
static std::mutex g_NetAlertMutex;


//辅助函数声明
static bool ReadKernelMemory(PVOID KernelAddress, PVOID Buffer, ULONG Length);
static bool IsKernelAddressInModule(uint64_t addr);
static std::wstring GetNtosPath();
static bool RefreshKernelModules();
static uint32_t GetExportRvaFromKernelFile(const wchar_t* filePath, const char* symbolName);
static ScanResult CheckProcess(DWORD pid, const std::wstring& processName);
static void BuildProcessTree();
static void NetworkMonitorThread();
static void ActiveScanThread();
static void ApplyParentChildRules(const ProcessInfo& child, const ProcessInfo& parent, ScanResult& result);
static void CheckSyscallStubs(HANDLE hProcess, const MODULEENTRY32W& mod, ScanResult& result);
static bool IsAddressInModule(uint64_t addr, const std::vector<MODULEENTRY32W>& modules);
static bool IsTextSectionWritableEx(HANDLE hProcess, uint64_t baseAddr);
static void AttackChainDetector(ScanResult& result, DWORD pid);
static void LoadMaliciousIPs();
static bool IsMaliciousIP(const std::string& ip);
static double CalculateEntropyString(const std::string& str);
static bool DecodeBase64(const std::wstring& encoded, std::vector<BYTE>& decoded);
static bool IsSimpleCommand(const std::vector<BYTE>& decoded);
static bool IsHighTrust(const std::wstring& path, FILETIME modTime, DWORD pid, DWORD ppid);
static void UpdateTrustCache(const std::wstring& path, FILETIME modTime, TrustLevel level);
VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
static bool CheckKdDebugger();
static void UpdateJITProcesses();
static bool IsJITProcess(DWORD pid);
static bool HasBSJBSignature(HANDLE hProcess, LPCVOID addr);
static bool IsSystemDirectory(const std::wstring& path);
static void UpdateProcessCPUUsage(DWORD pid);
static double GetProcessCPUUsage(DWORD pid);
static double GetSystemCPUUsage();

bool withUi;

static void LoadWhiteList() {
    // 1. 构造 WhiteList 文件路径（可执行文件同级目录下的 WhiteList\HighTrustWhiteList.json）
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        wprintf(L"[ERROR] GetModuleFileNameW failed\n");
        return;
    }
    wchar_t* pLast = wcsrchr(exePath, L'\\');
    if (pLast) *(pLast + 1) = L'\0';
    std::wstring baseDir = exePath;
    std::wstring jsonPath = baseDir + L"WhiteList\\HighTrustWhiteList.json";

    // 2. 使用 Win32 API 打开文件
    HANDLE hFile = CreateFileW(
        jsonPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[WARN] WhiteList file not found: %ls (error %lu)\n",
                jsonPath.c_str(), GetLastError());
        return;
    }

    // 3. 获取文件大小
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        wprintf(L"[ERROR] GetFileSizeEx failed\n");
        CloseHandle(hFile);
        return;
    }
    if (fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return;
    }

    // 4. 分配缓冲区并读取整个文件
    std::string fileContent;
    fileContent.resize(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, &fileContent[0], static_cast<DWORD>(fileSize.QuadPart), &bytesRead, NULL) ||
        bytesRead != fileSize.QuadPart) {
        wprintf(L"[ERROR] ReadFile failed or incomplete\n");
        CloseHandle(hFile);
        return;
    }
    CloseHandle(hFile);

    // 5. 解析 JSON
    try {
        json j = json::parse(fileContent);

        std::set<std::wstring> newFiles;
        std::vector<std::wstring> newPaths;

        // 解析 Files 数组（UTF-8 字符串转 wstring）
        if (j.contains("Files") && j["Files"].is_array()) {
            for (auto& item : j["Files"]) {
                std::string utf8 = item.get<std::string>();
                int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
                if (len > 0) {
                    std::wstring wstr(len, L'\0');
                    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], len);
                    if (!wstr.empty() && wstr.back() == L'\0') wstr.pop_back();
                    // 转为小写并存入
                    std::transform(wstr.begin(), wstr.end(), wstr.begin(), ::towlower);
                    newFiles.insert(wstr);
                }
            }
        }

        // 解析 Paths 数组
        if (j.contains("Paths") && j["Paths"].is_array()) {
            for (auto& item : j["Paths"]) {
                std::string utf8 = item.get<std::string>();
                int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
                if (len > 0) {
                    std::wstring wstr(len, L'\0');
                    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], len);
                    if (!wstr.empty() && wstr.back() == L'\0') wstr.pop_back();
                    std::transform(wstr.begin(), wstr.end(), wstr.begin(), ::towlower);
                    // 确保目录以反斜杠结尾
                    if (!wstr.empty() && wstr.back() != L'\\')
                        wstr.push_back(L'\\');
                    newPaths.push_back(wstr);
                }
            }
        }

        // 原子更新全局白名单
        {
            std::lock_guard<std::mutex> lock(g_WhiteListMutex);
            g_WhiteListFiles.swap(newFiles);
            g_WhiteListPaths.swap(newPaths);
        }
        wprintf(L"[INFO] WhiteList loaded: %zu files, %zu paths.\n",
                g_WhiteListFiles.size(), g_WhiteListPaths.size());

    } catch (const std::exception& e) {
        wprintf(L"[ERROR] Failed to parse white list JSON: %hs\n", e.what());
    }
}

static bool IsInWhiteList(const std::wstring& path) {
    if (path.empty()) return false;

    wchar_t fullPath[MAX_PATH];
    if (GetFullPathNameW(path.c_str(), MAX_PATH, fullPath, NULL) == 0)
        return false;

    std::wstring lowerPath = fullPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    std::lock_guard<std::mutex> lock(g_WhiteListMutex);

    // 精确匹配文件
    if (g_WhiteListFiles.find(lowerPath) != g_WhiteListFiles.end())
        return true;

    // 检查是否在任一白名单目录下
    for (const auto& dir : g_WhiteListPaths) {
        if (lowerPath.compare(0, dir.size(), dir) == 0)
            return true;
    }
    return false;
}

static std::wstring GetProcessNameCached(DWORD pid) {
    std::lock_guard<std::mutex> lock(g_ProcNameCacheMutex);
    auto it = g_ProcessNameCache.find(pid);
    if (it != g_ProcessNameCache.end()) return it->second;

    std::wstring name;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
            wchar_t* p = wcsrchr(path, L'\\');
            name = p ? (p + 1) : path;
        }
        CloseHandle(hProc);
    }
    g_ProcessNameCache[pid] = name;
    return name;
}

//判断是否为系统进程（低优先级进程）
static bool IsSystemProcess(DWORD pid) {
    std::wstring name = GetProcessNameCached(pid);
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
    static const std::set<std::wstring> systemNames = {
        L"svchost.exe", L"services.exe", L"lsass.exe",
        L"winlogon.exe", L"csrss.exe", L"smss.exe",
        L"system", L"wininit.exe", L"spoolsv.exe"
    };
    return systemNames.find(name) != systemNames.end();
}

//解析网络事件（仅 IPv4）
static bool ParseNetworkEvent(PEVENT_RECORD pEvent, DWORD& pid,
                              std::string& localIP, std::string& remoteIP,
                              USHORT& localPort, USHORT& remotePort) {
    UCHAR eventId = pEvent->EventHeader.EventDescriptor.Id;
    if (eventId != NET_EVENT_TCP_CONNECT_IPV4 && eventId != NET_EVENT_UDP_CONNECT_IPV4)
        return false;

    if (pEvent->UserDataLength < 20)
        return false;   // 确保至少 PID + size + 2个IP + 2个端口

    BYTE* data = (BYTE*)pEvent->UserData;
    pid = *(DWORD*)(data);                 // PID at offset 0
    // offset 4: size (忽略)
    DWORD daddr = *(DWORD*)(data + 8);     // 远程 IP (网络字节序)
    DWORD saddr = *(DWORD*)(data + 12);    // 本地 IP
    remotePort = ntohs(*(USHORT*)(data + 16));
    localPort  = ntohs(*(USHORT*)(data + 18));

    struct in_addr in;
    in.s_addr = daddr;
    remoteIP = inet_ntoa(in);
    in.s_addr = saddr;
    localIP = inet_ntoa(in);

    return true;
}

//更新网络统计并触发告警
static void UpdateNetworkStats(DWORD pid, const std::string& remoteIP, USHORT remotePort) {
    // 1. 过滤系统进程
    if (IsSystemProcess(pid)) return;

    // 2. 检查恶意 IP（C2）
    if (IsMaliciousIP(remoteIP)) {
        std::lock_guard<std::mutex> lock(g_NetAlertMutex);
        g_NetC2Flag[pid] = true;
        // 同时记录到时间线（便于攻击链）
        {
            std::lock_guard<std::mutex> tlock(g_TimelineMutex);
            EventNode ev;
            ev.type = EVT_EXTERNAL_CONNECT;
            ev.pid = pid;
            ev.detail = L"C2: " + std::wstring(remoteIP.begin(), remoteIP.end());
            GetSystemTimeAsFileTime(&ev.timestamp);
            g_Timeline[pid].push_back(ev);
            if (g_Timeline[pid].size() > 50)
                g_Timeline[pid].erase(g_Timeline[pid].begin(), g_Timeline[pid].end() - 50);
        }
    }

    // 3. 检查横向移动（内网 + 敏感端口）
    DWORD ip = inet_addr(remoteIP.c_str());
    if (ip != INADDR_NONE && IsPrivateIP(ip)) {
        if (g_LateralPorts.find(remotePort) != g_LateralPorts.end()) {
            std::lock_guard<std::mutex> lock(g_NetAlertMutex);
            g_NetLateralFlag[pid] = true;
            // 记录时间线
            {
                std::lock_guard<std::mutex> tlock(g_TimelineMutex);
                EventNode ev;
                ev.type = EVT_EXTERNAL_CONNECT;
                ev.pid = pid;
                wchar_t buf[64];
                swprintf(buf, 64, L"Lateral: %S:%u", remoteIP.c_str(), remotePort);
                ev.detail = buf;
                GetSystemTimeAsFileTime(&ev.timestamp);
                g_Timeline[pid].push_back(ev);
                if (g_Timeline[pid].size() > 50)
                    g_Timeline[pid].erase(g_Timeline[pid].begin(), g_Timeline[pid].end() - 50);
            }
        }
    }

    // 4. 扫描/爆破检测（60秒窗口内不同IP计数）
    {
        std::lock_guard<std::mutex> lock(g_NetConnMutex);
        auto now = std::chrono::steady_clock::now();
        auto& resetTime = g_ProcessConnResetTime[pid];
        auto& ipSet = g_ProcessConnIPs[pid];

        // 如果超过60秒，重置集合
        if (resetTime.time_since_epoch().count() == 0 ||
            std::chrono::duration_cast<std::chrono::seconds>(now - resetTime).count() > 60) {
            ipSet.clear();
            resetTime = now;
        }

        ipSet.insert(remoteIP);
        if (ipSet.size() > 50) {
            std::lock_guard<std::mutex> alertLock(g_NetAlertMutex);
            g_NetScanFlag[pid] = true;
            // 记录时间线
            {
                std::lock_guard<std::mutex> tlock(g_TimelineMutex);
                EventNode ev;
                ev.type = EVT_EXTERNAL_CONNECT;
                ev.pid = pid;
                ev.detail = L"Scanning: " + std::to_wstring(ipSet.size()) + L" unique IPs in 60s";
                GetSystemTimeAsFileTime(&ev.timestamp);
                g_Timeline[pid].push_back(ev);
                if (g_Timeline[pid].size() > 50)
                    g_Timeline[pid].erase(g_Timeline[pid].begin(), g_Timeline[pid].end() - 50);
            }
        }
    }
}

//批处理线程
static void BatchProcessorThread() {
    while (!g_StopBatch && !g_StopRequested) {
        int interval = BATCH_INTERVAL_NORMAL_MS;
        {
            std::lock_guard<std::mutex> lock(g_PendingMutex);
            if (g_PendingEvents.empty()) {
                interval = BATCH_INTERVAL_EMPTY_MS;
            } else if (g_PendingEvents.size() > BATCH_BUSY_THRESHOLD) {
                interval = BATCH_INTERVAL_BUSY_MS;
            }
        }
        WaitForSingleObject(g_hExitEvent,interval);
        if (g_StopBatch || g_StopRequested) break;

        std::map<DWORD, PendingEvent> pendingCopy;
        {
            std::lock_guard<std::mutex> lock(g_PendingMutex);
            pendingCopy.swap(g_PendingEvents);
        }
        if (pendingCopy.empty()) continue;

        for (auto& kv : pendingCopy) {
            WorkContext* ctx = new WorkContext;
            ctx->pid = kv.first;
            ctx->eventTime = kv.second.timestamp;
            PTP_WORK work = CreateThreadpoolWork(WorkCallback, ctx, NULL);
            if (work) {
                SubmitThreadpoolWork(work);
            } else {
                delete ctx;
                wprintf(L"[WARN] BatchProcessor: failed to create work for PID %d\n", kv.first);
            }
        }
    }
}

DWORD GetParentProcessId(DWORD targetPid) {
    DWORD parentPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == targetPid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return parentPid;
}

std::string GetProcessPathByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return "";
    }
    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    BOOL success = QueryFullProcessImageNameA(hProcess, 0, path, &size);
    CloseHandle(hProcess);
    if (!success) {
        return "";
    }
    return path;
}

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

void ClientThread_to_ControlCenter(MessagetoControlCenter_by_MemoryGuard* msg) {
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

void ServerThread_ControlCenter() {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    while (!g_StopRequested) {
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
            wprintf(L"[ERROR] CreateNamedPipe for control failed: %lu\n", GetLastError());
            break;
        }

        // 等待客户端连接
        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }

        // 读取命令循环
        CommandFromUser_UI msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            if (msg.command == 1) {   // 退出命令
                wprintf(L"[INFO] Received exit command from control pipe.\n");
                // 设置所有退出标志
                g_StopRequested = true;
                g_StopBatch = true;
                g_StopCleanup = true;
                g_StopTrustRefresh = true;
                if(g_hExitEvent)SetEvent(g_hExitEvent);

                // 停止 ETW 会话，使 ProcessTrace 返回
                if (g_SessionHandle && g_pProp) {
                    ControlTraceW(g_SessionHandle, SessionName, g_pProp, EVENT_TRACE_CONTROL_STOP);
                }

                // 断开并关闭管道
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                break;
            }
            // 可扩展其他命令 else if (msg.command == 2) { ... }
        }

        if (hPipe != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }
}

static HANDLE SafeCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID, int retries = 3) {
    for (int i = 0; i < retries; ++i) {
        HANDLE h = CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
        if (h != INVALID_HANDLE_VALUE) return h;
        DWORD err = GetLastError();
        if (err == ERROR_PARTIAL_COPY || err == ERROR_INVALID_HANDLE) {
            Sleep(10);
        } else {
            break;
        }
    }
    return INVALID_HANDLE_VALUE;
}

void InitNTFunctions() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pNtQueryVirtualMemory = (NtQueryVirtualMemoryFunc)GetProcAddress(hNtdll, "NtQueryVirtualMemory");
        pNtQueryInformationProcess = (NtQueryInformationProcessFunc)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        pNtQueryInformationThread = (NtQueryInformationThreadFunc)GetProcAddress(hNtdll, "NtQueryInformationThread");
        pNtSuspendThread = (NtSuspendThreadFunc)GetProcAddress(hNtdll, "NtSuspendThread");
        pNtResumeThread = (NtResumeThreadFunc)GetProcAddress(hNtdll, "NtResumeThread");
        pNtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        pNtSystemDebugControl = (NtSystemDebugControlFunc)GetProcAddress(hNtdll, "NtSystemDebugControl");
    }
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success && GetLastError() == ERROR_SUCCESS;
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

static bool IsAddressInModule(uint64_t addr, const std::vector<MODULEENTRY32W>& modules) {
    for (const auto& mod : modules) {
        uint64_t base = (uint64_t)mod.modBaseAddr;
        if (addr >= base && addr < base + mod.modBaseSize)
            return true;
    }
    return false;
}

static bool IsAddressRWX(HANDLE hProcess, uint64_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    return (mbi.Protect == PAGE_EXECUTE_READWRITE);
}

//CRC32 
static uint32_t crc32_table[256];
static bool crc32_init = false;
static void InitCRC32() {
    if (crc32_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320UL : 0);
        crc32_table[i] = crc;
    }
    crc32_init = true;
}
static uint32_t CalcCRC32(const uint8_t* data, size_t len) {
    InitCRC32();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

//从内存中读取 .text 节 CRC
static bool GetTextSectionHashFromProcess(HANDLE hProcess, uint64_t baseAddr, uint32_t& hash) {
    IMAGE_DOS_HEADER dos;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddr, &dos, sizeof(dos), &bytesRead) ||
        bytesRead != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)(baseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &bytesRead) || bytesRead != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return false;
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)(baseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &bytesRead) || bytesRead < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return false;
    WORD numSections = is64 ? pNt64->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.NumberOfSections;
    DWORD sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (is64)
        sectionOffset += pNt64->FileHeader.SizeOfOptionalHeader;
    else
        sectionOffset += ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.SizeOfOptionalHeader;

    IMAGE_SECTION_HEADER section;
    for (WORD i = 0; i < numSections; i++) {
        LPCVOID secAddr = (LPCVOID)(baseAddr + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
        if (!ReadProcessMemory(hProcess, secAddr, &section, sizeof(section), &bytesRead) || bytesRead != sizeof(section))
            continue;
        if (memcmp(section.Name, ".text", 5) == 0) {
            uint64_t textStart = baseAddr + section.VirtualAddress;
            size_t textSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (textSize == 0) return false;
            std::vector<uint8_t> buffer(textSize);
            if (!ReadProcessMemory(hProcess, (LPCVOID)textStart, buffer.data(), textSize, &bytesRead) || bytesRead != textSize)
                return false;
            hash = CalcCRC32(buffer.data(), textSize);
            return true;
        }
    }
    return false;
}

//从文件中读取 .text 节 CRC
static bool GetTextSectionHashFromFile(const wchar_t* filePath, uint32_t& hash) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return false; }
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return false; }
    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return false; }
    bool success = false;
    uint8_t* pData = (uint8_t*)pMap;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((uint8_t*)pData + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            bool is64 = (pNt->OptionalHeader.Magic == 0x020B);
            DWORD sectionOffset = pDos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
            if (is64)
                sectionOffset += pNt->FileHeader.SizeOfOptionalHeader;
            else
                sectionOffset += pNt->FileHeader.SizeOfOptionalHeader;
            PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((uint8_t*)pData + sectionOffset);
            for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
                if (memcmp(pSection[i].Name, ".text", 5) == 0) {
                    size_t textSize = pSection[i].Misc.VirtualSize ? pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;
                    if (textSize > 0 && pSection[i].PointerToRawData + textSize <= fileSize) {
                        hash = CalcCRC32(pData + pSection[i].PointerToRawData, textSize);
                        success = true;
                    }
                    break;
                }
            }
        }
    }
    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return success;
}

//检查 .text 节是否可写
static bool IsTextSectionWritableEx(HANDLE hProcess, uint64_t baseAddr) {
    IMAGE_DOS_HEADER dos;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddr, &dos, sizeof(dos), &bytesRead) ||
        bytesRead != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)(baseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &bytesRead) || bytesRead != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return false;
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)(baseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &bytesRead) || bytesRead < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return false;
    WORD numSections = is64 ? pNt64->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.NumberOfSections;
    DWORD sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (is64)
        sectionOffset += pNt64->FileHeader.SizeOfOptionalHeader;
    else
        sectionOffset += ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER section;
    for (WORD i = 0; i < numSections; i++) {
        LPCVOID secAddr = (LPCVOID)(baseAddr + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
        if (!ReadProcessMemory(hProcess, secAddr, &section, sizeof(section), &bytesRead) || bytesRead != sizeof(section))
            continue;
        if (memcmp(section.Name, ".text", 5) == 0) {
            uint64_t textStart = baseAddr + section.VirtualAddress;
            size_t textSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (textSize == 0) return false;
            MEMORY_BASIC_INFORMATION mbi;
            uint64_t addr = textStart;
            uint64_t textEnd = textStart + textSize;
            while (addr < textEnd) {
                if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi))
                    break;
                DWORD protect = mbi.Protect;
                if (protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                    return true;
                addr = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
                if (addr >= textEnd) break;
            }
            return false;
        }
    }
    return false;
}

// 反射式注入检测
static bool IsExecutablePrivateMemory(HANDLE hProcess, LPCVOID addr, const std::vector<MODULEENTRY32W>& modules) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.Type != MEM_PRIVATE) return false;
    DWORD execFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & execFlags)) return false;
    for (auto& mod : modules) {
        uint64_t base = (uint64_t)mod.modBaseAddr;
        uint64_t end = base + mod.modBaseSize;
        if ((uint64_t)addr >= base && (uint64_t)addr < end) return false;
    }
    return true;
}

static bool IsMemoryContainPE(HANDLE hProcess, LPCVOID addr) {
    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, addr, &dos, sizeof(dos), &read) || read != sizeof(dos)) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    DWORD ntSig;
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)addr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, &ntSig, sizeof(ntSig), &read) || read != sizeof(ntSig)) return false;
    return (ntSig == IMAGE_NT_SIGNATURE);
}

//熵值计算与 Shellcode 精筛
static double CalculateEntropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < len; ++i) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i]) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static bool HasExecutionFlowFeatures(const uint8_t* data, size_t len) {
    bool hasShortJump = false;
    bool hasCall = false;
    bool hasPop = false;
    for (size_t i = 0; i + 1 < len; ++i) {
        if (data[i] == 0xEB) {
            hasShortJump = true;
        }
        if (data[i] == 0xE9 && i + 4 < len) {
            hasShortJump = true;
        }
        if (data[i] == 0xE8 && i + 4 < len) {
            hasCall = true;
        }
        if (data[i] == 0x5D || data[i] == 0x5F || data[i] == 0x5E) {
            hasPop = true;
        }
        if (hasShortJump && (hasCall || hasPop)) return true;
    }
    return false;
}

//反射注入
static bool CheckReflectiveShellcodeEx(HANDLE hProcess, LPCVOID addr, SIZE_T regionSize,
                                       const std::vector<MODULEENTRY32W>& modules) {
    if (regionSize < 4096) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.Type != MEM_PRIVATE) return false;
    DWORD execFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & execFlags)) return false;
    if (IsAddressInModule((uint64_t)addr, modules)) return false;

    size_t readSize = std::min(regionSize, (SIZE_T)4096);
    std::vector<uint8_t> buffer(readSize);
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, addr, buffer.data(), readSize, &read) || read != readSize)
        return false;

    double entropy = CalculateEntropy(buffer.data(), readSize);
    if (entropy < 6.5) return false;
    if (entropy > 7.8) {
        if (!HasExecutionFlowFeatures(buffer.data(), readSize)) {
            return false;
        }
    }

    if (pNtQueryVirtualMemory) {
        MEMORY_SECTION_NAME sectionName;
        SIZE_T returnLen;
        NTSTATUS status = pNtQueryVirtualMemory(hProcess, (PVOID)addr, MemorySectionName,
                                                &sectionName, sizeof(sectionName), &returnLen);
        if (status == STATUS_SUCCESS && returnLen > sizeof(UNICODE_STRING)) {
            if (sectionName.SectionFileName.Buffer && sectionName.SectionFileName.Length > 0) {
                return false;
            }
        }
        return true;
    }
    return true;
}

// 内联钩子检测 
static uint32_t GetExportRvaFromFile(const wchar_t* dllPath, const char* funcName) {
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return 0;
    }

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    uint8_t* pData = (uint8_t*)pMap;
    uint32_t rva = 0;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        if (pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) <= fileSize) {
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pDos->e_lfanew);
            if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                IMAGE_DATA_DIRECTORY exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportDir.VirtualAddress != 0 && exportDir.Size > 0 &&
                    exportDir.VirtualAddress + exportDir.Size <= fileSize) {
                    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pData + exportDir.VirtualAddress);
                    if (pExp->AddressOfNames != 0 && pExp->AddressOfNameOrdinals != 0 && pExp->AddressOfFunctions != 0 &&
                        pExp->AddressOfNames + pExp->NumberOfNames * sizeof(DWORD) <= fileSize &&
                        pExp->AddressOfNameOrdinals + pExp->NumberOfNames * sizeof(WORD) <= fileSize &&
                        pExp->AddressOfFunctions + pExp->NumberOfFunctions * sizeof(DWORD) <= fileSize) {
                        DWORD* names = (DWORD*)(pData + pExp->AddressOfNames);
                        WORD* ordinals = (WORD*)(pData + pExp->AddressOfNameOrdinals);
                        DWORD* functions = (DWORD*)(pData + pExp->AddressOfFunctions);
                        size_t funcNameLen = strlen(funcName);
                        for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
                            if (names[i] + funcNameLen + 1 <= fileSize) {
                                char* name = (char*)(pData + names[i]);
                                if (strncmp(name, funcName, funcNameLen + 1) == 0) {
                                    if (ordinals[i] < pExp->NumberOfFunctions) {
                                        rva = functions[ordinals[i]];
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return rva;
}

static bool ReadRawFileBytes(const wchar_t* filePath, uint32_t offset, uint8_t* buffer, size_t size) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    SetFilePointer(hFile, offset, NULL, FILE_BEGIN);
    DWORD read;
    bool ok = ReadFile(hFile, buffer, (DWORD)size, &read, NULL) && read == size;
    CloseHandle(hFile);
    return ok;
}

static bool CheckInlineHook(HANDLE hProcess, const wchar_t* dllPath, const char* funcName, uint64_t moduleBase) {
    uint32_t rva = GetExportRvaFromFile(dllPath, funcName);
    if (rva == 0) return false;
    uint64_t funcAddr = moduleBase + rva;
    uint8_t memBytes[16];
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, (LPCVOID)funcAddr, memBytes, sizeof(memBytes), &read) || read != sizeof(memBytes))
        return false;
    uint8_t fileBytes[16];
    if (!ReadRawFileBytes(dllPath, rva, fileBytes, sizeof(fileBytes)))
        return false;
    return memcmp(memBytes, fileBytes, sizeof(memBytes)) != 0;
}

//扩展内联钩子检测 
static bool CheckExtendedInlineHook(HANDLE hProcess, const MODULEENTRY32W& mod,
                                    const std::vector<MODULEENTRY32W>& allModules) {
    std::wstring modName = mod.szModule;
    if (modName != L"ntdll.dll" && modName != L"kernel32.dll" &&
        modName != L"kernelbase.dll" && modName != L"user32.dll")
        return false;

    uint64_t base = (uint64_t)mod.modBaseAddr;
    uint64_t size = mod.modBaseSize;

    std::vector<uint8_t> moduleData(size);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)base, moduleData.data(), size, &bytesRead) || bytesRead != size)
        return false;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleData.data();
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(moduleData.data() + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;
    bool is64 = (pNt->OptionalHeader.Magic == 0x020B);
    DWORD sectionOffset = pDos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                          (is64 ? pNt->FileHeader.SizeOfOptionalHeader : pNt->FileHeader.SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(moduleData.data() + sectionOffset);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".text", 5) == 0) {
            uint64_t textStart = base + pSection[i].VirtualAddress;
            size_t textSize = pSection[i].Misc.VirtualSize ? pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;
            if (textSize == 0) break;

            std::vector<uint8_t> textData(textSize);
            if (!ReadProcessMemory(hProcess, (LPCVOID)textStart, textData.data(), textSize, &bytesRead) || bytesRead != textSize)
                break;

            for (size_t j = 0; j < textSize - 5; j++) {
                uint8_t op = textData[j];
                uint64_t target = 0;
                bool isJump = false;
                if (op == 0xE9) {
                    int32_t offset = *(int32_t*)(textData.data() + j + 1);
                    target = textStart + j + 5 + offset;
                    isJump = true;
                } else if (op == 0xEB) {
                    int8_t offset = *(int8_t*)(textData.data() + j + 1);
                    target = textStart + j + 2 + offset;
                    isJump = true;
                } else if (j < textSize - 6 && op == 0xFF && textData[j+1] == 0x25) {
                    uint64_t ptrAddr = textStart + j + 6;
                    uint64_t ptrVal;
                    if (ReadProcessMemory(hProcess, (LPCVOID)ptrAddr, &ptrVal, sizeof(ptrVal), &bytesRead) && bytesRead == sizeof(ptrVal)) {
                        target = ptrVal;
                        isJump = true;
                    }
                }

                if (isJump) {
                    if (IsAddressInModule(target, allModules)) continue;
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQueryEx(hProcess, (LPCVOID)target, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                            return true;
                        }
                    }
                }
            }
            break;
        }
    }
    return false;
}

// AT钩子检测 
static bool IsAddressInTextSection(HANDLE hProcess, uint64_t moduleBase, uint64_t addr) {
    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)(moduleBase + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return false;
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)(moduleBase + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return false;
    WORD numSections = is64 ? pNt64->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.NumberOfSections;
    DWORD sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (is64)
        sectionOffset += pNt64->FileHeader.SizeOfOptionalHeader;
    else
        sectionOffset += ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER section;
    for (WORD i = 0; i < numSections; i++) {
        LPCVOID secAddr = (LPCVOID)(moduleBase + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
        if (!ReadProcessMemory(hProcess, secAddr, &section, sizeof(section), &read) || read != sizeof(section))
            continue;
        if (memcmp(section.Name, ".text", 5) == 0) {
            uint64_t textStart = moduleBase + section.VirtualAddress;
            size_t textSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (addr >= textStart && addr < textStart + textSize)
                return true;
        }
    }
    return false;
}

static bool CheckIATHook(HANDLE hProcess, const MODULEENTRY32W& module, const std::vector<MODULEENTRY32W>& allModules) {
    std::wstring modName = module.szModule;
    if (modName != L"memoryguard.exe" && modName != L"notepad.exe" && modName != L"explorer.exe" &&
        modName != L"ntdll.dll" && modName != L"kernel32.dll" && modName != L"kernelbase.dll")
        return false;

    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, module.modBaseAddr, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)((uintptr_t)module.modBaseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return false;
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)module.modBaseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_DATA_DIRECTORY importDir = is64 ? pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] :
                                            ((PIMAGE_NT_HEADERS32)ntBuffer)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return false;

    uint64_t importDirAddr = (uint64_t)module.modBaseAddr + importDir.VirtualAddress;
    std::vector<uint8_t> importDirData(importDir.Size);
    if (!ReadProcessMemory(hProcess, (LPCVOID)importDirAddr, importDirData.data(), importDir.Size, &read) || read != importDir.Size)
        return false;

    PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)importDirData.data();
    while (pDesc->OriginalFirstThunk || pDesc->FirstThunk) {
        uint64_t thunkAddr = (uint64_t)module.modBaseAddr + pDesc->FirstThunk;
        for (uint32_t idx = 0; ; idx++) {
            uint64_t funcAddr;
            if (!ReadProcessMemory(hProcess, (LPCVOID)(thunkAddr + idx * (is64 ? 8 : 4)), &funcAddr, is64 ? 8 : 4, &read) || read != (is64 ? 8 : 4))
                break;
            if (funcAddr == 0) break;
            bool found = false;
            for (auto& mod : allModules) {
                if (IsAddressInTextSection(hProcess, (uint64_t)mod.modBaseAddr, funcAddr)) {
                    found = true;
                    break;
                }
            }
            if (!found) return true;
        }
        pDesc++;
    }
    return false;
}

// 精确IAT钩子检测 
static bool IsModuleSigned(const wchar_t* filePath) {
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA wintrustData = {0};
    wintrustData.cbStruct = sizeof(WINTRUST_DATA);
    wintrustData.pPolicyCallbackData = NULL;
    wintrustData.pSIPClientData = NULL;
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.hWVTStateData = NULL;
    wintrustData.pwszURLReference = NULL;
    wintrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID verifyAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &verifyAction, &wintrustData);

    wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &verifyAction, &wintrustData);

    return (status == ERROR_SUCCESS);
}

static bool CheckIATHookEx(HANDLE hProcess, const MODULEENTRY32W& module,
                           const std::vector<MODULEENTRY32W>& allModules) {
    std::wstring modName = module.szModule;
    if (modName != L"memoryguard.exe" && modName != L"notepad.exe" && modName != L"explorer.exe" &&
        modName != L"ntdll.dll" && modName != L"kernel32.dll" && modName != L"kernelbase.dll")
        return false;

    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, module.modBaseAddr, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)((uintptr_t)module.modBaseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return false;
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)module.modBaseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_DATA_DIRECTORY importDir = is64 ? pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] :
                                            ((PIMAGE_NT_HEADERS32)ntBuffer)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return false;

    uint64_t importDirAddr = (uint64_t)module.modBaseAddr + importDir.VirtualAddress;
    std::vector<uint8_t> importDirData(importDir.Size);
    if (!ReadProcessMemory(hProcess, (LPCVOID)importDirAddr, importDirData.data(), importDir.Size, &read) || read != importDir.Size)
        return false;

    PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)importDirData.data();
    while (pDesc->OriginalFirstThunk || pDesc->FirstThunk) {
        if (pDesc->Name == 0) { pDesc++; continue; }
        char dllName[256];
        uint64_t nameAddr = (uint64_t)module.modBaseAddr + pDesc->Name;
        if (!ReadProcessMemory(hProcess, (LPCVOID)nameAddr, dllName, sizeof(dllName)-1, &read) || read == 0)
            { pDesc++; continue; }
        dllName[read] = '\0';
        wchar_t wDllName[256];
        MultiByteToWideChar(CP_ACP, 0, dllName, -1, wDllName, 256);
        uint64_t dllBase = 0;
        for (auto& m : allModules) {
            if (_wcsicmp(m.szModule, wDllName) == 0) {
                dllBase = (uint64_t)m.modBaseAddr;
                break;
            }
        }
        if (dllBase == 0) { pDesc++; continue; }

        std::map<std::string, uint32_t> exportMap;
        IMAGE_DOS_HEADER dllDos;
        if (!ReadProcessMemory(hProcess, (LPCVOID)dllBase, &dllDos, sizeof(dllDos), &read) || read != sizeof(dllDos) || dllDos.e_magic != IMAGE_DOS_SIGNATURE)
            { pDesc++; continue; }
        WORD dllMagic = 0;
        LPCVOID dllMagicAddr = (LPCVOID)(dllBase + dllDos.e_lfanew + 0x18);
        if (!ReadProcessMemory(hProcess, dllMagicAddr, &dllMagic, sizeof(dllMagic), &read) || read != sizeof(dllMagic))
            { pDesc++; continue; }
        bool dll64 = (dllMagic == 0x020B);
        uint8_t dllNtBuffer[sizeof(IMAGE_NT_HEADERS64)];
        LPCVOID dllNtAddr = (LPCVOID)(dllBase + dllDos.e_lfanew);
        if (!ReadProcessMemory(hProcess, dllNtAddr, dllNtBuffer, sizeof(dllNtBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
            { pDesc++; continue; }
        PIMAGE_NT_HEADERS64 pDllNt = (PIMAGE_NT_HEADERS64)dllNtBuffer;
        if (pDllNt->Signature != IMAGE_NT_SIGNATURE) { pDesc++; continue; }
        IMAGE_DATA_DIRECTORY exportDir = dll64 ? pDllNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] :
                                                 ((PIMAGE_NT_HEADERS32)dllNtBuffer)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) { pDesc++; continue; }
        std::vector<uint8_t> expData(exportDir.Size);
        if (!ReadProcessMemory(hProcess, (LPCVOID)(dllBase + exportDir.VirtualAddress), expData.data(), exportDir.Size, &read) || read != exportDir.Size)
            { pDesc++; continue; }
        PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)expData.data();
        DWORD* names = (DWORD*)(expData.data() + (pExp->AddressOfNames - exportDir.VirtualAddress));
        WORD* ordinals = (WORD*)(expData.data() + (pExp->AddressOfNameOrdinals - exportDir.VirtualAddress));
        DWORD* functions = (DWORD*)(expData.data() + (pExp->AddressOfFunctions - exportDir.VirtualAddress));
        for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
            char* name = (char*)(expData.data() + (names[i] - exportDir.VirtualAddress));
            uint32_t rva = functions[ordinals[i]];
            exportMap[name] = rva;
        }

        uint64_t thunkAddr = (uint64_t)module.modBaseAddr + pDesc->FirstThunk;
        uint64_t origThunkAddr = (uint64_t)module.modBaseAddr + pDesc->OriginalFirstThunk;
        for (uint32_t idx = 0; ; idx++) {
            uint64_t funcAddr;
            if (!ReadProcessMemory(hProcess, (LPCVOID)(thunkAddr + idx * (is64 ? 8 : 4)), &funcAddr, is64 ? 8 : 4, &read) || read != (is64 ? 8 : 4))
                break;
            if (funcAddr == 0) break;
            uint64_t origThunkVal;
            if (!ReadProcessMemory(hProcess, (LPCVOID)(origThunkAddr + idx * (is64 ? 8 : 4)), &origThunkVal, is64 ? 8 : 4, &read) || read != (is64 ? 8 : 4))
                break;
            if (origThunkVal == 0) break;
            std::string funcName;
            if (origThunkVal & IMAGE_ORDINAL_FLAG64) {
                continue;
            } else {
                uint64_t nameAddr2 = (uint64_t)module.modBaseAddr + (origThunkVal & 0xFFFFFFFF);
                char nameBuf[256];
                if (!ReadProcessMemory(hProcess, (LPCVOID)nameAddr2, nameBuf, sizeof(nameBuf)-1, &read) || read == 0)
                    continue;
                nameBuf[read] = '\0';
                char* pName = nameBuf;
                if (pName[0] == '_') pName++;
                funcName = pName;
            }
            auto it = exportMap.find(funcName);
            if (it == exportMap.end()) continue;
            uint64_t expectedAddr = dllBase + it->second;
            if (funcAddr != expectedAddr) {
                bool inOtherModule = false;
                bool isWhiteList = false;
                bool targetSigned = false;
                for (auto& m : allModules) {
                    if ((uint64_t)m.modBaseAddr == dllBase) continue;
                    if (funcAddr >= (uint64_t)m.modBaseAddr && funcAddr < (uint64_t)m.modBaseAddr + m.modBaseSize) {
                        inOtherModule = true;
                        std::wstring mName = m.szModule;
                        if (_wcsicmp(mName.c_str(), L"apphelp.dll") == 0 || _wcsicmp(mName.c_str(), L"cryptsp.dll") == 0 ||
                            _wcsicmp(mName.c_str(), L"amsi.dll") == 0) {
                            isWhiteList = true;
                        }
                        if (IsModuleSigned(m.szExePath)) {
                            targetSigned = true;
                        }
                        break;
                    }
                }
                if (inOtherModule && !isWhiteList && !targetSigned) return true;
            }
        }
        pDesc++;
    }
    return false;
}

// 进程镂空检测
static bool GetEntryPointRVAFromFile(const wchar_t* filePath, uint32_t& entryRVA) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return false; }
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return false; }
    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return false; }
    uint8_t* pData = (uint8_t*)pMap;
    bool success = false;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            entryRVA = pNt->OptionalHeader.AddressOfEntryPoint;
            success = true;
        }
    }
    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return success;
}

static bool CheckProcessHollowing(HANDLE hProcess, DWORD pid, const std::vector<MODULEENTRY32W>& modules) {
    if (modules.empty()) return false;
    uint64_t mainBase = (uint64_t)modules[0].modBaseAddr;
    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, (LPCVOID)mainBase, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)(mainBase + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)(mainBase + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;
    uint32_t entryPointRVA = is64 ? pNt->OptionalHeader.AddressOfEntryPoint :
                                    ((PIMAGE_NT_HEADERS32)ntBuffer)->OptionalHeader.AddressOfEntryPoint;
    uint64_t entryPoint = mainBase + entryPointRVA;

    if (!IsAddressInTextSection(hProcess, mainBase, entryPoint))
        return true;

    WORD numSections = is64 ? pNt->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.NumberOfSections;
    DWORD sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (is64)
        sectionOffset += pNt->FileHeader.SizeOfOptionalHeader;
    else
        sectionOffset += ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER section;
    for (WORD i = 0; i < numSections; i++) {
        LPCVOID secAddr = (LPCVOID)(mainBase + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
        if (!ReadProcessMemory(hProcess, secAddr, &section, sizeof(section), &read) || read != sizeof(section))
            continue;
        DWORD rvaStart = section.VirtualAddress;
        DWORD rvaEnd = rvaStart + section.Misc.VirtualSize;
        if (entryPointRVA >= rvaStart && entryPointRVA < rvaEnd) {
            DWORD chars = section.Characteristics;
            if ((chars & IMAGE_SCN_MEM_WRITE) && (chars & IMAGE_SCN_MEM_EXECUTE)) {
                return true;
            }
            break;
        }
    }

    uint32_t fileEntryRVA = 0;
    if (GetEntryPointRVAFromFile(modules[0].szExePath, fileEntryRVA)) {
        if (entryPointRVA != fileEntryRVA) {
            return true;
        }
    }

    //比较主模块磁盘.text哈希与内存.text哈希
    uint32_t diskHash = 0, memHash = 0;
    if (GetTextSectionHashFromFile(modules[0].szExePath, diskHash)) {
        if (GetTextSectionHashFromProcess(hProcess, mainBase, memHash)) {
            if (diskHash != memHash) {
                return true;
            }
        }
    }

    return false;
}

//APC注入检测
static bool CheckAPCInjection(HANDLE hProcess, DWORD pid, const std::vector<MODULEENTRY32W>& modules) {
    HANDLE hThreadSnap = SafeCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hThreadSnap, &te)) { CloseHandle(hThreadSnap); return false; }

    int apcPendingCount = 0;
    bool hasSuspiciousStart = false;
    do {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!hThread) continue;
        if (pNtQueryInformationThread) {
            ULONG apcPending = 0;
            NTSTATUS status = pNtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadApcsPending,
                                                        &apcPending, sizeof(apcPending), NULL);
            if (status == STATUS_SUCCESS && apcPending > 0) {
                apcPendingCount++;
                uint64_t startAddr = 0;
                status = pNtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddr, sizeof(startAddr), NULL);
                if (status == STATUS_SUCCESS && startAddr != 0) {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                        if (mbi.Type == MEM_IMAGE) {
                        } else if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                            hasSuspiciousStart = true;
                        }
                    }
                }
            }
        }
        CloseHandle(hThread);
    } while (Thread32Next(hThreadSnap, &te));
    CloseHandle(hThreadSnap);

    if (apcPendingCount > 3 && hasSuspiciousStart) return true;
    return false;
}

//校验和检测 
static bool CheckChecksum(HANDLE hProcess, const MODULEENTRY32W& mod) {
    std::wstring modName = mod.szModule;
    if (modName != L"ntdll.dll" && modName != L"kernel32.dll" && modName != L"kernelbase.dll")
        return false;
    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, mod.modBaseAddr, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;
    uint32_t memCheckSum = is64 ? pNt->OptionalHeader.CheckSum :
                                 ((PIMAGE_NT_HEADERS32)ntBuffer)->OptionalHeader.CheckSum;
    HANDLE hFile = CreateFileW(mod.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return false; }
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return false; }
    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return false; }
    uint8_t* pData = (uint8_t*)pMap;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
    uint32_t fileCheckSum = 0;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNtFile = (PIMAGE_NT_HEADERS)(pData + pDos->e_lfanew);
        if (pNtFile->Signature == IMAGE_NT_SIGNATURE) {
            fileCheckSum = pNtFile->OptionalHeader.CheckSum;
        }
    }
    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
    if (memCheckSum != fileCheckSum) return true;
    return false;
}

//获取进程命令行
static bool GetProcessCommandLine(HANDLE hProcess, std::wstring& cmdLine) {
    if (!pNtQueryInformationProcess) return false;
    UNICODE_STRING commandLine;
    ULONG returnLength;
    NTSTATUS status = pNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)ProcessCommandLineInformation,
                                                  &commandLine, sizeof(commandLine), &returnLength);
    if (!NT_SUCCESS(status)) {
        return false;
    }
    if (commandLine.Length == 0 || commandLine.Buffer == NULL) return false;
    size_t charCount = commandLine.Length / sizeof(WCHAR);
    cmdLine.resize(charCount + 1);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, commandLine.Buffer, &cmdLine[0], commandLine.Length, &bytesRead) || bytesRead != commandLine.Length)
        return false;
    cmdLine[charCount] = L'\0';
    return true;
}

//Base64解码辅助
static bool DecodeBase64(const std::wstring& encoded, std::vector<BYTE>& decoded) {
    int len = WideCharToMultiByte(CP_UTF8, 0, encoded.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 0) return false;
    std::vector<char> utf8(len);
    WideCharToMultiByte(CP_UTF8, 0, encoded.c_str(), -1, utf8.data(), len, NULL, NULL);
    std::string str(utf8.data());
    str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
    if (str.empty()) return false;
    DWORD size = 0;
    if (!CryptStringToBinaryA(str.c_str(), str.length(), CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
        return false;
    decoded.resize(size);
    if (!CryptStringToBinaryA(str.c_str(), str.length(), CRYPT_STRING_BASE64, decoded.data(), &size, NULL, NULL))
        return false;
    return true;
}

static bool IsSimpleCommand(const std::vector<BYTE>& decoded) {
    if (decoded.empty()) return true;
    if (decoded.size() % 2 == 0) {
        std::wstring cmd((wchar_t*)decoded.data(), decoded.size() / 2);
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towlower);
        const wchar_t* dangerous[] = { L"iex", L"invoke-expression", L"invoke-cradle", L"downloadstring", L"start-process", L"new-object" };
        for (auto d : dangerous) {
            if (cmd.find(d) != std::wstring::npos)
                return false;
        }
        if (cmd.length() < 50)
            return true;
        bool hasSimple = false;
        const wchar_t* simpleCmds[] = { L"write-output", L"get-date", L"set-location", L"echo", L"dir", L"ls" };
        for (auto s : simpleCmds) {
            if (cmd.find(s) != std::wstring::npos) {
                hasSimple = true;
                break;
            }
        }
        if (hasSimple && cmd.length() < 100)
            return true;
        return false;
    }
    std::string byteStr((char*)decoded.data(), decoded.size());
    if (byteStr.length() < 50) return true;
    std::transform(byteStr.begin(), byteStr.end(), byteStr.begin(), ::tolower);
    const char* danger[] = { "iex", "invoke-expression", "downloadstring", "start-process" };
    for (auto d : danger) {
        if (byteStr.find(d) != std::string::npos)
            return false;
    }
    return true;
}

//信任缓存管理
static void UpdateTrustCache(const std::wstring& path, FILETIME modTime, TrustLevel level) {
    std::lock_guard<std::mutex> lock(g_TrustCacheExMutex);
    TrustEntryEx entry;
    entry.level = level;
    entry.lastWrite = modTime;
    // 获取签名者信息
    bool isSigned, isExpired, isSelfSigned;
    if (VerifySignatureEx(path.c_str(), isSigned, isExpired, isSelfSigned)) {
        if (isSigned) {
            // 尝试从证书链获取CN
            HCERTSTORE hStore = NULL;
            HCRYPTMSG hMsg = NULL;
            PCCERT_CONTEXT pCert = NULL;
            if (CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.c_str(),
                CERT_QUERY_CONTENT_FLAG_ALL,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                NULL,
                NULL,
                NULL,
                &hStore,
                &hMsg,
                (const void**)&pCert)) {
                if (pCert) {
                    DWORD size = 0;
                    if (CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0) > 0) {
                        wchar_t name[256];
                        if (CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, 256) > 0) {
                            entry.signer = name;
                        }
                    }
                    // 获取指纹
                    CRYPT_HASH_BLOB hashBlob;
                    if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, NULL, &hashBlob.cbData) && hashBlob.cbData > 0) {
                        std::vector<BYTE> hash(hashBlob.cbData);
                        hashBlob.pbData = hash.data();
                        if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hashBlob.pbData, &hashBlob.cbData)) {
                            wchar_t thumbprint[64];
                            for (DWORD i=0; i<hashBlob.cbData; i++) {
                                wsprintfW(thumbprint + i*2, L"%02X", hash[i]);
                            }
                            entry.thumbprint = thumbprint;
                        }
                    }
                    CertFreeCertificateContext(pCert);
                }
                if (hStore) CertCloseStore(hStore, 0);
                if (hMsg) CryptMsgClose(hMsg);
            }
        }
    }
    entry.lastVerify = modTime; // 使用修改时间作为验证时间
    g_TrustCacheEx.put(path, entry);
}

static bool IsHighTrust(const std::wstring& path, FILETIME modTime, DWORD pid, DWORD ppid) {
    {
        std::lock_guard<std::mutex> lock(g_TrustCacheExMutex);
        TrustEntryEx entry;
        if (g_TrustCacheEx.get(path, entry)) {
            if (CompareFileTime(&entry.lastWrite, &modTime) == 0) {
                // 检查是否需要重新验证（每小时）
                FILETIME now;
                GetSystemTimeAsFileTime(&now);
                ULARGE_INTEGER ulNow, ulLast;
                ulNow.LowPart = now.dwLowDateTime;
                ulNow.HighPart = now.dwHighDateTime;
                ulLast.LowPart = entry.lastVerify.dwLowDateTime;
                ulLast.HighPart = entry.lastVerify.dwHighDateTime;
                ULONGLONG diff = (ulNow.QuadPart - ulLast.QuadPart) / 10000000; // seconds
                if (diff < 3600) {
                    return entry.level == TRUST_HIGH;
                }
            }
        }
    }

    // 重新评估
    bool isHigh = false;
    bool isSigned = false, isExpired = false, isSelfSigned = false;
    if (VerifySignatureEx(path.c_str(), isSigned, isExpired, isSelfSigned)) {
        if (isSigned && !isExpired && !isSelfSigned) {
            // 检查是否为Microsoft签名
            HCERTSTORE hStore = NULL;
            HCRYPTMSG hMsg = NULL;
            PCCERT_CONTEXT pCert = NULL;
            bool microsoft = false;
            if (CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.c_str(),
                CERT_QUERY_CONTENT_FLAG_ALL,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                NULL,
                NULL,
                NULL,
                &hStore,
                &hMsg,
                (const void**)&pCert)) {
                if (pCert) {
                    wchar_t name[256];
                    if (CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, 256) > 0) {
                        std::wstring cn = name;
                        if (cn.find(L"Microsoft") != std::wstring::npos) {
                            microsoft = true;
                        }
                    }
                    CertFreeCertificateContext(pCert);
                }
                if (hStore) CertCloseStore(hStore, 0);
                if (hMsg) CryptMsgClose(hMsg);
            }
            if (microsoft) {
                // 检查路径是否在System32
                std::wstring lowerPath = path;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                if (lowerPath.find(L"c:\\windows\\system32") != std::wstring::npos) {
                    isHigh = true;
                }
            }
        }
    }

    // 条件2: 父进程为services.exe等
    if (!isHigh && ppid != 0) {
        HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ppid);
        if (hParent) {
            wchar_t parentPath[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hParent, 0, parentPath, &size)) {
                std::wstring parentName = parentPath;
                std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::towlower);
                if (parentName.find(L"services.exe") != std::wstring::npos) {
                    std::wstring selfName = path;
                    std::transform(selfName.begin(), selfName.end(), selfName.begin(), ::towlower);
                    if (selfName.find(L"svchost.exe") != std::wstring::npos ||
                        selfName.find(L"spoolsv.exe") != std::wstring::npos ||
                        selfName.find(L"winlogon.exe") != std::wstring::npos ||
                        selfName.find(L"lsass.exe") != std::wstring::npos) {
                        isHigh = true;
                    }
                }
            }
            CloseHandle(hParent);
        }
    }

    TrustLevel level = isHigh ? TRUST_HIGH : TRUST_LOW;
    UpdateTrustCache(path, modTime, level);
    return isHigh;
}

//检查是否为系统目录
static bool IsSystemDirectory(const std::wstring& path) {
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    if (lower.find(L"\\windows\\") != std::wstring::npos ||
        lower.find(L"\\microsoft\\") != std::wstring::npos) {
        return true;
    }
    return false;
}

//检测高危命令行 
static bool HasSuspiciousCommandLineEx(const std::wstring& cmdLine, bool& hasPersistence, bool& hasLateral) {
    hasPersistence = false;
    hasLateral = false;
    if (cmdLine.empty()) return false;

    std::wstring lower = cmdLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // 检测编码命令
    std::wregex encCmdPattern(L"-[Ee]ncod(?:ed)?[Cc]ommand\\s+([A-Za-z0-9+/=]+)");
    std::wsmatch match;
    bool encFound = false;
    if (std::regex_search(cmdLine, match, encCmdPattern) && match.size() > 1) {
        std::wstring encoded = match[1].str();
        encFound = true;
        std::vector<BYTE> decoded;
        if (DecodeBase64(encoded, decoded) && !IsSimpleCommand(decoded)) {
            // 复杂编码命令，报警
            // 但若命令只含简单操作且长度短，则不报警（已在IsSimpleCommand中处理）
            // 这里若IsSimpleCommand返回true，则直接返回false
            return false;
        } else {
            // 简单命令，不报警
            return false;
        }
    }

    // 白名单：-NoProfile -ExecutionPolicy Bypass 且无编码命令
    if (lower.find(L"-noprofile") != std::wstring::npos &&
        lower.find(L"-executionpolicy bypass") != std::wstring::npos &&
        !encFound) {
        if (lower.find(L"-command") == std::wstring::npos &&
            lower.find(L"-c ") == std::wstring::npos) {
            return false;
        }
    }

    const wchar_t* suspiciousPatterns[] = {
        L"mshta", L"javascript:", L"vbscript:",
        L"regsvr32 /s /u /i:", L"wmic process call create",
        L"cscript", L"wscript"
    };
    bool foundSusp = false;
    for (auto pat : suspiciousPatterns) {
        if (lower.find(pat) != std::wstring::npos) {
            foundSusp = true;
            break;
        }
    }

    // 持久化检测，如果目标指向系统目录则清除
    if (lower.find(L"schtasks") != std::wstring::npos && lower.find(L"/create") != std::wstring::npos) {
        // 尝试提取目标路径，若在系统目录则不清除
        if (lower.find(L"\\microsoft\\windows\\") != std::wstring::npos) {
            hasPersistence = true;
        } else {
            // 不清除，默认设置
        }
        hasPersistence = true;
    }
    if (lower.find(L"sc ") != std::wstring::npos && lower.find(L"create") != std::wstring::npos) {
        if (lower.find(L"\\microsoft\\windows\\") != std::wstring::npos) {
            hasPersistence = true;
        } else {
            hasPersistence = true;
        }
    }
    if (lower.find(L"reg add") != std::wstring::npos) {
        if (lower.find(L"\\microsoft\\windows\\") != std::wstring::npos) {
            hasPersistence = true;
        } else {
            hasPersistence = true;
        }
    }

    // 横向移动
    if (lower.find(L"psexec") != std::wstring::npos ||
        lower.find(L"wmic") != std::wstring::npos || lower.find(L"/node:") != std::wstring::npos ||
        lower.find(L"net use") != std::wstring::npos) {
        hasLateral = true;
    }

    if (foundSusp || hasPersistence || hasLateral)
        return true;
    return false;
}

//内存搜索
static void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    if (needlelen == 0) return (void*)haystack;
    if (haystacklen < needlelen) return nullptr;
    const uint8_t* h = (const uint8_t*)haystack;
    const uint8_t* n = (const uint8_t*)needle;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0)
            return (void*)(h + i);
    }
    return nullptr;
}

// 检测脚本引擎特征字符串
static bool CheckScriptEngineStrings(HANDLE hProcess, const std::vector<LPCVOID>& regions) {
    const char* patterns[] = {"WScript.Shell", "ScriptControl", "JScript", "VBScript", "ActiveXObject", "CreateObject"};
    const wchar_t* wpatterns[] = {L"WScript.Shell", L"ScriptControl", L"JScript", L"VBScript", L"ActiveXObject", L"CreateObject"};

    for (auto region : regions) {
        uint8_t buffer[512];
        SIZE_T read;
        if (!ReadProcessMemory(hProcess, region, buffer, sizeof(buffer), &read) || read == 0)
            continue;
        for (auto& pat : patterns) {
            if (memmem(buffer, read, pat, strlen(pat)))
                return true;
        }
        for (auto& wpat : wpatterns) {
            const char* bytePattern = (const char*)wpat;
            size_t byteLen = wcslen(wpat) * sizeof(wchar_t);
            if (memmem(buffer, read, bytePattern, byteLen))
                return true;
        }
    }
    return false;
}

// Process Doppelgänging / Herpaderping 检测
static bool CheckProcessDoppelgangingAdvanced(HANDLE hProcess, const std::wstring& modulePath, ScanResult& result) {
    bool fileMissing = false;
    DWORD attrs = GetFileAttributesW(modulePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        fileMissing = true;
        result.hasProcessDoppelganging = true;
        return true;
    }

    HANDLE hFile = CreateFileW(modulePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fileMissing = true;
        result.hasProcessDoppelganging = true;
        return true;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (!GetFileInformationByHandle(hFile, &fileInfo)) {
        CloseHandle(hFile);
    }
    CloseHandle(hFile);

    if (!pNtQueryInformationProcess) return false;
    UNICODE_STRING imageFileName;
    ULONG returnLen;
    NTSTATUS status = pNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)ProcessImageFileName,
                                                  &imageFileName, sizeof(imageFileName), &returnLen);
    if (!NT_SUCCESS(status) || imageFileName.Length == 0) {
        result.hasProcessDoppelganging = true;
        return true;
    }
    std::vector<wchar_t> buffer(imageFileName.Length / sizeof(wchar_t) + 1);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, imageFileName.Buffer, buffer.data(), imageFileName.Length, &bytesRead) || bytesRead != imageFileName.Length) {
        result.hasProcessDoppelganging = true;
        return true;
    }
    buffer[imageFileName.Length / sizeof(wchar_t)] = L'\0';
    std::wstring kernelPath = buffer.data();

    wchar_t userPath[MAX_PATH + 1] = {0};
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, userPath, &size)) {
        result.hasProcessDoppelganging = true;
        return true;
    }

    if (_wcsicmp(userPath, kernelPath.c_str()) != 0) {
        result.hasProcessDoppelganging = true;
        if (fileInfo.nFileIndexHigh != 0 || fileInfo.nFileIndexLow != 0) {
        }
        return true;
    }

    return false;
}

//PROPagate / AtomBombing / COM劫持
struct EnumWndParam {
    HANDLE hProcess;
    const std::vector<MODULEENTRY32W>* modules;
    bool found;
};

static BOOL CALLBACK EnumWndProc(HWND hWnd, LPARAM lParam) {
    EnumWndParam* p = (EnumWndParam*)lParam;
    DWORD pid;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid == GetProcessId(p->hProcess)) {
        WNDPROC wndProc = (WNDPROC)GetWindowLongPtrW(hWnd, GWLP_WNDPROC);
        if (wndProc) {
            uint64_t addr = (uint64_t)wndProc;
            if (!IsAddressInModule(addr, *p->modules)) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(p->hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    DWORD execFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                    if (mbi.Type == MEM_PRIVATE && (mbi.Protect & execFlags)) {
                        p->found = true;
                        return FALSE;
                    }
                }
            }
        }
    }
    return TRUE;
}

static bool CheckPROPagateForProcess(HANDLE hProcess, const std::vector<MODULEENTRY32W>& modules) {
    EnumWndParam param;
    param.hProcess = hProcess;
    param.modules = &modules;
    param.found = false;
    EnumWindows(EnumWndProc, (LPARAM)&param);
    return param.found;
}

static bool CheckAtomBombing() {
    bool found = false;
    const int ATOM_BASE = 0xC000;
    const int ATOM_MAX = 0xFFFF;
    wchar_t buffer[256];

    for (int atom = ATOM_BASE; atom <= ATOM_MAX; atom++) {
        int len = GlobalGetAtomNameW((ATOM)atom, buffer, 256);
        if (len > 0) {
            if (len >= 2 && buffer[0] == L'M' && buffer[1] == L'Z') {
                wprintf(L"[!] AtomBombing: Atom 0x%04X contains MZ header\n", atom);
                found = true;
            }
            uint8_t* bytes = (uint8_t*)buffer;
            int byteLen = len * sizeof(wchar_t);
            int jmpCount = 0;
            for (int i = 0; i < byteLen - 4; i++) {
                if (bytes[i] == 0xE8 || bytes[i] == 0xE9 || bytes[i] == 0xEB) {
                    jmpCount++;
                    if (jmpCount >= 3) {
                        wprintf(L"[!] AtomBombing: Atom 0x%04X contains multiple jmp/call opcodes\n", atom);
                        found = true;
                        break;
                    }
                } else {
                    jmpCount = 0;
                }
            }
        }
    }
    return found;
}

static bool CheckCOMHijacking(const MODULEENTRY32W& mod) {
    std::wstring path = mod.szExePath;
    std::transform(path.begin(), path.end(), path.begin(), ::towlower);
    if (path.find(L"\\temp\\") != std::wstring::npos ||
        path.find(L"\\appdata\\") != std::wstring::npos ||
        path.find(L"\\roaming\\") != std::wstring::npos) {
        uint32_t rva = GetExportRvaFromFile(mod.szExePath, "DllGetClassObject");
        if (rva != 0) {
            return true;
        }
    }
    return false;
}

// 现代攻击手法检测 
static bool CheckAMSIBypass(HANDLE hProcess, ScanResult& result) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return false;
    }
    DWORD modCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < modCount; i++) {
        wchar_t modName[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) continue;
        wchar_t* pName = wcsrchr(modName, L'\\');
        if (!pName) continue;
        pName++;
        if (_wcsicmp(pName, L"amsi.dll") != 0) continue;

        uint32_t rva = GetExportRvaFromFile(modName, "AmsiScanBuffer");
        if (rva == 0) continue;
        uint64_t funcAddr = (uint64_t)hMods[i] + rva;
        uint8_t firstByte;
        SIZE_T read;
        if (!ReadProcessMemory(hProcess, (LPCVOID)funcAddr, &firstByte, 1, &read) || read != 1)
            continue;
        if (firstByte == 0xC3) {
            result.hasAMSIBypass = true;
            return true;
        }
        if (firstByte == 0xE9) {
            result.hasAMSIBypass = true;
            return true;
        }
        break;
    }

    // 检测PowerShell内存中的amsiInitFailed标志
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LPCVOID addr = si.lpMinimumApplicationAddress;
    LPCVOID maxAddr = si.lpMaximumApplicationAddress;
    const char* amsiPatterns[] = {"System.Management.Automation.AmsiUtils", "amsiInitFailed"};
    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE))) {
            uint8_t buffer[1024];
            SIZE_T read;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, sizeof(buffer), &read) && read > 0) {
                for (auto pat : amsiPatterns) {
                    if (memmem(buffer, read, pat, strlen(pat))) {
                        result.hasAMSIBypass = true;
                        return true;
                    }
                }
            }
        }
        addr = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if ((uintptr_t)addr >= (uintptr_t)maxAddr) break;
    }

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\AMSI\\Providers", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subKeyCount = 0;
        if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (subKeyCount > 0) {
                result.hasAMSIBypass = true;
            }
        }
        RegCloseKey(hKey);
    }
    return result.hasAMSIBypass;
}

static bool CheckDirectSyscall(HANDLE hProcess, const MODULEENTRY32W& mod, ScanResult& result) {
    std::wstring modName = mod.szModule;
    if (modName == L"ntdll.dll") return false;

    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, mod.modBaseAddr, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return false;
    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return false;
    WORD numSections = is64 ? pNt64->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.NumberOfSections;
    DWORD sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (is64)
        sectionOffset += pNt64->FileHeader.SizeOfOptionalHeader;
    else
        sectionOffset += ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.SizeOfOptionalHeader;

    IMAGE_SECTION_HEADER section;
    for (WORD i = 0; i < numSections; i++) {
        LPCVOID secAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
        if (!ReadProcessMemory(hProcess, secAddr, &section, sizeof(section), &read) || read != sizeof(section))
            continue;
        if (memcmp(section.Name, ".text", 5) == 0) {
            uint64_t textStart = (uint64_t)mod.modBaseAddr + section.VirtualAddress;
            size_t textSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (textSize == 0) break;
            std::vector<uint8_t> textData(textSize);
            if (!ReadProcessMemory(hProcess, (LPCVOID)textStart, textData.data(), textSize, &read) || read != textSize)
                break;

            const uint8_t syscall[] = {0x0F, 0x05};
            for (size_t j = 0; j < textSize - 1; j++) {
                if (textData[j] == syscall[0] && textData[j+1] == syscall[1]) {
                    result.hasDirectSyscall = true;
                    return true;
                }
            }
            break;
        }
    }
    return false;
}

static bool CheckDLLSideLoad(HANDLE hProcess, DWORD pid, const MODULEENTRY32W& mod, ScanResult& result) {
    wchar_t procName[MAX_PATH];
    HANDLE hProcessTmp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcessTmp) return false;
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcessTmp, 0, procName, &size)) {
        CloseHandle(hProcessTmp);
        return false;
    }
    CloseHandle(hProcessTmp);
    std::wstring pName = procName;
    std::transform(pName.begin(), pName.end(), pName.begin(), ::towlower);
    if (pName.find(L"services.exe") == std::wstring::npos &&
        pName.find(L"winlogon.exe") == std::wstring::npos &&
        pName.find(L"lsass.exe") == std::wstring::npos &&
        pName.find(L"svchost.exe") == std::wstring::npos)
        return false;

    std::wstring dllPath = mod.szExePath;
    std::transform(dllPath.begin(), dllPath.end(), dllPath.begin(), ::towlower);
    if (dllPath.find(L"c:\\windows\\system32") != std::wstring::npos)
        return false;

    WCHAR curDir[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, curDir);
    std::wstring cwd = curDir;
    std::transform(cwd.begin(), cwd.end(), cwd.begin(), ::towlower);
    if (dllPath.find(cwd) == std::wstring::npos) {
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring temp = tempPath;
        std::transform(temp.begin(), temp.end(), temp.begin(), ::towlower);
        if (dllPath.find(temp) == std::wstring::npos)
            return false;
    }

    bool isSigned, isExpired, isSelfSigned;
    if (VerifySignatureEx(mod.szExePath, isSigned, isExpired, isSelfSigned)) {
        return false;
    }
    result.hasDLLSideLoad = true;
    return true;
}

static bool CheckFilelessPE(HANDLE hProcess, LPCVOID addr, ScanResult& result) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.Type != MEM_PRIVATE) return false;

    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, addr, &dos, sizeof(dos), &read) || read != sizeof(dos))
        return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;

    // 读前256字节，熵>7.8且含shellcode指令
    uint8_t first256[256];
    if (ReadProcessMemory(hProcess, addr, first256, 256, &read) && read == 256) {
        double entropy = CalculateEntropy(first256, 256);
        if (entropy > 7.8) {
            bool hasShellcode = false;
            for (size_t i=0; i<256; i++) {
                if (first256[i] == 0xE8 || first256[i] == 0xE9 || first256[i] == 0xEB) {
                    hasShellcode = true;
                    break;
                }
                if (i+2 < 256 && first256[i] == 0x0F && first256[i+1] == 0x34) { // int 2e
                    hasShellcode = true;
                    break;
                }
            }
            if (hasShellcode) {
                result.hasFilelessPE = true;
                return true;
            }
        }
    }

    // 原有检测：通过内存节区名
    if (pNtQueryVirtualMemory) {
        MEMORY_SECTION_NAME sectionName;
        SIZE_T returnLen;
        NTSTATUS status = pNtQueryVirtualMemory(hProcess, (PVOID)addr, MemorySectionName,
                                                &sectionName, sizeof(sectionName), &returnLen);
        if (status == STATUS_SUCCESS && returnLen > sizeof(UNICODE_STRING)) {
            if (sectionName.SectionFileName.Buffer && sectionName.SectionFileName.Length > 0) {
                return false;
            }
        }
        result.hasFilelessPE = true;
        return true;
    }
    return false;
}

static bool CheckThreadlessInjection(HANDLE hProcess, const std::vector<MODULEENTRY32W>& modules, ScanResult& result) {
    MODULEENTRY32W ntdllMod;
    bool found = false;
    for (auto& mod : modules) {
        if (_wcsicmp(mod.szModule, L"ntdll.dll") == 0) {
            ntdllMod = mod;
            found = true;
            break;
        }
    }
    if (!found) return false;

    uint32_t rva = GetExportRvaFromFile(ntdllMod.szExePath, "NtQueueApcThread");
    if (rva == 0) return false;
    uint64_t funcAddr = (uint64_t)ntdllMod.modBaseAddr + rva;
    uint8_t memBytes[16];
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, (LPCVOID)funcAddr, memBytes, sizeof(memBytes), &read) || read != sizeof(memBytes))
        return false;
    uint8_t fileBytes[16];
    if (!ReadRawFileBytes(ntdllMod.szExePath, rva, fileBytes, sizeof(fileBytes)))
        return false;
    bool hooked = (memcmp(memBytes, fileBytes, sizeof(memBytes)) != 0);
    if (hooked) {
        result.hasThreadlessInjection = true;
        return true;
    }

    HANDLE hThreadSnap = SafeCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(hProcess));
    if (hThreadSnap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hThreadSnap, &te)) { CloseHandle(hThreadSnap); return false; }
    do {
        if (te.th32OwnerProcessID != GetProcessId(hProcess)) continue;
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!hThread) continue;
        if (pNtQueryInformationThread) {
            uint64_t startAddr = 0;
            NTSTATUS status = pNtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddr, sizeof(startAddr), NULL);
            if (status == STATUS_SUCCESS && startAddr != 0) {
                if (!IsAddressInModule(startAddr, modules)) {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                        DWORD execFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & execFlags)) {
                            result.hasThreadlessInjection = true;
                            CloseHandle(hThread);
                            CloseHandle(hThreadSnap);
                            return true;
                        }
                    }
                }
            }
        }
        CloseHandle(hThread);
    } while (Thread32Next(hThreadSnap, &te));
    CloseHandle(hThreadSnap);
    return false;
}

static bool CheckDoppelgangV2(HANDLE hProcess, const std::wstring& modulePath, ScanResult& result) {
    if (!pNtQueryInformationProcess) return false;
    UNICODE_STRING imageFileName;
    ULONG returnLen;
    NTSTATUS status = pNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)ProcessImageFileName,
                                                  &imageFileName, sizeof(imageFileName), &returnLen);
    if (!NT_SUCCESS(status) || imageFileName.Length == 0) return false;
    std::vector<wchar_t> buffer(imageFileName.Length / sizeof(wchar_t) + 1);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, imageFileName.Buffer, buffer.data(), imageFileName.Length, &bytesRead) || bytesRead != imageFileName.Length)
        return false;
    buffer[imageFileName.Length / sizeof(wchar_t)] = L'\0';
    std::wstring kernelPath = buffer.data();

    HANDLE hModSnap = SafeCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
    if (hModSnap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);
    bool foundMod = false;
    if (Module32FirstW(hModSnap, &me)) {
        do {
            if (me.modBaseAddr != NULL) {
                foundMod = true;
                break;
            }
        } while (Module32NextW(hModSnap, &me));
    }
    CloseHandle(hModSnap);
    if (!foundMod) return false;

    HANDLE hFile = CreateFileW(me.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    wchar_t finalPath[MAX_PATH+1];
    DWORD len = GetFinalPathNameByHandleW(hFile, finalPath, MAX_PATH, FILE_NAME_NORMALIZED);
    CloseHandle(hFile);
    if (len == 0 || len >= MAX_PATH) return false;
    std::wstring userPath = finalPath;

    if (_wcsicmp(userPath.c_str(), kernelPath.c_str()) != 0) {
        result.hasDoppelgangV2 = true;
        return true;
    }
    return false;
}

//分数计算
static double ComputeScoreFromResult(const ScanResult& result) {
    double score = 0.0;

    bool critical = result.hasCodeTamper || result.hasProcessHollow || result.hasReflectiveInjection || result.hasSSDTHook;
    if (critical) score += 20;

    if (result.hasRWX) score += 7;
    if (result.hasAnonExec) score += 7;
    if (result.hasPEAnomaly) score += 4;
    if (result.hasModuleInc) score += 4;
    if (result.hasThreadOutOfModule) score += 7;
    if (result.hasCodeWrite) score += 7;
    if (result.hasCodeTamper) score += 10;
    if (result.hasThreadContextAbnormal) score += 7;
    if (result.hasReflectiveInjection) score += 10;
    if (result.hasInlineHook) score += 10;
    if (result.hasIATHook) score += 10;
    if (result.hasReflectiveShellcode) score += 10;
    if (result.hasInlineHookExt) score += 10;
    if (result.hasIATHookEx) score += 10;
    if (result.hasProcessHollow) score += 10;
    if (result.hasThreadContextExAbnormal) score += 7;
    if (result.hasAPCInjection) score += 10;
    if (result.hasCodeSignFailed) score += 4;
    if (result.hasSuspiciousCmdLine) score += 8;
    if (result.hasScriptEngine) score += 9;
    if (result.hasClrInNonManaged) score += 9;
    if (result.hasProcessDoppelganging) score += 10;
    if (result.hasPROPagate) score += 10;
    if (result.hasCOMHijacking) score += 10;
    if (result.hasPersistenceCmd) score += 9;
    if (result.hasLateralMovement) score += 9;
    if (result.hasIOC_IP) score += 5;
    if (result.hasIOC_Domain) score += 5;
    if (result.hasIOC_Mutex) score += 3;
    if (result.hasInvalidSignature) score += 8;
    if (result.hasDynamicAPI) score += 8;
    if (result.hasIDTHook) score += 10;
    if (result.hasGDTOverride) score += 7;
    if (result.hasKernelCallbackHook) score += 10;
    if (result.hasHiddenDriver) score += 10;
    if (result.hasAMSIBypass) score += 9;
    if (result.hasDirectSyscall) score += 10;
    if (result.hasDLLSideLoad) score += 8;
    if (result.hasFilelessPE) score += 10;
    if (result.hasThreadlessInjection) score += 10;
    if (result.hasDoppelgangV2) score += 10;
    if (result.hasSSDTHook) score += 10;
    if (result.hasShadowSSDTHook) score += 10;
    if (result.hasHiddenDriverEx) score += 10;
    if (result.hasDKOMProcess) score += 10;
    if (result.hasSyscallHook) score += 12;
    if (result.hasC2Beacon) score += 15;
    if (result.hasSuspiciousParent) score += 20;
    if (result.hasMsbuildCompile) score += 15;
    if (result.hasRegsvr32Download) score += 18;
    if (result.hasRundll32Suspicious) score += 15;

    double microScore = 0.0;
    if (result.hasNamedPipe) microScore += 1;
    if (result.hasSandboxStrings) microScore += 1;
    if (result.hasIOC_Mutex) microScore += 1;
    if (result.hasDebuggerFlag) microScore += 2;
    if (result.hasNtGlobalFlag) microScore += 1;
    if (result.hasHeapFlags) microScore += 1;
    if (microScore > 5.0) microScore = 5.0;
    score += microScore;

    if (result.hasRWX && result.hasAnonExec) score += 20;

    return score;
}

//反调试/反沙箱检测
static void CheckPEBDebugFlags(HANDLE hProcess, bool isWow64, ScanResult& result) {
    if (!pNtQueryInformationProcess) return;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLen;
    NTSTATUS status = pNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0,
                                                  &pbi, sizeof(pbi), &returnLen);
    if (!NT_SUCCESS(status) || pbi.PebBaseAddress == NULL) return;

    uint64_t pebAddr = (uint64_t)pbi.PebBaseAddress;
    SIZE_T read;

    uint8_t beingDebugged = 0;
    if (ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0x02), &beingDebugged, 1, &read) && read == 1) {
        if (beingDebugged != 0) result.hasDebuggerFlag = true;
    }

    DWORD ntGlobalFlag = 0;
    if (isWow64) {
        if (ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0x68), &ntGlobalFlag, sizeof(DWORD), &read) && read == sizeof(DWORD)) {
            if (ntGlobalFlag != 0) result.hasNtGlobalFlag = true;
        }
    } else {
        if (ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0x68), &ntGlobalFlag, sizeof(DWORD), &read) && read == sizeof(DWORD)) {
            if (ntGlobalFlag != 0) result.hasNtGlobalFlag = true;
        }
        if (!result.hasNtGlobalFlag) {
            if (ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0xBC), &ntGlobalFlag, sizeof(DWORD), &read) && read == sizeof(DWORD)) {
                if (ntGlobalFlag != 0) result.hasNtGlobalFlag = true;
            }
        }
    }

    uint64_t heapAddr = 0;
    if (isWow64) {
        uint32_t heapPtr32 = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0x18), &heapPtr32, sizeof(uint32_t), &read) && read == sizeof(uint32_t)) {
            heapAddr = heapPtr32;
        }
    } else {
        if (ReadProcessMemory(hProcess, (LPCVOID)(pebAddr + 0x30), &heapAddr, sizeof(uint64_t), &read) && read == sizeof(uint64_t)) {
        }
    }
    if (heapAddr != 0) {
        DWORD heapFlags = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(heapAddr + 0x0C), &heapFlags, sizeof(DWORD), &read) && read == sizeof(DWORD)) {
            if (heapFlags != 0x02) result.hasHeapFlags = true;
        }
    }
}

static void CheckSandboxAndPipeStrings(HANDLE hProcess, ScanResult& result) {
    const char* asciiPatterns[] = {
        "sandboxie", "vbox", "vmware", "qemu", "cuckoo",
        "\\\\.\\pipe\\", "\\\\.\\pipe", "\\.\\pipe"
    };
    const wchar_t* widePatterns[] = {
        L"sandboxie", L"vbox", L"vmware", L"qemu", L"cuckoo",
        L"\\\\.\\pipe\\", L"\\\\.\\pipe", L"\\.\\pipe"
    };
    int asciiCount = sizeof(asciiPatterns) / sizeof(asciiPatterns[0]);
    int wideCount = sizeof(widePatterns) / sizeof(widePatterns[0]);

    std::vector<std::vector<uint8_t>> wideBytes;
    for (int i = 0; i < wideCount; i++) {
        const wchar_t* wstr = widePatterns[i];
        size_t len = wcslen(wstr);
        std::vector<uint8_t> bytes(len * sizeof(wchar_t));
        memcpy(bytes.data(), wstr, len * sizeof(wchar_t));
        wideBytes.push_back(bytes);
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LPCVOID addr = si.lpMinimumApplicationAddress;
    LPCVOID maxAddr = si.lpMaximumApplicationAddress;

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            size_t readSize = (mbi.RegionSize > 65536) ? 65536 : mbi.RegionSize;
            std::vector<uint8_t> buffer(readSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), readSize, &bytesRead) && bytesRead > 0) {
                for (int i = 0; i < asciiCount; i++) {
                    if (memmem(buffer.data(), bytesRead, asciiPatterns[i], strlen(asciiPatterns[i]))) {
                        std::string pat = asciiPatterns[i];
                        if (pat.find("pipe") != std::string::npos) {
                            result.hasNamedPipe = true;
                        } else {
                            result.hasSandboxStrings = true;
                        }
                        break;
                    }
                }
                for (int i = 0; i < wideCount && !result.hasSandboxStrings && !result.hasNamedPipe; i++) {
                    if (memmem(buffer.data(), bytesRead, wideBytes[i].data(), wideBytes[i].size())) {
                        std::wstring wpat = widePatterns[i];
                        if (wpat.find(L"pipe") != std::wstring::npos) {
                            result.hasNamedPipe = true;
                        } else {
                            result.hasSandboxStrings = true;
                        }
                        break;
                    }
                }
            }
        }

        uintptr_t nextAddr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= (uintptr_t)addr) break;
        addr = (LPCVOID)nextAddr;
        if ((uintptr_t)addr >= (uintptr_t)maxAddr) break;
    }
}

static bool CheckLateralMovementModules(const std::vector<MODULEENTRY32W>& modules) {
    const wchar_t* tools[] = {L"psexec.exe", L"wmic.exe", L"net.exe", L"sc.exe", L"schtasks.exe"};
    for (auto& mod : modules) {
        std::wstring name = mod.szModule;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);
        for (auto tool : tools) {
            if (name.find(tool) != std::wstring::npos) {
                return true;
            }
        }
    }
    return false;
}

static bool GetSystemProcessIds(std::set<DWORD>& pids) {
    if (!pNtQuerySystemInformation) return false;
    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return false;

    std::vector<uint8_t> buffer(bufferSize);
    status = pNtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) return false;

    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer.data();
    while (true) {
        DWORD pid = (DWORD)(ULONG_PTR)pInfo->UniqueProcessId;
        if (pid != 0) pids.insert(pid);
        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((uint8_t*)pInfo + pInfo->NextEntryOffset);
    }
    return true;
}

//返回 int：-1=无法验证，0=未篡改，1=篡改
static int CompareExecutableSectionsHashes(HANDLE hProcess, const MODULEENTRY32W& mod, bool hasClr) {
    std::wstring modName = mod.szModule;
    if (modName != L"ntdll.dll" && modName != L"kernel32.dll" && modName != L"kernelbase.dll")
        return 0;

    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, mod.modBaseAddr, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return 0;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return 0;

    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return 0;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return 0;
    WORD numSections = is64 ? pNt64->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.NumberOfSections;
    DWORD sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (is64)
        sectionOffset += pNt64->FileHeader.SizeOfOptionalHeader;
    else
        sectionOffset += ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.SizeOfOptionalHeader;

    HANDLE hFile = CreateFileW(mod.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return -1; }
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return -1; }
    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return -1; }
    uint8_t* pData = (uint8_t*)pMap;

    bool mismatch = false;
    IMAGE_SECTION_HEADER section;
    for (WORD i = 0; i < numSections; i++) {
        LPCVOID secAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
        if (!ReadProcessMemory(hProcess, secAddr, &section, sizeof(section), &read) || read != sizeof(section))
            continue;
        if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (hasClr) {
        }
        uint64_t secStart = (uint64_t)mod.modBaseAddr + section.VirtualAddress;
        size_t secSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
        if (secSize == 0) continue;

        std::vector<uint8_t> memData(secSize);
        if (!ReadProcessMemory(hProcess, (LPCVOID)secStart, memData.data(), secSize, &read) || read != secSize)
            continue;
        uint32_t memHash = CalcCRC32(memData.data(), secSize);

        if (section.PointerToRawData + secSize > fileSize) continue;
        uint32_t fileHash = CalcCRC32(pData + section.PointerToRawData, secSize);

        if (memHash != fileHash) {
            mismatch = true;
            break;
        }
    }

    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return mismatch ? 1 : 0;
}

//IOC 字符串扫描
static bool IsValidIPv4(const char* str, size_t len) {
    if (len < 7 || len > 15) return false;
    int dots = 0;
    int num = 0;
    int numCount = 0;
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if (c == '.') {
            dots++;
            if (num < 0 || num > 255) return false;
            num = 0;
            numCount = 0;
        } else if (c >= '0' && c <= '9') {
            num = num * 10 + (c - '0');
            numCount++;
            if (numCount > 3) return false;
        } else {
            return false;
        }
    }
    if (dots != 3) return false;
    if (num < 0 || num > 255) return false;
    return true;
}

static void ScanIOCInRegion(const uint8_t* data, size_t size, ScanResult& result) {
    if (result.hasIOC_IP && result.hasIOC_Domain && result.hasIOC_Mutex) return;

    for (size_t i = 0; i < size; i++) {
        if (data[i] >= '0' && data[i] <= '9') {
            size_t start = i;
            while (i < size && (data[i] >= '0' || data[i] == '.')) i++;
            size_t len = i - start;
            if (len >= 7 && len <= 15) {
                char ip[16];
                if (len < sizeof(ip)) {
                    memcpy(ip, data + start, len);
                    ip[len] = '\0';
                    if (IsValidIPv4(ip, len)) {
                        result.hasIOC_IP = true;
                        break;
                    }
                }
            }
        }
    }

    const char* http = "http://";
    const char* https = "https://";
    for (size_t i = 0; i < size; i++) {
        if (i + 7 <= size && memcmp(data + i, http, 7) == 0) {
            result.hasIOC_Domain = true;
            break;
        }
        if (i + 8 <= size && memcmp(data + i, https, 8) == 0) {
            result.hasIOC_Domain = true;
            break;
        }
    }

    const char* mutex1 = "Global\\";
    const char* mutex2 = "Local\\";
    const char* mutex3 = "Session\\";
    for (size_t i = 0; i < size; i++) {
        if (i + 7 <= size && memcmp(data + i, mutex1, 7) == 0) {
            result.hasIOC_Mutex = true;
            break;
        }
        if (i + 6 <= size && memcmp(data + i, mutex2, 6) == 0) {
            result.hasIOC_Mutex = true;
            break;
        }
        if (i + 8 <= size && memcmp(data + i, mutex3, 8) == 0) {
            result.hasIOC_Mutex = true;
            break;
        }
    }

    const wchar_t* wHttp = L"http://";
    const wchar_t* wHttps = L"https://";
    const wchar_t* wMutex1 = L"Global\\";
    const wchar_t* wMutex2 = L"Local\\";
    const wchar_t* wMutex3 = L"Session\\";
    for (size_t i = 0; i < size - 1; i += 2) {
        if (i + 14 <= size && memcmp(data + i, wHttp, 14) == 0) {
            result.hasIOC_Domain = true;
            break;
        }
        if (i + 16 <= size && memcmp(data + i, wHttps, 16) == 0) {
            result.hasIOC_Domain = true;
            break;
        }
        if (i + 14 <= size && memcmp(data + i, wMutex1, 14) == 0) {
            result.hasIOC_Mutex = true;
            break;
        }
        if (i + 12 <= size && memcmp(data + i, wMutex2, 12) == 0) {
            result.hasIOC_Mutex = true;
            break;
        }
        if (i + 16 <= size && memcmp(data + i, wMutex3, 16) == 0) {
            result.hasIOC_Mutex = true;
            break;
        }
    }
}

static void ScanAllRegionsForIOC(HANDLE hProcess, ScanResult& result) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LPCVOID addr = si.lpMinimumApplicationAddress;
    LPCVOID maxAddr = si.lpMaximumApplicationAddress;

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            SIZE_T readSize = (mbi.RegionSize > 65536) ? 65536 : mbi.RegionSize;
            std::vector<uint8_t> buffer(readSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), readSize, &bytesRead) && bytesRead > 0) {
                ScanIOCInRegion(buffer.data(), bytesRead, result);
                if (result.hasIOC_IP && result.hasIOC_Domain && result.hasIOC_Mutex)
                    break;
            }
        }

        uintptr_t nextAddr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= (uintptr_t)addr) break;
        addr = (LPCVOID)nextAddr;
        if ((uintptr_t)addr >= (uintptr_t)maxAddr) break;
    }
}

//数字签名验证
static bool VerifySignatureEx(const wchar_t* filePath, bool& isSigned, bool& isExpired, bool& isSelfSigned) {
    isSigned = false;
    isExpired = false;
    isSelfSigned = false;

    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA wintrustData = {0};
    wintrustData.cbStruct = sizeof(WINTRUST_DATA);
    wintrustData.pPolicyCallbackData = NULL;
    wintrustData.pSIPClientData = NULL;
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.hWVTStateData = NULL;
    wintrustData.pwszURLReference = NULL;
    wintrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID verifyAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &verifyAction, &wintrustData);

    wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &verifyAction, &wintrustData);

    if (status == ERROR_SUCCESS) {
        isSigned = true;
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        PCCERT_CONTEXT pCertContext = NULL;
        if (CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            filePath,
            CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            NULL,
            NULL,
            NULL,
            &hStore,
            &hMsg,
            (const void**)&pCertContext)) {
            if (pCertContext) {
                CERT_CHAIN_PARA chainPara = {0};
                chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
                PCCERT_CHAIN_CONTEXT pChainContext = NULL;
                if (CertGetCertificateChain(
                    NULL,
                    pCertContext,
                    NULL,
                    NULL,
                    &chainPara,
                    0,
                    NULL,
                    &pChainContext)) {
                    if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) {
                        isExpired = true;
                    }
                    if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
                        isSelfSigned = true;
                    }
                    CertFreeCertificateChain(pChainContext);
                }
                CertFreeCertificateContext(pCertContext);
            }
            if (hStore) CertCloseStore(hStore, 0);
            if (hMsg) CryptMsgClose(hMsg);
        }
        return true;
    } else {
        isSigned = false;
        if (status == 0x800B0101L) {
            HCERTSTORE hStore = NULL;
            HCRYPTMSG hMsg = NULL;
            PCCERT_CONTEXT pCertContext = NULL;
            if (CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                filePath,
                CERT_QUERY_CONTENT_FLAG_ALL,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                NULL,
                NULL,
                NULL,
                &hStore,
                &hMsg,
                (const void**)&pCertContext)) {
                if (pCertContext) {
                    FILETIME now;
                    GetSystemTimeAsFileTime(&now);
                    if (CompareFileTime(&pCertContext->pCertInfo->NotBefore, &now) > 0 ||
                        CompareFileTime(&now, &pCertContext->pCertInfo->NotAfter) > 0) {
                        isExpired = true;
                    }
                    CertFreeCertificateContext(pCertContext);
                }
                if (hStore) CertCloseStore(hStore, 0);
                if (hMsg) CryptMsgClose(hMsg);
            }
        }
        return false;
    }
}

//动态API解析检测 
static bool CheckDynamicAPIDetection(HANDLE hProcess, const MODULEENTRY32W& mod, ScanResult& result) {
    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, mod.modBaseAddr, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return false;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return false;

    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return false;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_DATA_DIRECTORY importDir = is64 ? pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] :
                                            ((PIMAGE_NT_HEADERS32)ntBuffer)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return false;

    uint64_t importDirAddr = (uint64_t)mod.modBaseAddr + importDir.VirtualAddress;
    std::vector<uint8_t> importData(importDir.Size);
    if (!ReadProcessMemory(hProcess, (LPCVOID)importDirAddr, importData.data(), importDir.Size, &read) || read != importDir.Size)
        return false;

    bool hasGetProcAddress = false;
    bool hasLoadLibrary = false;

    PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)importData.data();
    while (pDesc->OriginalFirstThunk || pDesc->FirstThunk) {
        if (pDesc->Name == 0) { pDesc++; continue; }
        char dllName[256];
        uint64_t nameAddr = (uint64_t)mod.modBaseAddr + pDesc->Name;
        if (!ReadProcessMemory(hProcess, (LPCVOID)nameAddr, dllName, sizeof(dllName)-1, &read) || read == 0)
            { pDesc++; continue; }
        dllName[read] = '\0';

        if (strcmp(dllName, "kernel32.dll") != 0 && strcmp(dllName, "ntdll.dll") != 0) {
            pDesc++;
            continue;
        }

        uint64_t thunkAddr = (uint64_t)mod.modBaseAddr + pDesc->FirstThunk;
        uint64_t origThunkAddr = (uint64_t)mod.modBaseAddr + pDesc->OriginalFirstThunk;
        for (uint32_t idx = 0; ; idx++) {
            uint64_t funcAddr;
            if (!ReadProcessMemory(hProcess, (LPCVOID)(thunkAddr + idx * (is64 ? 8 : 4)), &funcAddr, is64 ? 8 : 4, &read) || read != (is64 ? 8 : 4))
                break;
            if (funcAddr == 0) break;
            uint64_t origThunkVal;
            if (!ReadProcessMemory(hProcess, (LPCVOID)(origThunkAddr + idx * (is64 ? 8 : 4)), &origThunkVal, is64 ? 8 : 4, &read) || read != (is64 ? 8 : 4))
                break;
            if (origThunkVal == 0) break;
            if (origThunkVal & IMAGE_ORDINAL_FLAG64) {
                continue;
            } else {
                uint64_t nameRVA = origThunkVal & 0xFFFFFFFF;
                uint64_t nameAddr2 = (uint64_t)mod.modBaseAddr + nameRVA;
                char nameBuf[256];
                if (!ReadProcessMemory(hProcess, (LPCVOID)nameAddr2, nameBuf, sizeof(nameBuf)-1, &read) || read == 0)
                    continue;
                nameBuf[read] = '\0';
                if (strcmp(nameBuf, "GetProcAddress") == 0) {
                    hasGetProcAddress = true;
                }
                if (strcmp(nameBuf, "LoadLibraryA") == 0 || strcmp(nameBuf, "LoadLibraryW") == 0) {
                    hasLoadLibrary = true;
                }
            }
        }
        pDesc++;
        if (hasGetProcAddress && hasLoadLibrary) break;
    }

    if (hasGetProcAddress && hasLoadLibrary) {
        DWORD sectionOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (is64)
            sectionOffset += pNt64->FileHeader.SizeOfOptionalHeader;
        else
            sectionOffset += ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.SizeOfOptionalHeader;
        WORD numSections = is64 ? pNt64->FileHeader.NumberOfSections : ((PIMAGE_NT_HEADERS32)ntBuffer)->FileHeader.NumberOfSections;

        IMAGE_SECTION_HEADER section;
        for (WORD i = 0; i < numSections; i++) {
            LPCVOID secAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
            if (!ReadProcessMemory(hProcess, secAddr, &section, sizeof(section), &read) || read != sizeof(section))
                continue;
            if (memcmp(section.Name, ".text", 5) == 0) {
                uint64_t textStart = (uint64_t)mod.modBaseAddr + section.VirtualAddress;
                size_t textSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
                if (textSize == 0) break;

                std::vector<uint8_t> textData(textSize);
                if (!ReadProcessMemory(hProcess, (LPCVOID)textStart, textData.data(), textSize, &read) || read != textSize)
                    break;

                const char* sensitiveApis[] = {
                    "NtCreateThreadEx", "VirtualAllocEx", "WriteProcessMemory",
                    "NtProtectVirtualMemory", "QueueUserAPC", "SetWindowsHookEx",
                    "CreateRemoteThread", "NtQueueApcThread"
                };
                for (auto api : sensitiveApis) {
                    if (memmem(textData.data(), textSize, api, strlen(api))) {
                        result.hasDynamicAPI = true;
                        return true;
                    }
                }
                break;
            }
        }
    }

    return result.hasDynamicAPI;
}

// 内核级检测 
static bool ReadKernelMemory(PVOID KernelAddress, PVOID Buffer, ULONG Length) {
    if (!pNtSystemDebugControl) return false;
    SYSDBG_VIRTUAL_MEMORY mem;
    mem.Address = KernelAddress;
    mem.Buffer = Buffer;
    mem.Length = Length;
    ULONG returnLength;
    NTSTATUS status = pNtSystemDebugControl(SYSDBG_READ_VIRTUAL_MEMORY, &mem, sizeof(mem), NULL, 0, &returnLength);
    return NT_SUCCESS(status);
}

static bool IsKernelAddressInModule(uint64_t addr) {
    for (const auto& mod : g_KernelModules) {
        if (addr >= mod.Base && addr < mod.Base + mod.Size)
            return true;
    }
    return false;
}

static std::wstring GetNtosPath() {
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring path = sysDir;
    path += L"\\ntoskrnl.exe";
    return path;
}

static bool RefreshKernelModules() {
    if (!pNtQuerySystemInformation) return false;
    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return false;

    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(bufferSize);
    if (!pModuleInfo) return false;

    status = pNtQuerySystemInformation(SystemModuleInformation, pModuleInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        free(pModuleInfo);
        return false;
    }

    g_KernelModules.clear();
    g_NtosBase = 0;
    g_NtosSize = 0;

    for (ULONG i = 0; i < pModuleInfo->Count; i++) {
        KernelModuleInfo km;
        km.Base = (uint64_t)pModuleInfo->Module[i].ImageBase;
        km.Size = pModuleInfo->Module[i].ImageSize;
        km.FullPath = (char*)pModuleInfo->Module[i].FullPathName;
        size_t pos = km.FullPath.find_last_of('\\');
        if (pos != std::string::npos)
            km.Name = km.FullPath.substr(pos + 1);
        else
            km.Name = km.FullPath;
        g_KernelModules.push_back(km);

        if (km.Name == "ntoskrnl.exe") {
            g_NtosBase = km.Base;
            g_NtosSize = km.Size;
        }
    }

    free(pModuleInfo);
    g_HasKernelModules = true;
    return true;
}

static uint32_t GetExportRvaFromKernelFile(const wchar_t* filePath, const char* symbolName) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return 0;
    }

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    uint8_t* pData = (uint8_t*)pMap;
    uint32_t rva = 0;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        if (pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) <= fileSize) {
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pDos->e_lfanew);
            if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                IMAGE_DATA_DIRECTORY exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportDir.VirtualAddress != 0 && exportDir.Size > 0 &&
                    exportDir.VirtualAddress + exportDir.Size <= fileSize) {
                    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pData + exportDir.VirtualAddress);
                    if (pExp->AddressOfNames != 0 && pExp->AddressOfNameOrdinals != 0 && pExp->AddressOfFunctions != 0 &&
                        pExp->AddressOfNames + pExp->NumberOfNames * sizeof(DWORD) <= fileSize &&
                        pExp->AddressOfNameOrdinals + pExp->NumberOfNames * sizeof(WORD) <= fileSize &&
                        pExp->AddressOfFunctions + pExp->NumberOfFunctions * sizeof(DWORD) <= fileSize) {
                        DWORD* names = (DWORD*)(pData + pExp->AddressOfNames);
                        WORD* ordinals = (WORD*)(pData + pExp->AddressOfNameOrdinals);
                        DWORD* functions = (DWORD*)(pData + pExp->AddressOfFunctions);
                        size_t symLen = strlen(symbolName);
                        for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
                            if (names[i] + symLen + 1 <= fileSize) {
                                char* name = (char*)(pData + names[i]);
                                if (strncmp(name, symbolName, symLen + 1) == 0) {
                                    if (ordinals[i] < pExp->NumberOfFunctions) {
                                        rva = functions[ordinals[i]];
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return rva;
}

//检测内核调试器 
static bool CheckKdDebugger() {
    if (!pNtQuerySystemInformation) return false;
    typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerPresent;
    } SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
    ULONG returnLen;
    NTSTATUS status = pNtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), &returnLen);
    if (NT_SUCCESS(status) && returnLen >= sizeof(info)) {
        return (info.KernelDebuggerEnabled != FALSE || info.KernelDebuggerPresent != FALSE);
    }
    return false;
}

//内核检测函数
static bool CheckSSDT(ScanResult& result) {
    if (g_HVCIEnabled || g_PatchGuardActive || g_KdDebuggerEnabled) {
        wprintf(L"[INFO] HVCI/PatchGuard/KdDebugger active, SSDT checks skipped.\n");
        return false;
    }
    if (!pNtSystemDebugControl || !g_HasKernelModules || g_NtosBase == 0) {
        wprintf(L"[-] Cannot check SSDT: missing prerequisites.\n");
        return false;
    }

    std::wstring ntosPath = GetNtosPath();
    uint32_t rva = GetExportRvaFromKernelFile(ntosPath.c_str(), "KeServiceDescriptorTable");
    if (rva == 0) {
        wprintf(L"[-] KeServiceDescriptorTable not found.\n");
        return false;
    }
    uint64_t tableAddr = g_NtosBase + rva;
    struct {
        uint64_t ServiceTableBase;
        uint64_t ServiceCounterTable;
        uint32_t NumberOfServices;
        uint32_t NumberOfParameters;
    } ssdt;
    if (!ReadKernelMemory((PVOID)tableAddr, &ssdt, sizeof(ssdt))) {
        wprintf(L"[WARN] Failed to read KeServiceDescriptorTable.\n");
        return false;
    }
    wprintf(L"[*] SSDT: ServiceTableBase=0x%p, NumberOfServices=%u\n", (void*)ssdt.ServiceTableBase, ssdt.NumberOfServices);
    if (ssdt.NumberOfServices == 0 || ssdt.ServiceTableBase == 0) return false;

    size_t arraySize = ssdt.NumberOfServices * sizeof(uint64_t);
    std::vector<uint64_t> funcPtrs(ssdt.NumberOfServices);
    if (!ReadKernelMemory((PVOID)ssdt.ServiceTableBase, funcPtrs.data(), arraySize)) {
        wprintf(L"[WARN] Failed to read SSDT array.\n");
        return false;
    }
    bool foundHook = false;
    for (uint32_t i = 0; i < ssdt.NumberOfServices; i++) {
        uint64_t addr = funcPtrs[i];
        if (addr == 0) continue;
        if (!IsKernelAddressInModule(addr)) {
            wprintf(L"[!] SSDT entry %u at 0x%p not in any kernel module\n", i, (void*)addr);
            foundHook = true;
        }
    }
    if (foundHook) {
        result.hasSSDTHook = true;
        wprintf(L"[!] SSDT hooks detected!\n");
    } else {
        wprintf(L"[+] SSDT appears clean.\n");
    }
    return foundHook;
}

static bool CheckShadowSSDT(ScanResult& result) {
    if (g_HVCIEnabled || g_PatchGuardActive || g_KdDebuggerEnabled) {
        wprintf(L"[INFO] HVCI/PatchGuard/KdDebugger active, Shadow SSDT skipped.\n");
        return false;
    }
    // 增加Windows版本白名单：Win10 19041+ 可能变化，跳过
    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (GetVersionExW((LPOSVERSIONINFOW)&osvi)) {
        if (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 19041) {
            wprintf(L"[INFO] Windows version >= 10.0.19041, Shadow SSDT check may be unstable, skipping.\n");
            return false;
        }
    }

    if (!pNtSystemDebugControl || !g_HasKernelModules) {
        wprintf(L"[-] Cannot check Shadow SSDT.\n");
        return false;
    }

    uint64_t win32kBase = 0;
    std::wstring win32kPath;
    for (auto& km : g_KernelModules) {
        if (km.Name.find("win32k") != std::string::npos) {
            win32kBase = km.Base;
            win32kPath = std::wstring(km.FullPath.begin(), km.FullPath.end());
            break;
        }
    }
    if (win32kBase == 0) {
        wprintf(L"[-] win32k.sys not found.\n");
        return false;
    }

    uint32_t rva = GetExportRvaFromKernelFile(win32kPath.c_str(), "KeServiceDescriptorTableShadow");
    if (rva == 0) {
        wprintf(L"[-] KeServiceDescriptorTableShadow not found.\n");
        return false;
    }
    uint64_t tableAddr = win32kBase + rva;
    struct {
        uint64_t ServiceTableBase;
        uint64_t ServiceCounterTable;
        uint32_t NumberOfServices;
        uint32_t NumberOfParameters;
    } ssdt;
    if (!ReadKernelMemory((PVOID)tableAddr, &ssdt, sizeof(ssdt))) {
        wprintf(L"[WARN] Failed to read Shadow SSDT.\n");
        return false;
    }
    wprintf(L"[*] Shadow SSDT: ServiceTableBase=0x%p, NumberOfServices=%u\n", (void*)ssdt.ServiceTableBase, ssdt.NumberOfServices);
    if (ssdt.NumberOfServices == 0 || ssdt.ServiceTableBase == 0) return false;

    size_t arraySize = ssdt.NumberOfServices * sizeof(uint64_t);
    std::vector<uint64_t> funcPtrs(ssdt.NumberOfServices);
    if (!ReadKernelMemory((PVOID)ssdt.ServiceTableBase, funcPtrs.data(), arraySize)) {
        wprintf(L"[WARN] Failed to read Shadow SSDT array.\n");
        return false;
    }
    bool foundHook = false;
    for (uint32_t i = 0; i < ssdt.NumberOfServices; i++) {
        uint64_t addr = funcPtrs[i];
        if (addr == 0) continue;
        if (!IsKernelAddressInModule(addr)) {
            wprintf(L"[!] Shadow SSDT entry %u at 0x%p not in any kernel module\n", i, (void*)addr);
            foundHook = true;
        }
    }
    if (foundHook) {
        result.hasShadowSSDTHook = true;
        wprintf(L"[!] Shadow SSDT hooks detected!\n");
    } else {
        wprintf(L"[+] Shadow SSDT appears clean.\n");
    }
    return foundHook;
}

static bool CheckSecurityEnvironment() {
    g_HVCIEnabled = false;
    g_PatchGuardActive = false;

    if (pNtQuerySystemInformation) {
        typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
            ULONG CodeIntegrityOptions;
        } SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

        SYSTEM_CODEINTEGRITY_INFORMATION info = {0};
        ULONG returnLength = 0;
        NTSTATUS status = pNtQuerySystemInformation(SystemCodeIntegrityInformation, &info, sizeof(info), &returnLength);
        if (NT_SUCCESS(status) && returnLength >= sizeof(info)) {
            if (info.CodeIntegrityOptions & 0x01) {
                g_HVCIEnabled = true;
                wprintf(L"[INFO] HVCI enabled.\n");
            }
            if (info.CodeIntegrityOptions & 0x02) {
                g_PatchGuardActive = true;
                wprintf(L"[INFO] PatchGuard active.\n");
            }
        } else {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD enableVBS = 0;
                DWORD size = sizeof(DWORD);
                if (RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", NULL, NULL,
                                     (LPBYTE)&enableVBS, &size) == ERROR_SUCCESS) {
                    if (enableVBS == 1) {
                        g_HVCIEnabled = true;
                        wprintf(L"[INFO] HVCI likely enabled (DeviceGuard registry).\n");
                    }
                }
                RegCloseKey(hKey);
            }
        }
    }
    return g_HVCIEnabled;
}

static bool CheckIDT(ScanResult& result) {
    if (g_HVCIEnabled || g_PatchGuardActive || g_KdDebuggerEnabled) {
        wprintf(L"[INFO] Environment active, IDT checks skipped.\n");
        return false;
    }
    if (!pNtSystemDebugControl) {
        wprintf(L"[-] NtSystemDebugControl not available.\n");
        return false;
    }

    struct IDTR {
        uint16_t Limit;
        uint64_t Base;
    } __attribute__((packed));
    IDTR idtr;
    __asm__ volatile ("sidt %0" : "=m"(idtr));

    if (idtr.Base == 0) {
        wprintf(L"[-] Failed to get IDT base.\n");
        return false;
    }

    const int IDT_ENTRIES = 256;
    const int ENTRY_SIZE = 16;
    uint8_t idtBuffer[IDT_ENTRIES * ENTRY_SIZE];
    if (!ReadKernelMemory((PVOID)idtr.Base, idtBuffer, sizeof(idtBuffer))) {
        wprintf(L"[WARN] Failed to read IDT entries.\n");
        return false;
    }

    bool foundHook = false;
    for (int i = 0; i < IDT_ENTRIES; i++) {
        uint8_t* entry = idtBuffer + i * ENTRY_SIZE;
        uint64_t offsetLow = *(uint16_t*)(entry);
        uint64_t offsetMid = *(uint16_t*)(entry + 6);
        uint64_t offsetHigh = *(uint32_t*)(entry + 8);
        uint64_t handler = offsetLow | (offsetMid << 16) | (offsetHigh << 32);

        if (handler != 0 && !IsKernelAddressInModule(handler)) {
            wprintf(L"[!] IDT entry %d handler at 0x%p not in any kernel module!\n", i, (void*)handler);
            foundHook = true;
        }
    }

    if (foundHook) {
        result.hasIDTHook = true;
        wprintf(L"[!] IDT hooks detected!\n");
    } else {
        wprintf(L"[+] IDT appears clean.\n");
    }
    return foundHook;
}

static bool CheckGDT(ScanResult& result) {
    if (g_HVCIEnabled || g_PatchGuardActive || g_KdDebuggerEnabled) {
        wprintf(L"[INFO] Environment active, GDT checks skipped.\n");
        return false;
    }
    if (!pNtSystemDebugControl) {
        wprintf(L"[-] NtSystemDebugControl not available.\n");
        return false;
    }

    struct GDTR {
        uint16_t Limit;
        uint64_t Base;
    } __attribute__((packed));
    GDTR gdtr;
    __asm__ volatile ("sgdt %0" : "=m"(gdtr));

    if (gdtr.Base == 0) {
        wprintf(L"[-] Failed to get GDT base.\n");
        return false;
    }

    const int GDT_ENTRIES = 128;
    const int ENTRY_SIZE = 16;
    uint8_t gdtBuffer[GDT_ENTRIES * ENTRY_SIZE];
    if (!ReadKernelMemory((PVOID)gdtr.Base, gdtBuffer, sizeof(gdtBuffer))) {
        wprintf(L"[WARN] Failed to read GDT entries.\n");
        return false;
    }

    bool foundOverride = false;
    for (int i = 0; i < GDT_ENTRIES; i++) {
        uint8_t* entry = gdtBuffer + i * ENTRY_SIZE;
        uint64_t baseLow = *(uint32_t*)(entry + 4);
        uint64_t baseMid = *(uint16_t*)(entry + 8);
        uint64_t baseHigh = *(uint16_t*)(entry + 12);
        uint64_t base = baseLow | (baseMid << 32) | (baseHigh << 48);
        if (base != 0 && (base & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) {
            wprintf(L"[!] GDT entry %d has unusual base 0x%p\n", i, (void*)base);
            foundOverride = true;
        }
    }

    if (foundOverride) {
        result.hasGDTOverride = true;
        wprintf(L"[!] GDT anomalies detected!\n");
    } else {
        wprintf(L"[+] GDT appears normal.\n");
    }
    return foundOverride;
}

static bool CheckKernelCallbacks(ScanResult& result) {
    if (g_HVCIEnabled || g_PatchGuardActive || g_KdDebuggerEnabled) {
        wprintf(L"[INFO] Environment active, kernel callback checks skipped.\n");
        return false;
    }
    if (!pNtSystemDebugControl) {
        wprintf(L"[-] NtSystemDebugControl not available.\n");
        return false;
    }
    if (g_NtosBase == 0) {
        wprintf(L"[-] ntoskrnl base not found.\n");
        return false;
    }

    std::wstring ntosPath = GetNtosPath();
    const char* callbackSymbols[] = {
        "PsCreateProcessNotifyRoutine",
        "PspCreateProcessNotifyRoutine",
        "PsCreateThreadNotifyRoutine",
        "PspCreateThreadNotifyRoutine",
        "PsLoadImageNotifyRoutine",
        "PspLoadImageNotifyRoutine"
    };

    const int MAX_CALLBACKS = 64;
    bool foundHook = false;

    for (const char* sym : callbackSymbols) {
        uint32_t rva = GetExportRvaFromKernelFile(ntosPath.c_str(), sym);
        if (rva == 0) continue;

        uint64_t addr = g_NtosBase + rva;
        uint64_t callbackArray[MAX_CALLBACKS];
        if (!ReadKernelMemory((PVOID)addr, callbackArray, sizeof(callbackArray))) {
            wprintf(L"[WARN] Failed to read callback array for %hs\n", sym);
            continue;
        }

        for (int i = 0; i < MAX_CALLBACKS; i++) {
            uint64_t cb = callbackArray[i];
            if (cb != 0 && !IsKernelAddressInModule(cb)) {
                wprintf(L"[!] Kernel callback %hs[%d] at 0x%p not in any kernel module!\n", sym, i, (void*)cb);
                foundHook = true;
            }
        }
    }

    if (foundHook) {
        result.hasKernelCallbackHook = true;
        wprintf(L"[!] Kernel callback hooks detected!\n");
    } else {
        wprintf(L"[+] Kernel callbacks appear clean.\n");
    }
    return foundHook;
}

static bool CheckHiddenDrivers(ScanResult& result) {
    if (g_HVCIEnabled || g_PatchGuardActive || g_KdDebuggerEnabled) {
        wprintf(L"[INFO] Environment active, hidden driver check skipped.\n");
        return false;
    }
    if (!pNtSystemDebugControl) {
        wprintf(L"[-] NtSystemDebugControl not available.\n");
        return false;
    }
    if (g_NtosBase == 0) {
        wprintf(L"[-] ntoskrnl base not found.\n");
        return false;
    }

    std::wstring ntosPath = GetNtosPath();
    uint32_t rva = GetExportRvaFromKernelFile(ntosPath.c_str(), "PsLoadedModuleList");
    if (rva == 0) {
        wprintf(L"[-] Cannot find PsLoadedModuleList export.\n");
        return false;
    }
    uint64_t listHeadAddr = g_NtosBase + rva;

    struct LIST_ENTRY64 {
        uint64_t Flink;
        uint64_t Blink;
    };
    LIST_ENTRY64 head;
    if (!ReadKernelMemory((PVOID)listHeadAddr, &head, sizeof(head))) {
        wprintf(L"[WARN] Failed to read PsLoadedModuleList head.\n");
        return false;
    }

    std::set<uint64_t> loadedBases;
    uint64_t cur = head.Flink;
    int maxIter = 1000;
    while (cur != listHeadAddr && maxIter-- > 0) {
        uint64_t dllBase = 0;
        if (!ReadKernelMemory((PVOID)(cur + 0x30), &dllBase, sizeof(dllBase)))
            break;
        if (dllBase != 0)
            loadedBases.insert(dllBase);

        uint64_t next;
        if (!ReadKernelMemory((PVOID)cur, &next, sizeof(next)))
            break;
        cur = next;
    }

    if (!g_HasKernelModules) RefreshKernelModules();
    std::set<uint64_t> systemBases;
    for (auto& km : g_KernelModules) {
        systemBases.insert(km.Base);
    }

    bool foundHidden = false;
    for (auto base : systemBases) {
        if (loadedBases.find(base) == loadedBases.end()) {
            std::wstring path;
            for (auto& km : g_KernelModules) {
                if (km.Base == base) {
                    path = std::wstring(km.FullPath.begin(), km.FullPath.end());
                    break;
                }
            }
            bool skip = false;
            if (!path.empty()) {
                std::wstring lowerPath = path;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                if (lowerPath.find(L"\\windows\\system32\\drivers\\") != std::wstring::npos) {
                    bool signedValid = false;
                    bool dummy1, dummy2, dummy3;
                    if (VerifySignatureEx(path.c_str(), signedValid, dummy1, dummy2)) {
                        if (signedValid) skip = true;
                    }
                }
            }
            if (!skip) {
                wprintf(L"[!] Hidden driver detected at 0x%p (not in PsLoadedModuleList)\n", (void*)base);
                foundHidden = true;
                IMAGE_DOS_HEADER dos;
                if (ReadKernelMemory((PVOID)base, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
                    wprintf(L"[*] Valid MZ header at 0x%p, confirmed as driver.\n", (void*)base);
                }
            }
        }
    }

    if (foundHidden) {
        result.hasHiddenDriver = true;
        wprintf(L"[!] Hidden drivers detected!\n");
    } else {
        wprintf(L"[+] No hidden drivers found.\n");
    }
    return foundHidden;
}

static bool CheckHiddenProcesses(std::set<DWORD>& systemPids, std::set<DWORD>& snapshotPids) {
    bool found = false;
    for (DWORD pid : systemPids) {
        if (snapshotPids.find(pid) == snapshotPids.end()) {
            wprintf(L"[!] DKOM hidden process detected: PID %d\n", pid);
            found = true;
        }
    }
    return found;
}

//  网络关联 
static bool ProcessHasExternalIPConnection(DWORD pid) {
    MIB_TCPTABLE_OWNER_PID* pTcpTable = NULL;
    DWORD dwSize = 0;
    if (GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return false;
    pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
    if (!pTcpTable) return false;
    DWORD result = GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        free(pTcpTable);
        return false;
    }
    bool external = false;
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
        if (row.dwOwningPid != pid) continue;
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
        DWORD remoteAddr = row.dwRemoteAddr;
        BYTE a = (remoteAddr >> 0) & 0xFF;
        BYTE b = (remoteAddr >> 8) & 0xFF;
        BYTE c = (remoteAddr >> 16) & 0xFF;
        BYTE d = (remoteAddr >> 24) & 0xFF;
        if (a == 10 || (a == 172 && (b >= 16 && b <= 31)) || (a == 192 && b == 168) || a == 127) {
            continue;
        }
        if (remoteAddr != 0) {
            external = true;
            break;
        }
    }
    free(pTcpTable);
    return external;
}

// Syscall Stub 完整性检测
static void CheckSyscallStubs(HANDLE hProcess, const MODULEENTRY32W& mod, ScanResult& result) {
    if (_wcsicmp(mod.szModule, L"ntdll.dll") != 0) return;

    IMAGE_DOS_HEADER dos;
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, mod.modBaseAddr, &dos, sizeof(dos), &read) || read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return;
    WORD magic = 0;
    LPCVOID magicAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew + 0x18);
    if (!ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &read) || read != sizeof(magic))
        return;
    bool is64 = (magic == 0x020B);
    if (magic != 0x010B && !is64) return;

    uint8_t ntBuffer[sizeof(IMAGE_NT_HEADERS64)];
    LPCVOID ntAddr = (LPCVOID)((uintptr_t)mod.modBaseAddr + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, ntBuffer, sizeof(ntBuffer), &read) || read < sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return;
    PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntBuffer;
    if (pNt64->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY exportDir = is64 ? pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] :
                                            ((PIMAGE_NT_HEADERS32)ntBuffer)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return;

    uint64_t exportAddr = (uint64_t)mod.modBaseAddr + exportDir.VirtualAddress;
    std::vector<uint8_t> expData(exportDir.Size);
    if (!ReadProcessMemory(hProcess, (LPCVOID)exportAddr, expData.data(), exportDir.Size, &read) || read != exportDir.Size)
        return;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)expData.data();
    DWORD* names = (DWORD*)(expData.data() + (pExp->AddressOfNames - exportDir.VirtualAddress));
    WORD* ordinals = (WORD*)(expData.data() + (pExp->AddressOfNameOrdinals - exportDir.VirtualAddress));
    DWORD* functions = (DWORD*)(expData.data() + (pExp->AddressOfFunctions - exportDir.VirtualAddress));

    HANDLE hFile = CreateFileW(mod.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return; }
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return; }
    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return; }
    uint8_t* fileData = (uint8_t*)pMap;

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char* name = (char*)(expData.data() + (names[i] - exportDir.VirtualAddress));
        if (strncmp(name, "Nt", 2) != 0) continue;
        uint32_t rva = functions[ordinals[i]];
        uint64_t funcAddr = (uint64_t)mod.modBaseAddr + rva;
        uint8_t memBytes[16];
        if (!ReadProcessMemory(hProcess, (LPCVOID)funcAddr, memBytes, sizeof(memBytes), &read) || read != sizeof(memBytes))
            continue;
        if (rva + sizeof(memBytes) > fileSize) continue;
        uint8_t* fileBytes = fileData + rva;
        if (memcmp(memBytes, fileBytes, sizeof(memBytes)) != 0) {
            result.hasSyscallHook = true;
            break;
        }
    }

    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
}

// JIT进程管理
static void UpdateJITProcesses() {
    std::lock_guard<std::mutex> lock(g_JITMutex);
    g_JITProcesses.clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                HMODULE hMods[256];
                DWORD cbNeeded;
                if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
                    DWORD modCount = cbNeeded / sizeof(HMODULE);
                    for (DWORD i=0; i<modCount; i++) {
                        wchar_t modName[MAX_PATH];
                        if (GetModuleFileNameExW(hProc, hMods[i], modName, MAX_PATH)) {
                            wchar_t* pName = wcsrchr(modName, L'\\');
                            if (pName) pName++;
                            else pName = modName;
                            std::wstring name = pName;
                            if (name == L"clr.dll" || name == L"v8.dll" || name == L"jvm.dll" ||
                                name == L"mozjs.dll" || name.find(L"python") != std::wstring::npos) {
                                g_JITProcesses.insert(pe.th32ProcessID);
                                break;
                            }
                        }
                    }
                }
                CloseHandle(hProc);
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    g_JITLastUpdate = std::chrono::steady_clock::now();
}

static bool IsJITProcess(DWORD pid) {
    std::lock_guard<std::mutex> lock(g_JITMutex);
    return g_JITProcesses.find(pid) != g_JITProcesses.end();
}

//检测BSJB签名（.NET JIT区域）
static bool HasBSJBSignature(HANDLE hProcess, LPCVOID addr) {
    uint8_t buffer[8];
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, addr, buffer, 4, &read) || read != 4) return false;
    // BSJB = 0x42 0x53 0x4A 0x42 (little endian)
    if (buffer[0] == 0x42 && buffer[1] == 0x53 && buffer[2] == 0x4A && buffer[3] == 0x42)
        return true;
    return false;
}

// 进程树构建 
static void BuildProcessTree() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return;
    }
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    g_ProcessMap.clear();
    do {
        ProcessInfo info;
        info.pid = pe.th32ProcessID;
        info.ppid = pe.th32ParentProcessID;
        info.processName = pe.szExeFile;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (hProc) {
            WCHAR path[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
                info.imagePath = path;
            }
            GetProcessCommandLine(hProc, info.commandLine);
            FILETIME exit, kernel, user;
            if (GetProcessTimes(hProc, &info.createTime, &exit, &kernel, &user)) {
                // filled
            }
            CloseHandle(hProc);
        }
        g_ProcessMap[info.pid] = info;
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
}

// 父进程规则应用
static void ApplyParentChildRules(const ProcessInfo& child, const ProcessInfo& parent, ScanResult& result) {
    if (child.pid == 0 || parent.pid == 0) return;

    std::wstring childName = child.processName;
    std::wstring parentName = parent.processName;
    std::transform(childName.begin(), childName.end(), childName.begin(), ::towlower);
    std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::towlower);

    bool parentOffice = (parentName.find(L"winword") != std::wstring::npos ||
                         parentName.find(L"excel") != std::wstring::npos ||
                         parentName.find(L"powerpnt") != std::wstring::npos ||
                         parentName.find(L"outlook") != std::wstring::npos);
    bool parentPDF = (parentName.find(L"acrord32") != std::wstring::npos ||
                      parentName.find(L"foxitreader") != std::wstring::npos);
    bool parentBrowser = (parentName.find(L"chrome") != std::wstring::npos ||
                          parentName.find(L"firefox") != std::wstring::npos ||
                          parentName.find(L"edge") != std::wstring::npos ||
                          parentName.find(L"iexplore") != std::wstring::npos);
    bool childScript = (childName == L"powershell.exe" || childName == L"wscript.exe" ||
                        childName == L"cscript.exe" || childName == L"mshta.exe" ||
                        childName == L"cmd.exe");

    if ((parentOffice || parentPDF || parentBrowser) && childScript) {
        result.hasSuspiciousParent = true;
        if (parentOffice && childName == L"powershell.exe") {
            if (child.commandLine.find(L"-Enc") != std::wstring::npos ||
                child.commandLine.find(L"-e") != std::wstring::npos) {
                result.hasC2Beacon = true;
            }
        }
    }

    if (parentName == L"svchost.exe") {
        if (parent.commandLine.find(L"-k netsvcs") != std::wstring::npos ||
            parent.commandLine.find(L"-k") != std::wstring::npos) {
            if (childName == L"cmd.exe") {
                result.hasSuspiciousParent = true;
                result.hasC2Beacon = true;
            }
        }
    }

    // msbuild.exe 编译恶意代码 -> 子进程外部连接
    if (parentName == L"msbuild.exe") {
        if (childName == L"powershell.exe" || childName == L"cmd.exe") {
            result.hasMsbuildCompile = true;
            if (ProcessHasExternalIPConnection(child.pid)) {
                result.hasC2Beacon = true;
            }
        }
    }

    // regsvr32 /s /u /i:http 下载执行
    if (parentName == L"regsvr32.exe") {
        if (parent.commandLine.find(L"/s") != std::wstring::npos &&
            parent.commandLine.find(L"/u") != std::wstring::npos &&
            parent.commandLine.find(L"/i:") != std::wstring::npos) {
            result.hasRegsvr32Download = true;
            if (parent.commandLine.find(L"http") != std::wstring::npos) {
                result.hasRegsvr32Download = true;
            }
        }
    }

    // rundll32 加载非系统DLL且内存异常
    if (parentName == L"rundll32.exe") {
        // 检查是否加载了非系统DLL，可以在模块遍历中处理
        // 此处仅标记，后续在CheckProcess中结合内存异常
        result.hasRundll32Suspicious = true;
    }
}

// 网络监控线程 
static void NetworkMonitorThread() {
    while (!g_StopRequested) {
        WaitForSingleObject(g_hExitEvent,10000); // 10秒间隔
        if (g_StopRequested) break;

        // 获取TCP连接
        MIB_TCPTABLE_OWNER_PID* pTcpTable = NULL;
        DWORD dwSize = 0;
        if (GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
            continue;
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
        if (!pTcpTable) continue;
        DWORD result = GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (result != NO_ERROR) {
            free(pTcpTable);
            continue;
        }

        std::map<DWORD, int> connCount;
        std::map<DWORD, std::map<std::string, std::vector<FILETIME>>> beaconTargets;
        FILETIME now;
        GetSystemTimeAsFileTime(&now);

        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
            if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
            DWORD remoteAddr = row.dwRemoteAddr;
            BYTE a = (remoteAddr >> 0) & 0xFF;
            BYTE b = (remoteAddr >> 8) & 0xFF;
            BYTE c = (remoteAddr >> 16) & 0xFF;
            BYTE d = (remoteAddr >> 24) & 0xFF;
            if (a == 10 || (a == 172 && (b >= 16 && b <= 31)) || (a == 192 && b == 168) || a == 127)
                continue;
            if (remoteAddr == 0) continue;
            char ipStr[16];
            sprintf_s(ipStr, sizeof(ipStr), "%d.%d.%d.%d", a, b, c, d);
            DWORD pid = row.dwOwningPid;
            connCount[pid]++;
            if (IsMaliciousIP(ipStr)) {
                connCount[pid] += 20;
            }
            beaconTargets[pid][ipStr].push_back(now);
        }
        free(pTcpTable);

        // UDP (DNS) 简单
        MIB_UDPTABLE_OWNER_PID* pUdpTable = NULL;
        dwSize = 0;
        if (GetExtendedUdpTable(NULL, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
            if (pUdpTable) {
                if (GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                    for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                        MIB_UDPROW_OWNER_PID row = pUdpTable->table[i];
                        if (row.dwLocalPort == htons(53)) {
                            DWORD pid = row.dwOwningPid;
                            connCount[pid] += 1;
                        }
                    }
                }
                free(pUdpTable);
            }
        }

        std::lock_guard<std::mutex> lock(g_C2Mutex);
        g_C2BeaconMap.clear();
        {
            std::lock_guard<std::mutex> tlock(g_TimelineMutex);
            for (auto& kv : connCount) {
                if (kv.second >= 5) {
                    g_C2BeaconMap[kv.first] = kv.second;
                }
                auto itTargets = beaconTargets.find(kv.first);
                if (itTargets != beaconTargets.end()) {
                    for (auto& ipEntry : itTargets->second) {
                        auto& times = ipEntry.second;
                        if (times.size() >= 3) {
                            std::vector<ULONGLONG> intervals;
                            for (size_t i = 1; i < times.size(); i++) {
                                ULARGE_INTEGER ul1, ul2;
                                ul1.LowPart = times[i-1].dwLowDateTime;
                                ul1.HighPart = times[i-1].dwHighDateTime;
                                ul2.LowPart = times[i].dwLowDateTime;
                                ul2.HighPart = times[i].dwHighDateTime;
                                intervals.push_back((ul2.QuadPart - ul1.QuadPart) / 10000);
                            }
                            if (intervals.size() >= 2) {
                                double avg = 0;
                                for (auto v : intervals) avg += v;
                                avg /= intervals.size();
                                double variance = 0;
                                for (auto v : intervals) variance += (v - avg) * (v - avg);
                                variance /= intervals.size();
                                if (variance < 90000) {
                                    g_C2BeaconMap[kv.first] += 10;
                                }
                            }
                        }
                        if (times.size() >= 3) {
                            std::vector<ULONGLONG> intervals;
                            for (size_t i = 1; i < times.size(); i++) {
                                ULARGE_INTEGER ul1, ul2;
                                ul1.LowPart = times[i-1].dwLowDateTime;
                                ul1.HighPart = times[i-1].dwHighDateTime;
                                ul2.LowPart = times[i].dwLowDateTime;
                                ul2.HighPart = times[i].dwHighDateTime;
                                intervals.push_back((ul2.QuadPart - ul1.QuadPart) / 10000);
                            }
                            if (intervals.size() >= 2) {
                                double avg = 0;
                                for (auto v : intervals) avg += v;
                                avg /= intervals.size();
                                double variance = 0;
                                for (auto v : intervals) variance += (v - avg) * (v - avg);
                                variance /= intervals.size();
                                if (avg > 200000 && variance < avg * 0.3) {
                                    g_C2BeaconMap[kv.first] += 15;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// 进程CPU使用率管理
static void UpdateProcessCPUUsage(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;
    FILETIME create, exit, kernel, user;
    if (GetProcessTimes(hProc, &create, &exit, &kernel, &user)) {
        std::lock_guard<std::mutex> lock(g_CPUMutex);
        auto& info = g_ProcessCPU[pid];
        info.createTime = create;
        info.kernelTime = kernel;
        info.userTime = user;
        info.lastUpdate = std::chrono::steady_clock::now();
    }
    CloseHandle(hProc);
}

static double GetProcessCPUUsage(DWORD pid) {
    std::lock_guard<std::mutex> lock(g_CPUMutex);
    auto it = g_ProcessCPU.find(pid);
    if (it == g_ProcessCPU.end()) return 0.0;
    auto& info = it->second;
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - info.lastUpdate).count();
    if (elapsed < 100) return 0.0;
    ULARGE_INTEGER k1, u1, k2, u2;
    k1.LowPart = info.kernelTime.dwLowDateTime; k1.HighPart = info.kernelTime.dwHighDateTime;
    u1.LowPart = info.userTime.dwLowDateTime; u1.HighPart = info.userTime.dwHighDateTime;
    // 再次获取当前时间
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return 0.0;
    FILETIME create, exit, kernel2, user2;
    if (!GetProcessTimes(hProc, &create, &exit, &kernel2, &user2)) {
        CloseHandle(hProc);
        return 0.0;
    }
    CloseHandle(hProc);
    k2.LowPart = kernel2.dwLowDateTime; k2.HighPart = kernel2.dwHighDateTime;
    u2.LowPart = user2.dwLowDateTime; u2.HighPart = user2.dwHighDateTime;
    ULONGLONG total1 = k1.QuadPart + u1.QuadPart;
    ULONGLONG total2 = k2.QuadPart + u2.QuadPart;
    ULONGLONG diff = (total2 - total1) / 10000; // ms
    double cpu = (double)diff / elapsed * 100.0;
    // 更新缓存
    info.kernelTime = kernel2;
    info.userTime = user2;
    info.lastUpdate = now;
    return cpu;
}

static double GetSystemCPUUsage() {
    static ULARGE_INTEGER lastIdle, lastKernel, lastUser;
    FILETIME idle, kernel, user;
    if (!GetSystemTimes(&idle, &kernel, &user)) return 0.0;
    ULARGE_INTEGER i, k, u;
    i.LowPart = idle.dwLowDateTime; i.HighPart = idle.dwHighDateTime;
    k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
    ULONGLONG idleDiff = i.QuadPart - lastIdle.QuadPart;
    ULONGLONG kernelDiff = k.QuadPart - lastKernel.QuadPart;
    ULONGLONG userDiff = u.QuadPart - lastUser.QuadPart;
    ULONGLONG total = kernelDiff + userDiff;
    if (total == 0) return 0.0;
    double usage = (double)(total - idleDiff) / total * 100.0;
    lastIdle = i; lastKernel = k; lastUser = u;
    return usage;
}

//主动扫描线程 
static void ActiveScanThread() {
    while (!g_StopRequested) {
        WaitForSingleObject(g_hExitEvent,90000);
        if (g_StopRequested) break;

        // 检查系统CPU
        double sysCPU = GetSystemCPUUsage();
        g_SystemCPUUsage = sysCPU;
        if (sysCPU > 70.0) {
            wprintf(L"[INFO] System CPU high (%.1f%%), skipping active scan.\n", sysCPU);
            continue;
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (!Process32FirstW(hSnap, &pe)) {
            CloseHandle(hSnap);
            continue;
        }

        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        std::vector<DWORD> pids;

        do {
            pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(hSnap, &pe));
        CloseHandle(hSnap);

        for (DWORD pid : pids) {
            if (g_StopRequested) break;

            // 仅扫描近5分钟CPU > 3%的进程
            double cpu = GetProcessCPUUsage(pid);
            if (cpu < 3.0) continue;

            // 冷却
            bool shouldLightScan = true;
            {
                std::lock_guard<std::mutex> lock(g_LightScanMutex);
                auto it = g_LastLightScanTime.find(pid);
                if (it != g_LastLightScanTime.end()) {
                    ULARGE_INTEGER ulLast, ulNow;
                    ulLast.LowPart = it->second.dwLowDateTime;
                    ulLast.HighPart = it->second.dwHighDateTime;
                    ulNow.LowPart = now.dwLowDateTime;
                    ulNow.HighPart = now.dwHighDateTime;
                    ULONGLONG diff = (ulNow.QuadPart - ulLast.QuadPart) / 10000000;
                    if (diff < LIGHT_SCAN_COOLDOWN_SEC) {
                        shouldLightScan = false;
                    }
                }
                if (shouldLightScan) {
                    g_LastLightScanTime[pid] = now;
                }
            }
            if (!shouldLightScan) continue;

            // 轻量级扫描
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hProc) continue;
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            LPCVOID addr = si.lpMinimumApplicationAddress;
            LPCVOID maxAddr = si.lpMaximumApplicationAddress;
            bool suspicious = false;
            while (addr < maxAddr) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
                    break;
                if (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                    if (mbi.RegionSize > 2*1024*1024) {
                        suspicious = true;
                        break;
                    }
                }
                uintptr_t nextAddr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                if (nextAddr <= (uintptr_t)addr) break;
                addr = (LPCVOID)nextAddr;
                if ((uintptr_t)addr >= (uintptr_t)maxAddr) break;
            }
            CloseHandle(hProc);

            if (suspicious) {
                wchar_t name[MAX_PATH];
                DWORD size = MAX_PATH;
                HANDLE hProc2 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (hProc2) {
                    if (QueryFullProcessImageNameW(hProc2, 0, name, &size)) {
                        std::wstring wname = name;
                        size_t pos = wname.find_last_of(L'\\');
                        if (pos != std::wstring::npos) wname = wname.substr(pos+1);
                        ScanResult result = CheckProcess(pid, wname);
                        if (result.finalScore >= 65 && ((result.hasC2Beacon) || (result.hasSuspiciousParent)) && withUi) {
                            MessagetoControlCenter_by_MemoryGuard message = {};
                            lstrcpyA(message.type, "MemoryGuard");
                            message.PID = pid;
                            message.ParentPID = GetParentProcessId(pid);
                            lstrcpyA(message.path, GetProcessPathByPID(pid).c_str());
                            message.score = (int)result.finalScore;
                            std::thread server(ClientThread_to_ControlCenter, &message);
                            server.join();
                        }
                    }
                    CloseHandle(hProc2);
                }
            }
        }
    }
}

//攻击链时序关联引擎
static void AttackChainDetector(ScanResult& result, DWORD pid) {
    std::lock_guard<std::mutex> lock(g_TimelineMutex);
    auto& events = g_Timeline[pid];
    if (events.empty()) return;

    FILETIME now;
    GetSystemTimeAsFileTime(&now);

    bool parentOffice = false;
    bool childScript = false;
    FILETIME parentTime = {0};
    FILETIME childTime = {0};
    for (auto& ev : events) {
        if (ev.type == EVT_PROCESS_CREATE) {
            if (ev.detail.find(L"winword") != std::wstring::npos ||
                ev.detail.find(L"excel") != std::wstring::npos ||
                ev.detail.find(L"powerpnt") != std::wstring::npos ||
                ev.detail.find(L"outlook") != std::wstring::npos ||
                ev.detail.find(L"acrord32") != std::wstring::npos ||
                ev.detail.find(L"foxitreader") != std::wstring::npos) {
                parentOffice = true;
                parentTime = ev.timestamp;
            }
            if (ev.detail.find(L"powershell.exe") != std::wstring::npos ||
                ev.detail.find(L"cmd.exe") != std::wstring::npos ||
                ev.detail.find(L"wscript.exe") != std::wstring::npos ||
                ev.detail.find(L"cscript.exe") != std::wstring::npos) {
                childScript = true;
                childTime = ev.timestamp;
            }
        }
    }
    if (parentOffice && childScript) {
        ULARGE_INTEGER ulParent, ulChild;
        ulParent.LowPart = parentTime.dwLowDateTime;
        ulParent.HighPart = parentTime.dwHighDateTime;
        ulChild.LowPart = childTime.dwLowDateTime;
        ulChild.HighPart = childTime.dwHighDateTime;
        ULONGLONG diff = (ulChild.QuadPart - ulParent.QuadPart) / 10000; // ms
        if (diff < 10000 && ProcessHasExternalIPConnection(pid)) { // 10秒
            result.hasC2Beacon = true;
            result.finalScore += 20;
        }
    }

    bool svchost = false;
    bool clrLoaded = false;
    FILETIME clrTime = {0};
    for (auto& ev : events) {
        if (ev.type == EVT_PROCESS_CREATE && ev.detail.find(L"svchost.exe") != std::wstring::npos) {
            svchost = true;
        }
        if (ev.type == EVT_IMAGE_LOAD && ev.detail.find(L"clr.dll") != std::wstring::npos) {
            clrLoaded = true;
            clrTime = ev.timestamp;
        }
    }
    if (svchost && clrLoaded) {
        for (auto& ev : events) {
            if (ev.type == EVT_MEMORY_ANOMALY) {
                ULARGE_INTEGER ulClr, ulMem;
                ulClr.LowPart = clrTime.dwLowDateTime;
                ulClr.HighPart = clrTime.dwHighDateTime;
                ulMem.LowPart = ev.timestamp.dwLowDateTime;
                ulMem.HighPart = ev.timestamp.dwHighDateTime;
                ULONGLONG diff = (ulMem.QuadPart - ulClr.QuadPart) / 10000;
                if (diff < 10000) {
                    result.hasClrInNonManaged = true;
                    result.finalScore += 15;
                    break;
                }
            }
        }
    }

    // 规则：msbuild编译后子进程连接
    for (auto& ev : events) {
        if (ev.type == EVT_PROCESS_CREATE && ev.detail.find(L"msbuild.exe") != std::wstring::npos) {
            // 检查是否有子进程的外部连接
            if (ProcessHasExternalIPConnection(pid)) {
                result.hasMsbuildCompile = true;
                result.hasC2Beacon = true;
            }
        }
    }
}

// 恶意IP加载与检查
static void LoadMaliciousIPs() {
    // 获取程序自身所在目录（ANSI 路径）
    char exePathA[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePathA, MAX_PATH) == 0) {
        // 失败则使用默认
        std::lock_guard<std::mutex> lock(g_MaliciousIPsMutex);
        g_MaliciousIPs.insert("5.5.5.5");
        g_MaliciousIPs.insert("6.6.6.6");
        wprintf(L"[WARN] Cannot get module path, using default IPs.\n");
        return;
    }

    // 截断到目录（去掉文件名，保留尾部反斜杠）
    char* pLastSlash = strrchr(exePathA, '\\');
    if (pLastSlash) {
        *(pLastSlash + 1) = '\0';          // 保留目录
    } else {
        // 无路径（理论上不会发生）
        exePathA[0] = '\0';
    }

    // 拼接 "malicious.txt"
    strcat_s(exePathA, MAX_PATH, "WhiteList\\malicious.txt");

    // 尝试打开文件
    std::ifstream file(exePathA);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            // 忽略空行和注释行（以 # 开头）
            if (!line.empty() && line[0] != '#') {
                // 去除末尾可能存在的回车符
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                std::lock_guard<std::mutex> lock(g_MaliciousIPsMutex);
                g_MaliciousIPs.insert(line);
            }
        }
        file.close();
        wprintf(L"[+] Loaded %zu malicious IPs from %hs.\n", g_MaliciousIPs.size(), exePathA);
    } else {
        // 文件不存在或无法读取，使用默认测试 IP
        std::lock_guard<std::mutex> lock(g_MaliciousIPsMutex);
        g_MaliciousIPs.insert("5.5.5.5");
        g_MaliciousIPs.insert("6.6.6.6");
        wprintf(L"[WARN] Malicious IP file '%hs' not found, using defaults.\n", exePathA);
    }
}

static bool IsMaliciousIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(g_MaliciousIPsMutex);
    return g_MaliciousIPs.find(ip) != g_MaliciousIPs.end();
}

//字符串熵值
static double CalculateEntropyString(const std::string& str) {
    if (str.empty()) return 0.0;
    int freq[256] = {0};
    for (char c : str) freq[(unsigned char)c]++;
    double entropy = 0.0;
    for (int i=0;i<256;i++) {
        if (freq[i]) {
            double p = (double)freq[i] / str.size();
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

//清理线程
static void CleanupThread() {
    while (!g_StopCleanup && !g_StopRequested) {
        WaitForSingleObject(g_hExitEvent,30000);
        if (g_StopCleanup || g_StopRequested) break;

        // 清理已退出进程的缓存
        std::set<DWORD> activePids;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    activePids.insert(pe.th32ProcessID);
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }

        // 清理g_LastScanInfo
        {
            std::lock_guard<std::mutex> lock(g_LastScanMutex);
            for (auto it = g_LastScanInfo.begin(); it != g_LastScanInfo.end();) {
                if (activePids.find(it->first) == activePids.end()) {
                    it = g_LastScanInfo.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // 清理g_ProcessCPU
        {
            std::lock_guard<std::mutex> lock(g_CPUMutex);
            for (auto it = g_ProcessCPU.begin(); it != g_ProcessCPU.end();) {
                if (activePids.find(it->first) == activePids.end()) {
                    it = g_ProcessCPU.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // 清理g_Timeline，每进程最多50条
        {
            std::lock_guard<std::mutex> lock(g_TimelineMutex);
            for (auto& kv : g_Timeline) {
                if (activePids.find(kv.first) == activePids.end()) {
                    kv.second.clear();
                } else if (kv.second.size() > 50) {
                    kv.second.erase(kv.second.begin(), kv.second.end() - 50);
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_LastEventTimeMutex);
            for (auto it = g_LastEventTime.begin(); it != g_LastEventTime.end(); ) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, it->first);
                if (!hProc) {
                    it = g_LastEventTime.erase(it);
                } else {
                    CloseHandle(hProc);
                    ++it;
                }
            }
        }
        {
            std::lock_guard<std::mutex> lock(g_NetConnMutex);
            for (auto it = g_ProcessConnIPs.begin(); it != g_ProcessConnIPs.end(); ) {
                if (activePids.find(it->first) == activePids.end()) {
                    it = g_ProcessConnIPs.erase(it);
                } else {
                    ++it;
                }
            }
            for (auto it = g_ProcessConnResetTime.begin(); it != g_ProcessConnResetTime.end(); ) {
                if (activePids.find(it->first) == activePids.end()) {
                    it = g_ProcessConnResetTime.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // 清理网络告警标记
        {
            std::lock_guard<std::mutex> lock(g_NetAlertMutex);
            for (auto it = g_NetC2Flag.begin(); it != g_NetC2Flag.end(); ) {
                if (activePids.find(it->first) == activePids.end())
                    it = g_NetC2Flag.erase(it);
                else
                    ++it;
            }
            for (auto it = g_NetLateralFlag.begin(); it != g_NetLateralFlag.end(); ) {
                if (activePids.find(it->first) == activePids.end())
                    it = g_NetLateralFlag.erase(it);
                else
                    ++it;
            }
            for (auto it = g_NetScanFlag.begin(); it != g_NetScanFlag.end(); ) {
                if (activePids.find(it->first) == activePids.end())
                    it = g_NetScanFlag.erase(it);
                else
                    ++it;
            }
        }

        // 清理进程名缓存
        {
            std::lock_guard<std::mutex> lock(g_ProcNameCacheMutex);
            for (auto it = g_ProcessNameCache.begin(); it != g_ProcessNameCache.end(); ) {
                if (activePids.find(it->first) == activePids.end())
                    it = g_ProcessNameCache.erase(it);
                else
                    ++it;
            }
        }
        // 更新JIT进程缓存
        UpdateJITProcesses();
    }
}

// 信任缓存刷新线程
static void TrustRefreshThreadFunc() {
    while (!g_StopTrustRefresh && !g_StopRequested) {
        WaitForSingleObject(g_hExitEvent,3600000); // 1小时
        if (g_StopTrustRefresh || g_StopRequested) break;
        // 清空信任缓存，强制重新验证
        std::lock_guard<std::mutex> lock(g_TrustCacheExMutex);
        g_TrustCacheEx.clear();
        wprintf(L"[INFO] Trust cache cleared for refresh.\n");
    }
}

// 进程检测函数
ScanResult CheckProcess(DWORD pid, const std::wstring& processName) {
    ScanResult result;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) return result;

    // 获取文件修改时间
    FILETIME modTime = {0};
    wchar_t imagePathTmp[MAX_PATH];
    DWORD sizePath = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, imagePathTmp, &sizePath)) {
        HANDLE hFile = CreateFileW(imagePathTmp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            GetFileTime(hFile, NULL, NULL, &modTime);
            CloseHandle(hFile);
        }
        result.imagePath = imagePathTmp;
    }

    if (IsInWhiteList(result.imagePath)) {
        result.finalScore = 0.0;
        result.baseScore = 0.0;
        CloseHandle(hProcess);
        return result;
    }

    if (pNtQueryInformationProcess) {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLen;
        NTSTATUS status = pNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &pbi, sizeof(pbi), &returnLen);
        if (NT_SUCCESS(status)) {
            result.ppid = (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId;
        }
    }

    bool isHighTrust = IsHighTrust(result.imagePath, modTime, pid, result.ppid);

    FILETIME exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &result.createTime, &exitTime, &kernelTime, &userTime)) {
    }

    GetProcessCommandLine(hProcess, result.commandLine);

    BOOL isWow64 = FALSE;
    IsWow64Process(hProcess, &isWow64);

    bool hasPersistence, hasLateral;
    if (HasSuspiciousCommandLineEx(result.commandLine, hasPersistence, hasLateral)) {
        result.hasSuspiciousCmdLine = true;
        {
            std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
            auto it = g_ProcessMap.find(result.ppid);
            if (it != g_ProcessMap.end()) {
                std::wstring parentName = it->second.processName;
                std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::towlower);
                if (parentName == L"explorer.exe" || parentName == L"cmd.exe") {
                    // 重置可疑命令行标志
                    result.hasSuspiciousCmdLine = false;
                    hasPersistence = false;
                    hasLateral = false;
                }
            }
        }
        if (hasPersistence) result.hasPersistenceCandidate = true;
        if (hasLateral) result.hasLateralCandidate = true;
    }

    CheckPEBDebugFlags(hProcess, isWow64 != FALSE, result);

    //级内存扫描
    bool suspiciousMemory = false;
    std::vector<LPCVOID> level1Regions;      // 一级：属性可疑
    std::vector<LPCVOID> level2Regions;      // 二级：熵/执行流可疑
    std::vector<LPCVOID> level3Regions;      // 三级：深度解析（最多5个）

    bool hasJITEngine = false;
    bool hasClr = false;

    // 获取模块列表，同时检测JIT引擎
    std::vector<MODULEENTRY32W> modules;
    HANDLE hModuleSnap = SafeCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hModuleSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hModuleSnap, &me)) {
            do {
                modules.push_back(me);
                std::wstring modName = me.szModule;
                if (modName == L"clr.dll" || modName == L"mscoree.dll")
                    hasClr = true;
                if (modName == L"clr.dll" || modName == L"mscoree.dll" ||
                    modName == L"jvm.dll" || modName == L"v8.dll" ||
                    modName == L"mozjs.dll" || modName.find(L"python") != std::wstring::npos) {
                    hasJITEngine = true;
                }
                // 其他模块检测（PE异常、模块异常等）
                IMAGE_DOS_HEADER dos;
                SIZE_T bytesRead;
                bool peValid = false;
                if (ReadProcessMemory(hProcess, me.modBaseAddr, &dos, sizeof(dos), &bytesRead) &&
                    bytesRead == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
                    WORD magic = 0;
                    LPCVOID magicAddr = (LPCVOID)((uintptr_t)me.modBaseAddr + dos.e_lfanew + 0x18);
                    if (ReadProcessMemory(hProcess, magicAddr, &magic, sizeof(magic), &bytesRead) && bytesRead == sizeof(magic)) {
                        if (magic == 0x010B || magic == 0x020B) {
                            DWORD signature = 0;
                            LPCVOID ntAddr = (LPCVOID)((uintptr_t)me.modBaseAddr + dos.e_lfanew);
                            if (ReadProcessMemory(hProcess, ntAddr, &signature, sizeof(signature), &bytesRead) &&
                                bytesRead == sizeof(signature) && signature == IMAGE_NT_SIGNATURE)
                                peValid = true;
                        }
                    }
                }
                if (!peValid) result.hasPEAnomaly = true;

                MEMORY_BASIC_INFORMATION mbiMod;
                if (VirtualQueryEx(hProcess, me.modBaseAddr, &mbiMod, sizeof(mbiMod)) == sizeof(mbiMod)) {
                    if (mbiMod.Type != MEM_IMAGE) result.hasModuleInc = true;
                } else result.hasModuleInc = true;

                if (!result.hasCodeWrite) {
                    if (IsTextSectionWritableEx(hProcess, (uint64_t)me.modBaseAddr))
                        result.hasCodeWrite = true;
                }

                // 扩展模块完整性校验

                if (CheckExtendedInlineHook(hProcess, me, modules))
                    result.hasInlineHookExt = true;

                if (CheckChecksum(hProcess, me))
                    result.hasCodeSignFailed = true;

                if (CheckCOMHijacking(me))
                    result.hasCOMHijacking = true;

                bool isSigned, isExpired, isSelfSigned;
                if (VerifySignatureEx(me.szExePath, isSigned, isExpired, isSelfSigned)) {
                    // 签名有效，后续降权
                } else {
                    std::wstring path = me.szExePath;
                    std::transform(path.begin(), path.end(), path.begin(), ::towlower);
                    if (path.find(L"\\temp\\") != std::wstring::npos ||
                        path.find(L"\\downloads\\") != std::wstring::npos ||
                        path.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
                        result.hasInvalidSignature = true;
                    }
                }

                CheckDynamicAPIDetection(hProcess, me, result);
                CheckDirectSyscall(hProcess, me, result);
                CheckDLLSideLoad(hProcess, pid, me, result);
                CheckSyscallStubs(hProcess, me, result);

            } while (Module32NextW(hModuleSnap, &me));
        }
        CloseHandle(hModuleSnap);
    }

    // 其他检测
    CheckAMSIBypass(hProcess, result);
    CheckThreadlessInjection(hProcess, modules, result);
    if (!modules.empty()) {
        CheckDoppelgangV2(hProcess, modules[0].szExePath, result);
        CheckProcessDoppelgangingAdvanced(hProcess, modules[0].szExePath, result);
    }
    if (CheckLateralMovementModules(modules))
        result.hasLateralCandidate = true;

    //一级扫描：内存属性
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LPCVOID addr = si.lpMinimumApplicationAddress;
    LPCVOID maxAddr = si.lpMaximumApplicationAddress;
    if (isWow64) {
        addr = (LPCVOID)0x10000;
        maxAddr = (LPCVOID)0xFFFFFFFF;
    }

    // 获取JIT状态
    bool isJITProcess = IsJITProcess(pid);
    if (isJITProcess) {
        // 更新JIT引擎标志
        hasJITEngine = true;
    }

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        // 跳过MEM_IMAGE区域
        if (mbi.Type == MEM_IMAGE) {
            goto next_region;
        }

        // 一级条件：MEM_PRIVATE + (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ) 且 >2MB
        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ))) {
            if (mbi.RegionSize > 2 * 1024 * 1024) {
                // JIT豁免：若为JIT进程且区域<=10MB，跳过
                if (isJITProcess && mbi.RegionSize <= 10 * 1024 * 1024) {
                    // 但检查是否包含BSJB签名
                    if (HasBSJBSignature(hProcess, mbi.BaseAddress)) {
                        // .NET JIT区域，豁免
                        goto next_region;
                    }
                }
                level1Regions.push_back(mbi.BaseAddress);
            }
        }

        // 对于PAGE_EXECUTE_READWRITE，若为MEM_MAPPED且签名有效，跳过
        if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.Type == MEM_MAPPED) {
            if (pNtQueryVirtualMemory) {
                MEMORY_SECTION_NAME sectionName;
                SIZE_T returnLen;
                NTSTATUS status = pNtQueryVirtualMemory(hProcess, (PVOID)mbi.BaseAddress, MemorySectionName,
                                                        &sectionName, sizeof(sectionName), &returnLen);
                if (status == STATUS_SUCCESS && returnLen > sizeof(UNICODE_STRING)) {
                    if (sectionName.SectionFileName.Buffer && sectionName.SectionFileName.Length > 0) {
                        std::wstring mappedPath(sectionName.SectionFileName.Buffer, sectionName.SectionFileName.Length / sizeof(wchar_t));
                        bool isSigned, isExpired, isSelfSigned;
                        if (VerifySignatureEx(mappedPath.c_str(), isSigned, isExpired, isSelfSigned)) {
                            if (isSigned) {
                                goto next_region;
                            }
                        }
                    }
                }
            }
        }

next_region:
        uintptr_t nextAddr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddr <= (uintptr_t)addr) break;
        addr = (LPCVOID)nextAddr;
        if ((uintptr_t)addr >= (uintptr_t)maxAddr) break;
    }

    //二级扫描：对一级区域读取前4KB，计算熵和shellcode特征
    for (auto region : level1Regions) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, region, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
        size_t readSize = std::min(mbi.RegionSize, (SIZE_T)4096);
        std::vector<uint8_t> buffer(readSize);
        SIZE_T read;
        if (!ReadProcessMemory(hProcess, region, buffer.data(), readSize, &read) || read != readSize)
            continue;
        double entropy = CalculateEntropy(buffer.data(), readSize);
        bool hasExecFlow = HasExecutionFlowFeatures(buffer.data(), readSize);
        // 若熵>7.5 且 有执行流特征，或熵>7.8，则进入三级
        if ((entropy > 7.5 && hasExecFlow) || entropy > 7.8) {
            level2Regions.push_back(region);
        }
        //若区域包含PE头，也进入三级
        if (IsMemoryContainPE(hProcess, region)) {
            level2Regions.push_back(region);
        }
    }

    //三级扫描：深度解析，最多5个区域
    size_t level3Count = 0;
    for (auto region : level2Regions) {
        if (level3Count >= 5) break;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, region, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;

        // 深度检测
        bool isJit = (hasJITEngine && mbi.Type == MEM_PRIVATE);
        if (!isJit || (isJit && mbi.RegionSize > 10 * 1024 * 1024)) {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize > 4096 && mbi.Type == MEM_PRIVATE) {
                result.hasRWX = true;
            }
            if ((mbi.AllocationProtect & PAGE_READWRITE) && (mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                result.hasRWX = true;
            }
        }

        if (IsExecutablePrivateMemory(hProcess, region, modules)) {
            if (IsMemoryContainPE(hProcess, region)) {
                result.hasReflectiveInjection = true;
            }
        }
        if (CheckReflectiveShellcodeEx(hProcess, region, mbi.RegionSize, modules)) {
            result.hasReflectiveShellcode = true;
        }
        if (CheckFilelessPE(hProcess, region, result)) {
        }

        level3Count++;
    }

    // 脚本引擎字符串扫描（在所有可疑区域）
    if (CheckScriptEngineStrings(hProcess, level1Regions))
        result.hasScriptEngine = true;

    // CLR检测
    static const std::vector<std::wstring> nonManagedProcesses = {
        L"explorer.exe", L"svchost.exe", L"winlogon.exe", L"lsass.exe",
        L"services.exe", L"csrss.exe", L"smss.exe", L"wininit.exe"
    };
    bool isNonManaged = false;
    for (auto& name : nonManagedProcesses) {
        if (processName == name) {
            isNonManaged = true;
            break;
        }
    }
    if (isNonManaged && hasClr) {
        if (!level1Regions.empty())
            result.hasClrInNonManaged = true;
    }
    std::wstring lowerProc = processName;
    std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::towlower);
    if ((lowerProc == L"winword.exe" || lowerProc == L"excel.exe" || lowerProc == L"chrome.exe") && hasJITEngine) {
        result.hasClrInNonManaged = false;
    }

    //钩子检测
    for (auto& mod : modules) {
        std::wstring modName = mod.szModule;
        if (modName == L"ntdll.dll") {
            if (CheckInlineHook(hProcess, mod.szExePath, "NtCreateThreadEx", (uint64_t)mod.modBaseAddr) ||
                CheckInlineHook(hProcess, mod.szExePath, "NtWriteVirtualMemory", (uint64_t)mod.modBaseAddr) ||
                CheckInlineHook(hProcess, mod.szExePath, "NtProtectVirtualMemory", (uint64_t)mod.modBaseAddr)) {
                result.hasInlineHook = true;
            }
            break;
        }
    }

    for (auto& mod : modules) {
        if (CheckIATHook(hProcess, mod, modules)) {
            result.hasIATHook = true;
            break;
        }
    }

    for (auto& mod : modules) {
        if (CheckIATHookEx(hProcess, mod, modules)) {
            result.hasIATHookEx = true;
            break;
        }
    }

    if (CheckProcessHollowing(hProcess, pid, modules))
        result.hasProcessHollow = true;

    // 线程注入检测
    HANDLE hThreadSnap = SafeCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hThreadSnap, &te)) {
            int abnormalThreads = 0;
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!hThread) continue;

                uint64_t startAddr = 0;
                if (pNtQueryInformationThread) {
                    NTSTATUS status = pNtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddr, sizeof(startAddr), NULL);
                    if (status == STATUS_SUCCESS && startAddr != 0) {
                        if (!IsAddressInModule(startAddr, modules)) {
                            MEMORY_BASIC_INFORMATION mbi3;
                            if (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &mbi3, sizeof(mbi3)) == sizeof(mbi3)) {
                                DWORD execFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                                if (mbi3.Type == MEM_PRIVATE && (mbi3.Protect & execFlags)) {
                                    abnormalThreads++;
                                    result.hasThreadContextExAbnormal = true;
                                }
                            }
                        }
                    }
                }
                CloseHandle(hThread);
                if (abnormalThreads > 3) {
                    result.hasThreadContextExAbnormal = true;
                    break;
                }
            } while (Thread32Next(hThreadSnap, &te));
        }
        CloseHandle(hThreadSnap);
    }

    if (CheckAPCInjection(hProcess, pid, modules))
        result.hasAPCInjection = true;

    if (CheckPROPagateForProcess(hProcess, modules))
        result.hasPROPagate = true;

    CheckSandboxAndPipeStrings(hProcess, result);
    ScanAllRegionsForIOC(hProcess, result);

    // 时序关联 
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ulNow, ulCreate;
    ulNow.LowPart = now.dwLowDateTime;
    ulNow.HighPart = now.dwHighDateTime;
    ulCreate.LowPart = result.createTime.dwLowDateTime;
    ulCreate.HighPart = result.createTime.dwHighDateTime;
    ULONGLONG diff = (ulNow.QuadPart - ulCreate.QuadPart) / 10000; // ms

    if (diff < 5000 && ProcessHasExternalIPConnection(pid)) {
        result.hasC2Beacon = true;
    }
    if (diff < 10000 && result.hasRWX) {
        result.finalScore += 10;
    }

    // 父进程规则
    {
        std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
        auto it = g_ProcessMap.find(pid);
        if (it != g_ProcessMap.end()) {
            ProcessInfo childInfo = it->second;
            auto parentIt = g_ProcessMap.find(result.ppid);
            if (parentIt != g_ProcessMap.end()) {
                ApplyParentChildRules(childInfo, parentIt->second, result);
                ULARGE_INTEGER ulParentCreate;
                ulParentCreate.LowPart = parentIt->second.createTime.dwLowDateTime;
                ulParentCreate.HighPart = parentIt->second.createTime.dwHighDateTime;
                ULONGLONG parentDiff = (ulNow.QuadPart - ulParentCreate.QuadPart) / 10000;
                if (parentDiff < 30000 && ProcessHasExternalIPConnection(pid)) {
                    result.hasC2Beacon = true;
                }
            }
        }
    }

    // C2信标
    {
        std::lock_guard<std::mutex> lock(g_C2Mutex);
        if (g_C2BeaconMap.find(pid) != g_C2BeaconMap.end()) {
            result.hasC2Beacon = true;
        }
    }

    // 攻击链
    AttackChainDetector(result, pid);

    //计算分数
    double baseScore = ComputeScoreFromResult(result);
    result.baseScore = baseScore;

    if (isHighTrust) {
        result.hasSuspiciousCmdLine = false;
        result.hasScriptEngine = false;
        baseScore -= 17;
        if (baseScore < 0) baseScore = 0;
        result.finalScore = baseScore - 25;
        if (result.finalScore < 0) result.finalScore = 0;
    } else {
        if (!modules.empty()) {
            bool isSigned = false, isExpired = false, isSelfSigned = false;
            if (VerifySignatureEx(modules[0].szExePath, isSigned, isExpired, isSelfSigned)) {
                if (isSigned && !isExpired && !isSelfSigned) {
                    baseScore -= 10;
                    std::wstring lowerPath = result.imagePath;
                    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                    if (lowerPath.find(L"microsoft") != std::wstring::npos ||
                        lowerPath.find(L"google") != std::wstring::npos ||
                        lowerPath.find(L"mozilla") != std::wstring::npos) {
                        baseScore -= 15;
                    }
                }
            }
        }
        result.finalScore = baseScore;
    }

    if (isHighTrust && (result.hasCodeTamper || result.hasProcessHollow || result.hasReflectiveInjection || result.hasSSDTHook)) {
        // 保留
    }
        // 读取网络告警标记
    {
        std::lock_guard<std::mutex> lock(g_NetAlertMutex);
        if (g_NetC2Flag.find(pid) != g_NetC2Flag.end() && g_NetC2Flag[pid]) {
            result.hasC2Beacon = true;
            g_NetC2Flag[pid] = false;  // 避免重复
        }
        if (g_NetLateralFlag.find(pid) != g_NetLateralFlag.end() && g_NetLateralFlag[pid]) {
            result.hasLateralCandidate = true;
            g_NetLateralFlag[pid] = false;
        }
        if (g_NetScanFlag.find(pid) != g_NetScanFlag.end() && g_NetScanFlag[pid]) {
            // 可以添加新标志或增加分数，这里复用横向移动标记
            result.hasLateralMovement = true;
            g_NetScanFlag[pid] = false;
        }
    }

    CloseHandle(hProcess);
    return result;
}

// WorkCallback
VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    WorkContext* ctx = (WorkContext*)Context;
    DWORD pid = ctx->pid;
    FILETIME eventTime = ctx->eventTime;
    delete ctx;

    // 记录时间线
    {
        std::lock_guard<std::mutex> lock(g_TimelineMutex);
        EventNode ev;
        ev.type = EVT_PROCESS_CREATE;
        ev.timestamp = eventTime;
        ev.pid = pid;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProc) {
            wchar_t name[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, name, &size)) {
                ev.detail = name;
            }
            CloseHandle(hProc);
        }
        g_Timeline[pid].push_back(ev);
        // 限制最多50条
        if (g_Timeline[pid].size() > 50) {
            g_Timeline[pid].erase(g_Timeline[pid].begin(), g_Timeline[pid].end() - 50);
        }
    }

    // 冷却
    auto now = std::chrono::steady_clock::now();
    bool shouldScan = true;
    {
        std::lock_guard<std::mutex> lock(g_LastScanMutex);
        auto it = g_LastScanInfo.find(pid);
        if (it != g_LastScanInfo.end()) {
            if (CompareFileTime(&it->second.first, &eventTime) != 0) {
                it->second.first = eventTime;
                it->second.second = now;
            } else {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.second).count();
                if (elapsed < COOLDOWN_SECONDS) {
                    shouldScan = false;
                } else {
                    it->second.second = now;
                }
            }
        } else {
            g_LastScanInfo[pid] = std::make_pair(eventTime, now);
        }
    }

    if (!shouldScan) {
        CloseThreadpoolWork(Work);
        return;
    }

    // 获取信号量，限制并发深度扫描
    g_DeepScanSemaphore.acquire();

    // 执行扫描
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t procName[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, procName, &size)) {
            std::wstring name = procName;
            size_t pos = name.find_last_of(L'\\');
            if (pos != std::wstring::npos) name = name.substr(pos + 1);
            wprintf(L"[ETW] Event triggered for PID %d (%ls)\n", pid, name.c_str());
            ScanResult result = CheckProcess(pid, name);
            if (result.baseScore > 0) {
                wprintf(L"[%ls] PID %d score:%.2f (final:%.2f)\n", name.c_str(), pid, result.baseScore, result.finalScore);
                if (result.finalScore >= 65 && (result.hasC2Beacon || result.hasSuspiciousParent) && withUi) {
                    std::cout<<"trying to send to controlcenter"<<std::endl;
                    MessagetoControlCenter_by_MemoryGuard message = {};
                    lstrcpyA(message.type, "MemoryGuard");
                    message.PID = pid;
                    message.ParentPID = GetParentProcessId(pid);
                    lstrcpyA(message.path, GetProcessPathByPID(pid).c_str());
                    message.score = (int)result.finalScore;
                    std::thread server(ClientThread_to_ControlCenter, &message);
                    server.join(); 
                }
            }
        }
        CloseHandle(hProc);
    }

    g_DeepScanSemaphore.release();
    CloseThreadpoolWork(Work);
}

//ETW 回调
VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (g_StopRequested) return;

    // 获取事件时间戳（100ns 单位）
    ULONGLONG eventTime = pEventRecord->EventHeader.TimeStamp.QuadPart;

    //去重过滤（对所有非内存异常事件生效）
    // 当前 memoryguard 未定义 EVT_MEMORY_ANOMALY，因此所有事件均参与过滤

    // 对于 KERNEL_PROCESS_GUID 和 KERNEL_IMAGE_GUID，提取 PID
    DWORD pid = 0;
    bool isProcessEvent = false;
    bool isImageEvent = false;

    if (pEventRecord->EventHeader.ProviderId == KERNEL_PROCESS_GUID) {
        DWORD eventId = pEventRecord->EventHeader.EventDescriptor.Id;
        if (eventId == 1 || eventId == 5) {
            if (pEventRecord->UserDataLength >= 24) {
                pid = *(DWORD*)((BYTE*)pEventRecord->UserData + 0x10);
                isProcessEvent = true;
            }
        }
    }
    else if (pEventRecord->EventHeader.ProviderId == KERNEL_IMAGE_GUID) {
        if (pEventRecord->EventHeader.EventDescriptor.Id == 10) {
            if (pEventRecord->UserDataLength >= 20) {
                pid = *(DWORD*)((BYTE*)pEventRecord->UserData + 4);
                isImageEvent = true;
            }
        }
    }
    // KERNEL_THREAD_GUID 当前未使用，可不处理，也可纳入过滤（但忽略）

    // 若提取到有效 PID，则执行去重检查
    if (pid != 0) {
        std::lock_guard<std::mutex> lock(g_LastEventTimeMutex);
        auto it = g_LastEventTime.find(pid);
        if (it != g_LastEventTime.end()) {
            // 1秒 = 10,000,000 个 100ns 单位
            if (eventTime - it->second < 10000000ULL) {
                // 重复事件，直接丢弃（不进行任何后续处理）
                return;
            }
        }
        // 更新该 PID 的最后处理时间
        g_LastEventTime[pid] = eventTime;
    }

    if (pEventRecord->EventHeader.ProviderId == KERNEL_PROCESS_GUID) {
        DWORD eventId = pEventRecord->EventHeader.EventDescriptor.Id;
        if (eventId == 1 || eventId == 5) {
            if (pEventRecord->UserDataLength < 24) return;
            DWORD pid = *(DWORD*)((BYTE*)pEventRecord->UserData + 0x10);
            if (pid == 0) return;

            WorkContext* ctx = new WorkContext;
            ctx->pid = pid;
            ctx->eventTime = *(FILETIME*)&pEventRecord->EventHeader.TimeStamp;
            PTP_WORK work = CreateThreadpoolWork(WorkCallback, ctx, NULL);
            if (work) {
                SubmitThreadpoolWork(work);
            } else {
                delete ctx;
                wprintf(L"[WARN] Failed to create threadpool work for PID %d\n", pid);
            }
        }
    }
    else if (pEventRecord->EventHeader.ProviderId == KERNEL_IMAGE_GUID) {
        if (pEventRecord->EventHeader.EventDescriptor.Id == 10) {
            if (pEventRecord->UserDataLength < 20) return;
            BYTE* data = (BYTE*)pEventRecord->UserData;
            DWORD pid = *(DWORD*)(data + 4);
            FILETIME ts = *(FILETIME*)&pEventRecord->EventHeader.TimeStamp;

            {
                std::lock_guard<std::mutex> lock(g_TimelineMutex);
                EventNode ev;
                ev.type = EVT_IMAGE_LOAD;
                ev.timestamp = ts;
                ev.pid = pid;
                ev.detail = L"image_load";
                g_Timeline[pid].push_back(ev);
                if (g_Timeline[pid].size() > 50) {
                    g_Timeline[pid].erase(g_Timeline[pid].begin(), g_Timeline[pid].end() - 50);
                }
            }

            {
                std::lock_guard<std::mutex> lock(g_PendingMutex);
                auto it = g_PendingEvents.find(pid);
                if (it != g_PendingEvents.end()) {
                    if (CompareFileTime(&ts, &it->second.timestamp) > 0)
                        it->second.timestamp = ts;
                } else {
                    PendingEvent pe;
                    pe.pid = pid;
                    pe.timestamp = ts;
                    g_PendingEvents[pid] = pe;
                }
            }
        }
    }
    else if (pEventRecord->EventHeader.ProviderId == KERNEL_THREAD_GUID) {
    }
    else if (pEventRecord->EventHeader.ProviderId == KERNEL_NETWORK_GUID) {
        DWORD pid = 0;
        std::string localIP, remoteIP;
        USHORT localPort = 0, remotePort = 0;
        if (ParseNetworkEvent(pEventRecord, pid, localIP, remoteIP, localPort, remotePort)) {
            if (pid != 0) {
                // 更新统计和告警
                UpdateNetworkStats(pid, remoteIP, remotePort);
            }
        }
    }
}

//Ctrl+C 处理
BOOL WINAPI ConsoleHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
        g_StopRequested = true;
        g_StopBatch = true;
        g_StopCleanup = true;
        g_StopTrustRefresh = true;
        if (g_SessionHandle && g_pProp) {
            ControlTraceW(g_SessionHandle, SessionName, g_pProp, EVENT_TRACE_CONTROL_STOP);
        }
        return TRUE;
    }
    return FALSE;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_SHUTDOWN_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT) {
        // 在系统强制终止前，立即解除关键状态
        SetProcessCritical(false);
        return TRUE;
    }
    return FALSE;
}

//主函数
int main(int argc, char* argv[]) {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    if(argc>=2){
        if(strcmp(argv[1], "--withoutUi")==0){
            withUi=false;
            std::cout << "running without Ui" << std::endl;}
        else{
            withUi=true;
            std::cout << "running with Ui" << std::endl;
        }
    }
    else{
        withUi=true;
        std::cout << "running with Ui" << std::endl;
    }
    _setmode(_fileno(stdout), _O_U16TEXT);
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    LoadWhiteList();
    InitNTFunctions();

    if (!EnableDebugPrivilege()) {
        wprintf(L"Warning: Failed to enable debug privilege.\n");
    }
    SetProcessShutdownParameters(0x100, 0);
    InstallShutdownHandler();
    SetProcessCritical(true);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    g_hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);   // 手动重置事件
    if (!g_hExitEvent) {
        wprintf(L"[-] Failed to create exit event.\n");
        SetProcessCritical(false);
        return 1;
    }

    BOOL isElevated = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    if (!isElevated) {
        wprintf(L"[-] Not running as administrator.\n");
    }

    if (!RefreshKernelModules()) {
        wprintf(L"[-] Failed to retrieve kernel modules.\n");
    }

    CheckSecurityEnvironment();
    g_KdDebuggerEnabled = CheckKdDebugger();
    if (g_KdDebuggerEnabled) {
        wprintf(L"[INFO] Kernel debugger enabled, skipping kernel hook checks.\n");
    }

    // 执行内核检测（仅当未调试）
    ScanResult globalResult;
    if (!g_KdDebuggerEnabled) {
        CheckIDT(globalResult);
        CheckGDT(globalResult);
        CheckKernelCallbacks(globalResult);
        CheckHiddenDrivers(globalResult);
        CheckSSDT(globalResult);
        CheckShadowSSDT(globalResult);
    }

    BuildProcessTree();
    wprintf(L"[+] Process tree built, %zu processes.\n", g_ProcessMap.size());

    LoadMaliciousIPs();

    // 启动网络监控线程
    g_NetworkThread = std::thread(NetworkMonitorThread);
    wprintf(L"[+] Network monitor thread started.\n");

    // 主动扫描线程
    g_ActiveScanThread = std::thread(ActiveScanThread);
    wprintf(L"[+] Active scan thread started.\n");

    // 批处理线程
    g_BatchThread = std::thread(BatchProcessorThread);
    wprintf(L"[+] Batch processor thread started.\n");

    // 清理线程
    g_CleanupThread = std::thread(CleanupThread);
    wprintf(L"[+] Cleanup thread started.\n");

    // 信任刷新线程
    g_TrustRefreshThread = std::thread(TrustRefreshThreadFunc);
    wprintf(L"[+] Trust refresh thread started.\n");

    g_WhiteListReloadThread = std::thread([]() {
    while (!g_StopWhiteListReload && !g_StopRequested) {
        WaitForSingleObject(g_hExitEvent,5 * 60 * 1000);   // 5 分钟
        if (g_StopWhiteListReload || g_StopRequested) break;
        LoadWhiteList();
    }
    });
    wprintf(L"[+] WhiteList reload thread started.\n");

    g_ControlPipeThread = std::thread(ServerThread_ControlCenter);
    g_ControlPipeThread.detach();
    wprintf(L"[+] Control pipe server thread started (detached).\n");

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    //ETW
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SessionName) * sizeof(WCHAR) + 256;
    g_pProp = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!g_pProp) {
        wprintf(L"[-] Memory allocation failed for ETW properties.\n");
        g_StopRequested = true;
        if (g_NetworkThread.joinable()) g_NetworkThread.join();
        if (g_ActiveScanThread.joinable()) g_ActiveScanThread.join();
        if (g_BatchThread.joinable()) g_BatchThread.join();
        if (g_CleanupThread.joinable()) g_CleanupThread.join();
        if (g_TrustRefreshThread.joinable()) g_TrustRefreshThread.join();
        SetProcessCritical(false);
        return 1;
    }
    ZeroMemory(g_pProp, bufferSize);
    g_pProp->Wnode.BufferSize = bufferSize;
    g_pProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_pProp->Wnode.ClientContext = 1;
    g_pProp->Wnode.Guid = KERNEL_PROCESS_GUID;
    g_pProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_pProp->MaximumFileSize = 0;
    g_pProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    g_pProp->LogFileNameOffset = 0;
    g_pProp->BufferSize = 1024;
    g_pProp->MinimumBuffers = 4;
    g_pProp->MaximumBuffers = 16;
    g_pProp->FlushTimer = 5;

    ULONG status = StartTraceW(&g_SessionHandle, SessionName, g_pProp);
    if (status != ERROR_SUCCESS) {
        wprintf(L"[-] StartTrace failed: 0x%08lx\n", status);
        free(g_pProp);
        g_StopRequested = true;
        if (g_NetworkThread.joinable()) g_NetworkThread.join();
        if (g_ActiveScanThread.joinable()) g_ActiveScanThread.join();
        if (g_BatchThread.joinable()) g_BatchThread.join();
        if (g_CleanupThread.joinable()) g_CleanupThread.join();
        if (g_TrustRefreshThread.joinable()) g_TrustRefreshThread.join();
        SetProcessCritical(false);
        return 1;
    }
    wprintf(L"[+] ETW session created.\n");

    status = EnableTraceEx2(g_SessionHandle, &KERNEL_PROCESS_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        wprintf(L"[-] EnableTraceEx2 for process failed: 0x%08lx\n", status);
        ControlTraceW(g_SessionHandle, SessionName, g_pProp, EVENT_TRACE_CONTROL_STOP);
        free(g_pProp);
        g_StopRequested = true;
        if (g_NetworkThread.joinable()) g_NetworkThread.join();
        if (g_ActiveScanThread.joinable()) g_ActiveScanThread.join();
        if (g_BatchThread.joinable()) g_BatchThread.join();
        if (g_CleanupThread.joinable()) g_CleanupThread.join();
        if (g_TrustRefreshThread.joinable()) g_TrustRefreshThread.join();
        SetProcessCritical(false);
        return 1;
    }

    status = EnableTraceEx2(g_SessionHandle, &KERNEL_IMAGE_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        wprintf(L"[-] EnableTraceEx2 for image failed: 0x%08lx\n", status);
    } else {
        wprintf(L"[+] Kernel-Image provider enabled.\n");
    }

    status = EnableTraceEx2(g_SessionHandle, &KERNEL_THREAD_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        wprintf(L"[-] EnableTraceEx2 for thread failed: 0x%08lx\n", status);
    } else {
        wprintf(L"[+] Kernel-Thread provider enabled.\n");
    }
    status = EnableTraceEx2(g_SessionHandle, &KERNEL_NETWORK_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION,               // Level
                            0x0000000000000030,                   // MatchAnyKeyword: TCPIP(0x10) + UDPIP(0x20)
                            0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        wprintf(L"[-] EnableTraceEx2 for network failed: 0x%08lx\n", status);
    } else {
        wprintf(L"[+] Kernel-Network provider enabled (TCP/UDP).\n");
    }
    // 线程池
    SYSTEM_INFO si2;
    GetSystemInfo(&si2);
    g_MaxThreads = 3;
    g_ThreadPool = CreateThreadpool(NULL);
    if (!g_ThreadPool) {
        wprintf(L"[-] CreateThreadpool failed.\n");
        ControlTraceW(g_SessionHandle, SessionName, g_pProp, EVENT_TRACE_CONTROL_STOP);
        free(g_pProp);
        g_StopRequested = true;
        if (g_NetworkThread.joinable()) g_NetworkThread.join();
        if (g_ActiveScanThread.joinable()) g_ActiveScanThread.join();
        if (g_BatchThread.joinable()) g_BatchThread.join();
        if (g_CleanupThread.joinable()) g_CleanupThread.join();
        if (g_TrustRefreshThread.joinable()) g_TrustRefreshThread.join();
        SetProcessCritical(false);
        return 1;
    }
    SetThreadpoolThreadMaximum(g_ThreadPool, g_MaxThreads);
    SetThreadpoolThreadMinimum(g_ThreadPool, 1);
    wprintf(L"[+] Threadpool created with max %d threads.\n", g_MaxThreads);

    // 打开跟踪
    wchar_t loggerName[] = SessionName;
    EVENT_TRACE_LOGFILEW logfile = {0};
    logfile.LoggerName = loggerName;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;

    g_TraceHandle = OpenTraceW(&logfile);
    if (g_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"[-] OpenTrace failed.\n");
        ControlTraceW(g_SessionHandle, SessionName, g_pProp, EVENT_TRACE_CONTROL_STOP);
        free(g_pProp);
        CloseThreadpool(g_ThreadPool);
        g_StopRequested = true;
        if (g_NetworkThread.joinable()) g_NetworkThread.join();
        if (g_ActiveScanThread.joinable()) g_ActiveScanThread.join();
        if (g_BatchThread.joinable()) g_BatchThread.join();
        if (g_CleanupThread.joinable()) g_CleanupThread.join();
        if (g_TrustRefreshThread.joinable()) g_TrustRefreshThread.join();
        SetProcessCritical(false);
        return 1;
    }
    wprintf(L"[+] ETW trace opened. Waiting for events...\n");
    status = ProcessTrace(&g_TraceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        wprintf(L"[-] ProcessTrace returned: 0x%08lx\n", status);
    }

    // 清理
    SetProcessCritical(false);
    g_StopRequested = true;
    g_StopBatch = true;
    g_StopCleanup = true;
    g_StopTrustRefresh = true;

    CloseTrace(g_TraceHandle);
    ControlTraceW(g_SessionHandle, SessionName, g_pProp, EVENT_TRACE_CONTROL_STOP);
    free(g_pProp);
    CloseThreadpool(g_ThreadPool);

    if (g_NetworkThread.joinable()) g_NetworkThread.join();
    if (g_ActiveScanThread.joinable()) g_ActiveScanThread.join();
    if (g_BatchThread.joinable()) g_BatchThread.join();
    if (g_CleanupThread.joinable()) g_CleanupThread.join();
    if (g_TrustRefreshThread.joinable()) g_TrustRefreshThread.join();
    g_StopWhiteListReload = true;
    if (g_WhiteListReloadThread.joinable())
        g_WhiteListReloadThread.join();

    wprintf(L"[+] ETW session closed.\n");
    return 0;
}