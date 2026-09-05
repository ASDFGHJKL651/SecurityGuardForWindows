/*
PEanalyzer_forWinPE.cpp
分析层

在WinPE环境中分析PE文件，评估并处理恶意代码

g++编译:
cd %g++Path%
g++ -fdiagnostics-color=always -g "%SourceCodePath%\PEanalyzer_forWinPE.cpp" -o "%ExecutableForWinPEPath%\PEanalyzer_forWinPE.exe"

运行权限：管理员权限
*/
#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#endif

// 宏定义 =
#ifndef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_RF
#define IMAGE_DLLCHARACTERISTICS_GUARD_RF 0x8000
#endif

#ifndef RTL_COMPRESSION_FORMAT_XPRESS_HUFF
#define RTL_COMPRESSION_FORMAT_XPRESS_HUFF 0x0003
#endif

#ifndef IMAGE_SUBSYSTEM_NATIVE
#define IMAGE_SUBSYSTEM_NATIVE 1
#endif
#ifndef IMAGE_FILE_SYSTEM
#define IMAGE_FILE_SYSTEM 0x1000
#endif

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <winerror.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <set>
#include <map>
#include <iomanip>
#include <unordered_set>
#include <cctype>
#include <ctime>
#include <functional>
#include <unordered_map>
#include <regex>
#include <CorHdr.h>

#include <compressapi.h>
#include <thread>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "compression.lib")

int withUi;
char filepath[32768];
#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_PEanalyzer"
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_PEanalyzer"

#pragma pack(push, 1)
struct MessagetoControlCenter_by_PEanalyzer {
    char type[256];
    int WindowType;
    char path[32768];
    int score;
    char details[131072];
};
#pragma pack(pop)

struct SectionInfo {
    DWORD rvaStart, rvaEnd;
    DWORD rawStart, rawSize;
    std::string name;
    bool isReadable;
};

#define PIPE_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_PEanalyzer)

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

void ClientThread_to_ControlCenter(MessagetoControlCenter_by_PEanalyzer* msg) {
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

// 动态加载 RtlDecompressBuffer =
typedef LONG NTSTATUS;
#define RTL_COMPRESSION_FORMAT_LZNT1       0x0001
#define RTL_COMPRESSION_FORMAT_XPRESS      0x0002

typedef NTSTATUS (WINAPI *RtlDecompressBufferPtr)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);
static RtlDecompressBufferPtr pRtlDecompressBuffer = nullptr;

// 动态加载压缩API =
typedef BOOL (WINAPI *CreateDecompressorPtr)(
    DWORD Algorithm,
    PVOID  pAllocationRoutine,
    PVOID  *DecompressorHandle
);
typedef BOOL (WINAPI *DecompressPtr)(
    PVOID  DecompressorHandle,
    PVOID  CompressedData,
    SIZE_T CompressedDataSize,
    PVOID  UncompressedBuffer,
    SIZE_T UncompressedBufferSize,
    SIZE_T *UncompressedDataSize
);
typedef BOOL (WINAPI *CloseDecompressorPtr)(PVOID DecompressorHandle);
static CreateDecompressorPtr pCreateDecompressor = nullptr;
static DecompressPtr pDecompress = nullptr;
static CloseDecompressorPtr pCloseDecompressor = nullptr;
static bool compressApiLoaded = false;

void LoadCompressApi() {
    if (compressApiLoaded) return;
    HMODULE hComp = LoadLibraryW(L"compressapi.dll");
    if (hComp) {
        pCreateDecompressor = (CreateDecompressorPtr)GetProcAddress(hComp, "CreateDecompressor");
        pDecompress = (DecompressPtr)GetProcAddress(hComp, "Decompress");
        pCloseDecompressor = (CloseDecompressorPtr)GetProcAddress(hComp, "CloseDecompressor");
        compressApiLoaded = true;
    }
}

// API 列表 =
static const char* suspicious_apis[] = {
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "NtCreateThreadEx",   "QueueUserAPC",   "SetThreadContext",
    "CreateProcess",      "ShellExecute",   "WinExec",
    "SetWindowsHookEx",   "CreateService",  "RegSetValueEx",
    "ChangeServiceConfig", "StartService",
    "URLDownloadToFile",  "InternetOpenUrl", "InternetReadFile",
    "HttpSendRequest",    "WinHttpOpen",
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
    "OpenProcess",        "TerminateProcess",
    "ReadProcessMemory",  "VirtualProtectEx",
    "NtQueryInformationProcess", "NtSetInformationProcess",
    "NtCreateFile",       "NtOpenKey",      "NtDeleteKey",
    "NtQuerySystemInformation", "NtSuspendProcess", "NtResumeProcess",
    "IsDebuggerPresent",  "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "OutputDebugStringA", "GetTickCount",    "Rdtsc",
    "CryptAcquireContext", "CryptEncrypt",   "CryptDecrypt",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",
    "CreateFileMapping",  "MapViewOfFile",
    "LoadLibraryA",       "LoadLibraryW",    "GetProcAddress",
    "GetModuleHandleA",   "GetModuleHandleW"
};
static const int SUSPICIOUS_API_COUNT = sizeof(suspicious_apis) / sizeof(suspicious_apis[0]);

static const char* anti_debug_apis[] = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "OutputDebugStringA", "GetTickCount", "Rdtsc",
    "NtQuerySystemInformation", "NtQueryObject",
    "NtRaiseHardError", "ZwQueryInformationProcess",
    "NtClose", "NtQueryInformationThread",
    "ZwSetInformationThread", "NtQueryVolumeInformationFile"
};
static const int ANTI_DEBUG_COUNT = sizeof(anti_debug_apis) / sizeof(anti_debug_apis[0]);

static const char* suspicious_exports[] = {
    "DllMain", "ServiceMain", "DriverEntry", "Start", "Run",
    "Install", "Uninstall", "DllRegisterServer", "DllUnregisterServer"
};
static const int SUSPICIOUS_EXPORT_COUNT = sizeof(suspicious_exports) / sizeof(suspicious_exports[0]);

static const char* legitimate_exports[] = {
    "DllMain", "DllGetClassObject", "DllCanUnloadNow",
    "DllRegisterServer", "DllUnregisterServer",
    "ServiceMain", "DriverEntry"
};
static const int LEGITIMATE_EXPORT_COUNT = sizeof(legitimate_exports) / sizeof(legitimate_exports[0]);

static const char* basic_functions[] = {
    "GetCurrentProcessId", "GetCurrentThreadId",
    "GetModuleHandleA", "GetModuleHandleW",
    "GetProcAddress", "VirtualAlloc", "HeapAlloc",
    "GetProcessHeap", "GetCommandLineA", "GetCommandLineW",
    "GetFileSize", "GetFileType", "GetStdHandle",
    "WriteFile", "ReadFile", "CloseHandle",
    "GetLastError", "SetLastError", "GetSystemTimeAsFileTime"
};
static const int BASIC_FUNCTION_COUNT = sizeof(basic_functions) / sizeof(basic_functions[0]);

static const char* packed_section_names[] = {
    "UPX0", "UPX1", "UPX2", ".UPX", ".packed", ".Packed",
    "MPRESS", ".MPRESS", "PEC", ".PEC", "RLPack", ".RLPack",
    "ASPack", ".ASPack", "PECompact", ".PECompact", ".y0da", ".y1da",
    ".vmp0", ".vmp1", ".vmp2", ".tmd", ".themida"
};
static const int PACKED_SECTION_COUNT = sizeof(packed_section_names) / sizeof(packed_section_names[0]);

static const char* standard_sections[] = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss",
    ".tls", ".crt", ".pdata", ".xdata", ".edata", ".idata",
    ".didat", ".00cfg", ".gfids", ".rtc", ".ctors", ".dtors"
};
static const int STANDARD_SECTION_COUNT = sizeof(standard_sections) / sizeof(standard_sections[0]);

static const char* sensitive_dlls[] = {
    "ntdll.dll", "kernel32.dll", "advapi32.dll", "user32.dll",
    "wininet.dll", "ws2_32.dll", "shell32.dll"
};
static const int SENSITIVE_DLL_COUNT = sizeof(sensitive_dlls) / sizeof(sensitive_dlls[0]);

static const std::vector<std::vector<std::string>> api_combinations = {
    {"CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx"},
    {"URLDownloadToFile", "WinExec", "ShellExecute"},
    {"SetWindowsHookEx", "CreateService", "RegSetValueEx"},
    {"CreateToolhelp32Snapshot", "OpenProcess", "ReadProcessMemory"},
    {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"},
    {"LoadLibraryA", "GetProcAddress", "VirtualProtect"},
    {"CreateProcess", "VirtualAllocEx", "WriteProcessMemory"}
};

// ROR13 哈希相关 =
static uint32_t ror13_hash(const char* str) {
    uint32_t hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);
        hash += (uint8_t)(*str);
        str++;
    }
    return hash;
}

static const char* ror13_blacklist_apis[] = {
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "CreateProcess", "ShellExecute",
    "WinExec", "SetWindowsHookEx", "CreateService", "RegSetValueEx",
    "ChangeServiceConfig", "StartService", "URLDownloadToFile", "InternetOpenUrl",
    "InternetReadFile", "HttpSendRequest", "WinHttpOpen", "CreateToolhelp32Snapshot",
    "Process32First", "Process32Next", "OpenProcess", "TerminateProcess",
    "ReadProcessMemory", "VirtualProtectEx", "NtQueryInformationProcess",
    "NtSetInformationProcess", "NtCreateFile", "NtOpenKey", "NtDeleteKey",
    "NtQuerySystemInformation", "NtSuspendProcess", "NtResumeProcess",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtSetInformationThread",
    "OutputDebugStringA", "GetTickCount", "Rdtsc", "CryptAcquireContext",
    "CryptEncrypt", "CryptDecrypt", "AdjustTokenPrivileges", "LookupPrivilegeValue",
    "CreateFileMapping", "MapViewOfFile", "LoadLibraryA", "LoadLibraryW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW"
};
static const int ROR13_BLACKLIST_COUNT = sizeof(ror13_blacklist_apis) / sizeof(ror13_blacklist_apis[0]);
static uint32_t ror13_blacklist_hashes[ROR13_BLACKLIST_COUNT];
static uint32_t djb2_blacklist_hashes[ROR13_BLACKLIST_COUNT];
static uint32_t murmur3_blacklist_hashes[ROR13_BLACKLIST_COUNT];
static bool ror13_hashes_initialized = false;

static uint32_t djb2_hash(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (uint8_t)(*str);
        str++;
    }
    return hash;
}

static uint32_t murmur3_32(const char* str) {
    uint32_t h = 0;
    const uint8_t* data = (const uint8_t*)str;
    size_t len = strlen(str);
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const uint32_t r1 = 15;
    const uint32_t r2 = 13;
    const uint32_t m = 5;
    const uint32_t n = 0xe6546b64;

    size_t nblocks = len / 4;
    for (size_t i = 0; i < nblocks; i++) {
        uint32_t k = data[4*i] | (data[4*i+1]<<8) | (data[4*i+2]<<16) | (data[4*i+3]<<24);
        k *= c1;
        k = (k << r1) | (k >> (32-r1));
        k *= c2;
        h ^= k;
        h = (h << r2) | (h >> (32-r2));
        h = h * m + n;
    }
    const uint8_t* tail = data + nblocks*4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= tail[2] << 16;
        case 2: k1 ^= tail[1] << 8;
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = (k1 << r1) | (k1 >> (32-r1));
                k1 *= c2;
                h ^= k1;
    };
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

static void init_ror13_hashes() {
    if (!ror13_hashes_initialized) {
        for (int i = 0; i < ROR13_BLACKLIST_COUNT; ++i) {
            ror13_blacklist_hashes[i] = ror13_hash(ror13_blacklist_apis[i]);
            djb2_blacklist_hashes[i] = djb2_hash(ror13_blacklist_apis[i]);
            murmur3_blacklist_hashes[i] = murmur3_32(ror13_blacklist_apis[i]);
        }
        ror13_hashes_initialized = true;
    }
}

// 工具函数 =
double calculate_entropy(const BYTE* data, size_t size) {
    if (size == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < size; ++i) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

template<typename T>
const T* safe_ptr(const BYTE* base, size_t baseSize, size_t offset) {
    if (offset + sizeof(T) > baseSize) return nullptr;
    return reinterpret_cast<const T*>(base + offset);
}

static time_t FileTimeToUnixTime(const FILETIME& ft) {
    ULARGE_INTEGER ul;
    ul.LowPart  = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    const uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;
    uint64_t seconds = (ul.QuadPart - EPOCH_DIFFERENCE) / 10000000;
    return static_cast<time_t>(seconds);
}

// 数字签名验证 =
bool GetSignatureStatus(const std::wstring& filePath,
                        std::wstring& outSubjectCN,
                        std::wstring& outIssuerCN,
                        bool& outExpired,
                        bool& outSelfSigned,
                        bool& outMultipleSignatures,
                        int& outSignerCount,
                        time_t& outNotBefore,
                        time_t& outNotAfter,
                        bool& outNameSpoofed,
                        bool& outRevocationCheckFailed,
                        bool& outIsEV,
                        bool& outTimeStampWarning)
{
    outSubjectCN.clear();
    outIssuerCN.clear();
    outExpired = false;
    outSelfSigned = false;
    outMultipleSignatures = false;
    outSignerCount = 0;
    outNotBefore = 0;
    outNotAfter = 0;
    outNameSpoofed = false;
    outRevocationCheckFailed = false;
    outIsEV = false;
    outTimeStampWarning = false;

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA wvtData = {0};
    wvtData.cbStruct = sizeof(WINTRUST_DATA);
    wvtData.pPolicyCallbackData = NULL;
    wvtData.pSIPClientData = NULL;
    wvtData.dwUIChoice = WTD_UI_NONE;
    wvtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wvtData.dwUnionChoice = WTD_CHOICE_FILE;
    wvtData.pFile = &fileInfo;
    wvtData.dwStateAction = WTD_STATEACTION_VERIFY;
    wvtData.hWVTStateData = NULL;
    wvtData.pwszURLReference = NULL;
    wvtData.dwProvFlags = WTD_SAFER_FLAG;

    LONG trustStatus = WinVerifyTrust(NULL, &guidAction, &wvtData);
    if (trustStatus == TRUST_E_TIME_STAMP) {
        outTimeStampWarning = true;
    }
    wvtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &wvtData);

    bool valid = (trustStatus == ERROR_SUCCESS);

    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCert = NULL;

    if (CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_ALL,
        0,
        NULL,
        NULL,
        NULL,
        &hStore,
        &hMsg,
        NULL)) {

        if (hMsg) {
            DWORD cbData = sizeof(DWORD);
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, (BYTE*)&outSignerCount, &cbData)) {
                if (outSignerCount > 1) outMultipleSignatures = true;
            }
        }

        pCert = CertEnumCertificatesInStore(hStore, NULL);
        if (pCert) {
            wchar_t nameBuf[256];
            DWORD len = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                                           nameBuf, 256);
            if (len > 1) outSubjectCN = nameBuf;

            len = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                     CERT_NAME_ISSUER_FLAG, NULL, nameBuf, 256);
            if (len > 1) outIssuerCN = nameBuf;

            outNotBefore = FileTimeToUnixTime(pCert->pCertInfo->NotBefore);
            outNotAfter  = FileTimeToUnixTime(pCert->pCertInfo->NotAfter);

            FILETIME now;
            GetSystemTimeAsFileTime(&now);
            if (CompareFileTime(&pCert->pCertInfo->NotAfter, &now) < 0) {
                outExpired = true;
            }

            wchar_t issuerBuf[256] = {0}, subjectBuf[256] = {0};
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               CERT_NAME_ISSUER_FLAG, NULL, issuerBuf, 256);
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0, NULL, subjectBuf, 256);
            if (wcscmp(issuerBuf, subjectBuf) == 0) {
                outSelfSigned = true;
            }

            // 名称欺骗检测
            const char* knownNames[] = {
                "Microsoft", "DigiCert", "VeriSign", "GlobalSign",
                "Comodo", "Symantec", "GoDaddy", "Let's Encrypt"
            };
            const int numKnown = sizeof(knownNames) / sizeof(knownNames[0]);

            const BYTE* enc = pCert->pbCertEncoded;
            DWORD encLen = pCert->cbCertEncoded;

            for (int i = 0; i < numKnown; ++i) {
                const char* pattern = knownNames[i];
                size_t patLen = strlen(pattern);
                if (patLen == 0 || encLen < patLen) continue;

                for (DWORD pos = 0; pos <= encLen - patLen; ++pos) {
                    if (memcmp(enc + pos, pattern, patLen) == 0) {
                        bool hasNull = false;
                        if (pos > 0 && enc[pos - 1] == 0x00) hasNull = true;
                        if (pos + patLen < encLen && enc[pos + patLen] == 0x00) hasNull = true;
                        if (hasNull) {
                            outNameSpoofed = true;
                            break;
                        }
                    }
                }
                if (outNameSpoofed) break;
            }

            // 证书链检查
            HCERTCHAINENGINE hChainEngine = NULL;
            CERT_CHAIN_PARA chainPara = { sizeof(CERT_CHAIN_PARA) };
            chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
            chainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
            chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;

            PCCERT_CHAIN_CONTEXT pChainContext = NULL;
            if (CertGetCertificateChain(hChainEngine, pCert, NULL, NULL, &chainPara, 0, NULL, &pChainContext)) {
                DWORD dwErrorStatus = pChainContext->TrustStatus.dwErrorStatus;
                if (dwErrorStatus & CERT_TRUST_IS_REVOKED) {
                    valid = false;
                }
                if (dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) {
                    outExpired = true;
                }
                if (dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) {
                    outRevocationCheckFailed = true;
                }

                // EV 检测
                const char* szOID_EV = "1.3.6.1.4.1.311.60.1.1";
                for (DWORD i = 0; i < pCert->pCertInfo->cExtension; ++i) {
                    PCERT_EXTENSION pExt = &pCert->pCertInfo->rgExtension[i];
                    if (strcmp(pExt->pszObjId, szOID_EV) == 0) {
                        outIsEV = true;
                        break;
                    }
                }
                if (!outIsEV) {
                    std::wstring issuer = outIssuerCN;
                    std::transform(issuer.begin(), issuer.end(), issuer.begin(), ::towlower);
                    if (issuer.find(L"ev") != std::wstring::npos) {
                        outIsEV = true;
                    }
                }

                CertFreeCertificateChain(pChainContext);
            }

            CertFreeCertificateContext(pCert);
        }

        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
    }

    return valid;
}

// 系统目录判断 =
bool IsSystemDirectory(const std::wstring& path) {
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    if (lower.find(L"c:\\windows\\system32") == 0 ||
        lower.find(L"c:\\windows\\syswow64") == 0 ||
        lower.find(L"c:\\program files\\windowsapps") == 0) {
        return true;
    }
    return false;
}

// Rich Header =
bool CheckRichHeader(const BYTE* base, size_t baseSize, bool& tampered) {
    const DWORD RICH_SIGNATURE = 0x68636952;
    const DWORD DANS_SIGNATURE = 0x536E6144;
    tampered = false;

    auto pDos = safe_ptr<IMAGE_DOS_HEADER>(base, baseSize, 0);
    if (!pDos) return false;
    DWORD e_lfanew = pDos->e_lfanew;
    if (e_lfanew > baseSize) return false;

    size_t start = sizeof(IMAGE_DOS_HEADER);
    size_t end = e_lfanew;
    if (end <= start) return false;

    bool foundRich = false, foundDanS = false;
    for (size_t i = start; i + 4 <= end; ++i) {
        if (*(DWORD*)(base + i) == RICH_SIGNATURE) {
            foundRich = true;
            for (size_t j = i + 4; j + 4 <= end; ++j) {
                if (*(DWORD*)(base + j) == DANS_SIGNATURE) {
                    foundDanS = true;
                    break;
                }
            }
            break;
        }
    }
    if (!foundRich) return false;
    if (!foundDanS) { tampered = true; return true; }
    return true;
}

// API 字符串扫描 =
int scan_section_for_api_strings(const BYTE* sectionData, size_t sectionSize,
                                 const std::unordered_set<std::string>& importedApisSet,
                                 std::vector<std::string>& warnings,
                                 std::unordered_set<std::string>& detectedApis) {
    if (sectionSize < 64) return 0;
    int found = 0;

    for (size_t i = 0; i < sectionSize; ++i) {
        if (isprint(sectionData[i]) && sectionData[i] != ' ') {
            size_t start = i;
            while (i < sectionSize && isprint(sectionData[i]) && sectionData[i] != ' ') i++;
            size_t len = i - start;
            if (len < 4) continue;
            std::string str((char*)&sectionData[start], len);
            for (int k = 0; k < SUSPICIOUS_API_COUNT; ++k) {
                const char* api = suspicious_apis[k];
                if (str.find(api) != std::string::npos) {
                    if (importedApisSet.find(str) == importedApisSet.end()) {
                        found++;
                        warnings.push_back("Dynamic-load API string (ASCII) found: " + str);
                        std::string apiLower = api;
                        std::transform(apiLower.begin(), apiLower.end(), apiLower.begin(), ::tolower);
                        detectedApis.insert(apiLower);
                        break;
                    }
                }
            }
        }
    }

    const wchar_t* wdata = reinterpret_cast<const wchar_t*>(sectionData);
    size_t wcount = sectionSize / sizeof(wchar_t);
    for (size_t i = 0; i < wcount; ++i) {
        if (iswprint(wdata[i]) && wdata[i] != L' ') {
            size_t start = i;
            while (i < wcount && iswprint(wdata[i]) && wdata[i] != L' ') i++;
            size_t len = i - start;
            if (len < 4) continue;
            std::string str;
            for (size_t j = start; j < i; ++j) {
                wchar_t wc = wdata[j];
                if (wc < 256 && isprint((char)wc)) str.push_back((char)wc);
                else { str.clear(); break; }
            }
            if (str.length() < 4) continue;
            for (int k = 0; k < SUSPICIOUS_API_COUNT; ++k) {
                const char* api = suspicious_apis[k];
                if (str.find(api) != std::string::npos) {
                    if (importedApisSet.find(str) == importedApisSet.end()) {
                        found++;
                        warnings.push_back("Dynamic-load API string (UTF-16) found: " + str);
                        std::string apiLower = api;
                        std::transform(apiLower.begin(), apiLower.end(), apiLower.begin(), ::tolower);
                        detectedApis.insert(apiLower);
                        break;
                    }
                }
            }
        }
    }
    return found;
}

void scan_section_for_split_apis(const BYTE* data, size_t size,
                                 std::vector<std::string>& warnings,
                                 int& score) {
    if (size < 6) return;

    struct StringInfo {
        size_t start;
        size_t end;
        std::string str;
    };
    std::vector<StringInfo> strings;

    for (size_t i = 0; i < size; ++i) {
        if (isprint(data[i]) && data[i] != ' ') {
            size_t start = i;
            while (i < size && isprint(data[i]) && data[i] != ' ') i++;
            size_t len = i - start;
            if (len >= 3 && len <= 8) {
                std::string s((char*)&data[start], len);
                bool valid = true;
                for (char c : s) {
                    if (!isalnum(c) && c != '_') { valid = false; break; }
                }
                if (valid) {
                    strings.push_back({start, i, s});
                }
            }
        }
    }

    if (strings.size() < 2) return;

    std::unordered_set<std::string> reported;
    for (size_t i = 0; i < strings.size(); ++i) {
        for (size_t j = i + 1; j < strings.size(); ++j) {
            if (strings[j].start < strings[i].end) continue;
            size_t gap = strings[j].start - strings[i].end;
            if (gap >= 20) continue;

            std::string combined = strings[i].str + strings[j].str;
            std::string combinedLower = combined;
            std::transform(combinedLower.begin(), combinedLower.end(), combinedLower.begin(), ::tolower);

            for (int k = 0; k < SUSPICIOUS_API_COUNT; ++k) {
                std::string apiLower = suspicious_apis[k];
                std::transform(apiLower.begin(), apiLower.end(), apiLower.begin(), ::tolower);
                if (combinedLower == apiLower) {
                    std::string key = combinedLower;
                    if (reported.find(key) == reported.end()) {
                        reported.insert(key);
                        warnings.push_back("Split API string detected: \"" + strings[i].str + "\" + \"" + strings[j].str +
                                           "\" -> " + std::string(suspicious_apis[k]) + " (likely dynamic resolve)");
                    }
                    break;
                }
            }
        }
    }

    if (reported.size() >= 2) {
        score += 8;
        warnings.push_back("High-confidence API obfuscation: multiple split API strings found.");
    }
}

static void scan_syscall_pattern(const BYTE* data, size_t size, int& score,
                                 std::vector<std::string>& warnings,
                                 std::vector<std::string>& info) {
    if (size < 7) return;
    int addedScore = 0;
    for (size_t i = 0; i + 6 < size; ++i) {
        if (data[i] == 0xB8) {
            if (i + 6 < size && data[i+5] == 0x0F && data[i+6] == 0x05) {
                if(addedScore < 96){addedScore += 12;}
                warnings.push_back("Syscall instruction detected with immediate mov eax (potential direct system call)");
                info.push_back("Added 12 points for syscall pattern");
                i += 6;
            }
        }
    }
    score += addedScore;
}

static void scan_ror13_hashes(const BYTE* data, size_t size, int& score,
                              std::vector<std::string>& warnings,
                              std::vector<std::string>& info) {
    if (size < 5) return;
    init_ror13_hashes();
    int hashMatches = 0;
    const int MAX_HASH_SCORE = 16;
    for (size_t i = 0; i + 4 < size; ++i) {
        if (data[i] == 0xB8) {
            uint32_t imm = *(uint32_t*)(data + i + 1);
            bool matched = false;
            for (int k = 0; k < ROR13_BLACKLIST_COUNT; ++k) {
                if (imm == ror13_blacklist_hashes[k] ||
                    imm == djb2_blacklist_hashes[k] ||
                    imm == murmur3_blacklist_hashes[k]) {
                    if (hashMatches < MAX_HASH_SCORE) {
                        int add = 8;
                        if (hashMatches + add > MAX_HASH_SCORE) add = MAX_HASH_SCORE - hashMatches;
                        score += add;
                        hashMatches += add;
                        warnings.push_back("Hash match (ROR13/DJB2/Murmur3): API " + std::string(ror13_blacklist_apis[k]) +
                                           " likely resolved via hash (imm=0x" + std::to_string(imm) + ")");
                        info.push_back("Added " + std::to_string(add) + " points for hash match");
                        matched = true;
                        break;
                    }
                }
            }
            if (matched) i += 4;
        }
    }
}

// push hash; call 模式检测
static void scan_push_hash_call(const BYTE* data, size_t size, int& score,
                                std::vector<std::string>& warnings,
                                std::vector<std::string>& info) {
    if (size < 5) return;
    init_ror13_hashes();
    int addedScore = 0;
    for (size_t i = 0; i + 4 < size; ++i) {
        if (data[i] == 0x68) { // push imm32
            uint32_t imm = *(uint32_t*)(data + i + 1);
            bool matched = false;
            // 检查是否匹配任何黑名单哈希
            for (int k = 0; k < ROR13_BLACKLIST_COUNT; ++k) {
                if (imm == ror13_blacklist_hashes[k] ||
                    imm == djb2_blacklist_hashes[k] ||
                    imm == murmur3_blacklist_hashes[k]) {
                    // 查找后面是否有 call (E8) 或 call dword ptr [addr] (FF 15)
                    size_t j = i + 5;
                    bool foundCall = false;
                    while (j < size && j - i < 20) {
                        if (data[j] == 0xE8) { // call rel32
                            foundCall = true;
                            break;
                        } else if (j + 1 < size && data[j] == 0xFF && data[j+1] == 0x15) {
                            foundCall = true;
                            break;
                        }
                        j++;
                    }
                    if (foundCall) {
                        if(addedScore < 40){addedScore += 4;}
                        warnings.push_back("push hash; call pattern detected for API " + std::string(ror13_blacklist_apis[k]));
                        info.push_back("Added 4 points for push hash call");
                        matched = true;
                        break;
                    }
                }
            }
            if (matched) i += 5; // skip this push
        }
    }
    score += addedScore;
}

static void scan_llvm_obfuscation(const BYTE* data, size_t size, bool has_chkstk,
                                  int& score, std::vector<std::string>& warnings,
                                  std::vector<std::string>& info) {
    if (size < 16) return;

    int jmpCount = 0;
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == 0xE9 || data[i] == 0xEB) jmpCount++;
    }
    double density = (size > 0) ? (double)jmpCount * 100 / size : 0;
    bool jmpDense = (density >= 4.0);
    if (jmpDense) {
        score += 3;
        warnings.push_back("High density of unconditional jumps (E9/EB): " + std::to_string(density) + " per 100 bytes");
        info.push_back("Added 3 points for high JMP density");
    }

    bool opaqueFreq = false;
    const int WINDOW = 512;
    if (size >= WINDOW) {
        int maxMatches = 0;
        for (size_t start = 0; start + WINDOW <= size; start += 256) {
            int matches = 0;
            for (size_t i = start; i < start + WINDOW - 4; ++i) {
                if (data[i] == 0xB8) {
                    size_t j = i + 5;
                    while (j < start + WINDOW && j < size && j - i < 20) {
                        if (data[j] == 0x3D) {
                            size_t k = j + 5;
                            while (k < start + WINDOW && k < size && k - j < 20) {
                                if (data[k] == 0x74 || data[k] == 0x75) {
                                    matches++;
                                    break;
                                }
                                k++;
                            }
                            break;
                        }
                        j++;
                    }
                }
            }
            if (matches > maxMatches) maxMatches = matches;
            if (maxMatches >= 5) {
                opaqueFreq = true;
                break;
            }
        }
        if (opaqueFreq) {
            score += 5;
            warnings.push_back("Frequent opaque predicate patterns (MOV EAX, imm; CMP EAX, imm; JE/JNE) in 512-byte window");
            info.push_back("Added 5 points for opaque predicates");
        }
    }

    if (has_chkstk && (jmpDense || opaqueFreq)) {
        score += 2;
        warnings.push_back("__chkstk import combined with LLVM obfuscation indicators");
        info.push_back("Added 2 points for __chkstk with obfuscation");
    }
}

static void analyze_entry_point_bytes(const BYTE* entryData, size_t len,
                                      int& score, std::vector<std::string>& warnings,
                                      std::vector<std::string>& info) {
    if (len < 2) return;

    for (size_t i = 0; i + 1 < len; ++i) {
        if (entryData[i] == 0x9C && entryData[i+1] == 0x9D) {
            score += 6;
            warnings.push_back("PUSHFD/POPFD combo found at entry point (VMProtect/Themida fingerprint)");
            info.push_back("Added 6 points for PUSHFD/POPFD");
            break;
        }
    }

    for (size_t i = 0; i + 3 < len; ++i) {
        if (entryData[i] == 0xFF && entryData[i+1] == 0x24) {
            BYTE modrm = entryData[i+2];
            if (modrm == 0x85 || modrm == 0x8D || modrm == 0x95 || modrm == 0xAD) {
                score += 8;
                warnings.push_back("Indirect jump table (FF 24 8x) found at entry point (VM dispatch)");
                info.push_back("Added 8 points for indirect jump table");
                break;
            }
        }
    }

    for (size_t i = 0; i + 3 < len; ++i) {
        if (entryData[i] == 0x31 && (entryData[i+1] == 0x04 || entryData[i+1] == 0x1C) && entryData[i+2] == 0x0F) {
            bool hasInc = false, hasLoop = false;
            for (size_t j = i+3; j < len && j < i+20; ++j) {
                if (entryData[j] == 0x41) hasInc = true;
                if (entryData[j] == 0xE2) hasLoop = true;
            }
            if (hasInc && hasLoop) {
                score += 10;
                warnings.push_back("XOR loop decoder found at entry point (31 04 0F / 31 1C 0F with INC/LOOP)");
                info.push_back("Added 10 points for XOR loop decoder");
                break;
            }
        }
    }

    for (size_t i = 0; i + 2 < len; ++i) {
        if (entryData[i] == 0xF3 && (entryData[i+1] == 0xA4 || entryData[i+1] == 0xAB)) {
            score += 8;
            warnings.push_back("REP MOVS/STOS instruction found at entry point (decompression stub)");
            info.push_back("Added 8 points for REP MOVS/STOS");
            break;
        }
    }
}

static void scan_stack_string_apis(const BYTE* data, size_t size,
                                   std::unordered_set<std::string>& detectedApis,
                                   int& score, std::vector<std::string>& warnings,
                                   std::vector<std::string>& info) {
    if (size < 12) return;

    size_t i = 0;
    while (i + 5 <= size) {
        if (data[i] == 0x68) {
            size_t start = i;
            std::vector<uint32_t> immediates;
            while (i + 5 <= size && data[i] == 0x68) {
                uint32_t imm = *(uint32_t*)(data + i + 1);
                immediates.push_back(imm);
                i += 5;
            }
            if (immediates.size() >= 2) {
                size_t j = i;
                bool hasPushReg = false;
                while (j < size && j - i < 10) {
                    if (data[j] >= 0x50 && data[j] <= 0x57) {
                        hasPushReg = true;
                        j++;
                        break;
                    }
                    break;
                }
                bool hasCall = false;
                if (j + 1 <= size) {
                    while (j < size && j - i < 20) {
                        if (data[j] == 0xE8) {
                            hasCall = true;
                            break;
                        }
                        j++;
                    }
                }
                if (hasCall) {
                    std::string combined;
                    for (uint32_t imm : immediates) {
                        char bytes[4];
                        bytes[0] = imm & 0xFF;
                        bytes[1] = (imm >> 8) & 0xFF;
                        bytes[2] = (imm >> 16) & 0xFF;
                        bytes[3] = (imm >> 24) & 0xFF;
                        for (int b = 0; b < 4; ++b) {
                            if (isprint(bytes[b]) && bytes[b] != ' ') combined.push_back(bytes[b]);
                        }
                    }
                    std::string combinedLower = combined;
                    std::transform(combinedLower.begin(), combinedLower.end(), combinedLower.begin(), ::tolower);
                    int matchedApiCount = 0;
                    for (int k = 0; k < SUSPICIOUS_API_COUNT; ++k) {
                        std::string apiLower = suspicious_apis[k];
                        std::transform(apiLower.begin(), apiLower.end(), apiLower.begin(), ::tolower);
                        if (combinedLower.find(apiLower) != std::string::npos) {
                            if (detectedApis.find(apiLower) == detectedApis.end()) {
                                detectedApis.insert(apiLower);
                                matchedApiCount++;
                                warnings.push_back("Stack string concatenated API: \"" + combined + "\" contains " + std::string(suspicious_apis[k]));
                            }
                        }
                    }
                    if (matchedApiCount > 0) {
                        int addScore = 6 + (matchedApiCount - 1) * 3;
                        if (addScore > 10) addScore = 10;
                        score += addScore;
                        info.push_back("Added " + std::to_string(addScore) + " points for stack string API detection (" + std::to_string(matchedApiCount) + " APIs)");
                    }
                }
            }
        } else {
            i++;
        }
    }
}

// 分析结果结构体 =
struct AnalysisResult {
    int score = 0;
    bool hasSig = false;
    bool isDotNet = false;
    std::vector<std::string> warnings;
    std::vector<std::string> info;
    std::vector<std::string> abnormalCalls;
    int dynamicCallCount = 0;
    bool hasSignature = false;
    bool certValid = false;
    bool isSelfSigned = false;
    std::wstring issuerName;
};

 //IOC 提取辅助函数
static bool isValidIPv4(const std::string& s) {
    int dots = 0;
    for (char c : s) if (c == '.') dots++;
    if (dots != 3) return false;

    size_t pos = 0;
    int parts[4];
    int partIndex = 0;
    while (pos < s.length() && partIndex < 4) {
        size_t nextDot = s.find('.', pos);
        std::string part = (nextDot == std::string::npos) ? s.substr(pos) : s.substr(pos, nextDot - pos);
        if (part.empty()) return false;
        if (part.length() > 1 && part[0] == '0') return false;
        for (char c : part) if (!isdigit(c)) return false;
        int val = std::stoi(part);
        if (val < 0 || val > 255) return false;
        parts[partIndex++] = val;
        if (nextDot == std::string::npos) break;
        pos = nextDot + 1;
    }
    if (partIndex != 4) return false;

    if (parts[0] == 10) return false;
    if (parts[0] == 192 && parts[1] == 168) return false;
    if (parts[0] == 127) return false;
    return true;
}

static bool isValidDomain(const std::string& s) {
    if (s.length() < 5 || s.length() > 64) return false;
    int dotCount = 0;
    bool hasLetter = false;
    for (char c : s) {
        if (c == '.') { dotCount++; continue; }
        if (isalnum(c) || c == '-') {
            if (isalpha(c)) hasLetter = true;
            continue;
        }
        return false;
    }
    if (dotCount < 2) return false;
    if (!hasLetter) return false;
    if (s.front() == '-' || s.back() == '-') return false;
    if (s.find("..") != std::string::npos) return false;
    return true;
}

static bool contains_case_insensitive(const BYTE* data, size_t size, const std::string& pattern) {
    if (pattern.empty() || size < pattern.size()) return false;
    for (size_t i = 0; i <= size - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            unsigned char a = data[i + j];
            unsigned char b = static_cast<unsigned char>(pattern[j]);
            if (std::tolower(a) != std::tolower(b)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

 //IOC：使用正则匹配
void ExtractIOCsFromSection(const BYTE* data, size_t size,
                            AnalysisResult& result, int& iocCount,
                            int& extraScore,
                            std::unordered_set<std::string>& reportedIOCs) {
    if (size < 4) return;
    int addedScore = 0;
    //  原有特征模式（保持不变） 
    struct Feature {
        std::string pattern;
        int weight;
        std::string warning;
    };
    static const std::vector<Feature> features = {
        {"software\\microsoft\\windows\\currentversion\\run", 2, "Registry auto-run key found"},
        {"runonce", 2, "Registry RunOnce key found"},
        {"services\\", 2, "Services registry key found"},
        {"winlogon\\shell", 2, "Winlogon shell registry key found"},
        {"schtasks /create", 2, "Scheduled task creation command found"},
        {"sc create", 2, "Service creation command found"},
        {"reg add", 2, "Registry modification command found"},
        {"powershell -e", 2, "PowerShell encoded command found"},
        {"powershell -enc", 2, "PowerShell encoded command found"},
        {"iex(new-object", 2, "PowerShell IEX with New-Object found"},
        {"invoke-expression", 2, "PowerShell Invoke-Expression found"},
        {"net.webclient", 2, "Net.WebClient downloader found"},
        {"downloadstring", 2, "DownloadString method found"},
        {"vbox", 1, "VirtualBox string found (anti-VM)"},
        {"vmware", 1, "VMware string found (anti-VM)"},
        {"qemu", 1, "QEMU string found (anti-VM)"},
        {"xensource", 1, "XenSource string found (anti-VM)"},
        {"sandboxie", 1, "Sandboxie string found (anti-sandbox)"},
        {"cuckoo", 1, "Cuckoo sandbox string found"},
        {"wireshark", 1, "Wireshark string found (debugger detection)"}
    };

    //  原有token扫描 
    for (size_t i = 0; i < size; ++i) {
        if (isprint(data[i]) && data[i] != ' ') {
            size_t start = i;
            while (i < size && isprint(data[i]) && data[i] != ' ') i++;
            size_t len = i - start;
            if (len < 4) continue;
            std::string token((char*)&data[start], len);

            bool matched = false;

            if (token.length() >= 4) {
                std::string lower = token;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.compare(0, 3, "c:\\") == 0 ||
                    lower.compare(0, 3, "d:\\") == 0 ||
                    lower.compare(0, 7, "\\\\?\\c:\\") == 0) {
                    result.info.push_back("Found absolute path: " + token);
                    matched = true;
                }
            }

            if (!matched && isValidIPv4(token)) {
                if (reportedIOCs.find(token) == reportedIOCs.end()) {
                    reportedIOCs.insert(token);
                    result.warnings.push_back("IOC (IP): " + token);
                    iocCount++;
                }
                matched = true;
            }

            if (!matched && isValidDomain(token)) {
                if (reportedIOCs.find(token) == reportedIOCs.end()) {
                    reportedIOCs.insert(token);
                    result.warnings.push_back("IOC (Domain): " + token);
                    iocCount++;
                }
                matched = true;
            }

            if (!matched && token.length() > 32) {
                bool isBase64 = true;
                for (char c : token) {
                    if (!isalnum(c) && c != '+' && c != '/' && c != '=') {
                        isBase64 = false;
                        break;
                    }
                }
                if (isBase64) {
                    double entropy = calculate_entropy((const BYTE*)token.data(), token.size());
                    if (entropy > 5.5) {
                        if (reportedIOCs.find(token) == reportedIOCs.end()) {
                            reportedIOCs.insert(token);
                            result.warnings.push_back("Potential Base64 payload (entropy " +
                                                      std::to_string(entropy) + "): " + token.substr(0, 64) + "...");
                            addedScore += 3;
                            result.info.push_back("Added 3 points for Base64 payload");
                        }
                        matched = true;
                    }
                }
            }
        }
    }

    //  原有特征匹配 
    for (const auto& feat : features) {
        std::string key = feat.pattern;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (reportedIOCs.find(key) != reportedIOCs.end()) continue;

        if (contains_case_insensitive(data, size, feat.pattern)) {
            reportedIOCs.insert(key);
            result.warnings.push_back(feat.warning + " (pattern: " + feat.pattern + ")");
            addedScore += feat.weight;
            result.info.push_back("Added " + std::to_string(feat.weight) + " points for IOC pattern: " + feat.pattern);
        }
    }

     //正则匹配注册表键、文件路径、互斥体
    try {
        std::string sectionStr((const char*)data, size);
        if (sectionStr.size() > 1024*1024) sectionStr.resize(1024*1024);

        std::regex regKey(R"(HKEY_[A-Z_]+\\[A-Za-z0-9_\\]+)");
        std::regex filePath(R"([A-Za-z]:\\[^\\*?<>|]*\\.(exe|dll|sys))");
        std::regex mutex(R"(Global\\[A-Za-z0-9_]+|Local\\[A-Za-z0-9_]+)");

        auto addMatch = [&](const std::smatch& m, const std::string& type) {
            std::string val = m.str();
            if (reportedIOCs.find(val) != reportedIOCs.end()) return;
            reportedIOCs.insert(val);
            result.warnings.push_back("IOC (" + type + "): " + val);
            addedScore += 1;
            result.info.push_back("Added 1 point for regex IOC: " + val);
        };

        std::sregex_iterator it(sectionStr.begin(), sectionStr.end(), regKey);
        std::sregex_iterator end;
        for (; it != end; ++it) {
            addMatch(*it, "RegistryKey");
        }

        std::sregex_iterator it2(sectionStr.begin(), sectionStr.end(), filePath);
        for (; it2 != end; ++it2) {
            addMatch(*it2, "FilePath");
        }

        std::sregex_iterator it3(sectionStr.begin(), sectionStr.end(), mutex);
        for (; it3 != end; ++it3) {
            addMatch(*it3, "Mutex");
        }
    } catch (const std::exception& e) {
        result.info.push_back("Regex matching failed: " + std::string(e.what()));
    }
    if(addedScore > 40){addedScore = 40;}
    extraScore += addedScore;
}

// API组合检测 =
int check_api_combinations(const std::vector<std::string>& imported_apis, std::vector<std::string>& warnings) {
    int extra = 0;
    std::unordered_set<std::string> apis_set(imported_apis.begin(), imported_apis.end());
    for (const auto& combo : api_combinations) {
        int match = 0;
        for (const auto& api : combo) {
            if (apis_set.find(api) != apis_set.end()) match++;
        }
        if (match >= 2) {
            extra += 2;
            std::string warn = "Suspicious API combination detected: ";
            for (size_t i = 0; i < combo.size() && i < 3; ++i) warn += combo[i] + " ";
            warnings.push_back(warn);
        }
    }
    return extra;
}

void scan_section_for_antidebug(const BYTE* data, size_t size, const std::string& secName,
                                std::unordered_set<std::string>& detectedPatterns,
                                int& rawHitCount) {
    if (size < 1) return;

    struct Pattern {
        const BYTE* bytes;
        size_t len;
        const char* name;
    };
    static const Pattern patterns[] = {
        { (const BYTE*)"\x0F\x31", 2, "RDTSC" },
        { (const BYTE*)"\x64\xA1\x30\x00\x00\x00", 6, "PEB_read_direct" },
        { (const BYTE*)"\x64\x8B\x0D\x30\x00\x00\x00", 7, "PEB_read_variant" },
        { (const BYTE*)"\xCC", 1, "INT3" },
        { (const BYTE*)"\x0F\x01\xC8", 3, "RDTSCP" },
        { (const BYTE*)"\x0F\x34", 2, "SYSENTER" },
        // int 2d
        { (const BYTE*)"\xCD\x2D", 2, "INT2D" },
        // icebp
        { (const BYTE*)"\xF1", 1, "ICEBP" }
    };
    static const int numPatterns = sizeof(patterns) / sizeof(patterns[0]);

    for (size_t i = 0; i < size; ++i) {
        for (int p = 0; p < numPatterns; ++p) {
            if (i + patterns[p].len <= size) {
                if (memcmp(data + i, patterns[p].bytes, patterns[p].len) == 0) {
                    rawHitCount++;
                    if (detectedPatterns.find(patterns[p].name) == detectedPatterns.end()) {
                        detectedPatterns.insert(patterns[p].name);
                    }
                }
            }
        }
    }
}

void scan_section_for_control_flow(const BYTE* data, size_t size,
                                   DWORD sectionRVA, DWORD rawOffset,
                                   const std::string& secName,
                                   const std::vector<std::pair<DWORD, DWORD>>& execRanges,
                                   DWORD iatRVA, DWORD iatSize,
                                   int& abnormalCount,
                                   std::vector<std::string>& abnormalDetails) {
    if (size < 5) return;

    for (size_t i = 0; i + 5 <= size; ) {
        BYTE b = data[i];
        if (b == 0xE8) {
            if (i + 5 <= size) {
                int32_t rel = *(int32_t*)(data + i + 1);
                DWORD instrRVA = sectionRVA + (DWORD)i;
                DWORD targetRVA = instrRVA + 5 + rel;

                bool inExec = false;
                for (const auto& range : execRanges) {
                    if (targetRVA >= range.first && targetRVA < range.second) {
                        inExec = true;
                        break;
                    }
                }
                if (!inExec) {
                    char buf[256];
                    snprintf(buf, sizeof(buf),
                             "Dynamic call (E8) at RVA 0x%08X, target 0x%08X, section %s",
                             instrRVA, targetRVA, secName.c_str());
                    abnormalDetails.push_back(buf);
                    abnormalCount++;
                }
            }
            i += 5;
        } else if (b == 0xFF && i + 6 <= size && data[i+1] == 0x15) {
            DWORD addrRVA = *(DWORD*)(data + i + 2);
            DWORD instrRVA = sectionRVA + (DWORD)i;

            bool inIAT = false;
            if (iatSize > 0 && addrRVA >= iatRVA && addrRVA < iatRVA + iatSize) {
                inIAT = true;
            }
            if (!inIAT) {
                char buf[256];
                snprintf(buf, sizeof(buf),
                         "Suspicious indirect call (FF 15) at RVA 0x%08X, operand 0x%08X (not in IAT), section %s",
                         instrRVA, addrRVA, secName.c_str());
                abnormalDetails.push_back(buf);
                abnormalCount++;
            }
            i += 6;
        } else {
            i++;
        }
    }
}

void detect_high_entropy_sliding(const BYTE* data, size_t size, DWORD rvaStart,
                                 const std::string& secName,
                                 AnalysisResult& result, int& score)
{
    const size_t WINDOW = 4096;
    const size_t STEP   = 1024;
    if (size <= WINDOW) return;

    std::vector<std::pair<DWORD, DWORD>> regions;
    size_t i = 0;
    while (i + WINDOW <= size) {
        double ent = calculate_entropy(data + i, WINDOW);
        if (ent > 7.8) {
            size_t start = i;
            size_t end   = i + WINDOW;
            size_t j = i + STEP;
            int consecutive = 1;
            while (j + WINDOW <= size) {
                double ent2 = calculate_entropy(data + j, WINDOW);
                if (ent2 > 7.8) {
                    consecutive++;
                    end = j + WINDOW;
                    j += STEP;
                } else {
                    break;
                }
            }
            if (consecutive >= 3) {
                regions.push_back({(DWORD)start, (DWORD)(end - start)});
                i = j;
            } else {
                i += STEP;
            }
        } else {
            i += STEP;
        }
    }

    if (regions.size() > 1) {
        std::vector<std::pair<DWORD, DWORD>> merged;
        merged.push_back(regions[0]);
        for (size_t k = 1; k < regions.size(); ++k) {
            auto& last = merged.back();
            DWORD gap = regions[k].first - (last.first + last.second);
            if (gap < 4096) {
                last.second = regions[k].first + regions[k].second - last.first;
            } else {
                merged.push_back(regions[k]);
            }
        }
        regions.swap(merged);
    }

    int totalBlocks = 0;
    int shown = 0;
    const int MAX_SHOW = 5;
    for (auto& reg : regions) {
        DWORD rva = rvaStart + reg.first;
        DWORD len = reg.second;
        int blocks = len / 4096;
        if (blocks == 0) blocks = 1;
        totalBlocks += blocks;
        if (shown < MAX_SHOW) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Hidden high-entropy payload detected at RVA 0x%08X, size %u bytes (section %s)",
                     rva, len, secName.c_str());
            result.warnings.push_back(buf);
            shown++;
        }
    }
    if (regions.size() > MAX_SHOW) {
        result.warnings.push_back("... and " + std::to_string(regions.size() - MAX_SHOW) + " more high-entropy regions.");
    }

    int addScore = std::min(totalBlocks, 15);
    if (addScore > 0) {
        score += addScore;
        result.info.push_back("Added " + std::to_string(addScore) + " points for high-entropy sliding windows (total blocks " +
                              std::to_string(totalBlocks) + ")");
    }
}

void detect_entropy_alternating(const BYTE* data, size_t size,
                                const std::string& secName,
                                AnalysisResult& result, int& score)
{
    const size_t BLOCK = 2048;
    if (size < BLOCK * 2) return;

    std::vector<std::pair<char, size_t>> blocks;
    size_t pos = 0;
    while (pos + BLOCK <= size) {
        double ent = calculate_entropy(data + pos, BLOCK);
        char type;
        if (ent < 2.0) type = 'L';
        else if (ent > 7.5) type = 'H';
        else type = 'M';
        blocks.push_back({type, pos});
        pos += BLOCK;
    }

    struct Region { char type; size_t start; size_t end; };
    std::vector<Region> regions;
    for (size_t i = 0; i < blocks.size(); ) {
        char curType = blocks[i].first;
        if (curType == 'M') { ++i; continue; }
        size_t start = i;
        while (i < blocks.size() && blocks[i].first == curType) ++i;
        size_t end = i;
        size_t length = (end - start) * BLOCK;
        if (length > BLOCK) {
            regions.push_back({curType, start, end});
        }
    }

    if (regions.size() < 2) return;

    bool alternating = true;
    for (size_t i = 1; i < regions.size(); ++i) {
        if (regions[i].type == regions[i-1].type) {
            alternating = false;
            break;
        }
    }
    if (alternating) {
        score += 6;
        result.warnings.push_back("Compressed/encrypted container detected: alternating low-entropy and high-entropy regions in section " + secName);
        result.info.push_back("Added 6 points for entropy alternation (compression/encryption fingerprint)");
    }
}

void scan_peb_anti_debug_pattern(const BYTE* data, size_t size, bool is64bit,
                                 AnalysisResult& result, int& score) {
    if (size < 7) return;
    const BYTE pattern32[] = {0x64, 0xA1, 0x30, 0x00, 0x00, 0x00};
    const BYTE pattern64[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00};
    const BYTE follow[] = {0x80, 0x78, 0x02, 0x00};
    const int follow_len = 4;

    if (is64bit) {
        for (size_t i = 0; i + 9 <= size; ++i) {
            if (memcmp(data + i, pattern64, 9) == 0) {
                for (size_t j = i + 9; j < size && j < i + 9 + 3; ++j) {
                    if (j + 4 <= size && memcmp(data + j, follow, 4) == 0) {
                        result.warnings.push_back("PEB beingdebugged flag access detected (anti-debug)");
                        score += 5;
                        result.info.push_back("Added 5 points for PEB anti-debug pattern (64-bit)");
                        return;
                    }
                }
            }
        }
    } else {
        for (size_t i = 0; i + 6 <= size; ++i) {
            if (memcmp(data + i, pattern32, 6) == 0) {
                for (size_t j = i + 6; j < size && j < i + 6 + 3; ++j) {
                    if (j + 4 <= size && memcmp(data + j, follow, 4) == 0) {
                        result.warnings.push_back("PEB beingdebugged flag access detected (anti-debug)");
                        score += 5;
                        result.info.push_back("Added 5 points for PEB anti-debug pattern (32-bit)");
                        return;
                    }
                }
            }
        }
    }
}

void scan_seh_anti_debug_pattern(const BYTE* data, size_t size,
                                 AnalysisResult& result, int& score) {
    const BYTE seq1[] = {0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00};
    const BYTE seq2[] = {0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00};
    const int seq_len = 7;
    if (size < seq_len * 2 + 200) return;

    for (size_t i = 0; i + seq_len <= size; ++i) {
        if (memcmp(data + i, seq1, seq_len) == 0) {
            size_t search_end = i + seq_len + 200;
            if (search_end > size) search_end = size;
            for (size_t j = i + seq_len; j + seq_len <= search_end; ++j) {
                if (memcmp(data + j, seq2, seq_len) == 0) {
                    bool found_int3 = false;
                    for (size_t k = i; k < search_end; ++k) {
                        if (data[k] == 0xCC) {
                            found_int3 = true;
                            break;
                        }
                    }
                    if (found_int3) {
                        result.warnings.push_back("SEH anti-debug pattern with INT3 detected");
                        score += 4;
                        result.info.push_back("Added 4 points for SEH+INT3 anti-debug pattern");
                    }
                    return;
                }
            }
        }
    }
}

// .NET 元数据表索引 =
#define TABLE_METHOD_DEF         0x06
#define TABLE_ASSEMBLY_REF       0x23
#define TABLE_MODULE_REF         0x1A
#define TABLE_TYPE_DEF          0x02
#define TABLE_FIELD             0x04
#define TABLE_MEMBER_REF        0x0A

// .NET 元数据结构辅助 =
struct MethodDefRecord {
    DWORD RVA;
    WORD ImplFlags;
    WORD Flags;
    DWORD Name;
    DWORD Signature;
    DWORD ParamList;
};

struct AssemblyRefRecord {
    WORD MajorVersion;
    WORD MinorVersion;
    WORD BuildNumber;
    WORD RevisionNumber;
    DWORD Flags;
    DWORD PublicKeyOrToken;
    DWORD Name;
    DWORD Culture;
    DWORD HashValue;
};

struct ModuleRefRecord {
    DWORD Name;
};

// .NET IL 扫描 =
static void scan_il_for_high_risk(const BYTE* ilData, size_t ilSize,
                                  const std::unordered_map<std::string, DWORD>& stringTokenMap,
                                  std::vector<std::string>& warnings,
                                  int& score, std::vector<std::string>& info) {
    if (ilSize < 1) return;
    // 操作码常量
    const BYTE OP_CALL = 0x28;
    const BYTE OP_CALLVIRT = 0x6F;
    const BYTE OP_NEWOBJ = 0x73;
    const BYTE OP_LDSTR = 0x72;

    int callCount = 0, callvirtCount = 0, newobjCount = 0, ldstrCallPair = 0;
    bool inLdstr = false;

    size_t i = 0;
    while (i < ilSize) {
        BYTE op = ilData[i];
        if (op == OP_LDSTR) {
            inLdstr = true;
            // 跳过操作码和 token（4字节）
            i += 1 + 4;
            // 检查后续是否有 call
            if (i + 1 < ilSize && ilData[i] == OP_CALL) {
                ldstrCallPair++;
                warnings.push_back("ldstr + call pair detected (potential string decryption)");
            }
            continue;
        } else if (op == OP_CALL) {
            callCount++;
            // 尝试解析目标 token
            if (i + 5 <= ilSize) {
                DWORD token = *(DWORD*)(ilData + i + 1);
                // 根据 token 类型判断是否高风险（如 MethodInfo.Invoke）
                BYTE table = token >> 24;
                if (table == TABLE_MEMBER_REF) {
                    warnings.push_back("MemberRef call (token 0x" + std::to_string(token) + ") - possible reflection");
                    score += 2;
                }
            }
            i += 5;
        } else if (op == OP_CALLVIRT) {
            callvirtCount++;
            i += 5;
        } else if (op == OP_NEWOBJ) {
            newobjCount++;
            i += 5;
        } else {
            i++;
        }
    }

    if (callCount + callvirtCount > 10) {
        int add = std::min((callCount + callvirtCount) / 5, 3);
        score += add;
        info.push_back("Added " + std::to_string(add) + " points for high number of call/callvirt instructions");
    }
    if (newobjCount > 3) {
        score += 2;
        warnings.push_back("Multiple 'newobj' instructions found (object creation)");
    }
    if (ldstrCallPair > 2) {
        score += 3;
        warnings.push_back("Multiple ldstr+call pairs - dynamic string construction");
    }
    info.push_back("IL scan: call=" + std::to_string(callCount) +
                   ", callvirt=" + std::to_string(callvirtCount) +
                   ", newobj=" + std::to_string(newobjCount) +
                   ", ldstr+call=" + std::to_string(ldstrCallPair));
}

// 解析 #~ 流，提取 MethodDef, AssemblyRef, ModuleRef =
// 完整解析 #~ 流，支持动态索引宽度
static bool ParseMetadataTables(const BYTE* metaBase, size_t metaSize,
                                std::vector<MethodDefRecord>& methodDefs,
                                std::vector<AssemblyRefRecord>& assemblyRefs,
                                std::vector<ModuleRefRecord>& moduleRefs,
                                const BYTE* stringsBase, size_t stringsSize) {
    // 定位 #~ 流（假设 metaBase 指向整个元数据头）
    const BYTE* p = metaBase;
    if (metaSize < 4) return false;
    DWORD sig = *(const DWORD*)p;
    if (sig != 0x424A5342) return false; // BSJB

    // 跳过版本信息，定位流头
    size_t offset = 4 + 2 + 2 + 4;
    if (offset + 4 > metaSize) return false;
    DWORD verLen = *(const DWORD*)(p + offset);
    offset += 4;
    if (offset + verLen > metaSize) return false;
    offset += verLen;
    while (offset % 4 != 0 && offset < metaSize) offset++;

    if (offset + 4 > metaSize) return false;
    WORD iStreams = *(const WORD*)(p + offset + 2);
    offset += 4;

    DWORD tildeOffset = 0, tildeSize = 0;
    for (WORD i = 0; i < iStreams; ++i) {
        if (offset + 8 > metaSize) break;
        DWORD iOff = *(const DWORD*)(p + offset);
        DWORD iSize = *(const DWORD*)(p + offset + 4);
        offset += 8;
        const char* name = (const char*)(p + offset);
        size_t nameLen = strnlen(name, 32);
        offset += nameLen + 1;
        while (offset % 4 != 0 && offset < metaSize) offset++;
        if (strcmp(name, "#~") == 0) {
            tildeOffset = iOff;
            tildeSize = iSize;
        }
    }

    if (tildeOffset == 0 || tildeSize == 0) return false;
    const BYTE* tildeBase = metaBase + tildeOffset;
    if (tildeBase + tildeSize > metaBase + metaSize) return false;

    // 解析表流头
    const BYTE* t = tildeBase;
    if (tildeSize < 24) return false;
    DWORD reserved = *(const DWORD*)t; t += 4;
    BYTE major = *t++; BYTE minor = *t++;
    BYTE heapSizes = *t++; BYTE reserved2 = *t++;
    ULONG64 valid = *(const ULONG64*)t; t += 8;
    ULONG64 sorted = *(const ULONG64*)t; t += 8;

    // 读取每表行数（压缩整数）
    auto readCompressedUInt = [&](const BYTE*& ptr, size_t max) -> DWORD {
        if (ptr >= ptr + max) return 0;
        BYTE b1 = *ptr;
        if (b1 < 0x80) {
            ptr += 1;
            return b1;
        } else if (b1 < 0xC0) {
            if (ptr + 1 >= ptr + max) return 0;
            BYTE b2 = *(ptr + 1);
            ptr += 2;
            return ((b1 & 0x3F) << 8) | b2;
        } else {
            if (ptr + 3 >= ptr + max) return 0;
            BYTE b2 = *(ptr + 1);
            BYTE b3 = *(ptr + 2);
            BYTE b4 = *(ptr + 3);
            ptr += 4;
            return ((b1 & 0x3F) << 24) | (b2 << 16) | (b3 << 8) | b4;
        }
    };

    DWORD rowCounts[64] = {0};
    for (int idx = 0; idx < 64; ++idx) {
        if (valid & (1ULL << idx)) {
            rowCounts[idx] = readCompressedUInt(t, tildeBase + tildeSize - t);
        }
    }

    // 确定各索引宽度（根据 heapSizes）
    bool stringsAre2Bytes = (heapSizes & 0x01) != 0;
    bool guidsAre2Bytes   = (heapSizes & 0x02) != 0;
    bool blobsAre2Bytes   = (heapSizes & 0x04) != 0;

    // 表记录大小的辅助函数（根据索引宽度动态计算）
    auto getRowSize = [&](int tableIndex) -> size_t {
        // ECMA-335 表定义
        switch (tableIndex) {
            case 0x00: // Module
                return 2 + 2 + (stringsAre2Bytes ? 2 : 4) + (guidsAre2Bytes ? 2 : 4) + 2 + 2;
            case 0x01: // TypeRef
                return (rowCounts[0x01] < 65536 ? 2 : 4) + (stringsAre2Bytes ? 2 : 4) + (stringsAre2Bytes ? 2 : 4);
            case 0x02: // TypeDef
                return 4 + 4 + (stringsAre2Bytes ? 2 : 4) + (rowCounts[0x01] < 65536 ? 2 : 4) + 2 + 2;
            case 0x03: // FieldPtr
                return (rowCounts[0x04] < 65536 ? 2 : 4);
            case 0x04: // Field
                return 2 + 2 + (stringsAre2Bytes ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x05: // MethodPtr
                return (rowCounts[0x06] < 65536 ? 2 : 4);
            case 0x06: // MethodDef
                return 4 + 2 + 2 + (stringsAre2Bytes ? 2 : 4) + (blobsAre2Bytes ? 2 : 4) + (rowCounts[0x08] < 65536 ? 2 : 4);
            case 0x07: // ParamPtr
                return (rowCounts[0x08] < 65536 ? 2 : 4);
            case 0x08: // Param
                return 2 + 2 + 2 + (stringsAre2Bytes ? 2 : 4);
            case 0x09: // InterfaceImpl
                return (rowCounts[0x02] < 65536 ? 2 : 4) + (rowCounts[0x01] < 65536 ? 2 : 4);
            case 0x0A: // MemberRef
                return (rowCounts[0x0A] < 65536 ? 2 : 4) + (stringsAre2Bytes ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x0B: // Constant
                return 2 + 2 + (rowCounts[0x04] < 65536 ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x0C: // CustomAttribute
                return (rowCounts[0x0C] < 65536 ? 2 : 4) + (rowCounts[0x0C] < 65536 ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x0D: // FieldMarshal
                return (rowCounts[0x04] < 65536 ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x0E: // DeclSecurity
                return 2 + 2 + (rowCounts[0x0E] < 65536 ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x0F: // ClassLayout
                return 2 + 4 + (rowCounts[0x02] < 65536 ? 2 : 4);
            case 0x10: // FieldLayout
                return 4 + (rowCounts[0x04] < 65536 ? 2 : 4);
            case 0x11: // StandAloneSig
                return (blobsAre2Bytes ? 2 : 4);
            case 0x12: // EventMap
                return (rowCounts[0x02] < 65536 ? 2 : 4) + (rowCounts[0x14] < 65536 ? 2 : 4);
            case 0x13: // EventPtr
                return (rowCounts[0x14] < 65536 ? 2 : 4);
            case 0x14: // Event
                return 2 + 2 + (stringsAre2Bytes ? 2 : 4) + (rowCounts[0x01] < 65536 ? 2 : 4);
            case 0x15: // PropertyMap
                return (rowCounts[0x02] < 65536 ? 2 : 4) + (rowCounts[0x17] < 65536 ? 2 : 4);
            case 0x16: // PropertyPtr
                return (rowCounts[0x17] < 65536 ? 2 : 4);
            case 0x17: // Property
                return 2 + 2 + (stringsAre2Bytes ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x18: // MethodSemantics
                return 2 + (rowCounts[0x06] < 65536 ? 2 : 4) + (rowCounts[0x0A] < 65536 ? 2 : 4);
            case 0x19: // MethodImpl
                return (rowCounts[0x02] < 65536 ? 2 : 4) + (rowCounts[0x06] < 65536 ? 2 : 4) + (rowCounts[0x06] < 65536 ? 2 : 4);
            case 0x1A: // ModuleRef
                return (stringsAre2Bytes ? 2 : 4);
            case 0x1B: // TypeSpec
                return (blobsAre2Bytes ? 2 : 4);
            case 0x1C: // ImplMap
                return 2 + 2 + (rowCounts[0x06] < 65536 ? 2 : 4) + (stringsAre2Bytes ? 2 : 4) + (rowCounts[0x1A] < 65536 ? 2 : 4);
            case 0x1D: // FieldRVA
                return 4 + (rowCounts[0x04] < 65536 ? 2 : 4);
            case 0x1E: // ENCLog
                return 4 + 4;
            case 0x1F: // ENCMap
                return 4;
            case 0x20: // Assembly
                return 4 + 2 + 2 + 2 + 2 + 4 + (blobsAre2Bytes ? 2 : 4) + (stringsAre2Bytes ? 2 : 4) + (stringsAre2Bytes ? 2 : 4);
            case 0x21: // AssemblyProcessor
                return 4;
            case 0x22: // AssemblyOS
                return 4 + 4 + 4;
            case 0x23: // AssemblyRef
                return 2 + 2 + 2 + 2 + 4 + (blobsAre2Bytes ? 2 : 4) + (stringsAre2Bytes ? 2 : 4) + (stringsAre2Bytes ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x24: // AssemblyRefProcessor
                return 4 + (rowCounts[0x23] < 65536 ? 2 : 4);
            case 0x25: // AssemblyRefOS
                return 4 + 4 + 4 + (rowCounts[0x23] < 65536 ? 2 : 4);
            case 0x26: // File
                return 4 + 4 + (stringsAre2Bytes ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x27: // ExportedType
                return 4 + 4 + (stringsAre2Bytes ? 2 : 4) + (rowCounts[0x26] < 65536 ? 2 : 4) + (rowCounts[0x02] < 65536 ? 2 : 4);
            case 0x28: // ManifestResource
                return 4 + 4 + (stringsAre2Bytes ? 2 : 4) + (rowCounts[0x26] < 65536 ? 2 : 4);
            case 0x29: // NestedClass
                return (rowCounts[0x02] < 65536 ? 2 : 4) + (rowCounts[0x02] < 65536 ? 2 : 4);
            case 0x2A: // GenericParam
                return 2 + 2 + 2 + (rowCounts[0x2A] < 65536 ? 2 : 4) + (rowCounts[0x2A] < 65536 ? 2 : 4);
            case 0x2B: // MethodSpec
                return (rowCounts[0x2B] < 65536 ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            case 0x2C: // GenericParamConstraint
                return (rowCounts[0x2A] < 65536 ? 2 : 4) + (rowCounts[0x01] < 65536 ? 2 : 4);
            default:
                return 4; // fallback
        }
    };

    // 计算各表起始偏移（从流起始）
    DWORD offsetTables = (DWORD)(t - tildeBase); // 当前指向表数据起始
    DWORD curOff = offsetTables;
    std::map<int, DWORD> tableOffsets;
    for (int idx = 0; idx < 64; ++idx) {
        if (valid & (1ULL << idx)) {
            tableOffsets[idx] = curOff;
            size_t rowSize = getRowSize(idx);
            curOff += rowCounts[idx] * rowSize;
        }
    }

    // 读取 MethodDef (0x06)
    if (valid & (1ULL << 0x06)) {
        DWORD off = tableOffsets[0x06];
        const BYTE* record = tildeBase + off;
        size_t rowSize = getRowSize(0x06);
        for (DWORD i = 0; i < rowCounts[0x06]; ++i) {
            if (record + rowSize > tildeBase + tildeSize) break;
            MethodDefRecord m;
            m.RVA = *(const DWORD*)(record);
            m.ImplFlags = *(const WORD*)(record + 4);
            m.Flags = *(const WORD*)(record + 6);
            // Name, Signature, ParamList 可能宽度不同，但我们只用于辅助
            // 但为了正确性，根据索引宽度读取
            DWORD nameOffset = 0;
            if (stringsAre2Bytes) {
                nameOffset = *(const WORD*)(record + 8);
            } else {
                nameOffset = *(const DWORD*)(record + 8);
            }
            m.Name = nameOffset; // 存储偏移（在 #Strings 中）
            DWORD sigOffset = 0;
            if (blobsAre2Bytes) {
                sigOffset = *(const WORD*)(record + 8 + (stringsAre2Bytes ? 2 : 4));
            } else {
                sigOffset = *(const DWORD*)(record + 8 + (stringsAre2Bytes ? 2 : 4));
            }
            m.Signature = sigOffset;
            // ParamList 是表索引，根据 Param 表行数决定宽度
            DWORD paramList = 0;
            size_t paramOffset = 8 + (stringsAre2Bytes ? 2 : 4) + (blobsAre2Bytes ? 2 : 4);
            if (rowCounts[0x08] < 65536) {
                paramList = *(const WORD*)(record + paramOffset);
            } else {
                paramList = *(const DWORD*)(record + paramOffset);
            }
            m.ParamList = paramList;

            methodDefs.push_back(m);
            record += rowSize;
        }
    }

    // 读取 AssemblyRef (0x23)
    if (valid & (1ULL << 0x23)) {
        DWORD off = tableOffsets[0x23];
        const BYTE* record = tildeBase + off;
        size_t rowSize = getRowSize(0x23);
        for (DWORD i = 0; i < rowCounts[0x23]; ++i) {
            if (record + rowSize > tildeBase + tildeSize) break;
            AssemblyRefRecord a;
            a.MajorVersion = *(const WORD*)(record);
            a.MinorVersion = *(const WORD*)(record + 2);
            a.BuildNumber = *(const WORD*)(record + 4);
            a.RevisionNumber = *(const WORD*)(record + 6);
            a.Flags = *(const DWORD*)(record + 8);
            // PublicKeyOrToken 是 Blob 索引
            if (blobsAre2Bytes) {
                a.PublicKeyOrToken = *(const WORD*)(record + 12);
            } else {
                a.PublicKeyOrToken = *(const DWORD*)(record + 12);
            }
            size_t pos = 12 + (blobsAre2Bytes ? 2 : 4);
            if (stringsAre2Bytes) {
                a.Name = *(const WORD*)(record + pos);
                pos += 2;
            } else {
                a.Name = *(const DWORD*)(record + pos);
                pos += 4;
            }
            if (stringsAre2Bytes) {
                a.Culture = *(const WORD*)(record + pos);
                pos += 2;
            } else {
                a.Culture = *(const DWORD*)(record + pos);
                pos += 4;
            }
            if (blobsAre2Bytes) {
                a.HashValue = *(const WORD*)(record + pos);
            } else {
                a.HashValue = *(const DWORD*)(record + pos);
            }
            assemblyRefs.push_back(a);
            record += rowSize;
        }
    }

    // 读取 ModuleRef (0x1A)
    if (valid & (1ULL << 0x1A)) {
        DWORD off = tableOffsets[0x1A];
        const BYTE* record = tildeBase + off;
        size_t rowSize = getRowSize(0x1A);
        for (DWORD i = 0; i < rowCounts[0x1A]; ++i) {
            if (record + rowSize > tildeBase + tildeSize) break;
            ModuleRefRecord m;
            if (stringsAre2Bytes) {
                m.Name = *(const WORD*)(record);
            } else {
                m.Name = *(const DWORD*)(record);
            }
            moduleRefs.push_back(m);
            record += rowSize;
        }
    }

    return true;
}

// .NET 混淆指纹 =
static void CheckObfuscationFingerprint(const BYTE* stringsBase, size_t stringsSize,
                                        std::vector<std::string>& warnings,
                                        int& score, std::vector<std::string>& info) {
    if (stringsSize == 0) return;
    int nameCount = 0;
    double totalEntropy = 0.0;
    int nonPrintableCount = 0;

    size_t pos = 0;
    while (pos < stringsSize) {
        if (stringsBase[pos] == 0) { ++pos; continue; }
        size_t start = pos;
        while (pos < stringsSize && stringsBase[pos] != 0) ++pos;
        size_t len = pos - start;
        if (len > 3 && len < 256) {
            nameCount++;
            double ent = calculate_entropy(stringsBase + start, len);
            totalEntropy += ent;
            // 检查不可打印字符（非 ASCII 字母数字和常用符号）
            for (size_t i = start; i < pos; ++i) {
                unsigned char c = stringsBase[i];
                if (!isprint(c) && c != '\0') {
                    nonPrintableCount++;
                    break;
                }
            }
        }
        if (pos < stringsSize) ++pos;
    }

    if (nameCount > 0) {
        double avgEntropy = totalEntropy / nameCount;
        info.push_back(".NET name entropy: " + std::to_string(avgEntropy) + " over " + std::to_string(nameCount) + " names");

        // 检查是否包含混淆特性（在 #Strings 中搜索 ObfuscationAttribute）
        bool hasObfuscationAttr = false;
        const char* obfPatterns[] = {"ObfuscationAttribute", "DotfuscatorAttribute"};
        for (const char* pat : obfPatterns) {
            if (contains_case_insensitive(stringsBase, stringsSize, pat)) {
                hasObfuscationAttr = true;
                break;
            }
        }

        if (hasObfuscationAttr) {
            score += 8;
            warnings.push_back("ObfuscationAttribute or DotfuscatorAttribute found - likely obfuscated");
            info.push_back("Added 8 points for obfuscation attribute");
        }

        if (avgEntropy > 6.0 && nameCount > 50) {
            score += 10;
            warnings.push_back("High average entropy (>6.0) with many names (>50) - obfuscation");
            info.push_back("Added 10 points for high entropy name obfuscation");
        } else if (avgEntropy > 5.5 && nameCount > 30) {
            score += 5;
            warnings.push_back("Moderate entropy (>5.5) with many names (>30) - possible obfuscation");
            info.push_back("Added 5 points for moderate entropy name obfuscation");
        }

        if (nonPrintableCount > 0 && nameCount > 20) {
            // 不可打印字符通常表示名称被编码
            score += 6;
            warnings.push_back("Non-printable characters in names detected - obfuscation");
            info.push_back("Added 6 points for non-printable characters");
        }
    }
}

// .NET 程序集引用检测 =
static void CheckAssemblyRefs(const std::vector<AssemblyRefRecord>& refs,
                              const BYTE* stringsBase, size_t stringsSize,
                              std::vector<std::string>& warnings,
                              int& score, std::vector<std::string>& info) {
    // 敏感列表
    const char* sensitiveAsm[] = {
        "System.Management",
        "System.Net.Http",
        "System.DirectoryServices",
        "System.Diagnostics.Process",
        "System.Runtime.Serialization.Formatters.Binary",
        "System.Reflection",
        "Microsoft.Win32"
    };
    int sensCount = 0;
    bool hasZeroVersion = false, hasEmptyPublicKey = false, hasRandomName = false;

    for (const auto& ref : refs) {
        std::string name;
        if (ref.Name != 0 && ref.Name + 4 <= stringsSize) {
            const char* n = (const char*)(stringsBase + ref.Name);
            name = n;
        }
        if (name.empty()) continue;

        // 检查敏感
        for (const char* sens : sensitiveAsm) {
            if (name.find(sens) != std::string::npos) {
                sensCount++;
                warnings.push_back("Sensitive assembly reference: " + name);
                break;
            }
        }

        // 可疑特征
        if (ref.MajorVersion == 0 && ref.MinorVersion == 0 &&
            ref.BuildNumber == 0 && ref.RevisionNumber == 0) {
            hasZeroVersion = true;
        }
        if (ref.PublicKeyOrToken == 0) {
            hasEmptyPublicKey = true;
        }

        // 随机名称检测：长度>8且含数字或特殊字符
        bool hasDigit = false, hasSpecial = false;
        for (char c : name) {
            if (isdigit(c)) hasDigit = true;
            if (c == '.' || c == '_' || c == '-') continue;
            if (!isalnum(c)) hasSpecial = true;
        }
        if (name.length() > 8 && (hasDigit || hasSpecial) && name.find("System") == std::string::npos) {
            hasRandomName = true;
        }
    }

    if (sensCount > 2) {
        score += 6;
        warnings.push_back("Multiple sensitive assembly references (" + std::to_string(sensCount) + ")");
        info.push_back("Added 6 points for sensitive references");
    }
    if (hasZeroVersion) {
        score += 3;
        warnings.push_back("Assembly reference with version 0.0.0.0");
        info.push_back("Added 3 points for zero version");
    }
    if (hasEmptyPublicKey) {
        score += 2;
        warnings.push_back("Assembly reference with empty public key token");
        info.push_back("Added 2 points for empty public key");
    }
    if (hasRandomName) {
        score += 4;
        warnings.push_back("Assembly reference with suspicious random-looking name");
        info.push_back("Added 4 points for random name");
    }
}

//  .NET 分析 =
void AnalyzeDotNetAssembly(const BYTE* base, size_t baseSize,
                           const IMAGE_COR20_HEADER* corHeader,
                           DWORD metaRaw, DWORD metaSize,
                           AnalysisResult& result,
                           bool is64bit,
                           std::function<DWORD(DWORD)> rvaToRaw)
{
    // 1. 解析元数据头，定位 #Strings 流和 #~ 流
    if (metaRaw == 0 || metaRaw + metaSize > baseSize) return;

    const BYTE* pMeta = base + metaRaw;
    DWORD sig = *(const DWORD*)pMeta;
    if (sig != 0x424A5342) return; // "BSJB"

    size_t offset = 4 + 2 + 2 + 4;
    if (offset + 4 > metaSize) return;
    DWORD verLen = *(const DWORD*)(pMeta + offset);
    offset += 4;
    if (offset + verLen > metaSize) return;
    offset += verLen;
    while (offset % 4 != 0 && offset < metaSize) offset++;

    if (offset + 4 > metaSize) return;
    WORD iStreams = *(const WORD*)(pMeta + offset + 2);
    offset += 4;

    DWORD stringsOffset = 0, stringsSize = 0;
    DWORD tildeOffset = 0, tildeSize = 0;

    for (WORD i = 0; i < iStreams; ++i) {
        if (offset + 4 + 4 > metaSize) break;
        DWORD iOff = *(const DWORD*)(pMeta + offset);
        DWORD iSize = *(const DWORD*)(pMeta + offset + 4);
        offset += 8;
        const char* name = (const char*)(pMeta + offset);
        size_t nameLen = strnlen(name, 32);
        offset += nameLen + 1;
        while (offset % 4 != 0 && offset < metaSize) offset++;

        if (strcmp(name, "#Strings") == 0) {
            stringsOffset = iOff;
            stringsSize = iSize;
        } else if (strcmp(name, "#~") == 0) {
            tildeOffset = iOff;
            tildeSize = iSize;
        }
    }

    if (stringsOffset == 0 || stringsSize == 0) return;
    const BYTE* pStrings = pMeta + stringsOffset;
    if (pStrings < pMeta || pStrings + stringsSize > pMeta + metaSize) return;

    // 2. 解析 #~ 流（完整表解析）
    std::vector<MethodDefRecord> methodDefs;
    std::vector<AssemblyRefRecord> assemblyRefs;
    std::vector<ModuleRefRecord> moduleRefs;
    bool metaParsed = ParseMetadataTables(pMeta, metaSize, methodDefs, assemblyRefs, moduleRefs, pStrings, stringsSize);

    int totalNetScore = 0;

     //检测 ObfuscationAttribute 和 SuppressIldasmAttribute
    {
        bool hasObfuscation = false;
        bool hasSuppressIldasm = false;
        const char* obfPatterns[] = {"ObfuscationAttribute", "DotfuscatorAttribute"};
        const char* suppressPattern = "SuppressIldasmAttribute";
        size_t pos = 0;
        while (pos < stringsSize) {
            if (pStrings[pos] == 0) { ++pos; continue; }
            size_t start = pos;
            while (pos < stringsSize && pStrings[pos] != 0) ++pos;
            size_t len = pos - start;
            if (len > 5 && len < 256) {
                std::string str((const char*)pStrings + start, len);
                for (const char* pat : obfPatterns) {
                    if (str.find(pat) != std::string::npos) {
                        hasObfuscation = true;
                        break;
                    }
                }
                if (str.find(suppressPattern) != std::string::npos) {
                    hasSuppressIldasm = true;
                }
            }
            if (pos < stringsSize) ++pos;
        }
        if (hasObfuscation) {
            totalNetScore += 10;
            result.warnings.push_back("ObfuscationAttribute found in #Strings - obfuscation");
            result.info.push_back("Added 10 points for ObfuscationAttribute");
        }
        if (hasSuppressIldasm) {
            totalNetScore += 10;
            result.warnings.push_back("SuppressIldasmAttribute found - likely obfuscated");
            result.info.push_back("Added 10 points for SuppressIldasmAttribute");
        }
    }

     //计算方法名平均熵
    if (metaParsed && !methodDefs.empty()) {
        int methodCount = 0;
        double totalEntropy = 0.0;
        for (const auto& md : methodDefs) {
            if (md.Name == 0) continue;
            if (md.Name + 4 <= stringsSize) {
                const char* name = (const char*)(pStrings + md.Name);
                size_t len = strlen(name);
                if (len > 2 && len < 256) {
                    double ent = calculate_entropy((const BYTE*)name, len);
                    totalEntropy += ent;
                    methodCount++;
                }
            }
        }
        if (methodCount > 0) {
            double avgEntropy = totalEntropy / methodCount;
            result.info.push_back(".NET method name average entropy: " + std::to_string(avgEntropy) + " over " + std::to_string(methodCount) + " methods");
            if (avgEntropy > 6.0 && methodCount > 50) {
                totalNetScore += 15;
                result.warnings.push_back("High method name entropy (>6.0) with many methods (>50) - strong obfuscation");
                result.info.push_back("Added 15 points for high method name entropy");
            } else if (avgEntropy > 5.5 && methodCount > 30) {
                totalNetScore += 8;
                result.warnings.push_back("Moderate method name entropy (>5.5) with many methods (>30) - possible obfuscation");
                result.info.push_back("Added 8 points for moderate method name entropy");
            }
        }
    }

     //检查敏感命名空间引用
    if (metaParsed) {
        int sensitiveRefCount = 0;
        for (const auto& ref : assemblyRefs) {
            if (ref.Name == 0) continue;
            if (ref.Name + 4 <= stringsSize) {
                const char* name = (const char*)(pStrings + ref.Name);
                std::string refName(name);
                bool isSensitive = false;
                const char* sensitiveNames[] = {
                    "System.Management",
                    "System.Net.Http",
                    "System.DirectoryServices",
                    "System.Diagnostics.Process",
                    "System.Runtime.Serialization.Formatters.Binary",
                    "System.Reflection",
                    "Microsoft.Win32"
                };
                for (const char* sn : sensitiveNames) {
                    if (refName.find(sn) != std::string::npos) {
                        isSensitive = true;
                        break;
                    }
                }
                if (isSensitive) {
                    sensitiveRefCount++;
                    result.warnings.push_back("Sensitive namespace reference: " + refName);
                }
            }
        }
        if (sensitiveRefCount > 0) {
            int addScore = sensitiveRefCount * 5;
            if (addScore > 25) addScore = 25; // cap
            totalNetScore += addScore;
            result.info.push_back("Added " + std::to_string(addScore) + " points for " + std::to_string(sensitiveRefCount) + " sensitive namespace references");
        }
    }

    // 3. 原有 #Strings 黑名单扫描（保留）
    struct BlackItem {
        const char* pattern;
        int category;
        int points;
    };
    static const BlackItem blacklist[] = {
        {"System.Reflection.Assembly.Load", 1, 3},
        {"Assembly.LoadFrom", 1, 3},
        {"Assembly.LoadFile", 1, 3},
        {"Activator.CreateInstance", 1, 3},
        {"Type.GetType", 1, 3},
        {"Process.Start", 2, 3},
        {"System.Diagnostics.Process", 2, 3},
        {"WebClient.DownloadString", 3, 4},
        {"WebClient.DownloadData", 3, 4},
        {"WebClient.DownloadFile", 3, 4},
        {"HttpClient", 3, 4},
        {"WebRequest", 3, 4},
        {"File.WriteAllBytes", 4, 3},
        {"File.WriteAllText", 4, 3},
        {"FileStream.Write", 4, 3},
        {"ManagementClass", 5, 3},
        {"ManagementObject", 5, 3},
        {"WMI", 5, 3},
        {"Marshal.PtrToStructure", 6, 2},
        {"Marshal.StructureToPtr", 6, 2},
        {"Marshal.AllocHGlobal", 6, 2},
        {"SuppressIldasmAttribute", 7, 2},
        {"Debugger.IsAttached", 7, 2},
        {"Environment.UserInteractive", 7, 2},
    };
    const size_t blackCount = sizeof(blacklist) / sizeof(blacklist[0]);

    // 原有扫描 #Strings
    size_t pos = 0;
    while (pos < stringsSize) {
        if (pStrings[pos] == 0) { ++pos; continue; }
        size_t start = pos;
        while (pos < stringsSize && pStrings[pos] != 0) ++pos;
        size_t len = pos - start;
        if (len > 3 && len < 256) {
            std::string str((const char*)pStrings + start, len);
            for (size_t i = 0; i < blackCount; ++i) {
                if (str.find(blacklist[i].pattern) != std::string::npos) {
                    totalNetScore += blacklist[i].points;
                    result.warnings.push_back(std::string(".NET blacklist match: ") + blacklist[i].pattern);
                    break;
                }
            }
        }
        if (pos < stringsSize) ++pos;
    }

    // 4. 使用解析出的表进行深入分析
    if (metaParsed) {
        // 检查程序集引用
        CheckAssemblyRefs(assemblyRefs, pStrings, stringsSize, result.warnings, totalNetScore, result.info);

        // 混淆指纹（原有）
        CheckObfuscationFingerprint(pStrings, stringsSize, result.warnings, totalNetScore, result.info);

        //  IL 扫描 
        if (!methodDefs.empty()) {
            int ilScore = 0;
            std::vector<std::string> ilWarnings;
            std::vector<std::string> ilInfo;

            // 遍历所有方法，提取 IL 并扫描
            for (const auto& md : methodDefs) {
                if (md.RVA == 0) continue;
                // 通过 RVA 获取文件偏移
                DWORD rawOffset = rvaToRaw(md.RVA);
                if (rawOffset == 0 || rawOffset >= baseSize) continue;

                const BYTE* methodData = base + rawOffset;
                size_t remaining = baseSize - rawOffset;
                if (remaining < 1) continue;

                // 解析方法头（Tiny / Fat）
                const BYTE* ilStart = nullptr;
                DWORD codeSize = 0;

                BYTE first = methodData[0];
                if ((first & 0x03) == 0x02) { // Tiny 格式
                    codeSize = first >> 2;    // 高6位
                    ilStart = methodData + 1;
                } else if ((first & 0x03) == 0x03) { // Fat 格式
                    if (remaining < 12) continue;
                    // 读取 header
                    WORD flags = *(const WORD*)(methodData + 0);
                    WORD maxStack = *(const WORD*)(methodData + 2);
                    codeSize = *(const DWORD*)(methodData + 4);
                    // localVarSigTok = *(const DWORD*)(methodData + 8); // 忽略
                    ilStart = methodData + 12;
                } else {
                    continue; // 未知格式
                }

                if (codeSize == 0 || ilStart == nullptr) continue;
                if (ilStart + codeSize > base + baseSize) continue; // 越界检查

                // 调用 IL 扫描函数
                std::unordered_map<std::string, DWORD> dummyMap; // 此处不需要 string token 映射
                scan_il_for_high_risk(ilStart, codeSize, dummyMap, ilWarnings, ilScore, ilInfo);
            }

            // 将 IL 扫描结果汇总到总得分和警告
            if (ilScore > 0) {
                totalNetScore += ilScore;
                result.info.push_back("IL scan added " + std::to_string(ilScore) + " points");
                for (const auto& w : ilWarnings) {
                    result.warnings.push_back("[IL] " + w);
                }
                for (const auto& i : ilInfo) {
                    result.info.push_back("[IL] " + i);
                }
            }
        }

        // 处理 ModuleRef
        for (const auto& mr : moduleRefs) {
            if (mr.Name != 0 && mr.Name + 4 <= stringsSize) {
                const char* modName = (const char*)(pStrings + mr.Name);
                std::string mod(modName);
                if (mod.find("kernel32") != std::string::npos ||
                    mod.find("ntdll") != std::string::npos ||
                    mod.find("advapi32") != std::string::npos) {
                    totalNetScore += 3;
                    result.warnings.push_back("ModuleRef to native DLL: " + mod + " (P/Invoke)");
                }
            }
        }
    }

    // 组合加成
    if (totalNetScore > 0) {
        result.score += totalNetScore;
        result.info.push_back(".NET-specific analysis added " + std::to_string(totalNetScore) + " points");
    }

    // 签名降权（保留）
    if (result.hasSig && result.certValid) {
        totalNetScore = totalNetScore / 2;
        result.info.push_back(".NET score halved due to valid digital signature");
    }
}

// 资源解压辅助函数 =
static bool DecompressWithCompressApi(DWORD algorithm, const BYTE* inData, size_t inSize,
                                      std::vector<BYTE>& outData) {
    LoadCompressApi();
    if (!pCreateDecompressor || !pDecompress || !pCloseDecompressor) return false;
    PVOID decompressor = nullptr;
    if (!pCreateDecompressor(algorithm, NULL, &decompressor)) return false;
    // 先尝试解压（需要知道输出大小，用猜测或两次解压）
    // 通常输出大小未知，但我们可以先尝试一个较大的缓冲区，失败则扩展。
    SIZE_T outSizeGuess = inSize * 4;
    if (outSizeGuess < 1024) outSizeGuess = 1024;
    const int MAX_RETRY = 3;
    for (int attempt = 0; attempt < MAX_RETRY; ++attempt) {
        outData.resize(outSizeGuess);
        SIZE_T uncompressedSize = 0;
        if (pDecompress(decompressor, (PVOID)inData, inSize,
                        outData.data(), outSizeGuess, &uncompressedSize)) {
            outData.resize(uncompressedSize);
            pCloseDecompressor(decompressor);
            return true;
        }
        // 如果失败，可能是缓冲区太小，增大
        outSizeGuess *= 2;
        if (outSizeGuess > 100 * 1024 * 1024) break; // 防止过大
    }
    pCloseDecompressor(decompressor);
    return false;
}

static bool TryXorDecrypt(const BYTE* data, size_t size, BYTE key, std::vector<BYTE>& out) {
    if (size < 2) return false;
    out.resize(size);
    for (size_t i = 0; i < size; ++i) out[i] = data[i] ^ key;
    // 检查解密后是否有 PE 或 ZIP 头
    if (out.size() >= 2) {
        if ((out[0] == 0x4D && out[1] == 0x5A) || (out[0] == 0x50 && out[1] == 0x4B)) {
            return true;
        }
        // 检查 .NET 序列化流 \x01\x00\x00\x00
        if (out.size() >= 4 && out[0] == 0x01 && out[1] == 0x00 && out[2] == 0x00 && out[3] == 0x00) {
            return true;
        }
    }
    return false;
}

static void scan_rootkit_indicators(const BYTE* base, size_t baseSize,
                                    const std::vector<SectionInfo>& sections,
                                    const std::set<std::string>& importedDlls,
                                    const std::unordered_set<std::string>& importedApisSet,
                                    int& score, std::vector<std::string>& warnings,
                                    std::vector<std::string>& info)
{
    int rootkitScore = 0;

    // 1. 检测是否导入内核驱动专用 DLL（ntoskrnl.exe, hal.dll）
    bool importsNtoskrnl = false, importsHal = false;
    for (const std::string& dll : importedDlls) { // 需将 importedDlls 传进来
        std::string lower = dll;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ntoskrnl.exe") != std::string::npos) importsNtoskrnl = true;
        if (lower.find("hal.dll") != std::string::npos) importsHal = true;
    }
    if (importsNtoskrnl || importsHal) {
        rootkitScore += 15;
        warnings.push_back("Imports kernel-mode DLL (ntoskrnl/hal) – strong rootkit indicator");
        info.push_back("Added 15 points for kernel DLL import");
    }

    // 2. 检测大量 Zw* 函数（NTAPI）使用
    int zwCount = 0;
    for (const std::string& api : importedApisSet) {
        if (api.compare(0, 2, "zw") == 0) zwCount++;
    }
    if (zwCount >= 5) {
        rootkitScore += 10;
        warnings.push_back("Heavy usage of Zw* functions (" + std::to_string(zwCount) + ") – typical of kernel-mode or rootkit");
        info.push_back("Added 10 points for numerous Zw* APIs");
    }

    // 3. 扫描字符串中的 RootKit 特征（设备名、服务名、隐藏关键字等）
    const char* rootkit_strings[] = {
        "\\\\.\\PhysicalDrive", "\\\\.\\C:", "\\Device\\", "\\Driver\\",
        "ZwQuerySystemInformation", "ZwOpenProcess", "ZwTerminateProcess",
        "ZwSetInformationProcess", "ZwSuspendProcess", "ZwResumeProcess",
        "ZwDeleteKey", "ZwCreateKey", "ZwOpenKey",
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services",
        "HideDriver", "RootKit", "UnHook", "SSDT", "IDT", "DKOM"
    };
    int strHits = 0;
    for (const auto& sec : sections) {
        if (!sec.isReadable || sec.rawSize == 0) continue;
        if (sec.rawStart > baseSize - sec.rawSize) continue;
        const BYTE* data = base + sec.rawStart;
        for (size_t i = 0; i < sec.rawSize; ++i) {
            if (isprint(data[i]) && data[i] != ' ') {
                size_t start = i;
                while (i < sec.rawSize && isprint(data[i]) && data[i] != ' ') i++;
                size_t len = i - start;
                if (len < 4) continue;
                std::string token((char*)&data[start], len);
                for (const char* pat : rootkit_strings) {
                    if (token.find(pat) != std::string::npos) {
                        strHits++;
                        warnings.push_back("RootKit string pattern found: " + token);
                        break;
                    }
                }
            }
        }
    }
    if (strHits > 0) {
        int add = std::min(strHits * 2, 12);
        rootkitScore += add;
        info.push_back("Added " + std::to_string(add) + " points for rootkit string hits");
    }

    // 4. 检测入口点是否位于非标准节且节名为 .text 以外的可写区（驱动常见）
    // 该检测已存在，但可额外加分
    // ...

    // 5. 检测是否有 "DriverEntry" 导出但无签名或签名无效（已存在，但可加重）
    // 已有导出表检测，可略。

    // 应用 RootKit 额外得分，上限 30 分
    if (rootkitScore > 30) rootkitScore = 30;
    score += rootkitScore;
}

// 主分析函数 =
bool AnalyzePE(const BYTE* base, size_t baseSize, const std::wstring& filePath, AnalysisResult& result, int depth = 0) {
    init_ror13_hashes();

    // 加载 RtlDecompressBuffer（只一次）
    static bool ntdllLoaded = false;
    if (!ntdllLoaded) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            pRtlDecompressBuffer = (RtlDecompressBufferPtr)GetProcAddress(hNtdll, "RtlDecompressBuffer");
        }
        ntdllLoaded = true;
    }

    auto pDos = safe_ptr<IMAGE_DOS_HEADER>(base, baseSize, 0);
    if (!pDos || pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS header" << std::endl;
        return false;
    }

    DWORD ntOffset = pDos->e_lfanew;
    auto pNt = safe_ptr<IMAGE_NT_HEADERS>(base, baseSize, ntOffset);
    if (!pNt || pNt->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT header" << std::endl;
        return false;
    }

    WORD magic = pNt->OptionalHeader.Magic;
    bool is64bit = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    bool is32bit = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    if (!is64bit && !is32bit) {
        std::cerr << "Unknown PE magic" << std::endl;
        return false;
    }

    bool isDLL = (pNt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    const IMAGE_DATA_DIRECTORY* dataDir = nullptr;
    size_t optHeaderOffset = ntOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader);
    WORD dllCharacteristics = 0;
    DWORD numberOfRvaAndSizes = 0;
    WORD subsystem = 0;

    if (is32bit) {
        auto pOpt32 = safe_ptr<IMAGE_OPTIONAL_HEADER32>(base, baseSize, optHeaderOffset);
        if (pOpt32) {
            dataDir = pOpt32->DataDirectory;
            dllCharacteristics = pOpt32->DllCharacteristics;
            numberOfRvaAndSizes = pOpt32->NumberOfRvaAndSizes;
            subsystem = pOpt32->Subsystem;
        }
    } else {
        auto pOpt64 = safe_ptr<IMAGE_OPTIONAL_HEADER64>(base, baseSize, optHeaderOffset);
        if (pOpt64) {
            dataDir = pOpt64->DataDirectory;
            dllCharacteristics = pOpt64->DllCharacteristics;
            numberOfRvaAndSizes = pOpt64->NumberOfRvaAndSizes;
            subsystem = pOpt64->Subsystem;
        }
    }
    if (!dataDir) {
        std::cerr << "Cannot access data directory" << std::endl;
        return false;
    }

     //判断是否为驱动程序
    bool isDriver = (subsystem == IMAGE_SUBSYSTEM_NATIVE) ||
                    ((pNt->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) != 0);

    if (isDriver) {
        result.info.push_back("Detected as kernel driver (Subsystem=NATIVE or IMAGE_FILE_SYSTEM)");
        result.info.push_back("Driver-specific analysis enabled (some user-mode checks skipped)");
    }

    WORD numberOfSections = pNt->FileHeader.NumberOfSections;
    DWORD optionalHeaderSize = is32bit ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64);
    DWORD sectionOffset = ntOffset + 24 + optionalHeaderSize;

    DWORD maxSections = 0;
    if (baseSize > sectionOffset) {
        maxSections = (baseSize - sectionOffset) / sizeof(IMAGE_SECTION_HEADER);
    }
    WORD numSections = (WORD)std::min((DWORD)numberOfSections, maxSections);

    auto pSection = safe_ptr<IMAGE_SECTION_HEADER>(base, baseSize, sectionOffset);
    if (!pSection) {
        std::cerr << "Cannot access section headers" << std::endl;
        return false;
    }

    std::vector<SectionInfo> sections;
    DWORD relocSize = 0;
    bool relocFound = false;

    for (WORD i = 0; i < numSections; ++i) {
        const auto& sec = pSection[i];
        char name[9] = {0};
        memcpy(name, sec.Name, 8);
        SectionInfo info;
        info.name = name;
        info.rvaStart = sec.VirtualAddress;
        info.rvaEnd = sec.VirtualAddress + sec.Misc.VirtualSize;
        info.rawStart = sec.PointerToRawData;
        info.rawSize = sec.SizeOfRawData;
        info.isReadable = (sec.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        sections.push_back(info);

        std::string secName(name);
        std::string lowerSecName = secName;
        std::transform(lowerSecName.begin(), lowerSecName.end(), lowerSecName.begin(), ::tolower);
        if (lowerSecName == ".reloc") {
            relocFound = true;
            relocSize = sec.SizeOfRawData;
        }
    }

    auto RVAtoRaw = [&](DWORD rva) -> DWORD {
        for (const auto& sec : sections) {
            if (rva >= sec.rvaStart && rva < sec.rvaEnd) {
                DWORD offset = rva - sec.rvaStart;
                if (offset < sec.rawSize) {
                    DWORD rawAddr = sec.rawStart + offset;
                    if (rawAddr < baseSize)
                        return rawAddr;
                }
                return 0;
            }
        }
        return 0;
    };
    bool isDotNet = false;
    if (numberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
        const auto& comDir = dataDir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (comDir.VirtualAddress != 0 && comDir.Size != 0) {
            DWORD corRaw = RVAtoRaw(comDir.VirtualAddress);
            if (corRaw != 0 && corRaw + sizeof(IMAGE_COR20_HEADER) <= baseSize) {
                const IMAGE_COR20_HEADER* corHeader = reinterpret_cast<const IMAGE_COR20_HEADER*>(base + corRaw);
                DWORD metaRVA = corHeader->MetaData.VirtualAddress;
                DWORD metaSize = corHeader->MetaData.Size;
                DWORD metaRaw = RVAtoRaw(metaRVA);
                if (metaRaw != 0 && metaRaw + metaSize <= baseSize) {
                    AnalyzeDotNetAssembly(base, baseSize, corHeader, metaRaw, metaSize, result, is64bit, RVAtoRaw);
                    isDotNet = true;
                }
            }
        }
    }
    result.isDotNet = isDotNet;

     //签名状态
    std::wstring signerCN, issuerCN;
    bool expired = false, selfSigned = false, multiple = false;
    int signerCount = 0;
    time_t notBefore = 0, notAfter = 0;
    bool nameSpoofed = false;
    bool revocationCheckFailed = false;
    bool isEV = false;
    bool timeStampWarning = false;
    bool validSig = GetSignatureStatus(filePath, signerCN, issuerCN,
                                       expired, selfSigned, multiple,
                                       signerCount, notBefore, notAfter,
                                       nameSpoofed, revocationCheckFailed, isEV, timeStampWarning);
    result.hasSig = validSig;

    DWORD securityRVA = dataDir[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    DWORD securitySize = dataDir[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    if (securitySize > 0) {
        result.hasSignature = true;
        result.certValid = !expired;
        result.isSelfSigned = selfSigned;
        result.issuerName = issuerCN;
    } else {
        result.hasSignature = false;
        result.certValid = false;
        result.isSelfSigned = false;
        result.issuerName = L"";
    }

    int score = 0;
    DWORD maxRawEnd = 0;
    bool textFound = false;
    DWORD textRawOff = 0, textRawSize = 0;
    bool hasWritableExec = false;
    int suspiciousSectionCount = 0;
    bool hasPackedSectionName = false;
    double entryPointSectionEntropy = 0.0;
    DWORD entryRVA = pNt->OptionalHeader.AddressOfEntryPoint;
    bool entryInText = false;

    DWORD entrySecRVAStart = 0;
    DWORD entrySecRawOff = 0;
    DWORD entrySecRawSize = 0;
    DWORD textRVAStart = 0, textRVAEnd = 0;

    double weightedSum = 0.0, totalRawSize = 0.0;
    double textEntropy = -1.0, rdataEntropy = -1.0;

     //PE结构完整性异常检测
    bool rvaOverlap = false;
    bool rawOverlap = false;
    for (size_t i = 0; i < sections.size(); ++i) {
        for (size_t j = i + 1; j < sections.size(); ++j) {
            const auto& a = sections[i];
            const auto& b = sections[j];
            if (a.rvaStart < b.rvaEnd && b.rvaStart < a.rvaEnd) {
                rvaOverlap = true;
            }
            if (a.rawSize > 0 && b.rawSize > 0) {
                DWORD aEnd = a.rawStart + a.rawSize;
                DWORD bEnd = b.rawStart + b.rawSize;
                if (a.rawStart < bEnd && b.rawStart < aEnd) {
                    rawOverlap = true;
                }
            }
        }
    }
    if (rvaOverlap || rawOverlap) {
        score += 5;
        std::string warn = "Malformed PE: overlapping sections detected";
        if (rvaOverlap) warn += " (RVA)";
        if (rawOverlap) warn += " (Raw)";
        result.warnings.push_back(warn);
    }

    for (const auto& sec : sections) {
        if (sec.rawSize > 0) {
            if (sec.rawStart > baseSize - sec.rawSize) {
                score += 4;
                result.warnings.push_back("Malformed PE: raw data pointer out of file bounds in section " + sec.name);
            }
        }
    }

    DWORD sizeOfImage = pNt->OptionalHeader.SizeOfImage;
    if (sizeOfImage > baseSize * 10) {
        score += 3;
        result.warnings.push_back("Malformed PE: SizeOfImage (" + std::to_string(sizeOfImage) +
                                  ") is more than 10 times file size (" + std::to_string(baseSize) + ")");
    }

     //对齐值异常检测
    {
        DWORD fileAlignment = pNt->OptionalHeader.FileAlignment;
        DWORD sectionAlignment = pNt->OptionalHeader.SectionAlignment;
        DWORD sizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;

        if (fileAlignment == 0 || sectionAlignment == 0) {
            score += 5;
            result.warnings.push_back("Malformed PE: FileAlignment or SectionAlignment is zero");
        }
        if (fileAlignment < 0x200 && sectionAlignment > 0x1000) {
            score += 2;
            result.warnings.push_back("Misaligned section/file alignment (packer artifact)");
        }
        if (sizeOfHeaders < 0x200 && numSections > 5) {
            score += 1;
            result.warnings.push_back("SizeOfHeaders smaller than 0x200 with many sections (header stripped)");
        }

        DWORD dosSize = sizeof(IMAGE_DOS_HEADER);
        DWORD ntHeaderSize = is32bit ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
        DWORD sectionHeadersSize = numSections * sizeof(IMAGE_SECTION_HEADER);
        DWORD minHeadersSize = pDos->e_lfanew + ntHeaderSize + sectionHeadersSize;
        if (sizeOfHeaders < minHeadersSize) {
            score += 5;
            result.warnings.push_back("SizeOfHeaders is smaller than required (" + std::to_string(sizeOfHeaders) +
                                      " < " + std::to_string(minHeadersSize) + ") - possible header manipulation");
        }

        if (numberOfRvaAndSizes < 16) {
            score += 1;
            result.warnings.push_back("NumberOfRvaAndSizes is less than 16 (" + std::to_string(numberOfRvaAndSizes) +
                                      ") - old linker or suspicious");
        } else if (numberOfRvaAndSizes > 16) {
            score += 3;
            result.warnings.push_back("NumberOfRvaAndSizes is greater than 16 (" + std::to_string(numberOfRvaAndSizes) +
                                      ") - possible malicious padding");
        }

        if (fileAlignment > 512) {
            int misalignedCount = 0;
            for (const auto& sec : sections) {
                if (sec.rawStart != 0 && (sec.rawStart % fileAlignment) != 0) {
                    misalignedCount++;
                    result.warnings.push_back("Section " + sec.name + " has PointerToRawData (" +
                                              std::to_string(sec.rawStart) + ") not aligned to FileAlignment (" +
                                              std::to_string(fileAlignment) + ")");
                }
            }
            if (misalignedCount > 0) {
                int add = std::min(misalignedCount, 3);
                score += add;
                result.warnings.push_back("Found " + std::to_string(misalignedCount) +
                                          " section(s) with misaligned raw data pointer");
            }
        }

        if (sizeOfHeaders > 0x10000 && numSections < 5) {
            score += 5;
            result.warnings.push_back("SizeOfHeaders inflated (>64KB) with few sections - anti-mapping trick");
            result.info.push_back("Added 5 points for inflated SizeOfHeaders");
        }
        if (fileAlignment < 0x200 && sectionAlignment < 0x1000) {
            score += 3;
            result.warnings.push_back("Non-standard alignment: FileAlignment < 0x200 and SectionAlignment < 0x1000 - custom packer characteristic");
            result.info.push_back("Added 3 points for non-standard alignment combination");
        }
        if (fileAlignment > 8192) {
            score += 3;
            result.warnings.push_back("Extremely large FileAlignment (" + std::to_string(fileAlignment) + ") - anti-parser trick");
            result.info.push_back("Added 3 points for oversized FileAlignment");
        }
    }

    int spoofSectionCount = 0, nonStandardSectionCount = 0;
    DWORD maxVaEnd = 0;
    for (const auto& sec : sections) {
        if (sec.rvaEnd > maxVaEnd) maxVaEnd = sec.rvaEnd;
    }

    int vmpSectionCount = 0;

    for (WORD i = 0; i < numSections; ++i) {
        const auto& sec = pSection[i];
        char name[9] = {0};
        memcpy(name, sec.Name, 8);
        std::string secName(name);
        std::string lowerSecName = secName;
        std::transform(lowerSecName.begin(), lowerSecName.end(), lowerSecName.begin(), ::tolower);

        double entropy = 0.0;
        if (sec.SizeOfRawData > 0 && sec.PointerToRawData <= baseSize - sec.SizeOfRawData) {
            entropy = calculate_entropy(base + sec.PointerToRawData, sec.SizeOfRawData);
        }

        if (sec.SizeOfRawData > 0 && sec.PointerToRawData <= baseSize - sec.SizeOfRawData) {
            weightedSum += entropy * sec.SizeOfRawData;
            totalRawSize += sec.SizeOfRawData;
            if (lowerSecName == ".text") textEntropy = entropy;
            if (lowerSecName == ".rdata") rdataEntropy = entropy;
        }

        if (entryRVA >= sec.VirtualAddress && entryRVA < sec.VirtualAddress + sec.Misc.VirtualSize) {
            entryPointSectionEntropy = entropy;
            entrySecRVAStart = sec.VirtualAddress;
            entrySecRawOff = sec.PointerToRawData;
            entrySecRawSize = sec.SizeOfRawData;
            if (secName == ".text") entryInText = true;
        }

        bool packed = false;
        for (int k = 0; k < PACKED_SECTION_COUNT; ++k) {
            if (secName.find(packed_section_names[k]) != std::string::npos) {
                packed = true;
                hasPackedSectionName = true;
                break;
            }
        }
        if (packed) { score += 2; result.warnings.push_back("Packed section name: " + secName); }

        std::string lowerName = lowerSecName;
        if (lowerName.find(".vmp") != std::string::npos || lowerName.find(".tmd") != std::string::npos ||
            lowerName.find(".themida") != std::string::npos) {
            vmpSectionCount++;
            score += 2;
        }

        {
            int len = strlen(name);
            if (len >= 3) {
                int spaceCount = 0;
                for (int idx = len - 1; idx >= 0; --idx) {
                    if (name[idx] == ' ' || name[idx] == '\t') {
                        spaceCount++;
                    } else {
                        break;
                    }
                }
                if (spaceCount >= 3) {
                    score += 3;
                    result.warnings.push_back("Section name padded with spaces/tabs (visual deception): " + secName);
                    result.info.push_back("Added 3 points for section name padding");
                }
            }
        }

        bool isStandard = false;
        for (int s = 0; s < STANDARD_SECTION_COUNT; ++s) {
            if (lowerSecName == standard_sections[s]) { isStandard = true; break; }
        }

        if (!isStandard && !packed) {
            bool isSpoof = false;
            for (int s = 0; s < STANDARD_SECTION_COUNT; ++s) {
                std::string stdLower = standard_sections[s];
                std::transform(stdLower.begin(), stdLower.end(), stdLower.begin(), ::tolower);
                if (lowerSecName == stdLower && secName != standard_sections[s]) { isSpoof = true; break; }
            }
            if (!isSpoof) {
                for (int s = 0; s < STANDARD_SECTION_COUNT; ++s) {
                    std::string stdLower = standard_sections[s];
                    std::transform(stdLower.begin(), stdLower.end(), stdLower.begin(), ::tolower);
                    if (lowerSecName.find(stdLower) == 0 && lowerSecName.length() > stdLower.length()) {
                        char extra = secName[stdLower.length()];
                        if (extra == ' ' || extra == '\x01' || extra == '\x02' || extra == '\t') {
                            isSpoof = true; break;
                        }
                    }
                }
            }
            if (!isSpoof) {
                for (char c : secName) {
                    if (c == '?' || c == '*' || c == '!' || c == '@' || c == '#') { isSpoof = true; break; }
                }
            }
            if (isSpoof) { spoofSectionCount++; result.warnings.push_back("Possibly spoofed section name: " + secName); }
            else nonStandardSectionCount++;
        }
        if (secName.length() > 0 && secName.length() < 3 && !isStandard && !packed) {
            spoofSectionCount++;
            result.warnings.push_back("Unusual short section name: " + secName);
        }

        if (sec.SizeOfRawData == 0 && sec.Misc.VirtualSize > 0) {
            score += 1; result.warnings.push_back("Section with zero raw data but virtual size >0: " + secName);
        }
        if (sec.SizeOfRawData > 0 && sec.Misc.VirtualSize > 0) {
            double ratio = (double)sec.SizeOfRawData / sec.Misc.VirtualSize;
            if (ratio < 0.2 || ratio > 5.0) {
                score += 1; result.warnings.push_back("Large discrepancy between raw/virtual size in " + secName);
                suspiciousSectionCount++;
            }
        }

        DWORD ch = sec.Characteristics;
        bool isWrite = (ch & IMAGE_SCN_MEM_WRITE) != 0;
        bool isExec = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (isWrite && isExec) {
            hasWritableExec = true;
            if (secName == ".text") {
                int add = 3;
                if (pNt->OptionalHeader.MajorOperatingSystemVersion < 6) {
                    add += 5;
                    result.info.push_back("OS version < 6, added 5 points for W^X in .text (legacy exploit)");
                }
                score += add;
                result.warnings.push_back(".text section is writable and executable (W^X violation)");
            } else {
                score += 2;
                result.warnings.push_back("W^X in section: " + secName);
            }
        }
        if (secName == ".text" && isWrite) { score += 1; result.warnings.push_back(".text section is writable"); }
        if ((secName == ".data" || secName == ".rdata") && isExec) { score += 2; result.warnings.push_back(secName + " section is executable"); }

        if (lowerSecName == ".reloc" && isExec) {
            score += 3;
            result.warnings.push_back(".reloc section should not be executable");
        }
        if (lowerSecName == ".rsrc" && isWrite) {
            score += 3;
            result.warnings.push_back(".rsrc section should not be writable");
        }

        if (secName == ".text") {
            textFound = true;
            textRawOff = sec.PointerToRawData;
            textRawSize = sec.SizeOfRawData;
            textRVAStart = sec.VirtualAddress;
            textRVAEnd = sec.VirtualAddress + sec.Misc.VirtualSize;
        }

        if (sec.PointerToRawData <= baseSize - sec.SizeOfRawData) {
            DWORD rawEnd = sec.PointerToRawData + sec.SizeOfRawData;
            if (rawEnd > maxRawEnd) maxRawEnd = rawEnd;
        }
    }

    if (vmpSectionCount > 0) {
        score -= vmpSectionCount * 2;
        score += std::min(vmpSectionCount * 2, 4);
        if (vmpSectionCount > 0) {
            result.info.push_back("Added " + std::to_string(std::min(vmpSectionCount * 2, 4)) +
                                  " points for VMProtect/Themida section names (" + std::to_string(vmpSectionCount) + " sections)");
        }
    }

    bool has_chkstk = false;

    // 这些用户态检测仅对非驱动执行
    if (!isDriver && !isDotNet) {
        if (textFound && textRawOff != 0 && textRawSize > 0 && textRawOff <= baseSize - textRawSize) {
            const BYTE* textData = base + textRawOff;
            scan_syscall_pattern(textData, textRawSize, score, result.warnings, result.info);
            scan_ror13_hashes(textData, textRawSize, score, result.warnings, result.info);
        }
    }

    if (spoofSectionCount > 0) { int add = std::min(spoofSectionCount, 2); score += add; result.warnings.push_back("Section name spoofing indicators: " + std::to_string(spoofSectionCount)); }
    if (nonStandardSectionCount > 3) { score += 1; result.warnings.push_back("Many non-standard section names (" + std::to_string(nonStandardSectionCount) + ")"); }

    DWORD overlaySize = (maxRawEnd < baseSize) ? (baseSize - maxRawEnd) : 0;
    if (overlaySize > 0) { score += 1; result.warnings.push_back("Overlay data present: " + std::to_string(overlaySize) + " bytes"); }
    if (overlaySize > 0) {
        const BYTE* overlayData = base + maxRawEnd;

        if (overlaySize >= 4) {
            if (overlayData[0] == 0x50 && overlayData[1] == 0x4B &&
                overlayData[2] == 0x03 && overlayData[3] == 0x04) {
                score += 4;
                result.warnings.push_back("Overlay contains ZIP header (PK\\x03\\x04)");
                result.info.push_back("Added 4 points for ZIP overlay");
            }
            else if (overlayData[0] == 0x4D && overlayData[1] == 0x5A) {
                score += 6;
                result.warnings.push_back("Overlay contains PE header (MZ)");
                result.info.push_back("Added 6 points for PE overlay");
            }
        }

        size_t maxBase64Len = 0;
        size_t currentLen = 0;
        for (size_t i = 0; i < overlaySize; ++i) {
            unsigned char c = overlayData[i];
            bool isBase64Char = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (isBase64Char) {
                ++currentLen;
                if (currentLen > maxBase64Len) maxBase64Len = currentLen;
            } else {
                currentLen = 0;
            }
        }
        if (maxBase64Len >= 64) {
            score += 4;
            result.warnings.push_back("Overlay contains base64 encoded blob (length >= 64)");
            result.info.push_back("Added 4 points for Base64 overlay");
        }
    }
    if (hasWritableExec && !relocFound) { score += 1; result.warnings.push_back("W^X section and no .reloc section"); }

    DWORD sizeOfImage2 = pNt->OptionalHeader.SizeOfImage;
    if (sizeOfImage2 > maxVaEnd + 0x1000) {
        score += 2; result.warnings.push_back("Image size significantly larger than sections (possible unpacking stub)");
        if (!relocFound && !entryInText) { score += 2; result.warnings.push_back("No reloc and entry not in .text, highly indicative of unpacker"); }
    }

    if (sizeOfImage2 > maxVaEnd) {
        DWORD gap = sizeOfImage2 - maxVaEnd;
        if (gap > 0x10000) {
            score += 4;
            char buf[256];
            snprintf(buf, sizeof(buf), "Large gap in virtual memory layout: SizeOfImage - maxSectionEndRVA = %u bytes - potential process hollowing reserve", gap);
            result.warnings.push_back(buf);
            result.info.push_back("Added 4 points for large virtual gap");
        }
    }

    // 导入表 =
    DWORD importRVA = dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    int suspiciousApiCount = 0, antiDebugCount = 0, totalImported = 0;
    std::set<std::string> importedDlls;
    std::vector<std::string> importedApis;
    std::unordered_set<std::string> importedApisSet;
    int suspiciousOrdinalCount = 0;

    int normalImportCount = 0;
    int normalSuspiciousCount = 0;

    std::unordered_set<std::string> allDetectedApis;

    // 用于代理DLL检测的统计
    bool hasBasicFunction = false;
    int loadLibraryCount = 0;
    int getProcAddressCount = 0;

    static const std::unordered_map<std::string, std::unordered_map<WORD, std::string>> ordinal_blacklist = {
        {"ntdll.dll", {
            {0x3A, "NtCreateThreadEx"},
            {0x2C, "NtOpenProcess"}
        }},
    };

     //IAT劫持检测辅助
    bool iatHijackDetected = false;

    if (importRVA == 0) {
        if (!isDriver) {
            score += 4; // 驱动可以无导入表（如自己解析）
            result.warnings.push_back("No import table (highly suspicious)");}
    } else {
        DWORD importRaw = RVAtoRaw(importRVA);
        if (importRaw == 0) result.warnings.push_back("Cannot locate import table in file");
        else {
            auto pImport = safe_ptr<IMAGE_IMPORT_DESCRIPTOR>(base, baseSize, importRaw);
            bool dllCommandLineWarned = false;

            while (pImport && pImport->Name != 0) {
                DWORD dllNameRVA = pImport->Name;
                DWORD dllNameRaw = RVAtoRaw(dllNameRVA);
                std::string dllName;
                if (dllNameRaw) { const char* namePtr = reinterpret_cast<const char*>(base + dllNameRaw); dllName = namePtr; importedDlls.insert(dllName); }

                // 如果是驱动，检查是否导入了用户态DLL
                if (isDriver) {
                    std::string dllLower = dllName;
                    std::transform(dllLower.begin(), dllLower.end(), dllLower.begin(), ::tolower);
                    bool isUserDll = false;
                    for (int i = 0; i < SENSITIVE_DLL_COUNT; ++i) {
                        if (dllLower.find(sensitive_dlls[i]) != std::string::npos) {
                            isUserDll = true;
                            break;
                        }
                    }
                    if (isUserDll) {
                        score += 10;
                        result.warnings.push_back("Driver imports user-mode DLL: " + dllName + " (highly suspicious)");
                        result.info.push_back("Added 10 points for user-mode DLL import in driver");
                    }
                }

                DWORD thunkRVA = pImport->OriginalFirstThunk;
                if (thunkRVA == 0) thunkRVA = pImport->FirstThunk;
                DWORD thunkRaw = RVAtoRaw(thunkRVA);
                if (thunkRaw) {
                    auto pThunk = safe_ptr<IMAGE_THUNK_DATA>(base, baseSize, thunkRaw);
                    int thunkCount = 0;
                    int ordinalCount = 0;

                    int thunkLoopCount = 0;
                    const int MAX_THUNK_LOOP = 10000;

                    while (pThunk && pThunk->u1.AddressOfData != 0 && thunkLoopCount < MAX_THUNK_LOOP) {
                        thunkLoopCount++;
                        thunkCount++;
                        bool isOrdinal = (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0;
                        if (isOrdinal) {
                            ordinalCount++;
                            WORD ordinal = pThunk->u1.Ordinal & 0xFFFF;
                            bool isSensitiveDll = false;
                            std::string dllLower = dllName;
                            std::transform(dllLower.begin(), dllLower.end(), dllLower.begin(), ::tolower);
                            for (int i = 0; i < SENSITIVE_DLL_COUNT; ++i) {
                                if (dllLower.find(sensitive_dlls[i]) != std::string::npos) { isSensitiveDll = true; break; }
                            }
                            if (isSensitiveDll) {
                                suspiciousOrdinalCount++;
                                result.warnings.push_back("Suspicious ordinal import from " + dllName + " (ordinal " + std::to_string(ordinal) + ")");
                                if (!isDriver) score += 1;
                            }
                            auto itDll = ordinal_blacklist.find(dllLower);
                            if (itDll != ordinal_blacklist.end()) {
                                auto itOrd = itDll->second.find(ordinal);
                                if (itOrd != itDll->second.end()) {
                                    if (!isDriver) score += 2;
                                    result.warnings.push_back("Blacklisted ordinal import: " + dllName + "!" + itOrd->second + " (ordinal " + std::to_string(ordinal) + ")");
                                }
                            }
                        } else {
                            DWORD funcNameRaw = RVAtoRaw(pThunk->u1.AddressOfData);
                            if (funcNameRaw) {
                                auto pFunc = safe_ptr<IMAGE_IMPORT_BY_NAME>(base, baseSize, funcNameRaw);
                                if (pFunc) {
                                    const char* funcName = reinterpret_cast<const char*>(pFunc->Name);
                                    importedApis.push_back(funcName);
                                    importedApisSet.insert(funcName);
                                    std::string apiLower = funcName;
                                    std::transform(apiLower.begin(), apiLower.end(), apiLower.begin(), ::tolower);
                                    allDetectedApis.insert(apiLower);
                                    totalImported++;
                                    normalImportCount++;
                                    normalSuspiciousCount++;

                                    // 检查基本函数
                                    for (int j = 0; j < BASIC_FUNCTION_COUNT; ++j) {
                                        if (strcmp(funcName, basic_functions[j]) == 0) {
                                            hasBasicFunction = true;
                                            break;
                                        }
                                    }
                                    // 统计 LoadLibrary / GetProcAddress
                                    if (strcmp(funcName, "LoadLibraryA") == 0 || strcmp(funcName, "LoadLibraryW") == 0)
                                        loadLibraryCount++;
                                    if (strcmp(funcName, "GetProcAddress") == 0)
                                        getProcAddressCount++;

                                    // 仅对非驱动检查可疑API
                                    if (!isDriver) {
                                        bool isSuspicious = false;
                                        for (int j = 0; j < SUSPICIOUS_API_COUNT; ++j) {
                                            if (strcmp(funcName, suspicious_apis[j]) == 0) {
                                                suspiciousApiCount++;
                                                isSuspicious = true;
                                                normalSuspiciousCount++;
                                                result.warnings.push_back("Suspicious API: " + std::string(funcName));
                                                break;
                                            }
                                        }
                                        if (!isSuspicious) {
                                            for (int j = 0; j < ANTI_DEBUG_COUNT; ++j) {
                                                if (strcmp(funcName, anti_debug_apis[j]) == 0) {
                                                    antiDebugCount++;
                                                    result.warnings.push_back("Anti-debug API: " + std::string(funcName));
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    if (isDLL) {
                                        if (strcmp(funcName, "GetCommandLineA") == 0 ||
                                            strcmp(funcName, "GetCommandLineW") == 0) {
                                            if (!dllCommandLineWarned) {
                                                dllCommandLineWarned = true;
                                                score += 5;
                                                result.warnings.push_back(
                                                    "DLL imports GetCommandLine - suspicious for DLL proxying");
                                                result.info.push_back(
                                                    "Added 5 points for DLL importing GetCommandLine");
                                            }
                                        }
                                    }

                                    if (strcmp(funcName, "__chkstk") == 0) {
                                        has_chkstk = true;
                                    }

                                    //  IAT劫持检查 
                                    DWORD nameRVA = pThunk->u1.AddressOfData;
                                    if (RVAtoRaw(nameRVA) == 0) {
                                        if (!iatHijackDetected) {
                                            iatHijackDetected = true;
                                            score += 4;
                                            result.warnings.push_back("Potential IAT hijacking: import name RVA invalid for " + dllName + "!" + funcName);
                                            result.info.push_back("Added 4 points for possible IAT hijacking");
                                        }
                                    }
                                }
                            } else {
                                if (!iatHijackDetected) {
                                    iatHijackDetected = true;
                                    score += 4;
                                    result.warnings.push_back("Potential IAT hijacking: import name RVA invalid for " + dllName);
                                    result.info.push_back("Added 4 points for possible IAT hijacking");
                                }
                            }
                        }
                        ++pThunk;
                    }

                    if (thunkCount > 0 && ordinalCount == thunkCount) {
                        bool isSystemDll = false;
                        std::string dllLower = dllName;
                        std::transform(dllLower.begin(), dllLower.end(), dllLower.begin(), ::tolower);
                        for (int i = 0; i < SENSITIVE_DLL_COUNT; ++i) {
                            if (dllLower.find(sensitive_dlls[i]) != std::string::npos) {
                                isSystemDll = true;
                                break;
                            }
                        }
                        if (!isDriver) {
                            score += 6;
                            std::string warn = "All imports from " + dllName + " are by ordinal (no function names) - suspicious";
                            if (isSystemDll) warn += " (System DLL)";
                            result.warnings.push_back(warn);
                            result.info.push_back("Added 6 points for ordinal-only import from " + dllName);
                        } else {
                            // 驱动中可能正常，仅记录
                            result.info.push_back("Driver uses ordinal-only imports from " + dllName + " (may be normal)");
                        }
                    }
                }
                ++pImport;
            }
        }
    }

     //延迟导入表（仅非驱动）
    if (!isDriver) {
        DWORD delayImportRVA = dataDir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
        if (delayImportRVA != 0) {
            DWORD delayImportRaw = RVAtoRaw(delayImportRVA);
            if (delayImportRaw == 0) {
                result.warnings.push_back("Cannot locate delay-load import table in file");
            } else {
                struct ImgDelayDescr {
                    DWORD grAttrs;
                    DWORD rvaDLLName;
                    DWORD rvaHmod;
                    DWORD rvaIAT;
                    DWORD rvaINT;
                    DWORD rvaBoundIAT;
                    DWORD rvaUnloadIAT;
                    DWORD dwTimeStamp;
                };

                size_t offset = delayImportRaw;
                while (offset + sizeof(ImgDelayDescr) <= baseSize) {
                    auto pDelay = safe_ptr<ImgDelayDescr>(base, baseSize, offset);
                    if (!pDelay) break;
                    if (pDelay->rvaDLLName == 0 && pDelay->rvaINT == 0 && pDelay->rvaIAT == 0) break;

                    if (pDelay->rvaINT != 0) {
                        DWORD intRVA = pDelay->rvaINT;
                        DWORD intRaw = RVAtoRaw(intRVA);
                        if (intRaw != 0) {
                            size_t intOffset = intRaw;
                            int intLoopCount = 0;
                            const int MAX_INT_LOOP = 10000;
                            while (intOffset + sizeof(DWORD) <= baseSize && intLoopCount < MAX_INT_LOOP) {
                                intLoopCount++;
                                auto pInt = safe_ptr<DWORD>(base, baseSize, intOffset);
                                if (!pInt) break;
                                DWORD val = *pInt;
                                if (val == 0) break;
                                bool isOrdinal = (val & IMAGE_ORDINAL_FLAG) != 0;
                                if (!isOrdinal) {
                                    DWORD nameRVA = val;
                                    DWORD nameRaw = RVAtoRaw(nameRVA);
                                    if (nameRaw) {
                                        auto pFunc = safe_ptr<IMAGE_IMPORT_BY_NAME>(base, baseSize, nameRaw);
                                        if (pFunc) {
                                            const char* funcName = reinterpret_cast<const char*>(pFunc->Name);
                                            importedApis.push_back(funcName);
                                            importedApisSet.insert(funcName);
                                            std::string apiLower = funcName;
                                            std::transform(apiLower.begin(), apiLower.end(), apiLower.begin(), ::tolower);
                                            allDetectedApis.insert(apiLower);
                                            totalImported++;

                                            for (int j = 0; j < BASIC_FUNCTION_COUNT; ++j) {
                                                if (strcmp(funcName, basic_functions[j]) == 0) {
                                                    hasBasicFunction = true;
                                                    break;
                                                }
                                            }
                                            if (strcmp(funcName, "LoadLibraryA") == 0 || strcmp(funcName, "LoadLibraryW") == 0)
                                                loadLibraryCount++;
                                            if (strcmp(funcName, "GetProcAddress") == 0)
                                                getProcAddressCount++;

                                            bool isSuspicious = false;
                                            for (int j = 0; j < SUSPICIOUS_API_COUNT; ++j) {
                                                if (strcmp(funcName, suspicious_apis[j]) == 0) {
                                                    suspiciousApiCount++;
                                                    isSuspicious = true;
                                                    result.warnings.push_back("Suspicious API (delay-load): " + std::string(funcName));
                                                    break;
                                                }
                                            }
                                            if (!isSuspicious) {
                                                for (int j = 0; j < ANTI_DEBUG_COUNT; ++j) {
                                                    if (strcmp(funcName, anti_debug_apis[j]) == 0) {
                                                        antiDebugCount++;
                                                        result.warnings.push_back("Anti-debug API (delay-load): " + std::string(funcName));
                                                        break;
                                                    }
                                                }
                                            }
                                            if (strcmp(funcName, "__chkstk") == 0) {
                                                has_chkstk = true;
                                            }

                                            if (RVAtoRaw(nameRVA) == 0) {
                                                if (!iatHijackDetected) {
                                                    iatHijackDetected = true;
                                                    score += 4;
                                                    result.warnings.push_back("Potential IAT hijacking (delay-load): import name RVA invalid");
                                                    result.info.push_back("Added 4 points for possible IAT hijacking");
                                                }
                                            }
                                        }
                                    }
                                }
                                intOffset += sizeof(DWORD);
                            }
                        }
                    }
                    offset += sizeof(ImgDelayDescr);
                }
            }
        }
    }

    if (!isDriver) {
        if (suspiciousApiCount >= 10) { score += 4; result.warnings.push_back("Very high number of suspicious APIs (" + std::to_string(suspiciousApiCount) + ")"); }
        else if (suspiciousApiCount >= 5) { score += 2; result.warnings.push_back("High number of suspicious APIs (" + std::to_string(suspiciousApiCount) + ")"); }
        else if (suspiciousApiCount >= 3) { score += 1; }

        if (antiDebugCount >= 5) { score += 2; result.warnings.push_back("Multiple anti-debug APIs (" + std::to_string(antiDebugCount) + ")"); }
        else if (antiDebugCount >= 3) { score += 1; }

        if (suspiciousOrdinalCount > 0) { int add = std::min(suspiciousOrdinalCount, 3); score += add; result.warnings.push_back("Found " + std::to_string(suspiciousOrdinalCount) + " ordinal imports from sensitive DLLs"); }

        int sensDllCount = 0;
        for (const auto& dll : importedDlls) {
            for (int i = 0; i < SENSITIVE_DLL_COUNT; ++i) {
                if (_stricmp(dll.c_str(), sensitive_dlls[i]) == 0) { sensDllCount++; break; }
            }
        }
        if (sensDllCount >= 5) { score += 1; result.warnings.push_back("Imports many sensitive DLLs"); }

        int comboScore = check_api_combinations(importedApis, result.warnings);
        score += comboScore;

        if (totalImported > 0 && suspiciousApiCount > 0) {
            double ratio = static_cast<double>(suspiciousApiCount) / totalImported;
            if (ratio > 0.6 && suspiciousApiCount >= 5) {
                score += 2;
                result.warnings.push_back("High proportion of suspicious APIs (" + std::to_string(ratio*100) + "%)");
            }
        }

        if (normalImportCount > 50) {
            double suspiciousRatio = static_cast<double>(normalSuspiciousCount) / normalImportCount;
            if (suspiciousRatio > 0.7) {
                score += 3;
                result.warnings.push_back("IAT contains very few legitimate APIs: suspicious API ratio = " +
                                          std::to_string(suspiciousRatio * 100) + "% (threshold >70%)");
                result.info.push_back("Added 3 points for abnormal legitimate import ratio");
            }
        }
    }

    // 以下用户态检测仅非驱动
    if (!isDriver && !isDotNet) {
        if (textFound && textRawOff != 0 && textRawSize > 0 && textRawOff <= baseSize - textRawSize) {
            const BYTE* textData = base + textRawOff;
            scan_llvm_obfuscation(textData, textRawSize, has_chkstk, score, result.warnings, result.info);
        }

        if (textFound && textRawOff != 0 && textRawSize > 0 && textRawOff <= baseSize - textRawSize) {
            const BYTE* textData = base + textRawOff;
            std::unordered_set<std::string> stackDetectedApis;
            scan_stack_string_apis(textData, textRawSize, stackDetectedApis, score, result.warnings, result.info);
            for (const auto& api : stackDetectedApis) {
                allDetectedApis.insert(api);
            }
        }

        if (entrySecRawOff != 0 && entrySecRawSize > 0) {
            DWORD offsetInSec = entryRVA - entrySecRVAStart;
            if (offsetInSec < entrySecRawSize) {
                DWORD entryRawOffset = entrySecRawOff + offsetInSec;
                DWORD bytesToRead = 128;
                if (entryRawOffset > baseSize - bytesToRead) {
                    bytesToRead = baseSize - entryRawOffset;
                }
                if (bytesToRead >= 2) {
                    const BYTE* entryData = base + entryRawOffset;
                    analyze_entry_point_bytes(entryData, bytesToRead, score, result.warnings, result.info);
                }
            }
        }

        std::unordered_set<std::string> reportedIOCs;
        int iocCount = 0;
        int extraIOCScore = 0;

        for (size_t i = 0; i < sections.size(); ++i) {
            const auto& sec = sections[i];
            if (sec.isReadable && sec.rawStart > 0 && sec.rawSize > 0) {
                if (sec.rawStart > baseSize - sec.rawSize) continue;
                if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
                std::string lowerName = sec.name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                if (lowerName.find(".rdata") != std::string::npos ||
                    lowerName.find(".data") != std::string::npos ||
                    lowerName.find(".rsrc") != std::string::npos) {
                        int found = scan_section_for_api_strings(base + sec.rawStart, sec.rawSize, importedApisSet, result.warnings, allDetectedApis);
                        if (found > 0) {
                            score += std::min(found, 5);
                            result.warnings.push_back("Found " + std::to_string(found) + " potential dynamic-load API strings");
                        }
                        ExtractIOCsFromSection(base + sec.rawStart, sec.rawSize, result, iocCount, extraIOCScore, reportedIOCs);

                        if (lowerName.find(".rdata") != std::string::npos || lowerName.find(".data") != std::string::npos) {
                            scan_section_for_split_apis(base + sec.rawStart, sec.rawSize, result.warnings, score);
                        }
                        if (sec.rawSize > 4096) {
                            detect_high_entropy_sliding(base + sec.rawStart, sec.rawSize, sec.rvaStart, sec.name, result, score);
                            detect_entropy_alternating(base + sec.rawStart, sec.rawSize, sec.name, result, score);
                        }
                    }
            }
        }

        int iocScore = std::min(iocCount, 4);
        if (iocScore > 0) {
            score += iocScore;
            result.info.push_back("Added " + std::to_string(iocScore) + " points for IOC indicators (IP/domain)");
        }
        if (extraIOCScore > 0) {
            score += extraIOCScore;
            result.info.push_back("Added " + std::to_string(extraIOCScore) + " points for extended IOC patterns (registry, commands, anti-VM, Base64, regex)");
        }
    } // end if (!isDriver)

     //基于节区熵的异常检测（对驱动也适用)
    {
        if (textEntropy >= 0.0 && rdataEntropy >= 0.0) {
            bool separated = false;
            if ((textEntropy > 6.8 && rdataEntropy < 3.0) ||
                (textEntropy < 3.0 && rdataEntropy > 6.8)) {
                separated = true;
            }
            if (separated) {
                score += 6;
                result.warnings.push_back("Code/data separation: .text entropy " + std::to_string(textEntropy) +
                                          " and .rdata entropy " + std::to_string(rdataEntropy) +
                                          " - one high one low, typical of encryption/packing");
                result.info.push_back("Added 6 points for entropy separation (text/rdata)");
            }
        }

        for (const auto& sec : sections) {
            std::string lower = sec.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower == ".rsrc") continue;
            if (sec.rawSize > 50*1024 && sec.rawStart != 0 && sec.rawStart <= baseSize - sec.rawSize) {
                double ent = calculate_entropy(base + sec.rawStart, sec.rawSize);
                if (ent > 7.8) {
                    score += 4;
                    result.warnings.push_back("High-entropy (>7.8) large section (>50KB): " + sec.name + " (entropy " + std::to_string(ent) + ") - potential encrypted payload");
                    result.info.push_back("Added 4 points for high-entropy large section");
                }
            }
        }
    }

     //时间差检测（仅非驱动）
    if (!isDriver) {
        bool hasQueryPerf = (allDetectedApis.find("queryperformancecounter") != allDetectedApis.end());
        bool hasGetTick = (allDetectedApis.find("gettickcount") != allDetectedApis.end());
        if (hasQueryPerf && hasGetTick) {
            score += 2;
            result.warnings.push_back("Time-difference anti-debug APIs: QueryPerformanceCounter and GetTickCount both used");
            result.info.push_back("Added 2 points for time-difference API combination");

            bool hasConst = false;
            for (size_t i = 0; i < sections.size(); ++i) {
                const auto& sec = sections[i];
                if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                if (sec.rawSize == 0 || sec.rawStart == 0) continue;
                if (sec.rawStart > baseSize - sec.rawSize) continue;
                const BYTE* data = base + sec.rawStart;
                for (size_t off = 0; off < sec.rawSize; ++off) {
                    if (data[off] == 0x0A || data[off] == 0x64) {
                        hasConst = true;
                        break;
                    }
                }
                if (hasConst) break;
            }
            if (hasConst) {
                score += 2;
                result.warnings.push_back("Constant 0x0A or 0x64 found in code, likely sleep/loop timing");
                result.info.push_back("Added 2 points for sleep/loop constant");
            }
        }
    }


     //导出表（EAT）定向启发式检测 & 深度分析（P1）

    DWORD exportRVA = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportRVA) {
        DWORD exportRaw = RVAtoRaw(exportRVA);
        if (exportRaw) {
            auto pExport = safe_ptr<IMAGE_EXPORT_DIRECTORY>(base, baseSize, exportRaw);
            if (pExport) {
                DWORD funcsRVA = pExport->AddressOfFunctions;
                DWORD namesRVA = pExport->AddressOfNames;
                DWORD ordinalsRVA = pExport->AddressOfNameOrdinals;
                DWORD nameCount = pExport->NumberOfNames;
                DWORD funcCount = pExport->NumberOfFunctions;
                DWORD funcsRaw = RVAtoRaw(funcsRVA);
                DWORD namesRaw = RVAtoRaw(namesRVA);
                DWORD ordinalsRaw = RVAtoRaw(ordinalsRVA);

                std::unordered_map<std::string, DWORD> exportFuncRVA;
                std::unordered_map<std::string, bool> exportIsForward;
                std::unordered_map<std::string, std::string> exportForwardTarget;
                std::vector<std::string> exportNames; // 用于代理DLL检测

                const char* high_risk_exports[] = {
                    "ReflectiveLoader", "DllInstall", "MiniDump", "DllEntryPoint"
                };
                const int HIGH_RISK_EXPORT_COUNT = sizeof(high_risk_exports) / sizeof(high_risk_exports[0]);

                if (namesRaw && ordinalsRaw && funcsRaw && nameCount > 0) {
                    auto namePtrs = safe_ptr<DWORD>(base, baseSize, namesRaw);
                    auto funcPtrs = safe_ptr<DWORD>(base, baseSize, funcsRaw);
                    auto ordPtrs = safe_ptr<WORD>(base, baseSize, ordinalsRaw);
                    if (namePtrs && funcPtrs && ordPtrs) {
                        for (DWORD i = 0; i < nameCount && i < 500; ++i) {
                            DWORD nameRVA = namePtrs[i];
                            DWORD nameRaw = RVAtoRaw(nameRVA);
                            if (!nameRaw) continue;
                            const char* expName = reinterpret_cast<const char*>(base + nameRaw);
                            exportNames.push_back(expName);
                            WORD ordinal = ordPtrs[i];
                            if (ordinal >= funcCount) continue;
                            DWORD funcRVA = funcPtrs[ordinal];

                            exportFuncRVA[expName] = funcRVA;
                            bool isForward = (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize);
                            exportIsForward[expName] = isForward;
                            if (isForward) {
                                DWORD funcRaw = RVAtoRaw(funcRVA);
                                if (funcRaw) {
                                    const char* target = reinterpret_cast<const char*>(base + funcRaw);
                                    exportForwardTarget[expName] = target;
                                } else {
                                    exportForwardTarget[expName] = "";
                                }
                            }

                            if (isForward) {
                                DWORD funcRaw = RVAtoRaw(funcRVA);
                                if (funcRaw) {
                                    const char* target = reinterpret_cast<const char*>(base + funcRaw);
                                    size_t len = strlen(target);
                                    if (len > 5 && (strstr(target, ".dll") || strchr(target, '.'))) {
                                        result.warnings.push_back("Export forwarder detected: " + std::string(expName) + " -> " + target);
                                        bool isSystem = false;
                                        std::string targetLower = target;
                                        std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::tolower);
                                        for (int s = 0; s < SENSITIVE_DLL_COUNT; ++s) {
                                            if (targetLower.find(sensitive_dlls[s]) == 0) {
                                                isSystem = true;
                                                break;
                                            }
                                        }
                                        if (!isSystem) {
                                            score += 4;
                                            result.warnings.push_back("Forwarder target points to non-system DLL (HIGH RISK)");
                                            result.info.push_back("Added 4 points for forwarder to non-system DLL");
                                        }
                                    }
                                }
                            }

                            for (int j = 0; j < SUSPICIOUS_EXPORT_COUNT; ++j) {
                                if (strcmp(expName, suspicious_exports[j]) == 0) {
                                    score += 1;
                                    result.warnings.push_back("Suspicious export: " + std::string(expName));
                                    break;
                                }
                            }
                            for (int h = 0; h < HIGH_RISK_EXPORT_COUNT; ++h) {
                                if (strcmp(expName, high_risk_exports[h]) == 0) {
                                    score += 4;
                                    result.warnings.push_back("High-risk export found: " + std::string(expName));
                                    result.info.push_back("Added 4 points for high-risk export");
                                    break;
                                }
                            }
                        }
                    }
                }

                //  递归解析转发链 + 环检测（对驱动也有效） 
                bool cycleDetected = false;
                std::function<std::string(const std::string&, int, int&, std::unordered_set<std::string>&)> resolveForwarder =
                    [&](const std::string& target, int depth, int& chainLen, std::unordered_set<std::string>& visited) -> std::string {
                        if (depth > 3) return "";
                        if (visited.find(target) != visited.end()) {
                            cycleDetected = true;
                            return "";
                        }
                        visited.insert(target);
                        chainLen++;

                        size_t dot = target.find('.');
                        std::string dllName, funcName;
                        if (dot != std::string::npos) {
                            dllName = target.substr(0, dot);
                            funcName = target.substr(dot + 1);
                        } else {
                            dllName = target;
                            funcName = "";
                        }

                        if (!funcName.empty()) {
                            auto it = exportFuncRVA.find(funcName);
                            if (it != exportFuncRVA.end()) {
                                auto itForward = exportIsForward.find(funcName);
                                if (itForward != exportIsForward.end() && itForward->second) {
                                    std::string nextTarget = exportForwardTarget[funcName];
                                    if (!nextTarget.empty()) {
                                        return resolveForwarder(nextTarget, depth + 1, chainLen, visited);
                                    } else {
                                        return "";
                                    }
                                } else {
                                    return dllName;
                                }
                            } else {
                                return dllName;
                            }
                        } else {
                            return dllName;
                        }
                    };

                for (const auto& pair : exportIsForward) {
                    if (!pair.second) continue;
                    const std::string& expName = pair.first;
                    std::string target = exportForwardTarget[expName];
                    if (target.empty()) continue;

                    int chainLen = 0;
                    std::unordered_set<std::string> visited;
                    std::string finalDll = resolveForwarder(target, 0, chainLen, visited);

                    if (cycleDetected) {
                        score += 12;
                        result.warnings.push_back("Export forwarder chain contains a cycle (ring) for export " + expName +
                                                  " - highly suspicious API redirection");
                        result.info.push_back("Added 12 points for forwarder cycle");
                        cycleDetected = false;
                        continue;
                    }

                    if (chainLen > 2) {
                        bool isSensitive = false;
                        if (!finalDll.empty()) {
                            std::string dllLower = finalDll;
                            std::transform(dllLower.begin(), dllLower.end(), dllLower.begin(), ::tolower);
                            if (dllLower.find(".dll") == std::string::npos) {
                                dllLower += ".dll";
                            }
                            for (int s = 0; s < SENSITIVE_DLL_COUNT; ++s) {
                                if (dllLower == sensitive_dlls[s]) {
                                    isSensitive = true;
                                    break;
                                }
                            }
                        } else {
                            isSensitive = false;
                        }

                        if (!isSensitive) {
                            score += 10;
                            std::string warn = "Deep export forwarder chain detected (API redirection): " + expName;
                            warn += " -> ... (length " + std::to_string(chainLen) + ")";
                            if (!finalDll.empty()) {
                                warn += " -> " + finalDll;
                            } else {
                                warn += " -> internal function";
                            }
                            result.warnings.push_back(warn);
                            result.info.push_back("Added 10 points for deep export forwarder chain");
                        }
                    }
                }

                if (funcCount == 1 && baseSize > 1024 * 1024) {
                    score += 3;
                    result.warnings.push_back("Single export function with large file size (>1MB) - potential downloader/loader");
                    result.info.push_back("Added 3 points for single export + large file");
                }
                if (pExport->NumberOfFunctions > 1000) {
                    score += 1;
                    result.warnings.push_back("Large number of exports (" + std::to_string(pExport->NumberOfFunctions) + ")");
                }

                //导出表深度分析
                {
                    int nonExecCount = 0;
                    std::string allNamesStr;
                    if (funcsRaw && funcCount > 0) {
                        auto funcPtrs = safe_ptr<DWORD>(base, baseSize, funcsRaw);
                        if (funcPtrs) {
                            for (DWORD i = 0; i < funcCount; ++i) {
                                DWORD funcRVA = funcPtrs[i];
                                bool found = false;
                                bool isExec = false;
                                for (size_t s = 0; s < sections.size(); ++s) {
                                    if (funcRVA >= sections[s].rvaStart && funcRVA < sections[s].rvaEnd) {
                                        found = true;
                                        if (pSection[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                                            isExec = true;
                                        }
                                        break;
                                    }
                                }
                                if (!found || !isExec) {
                                    nonExecCount++;
                                }
                            }
                        }
                    }
                    if (namesRaw && nameCount > 0) {
                        auto namePtrs = safe_ptr<DWORD>(base, baseSize, namesRaw);
                        if (namePtrs) {
                            for (DWORD i = 0; i < nameCount; ++i) {
                                DWORD nameRVA = namePtrs[i];
                                DWORD nameRaw = RVAtoRaw(nameRVA);
                                if (nameRaw) {
                                    const char* name = reinterpret_cast<const char*>(base + nameRaw);
                                    allNamesStr += name;
                                }
                            }
                        }
                    }
                    double entropy = 0.0;
                    if (!allNamesStr.empty()) {
                        entropy = calculate_entropy((const BYTE*)allNamesStr.c_str(), allNamesStr.size());
                    }
                    result.info.push_back("Total exports: " + std::to_string(funcCount));
                    result.info.push_back("Exports pointing to non-executable sections: " + std::to_string(nonExecCount));
                    result.info.push_back("Export name entropy: " + std::to_string(entropy));
                    double ratio = (funcCount > 0) ? (double)nonExecCount / funcCount * 100.0 : 0.0;
                    if (ratio > 30.0) {
                        score += 15;
                        result.warnings.push_back("Exports pointing to non-executable section (ratio " + std::to_string(ratio) + "%)");
                        result.info.push_back("Added 15 points for exports in non-executable sections");
                    }
                    if (entropy > 6.0 && nameCount > 5) {
                        score += 8;
                        result.warnings.push_back("High export name entropy (" + std::to_string(entropy) + ") with " + std::to_string(nameCount) + " exports");
                        result.info.push_back("Added 8 points for high export name entropy");
                    }
                }

                 //DLL侧加载/代理执行特化规则（对驱动部分调整）
                if (isDLL) {
                    int legitCount = 0;
                    for (const auto& exp : exportNames) {
                        for (int j = 0; j < LEGITIMATE_EXPORT_COUNT; ++j) {
                            if (strcmp(exp.c_str(), legitimate_exports[j]) == 0) {
                                legitCount++;
                                break;
                            }
                        }
                    }
                    bool hasSuspiciousLoad = (loadLibraryCount >= 2 && getProcAddressCount >= 1);
                    if (legitCount >= 5 && !hasBasicFunction && hasSuspiciousLoad) {
                        if (!isDriver) {
                            score += 20;
                            result.warnings.push_back("HIGH RISK: DLL with >=5 legitimate exports but lacks basic imports and has LoadLibrary/GetProcAddress - likely malicious proxy DLL");
                            result.info.push_back("Added 20 points for proxy DLL detection");
                        } else {
                            result.info.push_back("Driver with many exports and LoadLibrary/GetProcAddress - may be legitimate (e.g., driver with user-mode helper)");
                        }
                    }
                }

                // 重定位表检查（对驱动尤其重要）
                if (!relocFound) {
                    if (isDriver) {
                        score += 8;
                        result.warnings.push_back("Driver missing .reloc section - may cause loading issues, but could be intentional");
                        result.info.push_back("Added 8 points for driver missing relocation");
                    } else {
                        bool isSystem = IsSystemDirectory(filePath);
                        if (isSystem) {
                            score += 15;
                            result.warnings.push_back("System directory DLL missing .reloc section - highly suspicious (may be hijacked)");
                            result.info.push_back("Added 15 points for system DLL missing relocation");
                        } else {
                            score += 10;
                            result.warnings.push_back("DLL missing .reloc section - requires ASLR, suspicious for non-system DLL");
                            result.info.push_back("Added 10 points for DLL missing relocation");
                        }
                    }
                }

                //  驱动特有：检查是否导出 DriverEntry 
                if (isDriver) {
                    bool hasDriverEntry = false;
                    for (const auto& exp : exportNames) {
                        if (strcmp(exp.c_str(), "DriverEntry") == 0) {
                            hasDriverEntry = true;
                            break;
                        }
                    }
                    if (hasDriverEntry) {
                        score = std::max(0, score - 5);
                        result.info.push_back("Driver exports DriverEntry - normal. Reduced score by 5.");
                    } else {
                        score += 5;
                        result.warnings.push_back("Driver does not export DriverEntry - unusual for a kernel driver");
                        result.info.push_back("Added 5 points for missing DriverEntry");
                    }
                }

            } // end if pExport
        }
    }

     //资源节（.rsrc）深度拆解与载荷检测（仅非驱动）
    if (!isDriver) {
        DWORD resourceRVA = dataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        DWORD resourceSize = dataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        if (resourceRVA != 0 && resourceSize > 0) {
            DWORD totalResourceSize = 0;
            bool embeddedPE = false;
            bool embeddedZIP = false;
            bool stealthPE = false;
            bool stealthZIP = false;
            bool largeRcData = false;
            bool hasAnyResourceAnomaly = false;
            int totalResourceCount = 0;
            int hiddenPayloadCount = 0;
            int encryptedPayloadCount = 0;

            std::map<DWORD, DWORD> customTypeSizeMap;
            bool e2Added = false;

            struct ResourceBlob {
                DWORD dataSize;
                double entropy;
                DWORD rawOffset;
            };
            std::vector<ResourceBlob> rsrcBlobs;
            int encryptedLargeCount = 0;

            const int MAX_RESOURCE_DEPTH = 10;
            std::function<void(DWORD, int, DWORD, int)> scanDir = [&](DWORD dirRVA, int level, DWORD typeId, int curDepth) {
                if (curDepth > MAX_RESOURCE_DEPTH) return;
                DWORD dirRaw = RVAtoRaw(dirRVA);
                if (dirRaw == 0 || dirRaw + sizeof(IMAGE_RESOURCE_DIRECTORY) > baseSize) return;
                auto pDir = safe_ptr<IMAGE_RESOURCE_DIRECTORY>(base, baseSize, dirRaw);
                if (!pDir) return;

                DWORD numEntries = pDir->NumberOfNamedEntries + pDir->NumberOfIdEntries;
                DWORD entryOffset = dirRaw + sizeof(IMAGE_RESOURCE_DIRECTORY);

                for (DWORD i = 0; i < numEntries; ++i) {
                    if (entryOffset + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > baseSize) break;
                    auto pEntry = safe_ptr<IMAGE_RESOURCE_DIRECTORY_ENTRY>(base, baseSize, entryOffset);
                    if (!pEntry) break;

                    DWORD offsetToData = pEntry->OffsetToData;
                    if (offsetToData & 0x80000000) {
                        DWORD subRVA = offsetToData & 0x7FFFFFFF;
                        DWORD nextTypeId = typeId;
                        if (level == 0) {
                            if (pEntry->Name & 0x80000000) {
                                nextTypeId = 0xFFFFFFFF;
                            } else {
                                nextTypeId = pEntry->Name & 0xFFFF;
                            }
                        }
                        scanDir(subRVA, level + 1, nextTypeId, curDepth + 1);
                    } else {
                        DWORD dataEntryRVA = offsetToData;
                        DWORD dataEntryRaw = RVAtoRaw(dataEntryRVA);
                        if (dataEntryRaw == 0 || dataEntryRaw + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > baseSize) {
                            entryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
                            continue;
                        }
                        auto pDataEntry = safe_ptr<IMAGE_RESOURCE_DATA_ENTRY>(base, baseSize, dataEntryRaw);
                        if (!pDataEntry) { entryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY); continue; }

                        DWORD dataRVA = pDataEntry->OffsetToData;
                        DWORD dataSize = pDataEntry->Size;
                        totalResourceSize += dataSize;
                        totalResourceCount++;

                        DWORD dataRaw = RVAtoRaw(dataRVA);

                        if (typeId != 0xFFFFFFFF && typeId > 100) {
                            customTypeSizeMap[typeId] += dataSize;
                        }

                        if (!e2Added) {
                            bool invalid = false;
                            if (dataRVA != 0 && dataSize > 0 && dataRaw == 0) {
                                invalid = true;
                            }
                            if (dataRaw != 0 && dataRaw + dataSize > baseSize) {
                                invalid = true;
                            }
                            if (invalid) {
                                score += 7;
                                result.warnings.push_back("Resource data pointer points to invalid raw offset - structural anomaly");
                                result.info.push_back("Added 7 points for invalid resource data pointer");
                                e2Added = true;
                            }
                        }

                        double resourceEntropy = 0.0;
                        bool entropyComputed = false;
                        if (dataRaw != 0 && dataRaw <= baseSize - dataSize && dataSize >= 2) {
                            resourceEntropy = calculate_entropy(base + dataRaw, dataSize);
                            entropyComputed = true;
                        }

                        if (typeId == 10 && entropyComputed && dataRaw != 0) {
                            rsrcBlobs.push_back({dataSize, resourceEntropy, dataRaw});
                        }

                        if (typeId == 10 && entropyComputed && dataSize > 200 * 1024 && resourceEntropy > 7.8) {
                            if (encryptedLargeCount < 3) {
                                score += 4;
                                encryptedLargeCount++;
                                result.warnings.push_back("Encrypted large payload in RT_RCDATA resource (size=" +
                                                          std::to_string(dataSize) + ", entropy=" + std::to_string(resourceEntropy) + ")");
                                result.info.push_back("Added 4 points for encrypted large payload (count " +
                                                      std::to_string(encryptedLargeCount) + "/3)");
                            }
                            if (dataRaw + dataSize > baseSize - 0x1000) {
                                score += 2;
                                result.warnings.push_back("Large encrypted resource located near file end - unusual");
                                result.info.push_back("Added 2 points for resource near file end");
                            }
                        }

                        // 扩展资源解压与解密（ LZMS 和更多 XOR） =
                        if (typeId == 10 && entropyComputed && dataRaw != 0 && dataSize >= 8) {
                            const BYTE* data = base + dataRaw;
                            bool decompressed = false;
                            std::vector<BYTE> decompData;

                            // 1. 原有 LZNT1 / XPRESS（通过 RtlDecompressBuffer）
                            if (!decompressed && pRtlDecompressBuffer) {
                                USHORT format = 0;
                                if (data[0] == 0x4C && data[1] == 0x5A && data[2] == 0x4E && data[3] == 0x54) {
                                    format = RTL_COMPRESSION_FORMAT_LZNT1;
                                } else if (data[0] == 0x58 && data[1] == 0x50 && data[2] == 0x53 && data[3] == 0x45) {
                                    format = RTL_COMPRESSION_FORMAT_XPRESS;
                                }
                                if (format != 0) {
                                    DWORD decompSize = *(DWORD*)(data + 4);
                                    if (decompSize > 0 && decompSize < 100 * 1024 * 1024) {
                                        decompData.resize(decompSize);
                                        ULONG finalSize = 0;
                                        NTSTATUS status = pRtlDecompressBuffer(format, decompData.data(), decompSize,
                                                                               (PUCHAR)data, dataSize, &finalSize);
                                        if (status == 0 && finalSize > 0) {
                                            decompData.resize(finalSize);
                                            decompressed = true;
                                        }
                                    }
                                }
                            }

                            // 2. Deflate (MSZIP) 和 GZip（原有）
                            if (!decompressed) {
                                // 检测 GZip 头部 (1F 8B)
                                if (dataSize > 10 && data[0] == 0x1F && data[1] == 0x8B) {
                                    // GZip 格式，剥离头部后解压 Deflate
                                    size_t start = 10;
                                    BYTE flg = data[3];
                                    if (flg & 0x04) { // FEXTRA
                                        start += 2 + data[10] + (data[11] << 8);
                                    }
                                    if (flg & 0x08) start += strlen((const char*)data + start) + 1; // FNAME
                                    if (flg & 0x10) start += strlen((const char*)data + start) + 1; // FCOMMENT
                                    if (flg & 0x02) start += 2; // FHCRC

                                    if (start < dataSize) {
                                        std::vector<BYTE> deflateData(data + start, data + dataSize);
                                        if (DecompressWithCompressApi(COMPRESS_ALGORITHM_MSZIP, deflateData.data(), deflateData.size(), decompData)) {
                                            decompressed = true;
                                        }
                                    }
                                }
                                if (!decompressed) {
                                    if (DecompressWithCompressApi(COMPRESS_ALGORITHM_MSZIP, data, dataSize, decompData)) {
                                        decompressed = true;
                                    }
                                }
                            }

                            // 3. LZMS（Windows 压缩 API）
                            if (!decompressed) {
                                if (DecompressWithCompressApi(COMPRESS_ALGORITHM_LZMS, data, dataSize, decompData)) {
                                    decompressed = true;
                                }
                            }

                            // 4. XPRESS_HUFF（Windows 压缩 API）
                            if (!decompressed) {
                                if (DecompressWithCompressApi(COMPRESS_ALGORITHM_XPRESS_HUFF, data, dataSize, decompData)) {
                                    decompressed = true;
                                }
                            }

                            // 5. 多种 XOR 密钥爆破（AA, 55, FF, 33, CC, 66, 99）
                            if (!decompressed) {
                                BYTE xorKeys[] = {0xAA, 0x55, 0xFF, 0x33, 0xCC, 0x66, 0x99};
                                for (BYTE key : xorKeys) {
                                    std::vector<BYTE> xorData;
                                    if (TryXorDecrypt(data, dataSize, key, xorData)) {
                                        // 检查解扰后的头部
                                        if (xorData.size() >= 2) {
                                            if ((xorData[0] == 0x4D && xorData[1] == 0x5A) ||
                                                (xorData[0] == 0x50 && xorData[1] == 0x4B)) {
                                                // 有效 PE 或 ZIP
                                                decompressed = true;
                                                decompData = std::move(xorData);
                                                result.warnings.push_back("XOR decrypted resource (key 0x" + std::to_string(key) + ") yields PE/ZIP");
                                                score += 5;
                                                break;
                                            }
                                            // 检查 .NET 序列化流
                                            if (xorData.size() >= 4 && xorData[0] == 0x01 && xorData[1] == 0x00 &&
                                                xorData[2] == 0x00 && xorData[3] == 0x00) {
                                                decompressed = true;
                                                decompData = std::move(xorData);
                                                result.warnings.push_back("XOR decrypted resource (key 0x" + std::to_string(key) + ") yields .NET serialization stream");
                                                score += 4;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            // 如果解压成功，进行递归分析
                            if (decompressed && decompData.size() > 0) {
                                // 检测 PE
                                if (decompData.size() >= 2 && decompData[0] == 0x4D && decompData[1] == 0x5A) {
                                    AnalysisResult innerResult;
                                    if (AnalyzePE(decompData.data(), decompData.size(), L"", innerResult, depth + 1)) {
                                        // 累加评分 * 0.5
                                        int addScore = (int)(innerResult.score * 0.5);
                                        if (addScore > 0) {
                                            score += addScore;
                                            result.info.push_back("Decompressed/decrypted resource PE analysis added " + std::to_string(addScore) + " points (inner score " + std::to_string(innerResult.score) + ")");
                                        }
                                        if (innerResult.score >= 30) {
                                            result.warnings.push_back("Decompressed/decrypted resource contains high-scoring PE (>=30)");
                                        }
                                    }
                                }
                                // 检测 ZIP
                                else if (decompData.size() >= 4 && decompData[0] == 0x50 && decompData[1] == 0x4B &&
                                         decompData[2] == 0x03 && decompData[3] == 0x04) {
                                    score += 4;
                                    result.warnings.push_back("Decompressed/decrypted resource contains ZIP archive");
                                }
                                // 检测 .NET 序列化流
                                else if (decompData.size() >= 4 && decompData[0] == 0x01 && decompData[1] == 0x00 &&
                                         decompData[2] == 0x00 && decompData[3] == 0x00) {
                                    score += 6;
                                    result.warnings.push_back(".NET binary serialization stream found in resource - possible deserialization payload");
                                    result.info.push_back("Added 6 points for .NET serialization stream");
                                }
                            }
                        }

                        // 原有 MZ/ZIP 头部检测（保留）
                        if (dataRaw != 0 && dataRaw <= baseSize - dataSize && dataSize >= 2) {
                            const BYTE* data = base + dataRaw;

                            if (depth < 3) {
                                DWORD offset = 0;
                                while (offset + 2 <= dataSize) {
                                    if (data[offset] == 0x4D && data[offset+1] == 0x5A) {
                                        if (offset > 0) {
                                            DWORD embeddedSize = dataSize - offset;
                                            std::vector<BYTE> embedded_data(embeddedSize);
                                            memcpy(embedded_data.data(), data + offset, embeddedSize);
                                            AnalysisResult innerResult;
                                            if (AnalyzePE(embedded_data.data(), embedded_data.size(), L"", innerResult, depth + 1)) {
                                                int addScore = (int)(innerResult.score * 0.5);
                                                if (addScore > 0) {
                                                    score += addScore;
                                                    result.info.push_back("Embedded PE resource analysis added " + std::to_string(addScore) + " points (inner score " + std::to_string(innerResult.score) + ")");
                                                }
                                                if (innerResult.score >= 30) {
                                                    result.warnings.push_back("Contains hidden dropper (embedded PE scored >=30)");
                                                }
                                            }
                                            break;
                                        } else {
                                            embeddedPE = true;
                                            break;
                                        }
                                    }
                                    offset++;
                                }
                            }

                            const BYTE mzPattern[] = {0x4D, 0x5A, 0x90, 0x00};
                            const BYTE commentPattern[] = {0x2F, 0x2A, 0x20, 0x20, 0x2A, 0x2F};
                            for (DWORD off = 0; off + 4 <= dataSize; ++off) {
                                if (memcmp(data + off, mzPattern, 4) == 0) {
                                    score += 4;
                                    result.warnings.push_back("MZ pattern (4D 5A 90 00) found in resource data - potential PE fragment");
                                    result.info.push_back("Added 4 points for MZ pattern in resource");
                                    break;
                                }
                            }
                            for (DWORD off = 0; off + 6 <= dataSize; ++off) {
                                if (memcmp(data + off, commentPattern, 6) == 0) {
                                    score += 2;
                                    result.warnings.push_back("C-style comment header (/*  */) found in resource - likely embedded source or serialized data");
                                    result.info.push_back("Added 2 points for C comment pattern in resource");
                                    break;
                                }
                            }

                            if ((data[0] == 0x4D && data[1] == 0x5A) ||
                                (data[0] == 0x50 && data[1] == 0x4B) ||
                                (data[0] == 0x1F && data[1] == 0x8B)) {
                                hiddenPayloadCount++;
                            }

                            if (dataSize > 200 * 1024 && entropyComputed && resourceEntropy > 7.8) {
                                encryptedPayloadCount++;
                            }

                            if (typeId == 10 && dataSize > 100 * 1024) {
                                largeRcData = true;
                                hasAnyResourceAnomaly = true;
                                result.warnings.push_back("RT_RCDATA resource size >100KB (" + std::to_string(dataSize) + " bytes) - potential payload");
                            }

                            bool foundMZ = false, foundPK = false;
                            for (DWORD off = 0; off + 2 <= dataSize; ++off) {
                                if (data[off] == 0x4D && data[off+1] == 0x5A) {
                                    foundMZ = true;
                                    if (off != 0) {
                                        stealthPE = true;
                                        hasAnyResourceAnomaly = true;
                                        result.warnings.push_back("Embedded PE with non-zero offset (0x" + std::to_string(off) + ") in resource - steganography");
                                    } else {
                                        embeddedPE = true;
                                    }
                                    break;
                                }
                                if (data[off] == 0x50 && data[off+1] == 0x4B) {
                                    foundPK = true;
                                    if (off != 0) {
                                        stealthZIP = true;
                                        hasAnyResourceAnomaly = true;
                                        result.warnings.push_back("Embedded ZIP with non-zero offset (0x" + std::to_string(off) + ") in resource - steganography");
                                    } else {
                                        embeddedZIP = true;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    entryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
                }
            };

            scanDir(resourceRVA, 0, 0, 0);

            DWORD totalCustomSize = 0;
            for (const auto& pair : customTypeSizeMap) {
                totalCustomSize += pair.second;
            }
            if (totalCustomSize > 0 && baseSize > 0) {
                double ratio = static_cast<double>(totalCustomSize) / baseSize;
                if (ratio > 0.3) {
                    score += 8;
                    result.warnings.push_back("Suspicious custom resource types (>100) dominate file size");
                    result.info.push_back("Added 8 points for custom resource types (>100) > 30% of file size");
                }
            }

            if (rsrcBlobs.size() >= 3) {
                std::sort(rsrcBlobs.begin(), rsrcBlobs.end(),
                          [](const ResourceBlob& a, const ResourceBlob& b) { return a.dataSize < b.dataSize; });
                for (size_t i = 0; i + 2 < rsrcBlobs.size(); ++i) {
                    double baseSizeRef = rsrcBlobs[i].dataSize;
                    size_t j = i + 1;
                    while (j < rsrcBlobs.size() && (double)rsrcBlobs[j].dataSize / baseSizeRef <= 1.05 &&
                           (double)rsrcBlobs[j].dataSize / baseSizeRef >= 0.95) {
                        j++;
                    }
                    if (j - i >= 3) {
                        bool allHighEntropy = true;
                        for (size_t k = i; k < j; ++k) {
                            if (rsrcBlobs[k].entropy <= 7.8) { allHighEntropy = false; break; }
                        }
                        if (allHighEntropy) {
                            score += 7;
                            result.warnings.push_back("Multiple (≥3) RT_RCDATA resources with similar size and high entropy detected - possible sharded payload");
                            result.info.push_back("Added 7 points for sharded payload detection");

                            std::vector<ResourceBlob> sortedBlobs(rsrcBlobs.begin() + i, rsrcBlobs.begin() + j);
                            std::sort(sortedBlobs.begin(), sortedBlobs.end(),
                                      [](const ResourceBlob& a, const ResourceBlob& b) { return a.rawOffset < b.rawOffset; });
                            std::vector<BYTE> assembled;
                            size_t totalSize = 0;
                            for (const auto& blob : sortedBlobs) {
                                if (blob.rawOffset + blob.dataSize <= baseSize) {
                                    assembled.insert(assembled.end(), base + blob.rawOffset, base + blob.rawOffset + blob.dataSize);
                                    totalSize += blob.dataSize;
                                }
                            }
                            if (totalSize >= 2 && assembled.size() >= 2) {
                                if (assembled[0] == 0x4D && assembled[1] == 0x5A) {
                                    AnalysisResult innerResult;
                                    if (AnalyzePE(assembled.data(), assembled.size(), L"", innerResult, depth + 1)) {
                                        int addScore = (int)(innerResult.score * 0.5);
                                        if (addScore > 0) {
                                            score += addScore;
                                            result.info.push_back("Assembled sharded payload PE analysis added " + std::to_string(addScore) + " points (inner score " + std::to_string(innerResult.score) + ")");
                                        }
                                        if (innerResult.score >= 30) {
                                            result.warnings.push_back("Assembled sharded payload is a valid PE with high score (>=30) - potential dropper");
                                        }
                                    }
                                } else {
                                    result.info.push_back("Assembled sharded payload is not a PE (size " + std::to_string(totalSize) + ")");
                                }
                            }
                            break;
                        }
                    }
                    i = j - 1;
                }
            }

            if (embeddedPE) {
                score += 6;
                result.info.push_back("Embedded PE found in resources (normal)");
            }
            if (embeddedZIP) {
                score += 3;
                result.info.push_back("Embedded ZIP found in resources");
            }
            if (stealthPE) {
                score += 8;
                result.info.push_back("Added 8 points for stealth PE (non-zero offset)");
            }
            if (stealthZIP) {
                score += 6;
                result.info.push_back("Added 6 points for stealth ZIP (non-zero offset)");
            }
            if (largeRcData) {
                score += 3;
                result.info.push_back("Added 3 points for large RT_RCDATA payload");
            }

            int hiddenScore = std::min(hiddenPayloadCount * 6, 20);
            int encryptedScore = std::min(encryptedPayloadCount * 8, 20);
            if (hiddenScore > 0) {
                score += hiddenScore;
                result.info.push_back("Added " + std::to_string(hiddenScore) + " points for hidden payloads (" + std::to_string(hiddenPayloadCount) + " found)");
            }
            if (encryptedScore > 0) {
                score += encryptedScore;
                result.info.push_back("Added " + std::to_string(encryptedScore) + " points for encrypted payloads (" + std::to_string(encryptedPayloadCount) + " found)");
            }

            result.info.push_back("Total resource items: " + std::to_string(totalResourceCount));
            result.info.push_back("Hidden payload count (PE/ZIP/GZIP): " + std::to_string(hiddenPayloadCount));
            result.info.push_back("Encrypted payload count (size>200KB, entropy>7.8): " + std::to_string(encryptedPayloadCount));

            if (totalResourceSize > 0) {
                double ratio = static_cast<double>(totalResourceSize) / baseSize * 100.0;
                if (ratio > 60.0) {
                    score += 2;
                    result.warnings.push_back("Resource section dominates file size (" + std::to_string(ratio) + "%) - potential dropper");
                    if (hasAnyResourceAnomaly) {
                        score += 3;
                        result.warnings.push_back("Resource size >60% with anomalies - additional penalty");
                        result.info.push_back("Added 3 points for resource size >60% with anomalies");
                    }
                }
            }

            if (totalResourceSize > 0) {
                result.info.push_back("Total resource size: " + std::to_string(totalResourceSize) + " bytes");
            }
        }
    } // end if (!isDriver)


    // TLS 回调深度分析（仅非驱动）

    if (!isDriver) {
        DWORD tlsRVA = dataDir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        if (tlsRVA != 0) {
            DWORD tlsRaw = RVAtoRaw(tlsRVA);
            if (tlsRaw) {
                size_t callbackPtrOffset = is64bit ? 24 : 12;
                if (tlsRaw + callbackPtrOffset + (is64bit ? 8 : 4) <= baseSize) {
                    DWORD_PTR callbackPtrRVA = 0;
                    if (is64bit) {
                        callbackPtrRVA = *reinterpret_cast<const DWORD_PTR*>(base + tlsRaw + callbackPtrOffset);
                    } else {
                        callbackPtrRVA = *reinterpret_cast<const DWORD*>(base + tlsRaw + callbackPtrOffset);
                    }

                    if (callbackPtrRVA != 0) {
                        DWORD callbackArrayRaw = RVAtoRaw((DWORD)callbackPtrRVA);
                        if (callbackArrayRaw) {
                            size_t elemSize = is64bit ? 8 : 4;
                            int callbackCount = 0;
                            bool hasWritable = false;
                            std::vector<DWORD> callbackRVAs;

                            size_t offset = 0;
                            int callbackLimit = 1024;
                            while (true) {
                                if (callbackCount >= callbackLimit) break;
                                if (callbackArrayRaw + offset + elemSize > baseSize) break;
                                DWORD_PTR funcRVA = 0;
                                if (is64bit) {
                                    funcRVA = *reinterpret_cast<const DWORD_PTR*>(base + callbackArrayRaw + offset);
                                } else {
                                    funcRVA = *reinterpret_cast<const DWORD*>(base + callbackArrayRaw + offset);
                                }
                                if (funcRVA == 0) break;
                                callbackRVAs.push_back((DWORD)funcRVA);
                                callbackCount++;
                                offset += elemSize;

                                bool found = false;
                                for (size_t i = 0; i < sections.size(); ++i) {
                                    if ((DWORD)funcRVA >= sections[i].rvaStart && (DWORD)funcRVA < sections[i].rvaEnd) {
                                        if (pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                                            hasWritable = true;
                                        }
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    result.warnings.push_back("TLS callback at RVA 0x" + std::to_string((DWORD)funcRVA) + " does not belong to any section (unusual)");
                                }
                            }

                            if (callbackCount > 0) {
                                score += 5;
                                result.warnings.push_back("TLS callbacks present: " + std::to_string(callbackCount) + " callback(s) found.");
                                std::string rvaList = "TLS callback RVAs: ";
                                for (size_t i = 0; i < callbackRVAs.size(); ++i) {
                                    char buf[16];
                                    snprintf(buf, sizeof(buf), "0x%08X", callbackRVAs[i]);
                                    rvaList += buf;
                                    if (i != callbackRVAs.size() - 1) rvaList += ", ";
                                }
                                result.info.push_back(rvaList);

                                if (hasWritable) {
                                    score += 12;
                                    result.warnings.push_back("HIGH RISK: TLS callback in writable section – possible code injection/hooking");
                                } else {
                                    result.info.push_back("TLS callbacks are in non-writable sections.");
                                }

                                //  对每个 TLS 回调进行入口字节模式检测 
                                for (DWORD rva : callbackRVAs) {
                                    DWORD raw = RVAtoRaw(rva);
                                    if (raw != 0 && raw + 64 <= baseSize) {
                                        const BYTE* data = base + raw;
                                        analyze_entry_point_bytes(data, 64, score, result.warnings, result.info);
                                    }
                                }
                            }
                        } else {
                            result.warnings.push_back("TLS directory present but callback array not found in file");
                        }
                    } else {
                        result.info.push_back("TLS directory present but no callbacks (AddressOfCallBacks = 0)");
                    }
                } else {
                    result.warnings.push_back("TLS directory RVA exists but cannot map to raw data");
                }
            } else {
                result.warnings.push_back("TLS directory RVA exists but cannot map to raw data");
            }
        }
    }


     //.pdata 异常目录有效性验证（64位） =

    if (is64bit) {
        DWORD exceptionRVA = dataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        DWORD exceptionSize = dataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        if (exceptionRVA != 0 && exceptionSize >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) {
            DWORD exceptionRaw = RVAtoRaw(exceptionRVA);
            if (exceptionRaw != 0 && exceptionRaw + exceptionSize <= baseSize) {
                int badEntries = 0;
                DWORD numEntries = exceptionSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
                const IMAGE_RUNTIME_FUNCTION_ENTRY* entries = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(base + exceptionRaw);
                for (DWORD i = 0; i < numEntries; ++i) {
                    DWORD begin = entries[i].BeginAddress;
                    // 检查 BeginAddress 是否落在可执行节内
                    bool inExec = false;
                    for (const auto& sec : sections) {
                        if (begin >= sec.rvaStart && begin < sec.rvaEnd) {
                            // 查找对应节特性
                            for (WORD si = 0; si < numSections; ++si) {
                                if (pSection[si].VirtualAddress == sec.rvaStart) {
                                    if (pSection[si].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                                        inExec = true;
                                    }
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    if (!inExec) {
                        badEntries++;
                    }
                }
                if (badEntries > 0) {
                    int add = std::min(badEntries * 3, 15);
                    score += add;
                    result.warnings.push_back(".pdata contains " + std::to_string(badEntries) + " exception entries pointing to non-executable sections");
                    result.info.push_back("Added " + std::to_string(add) + " points for invalid .pdata entries");
                }
            }
        }
    }

    // 时间戳反绕检测
    if (timeStampWarning) {
        score += 6;
        result.warnings.push_back("Timestamp anti-rollback detected: TRUST_E_TIME_STAMP (signature timestamp invalid)");
        result.info.push_back("Added 6 points for timestamp anti-rollback");
    }

     //安全缓解措施检查
    {
        int missingCount = 0;
        std::string missingList;
        if (!(dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
            score += 2;
            missingCount++;
            missingList += "ASLR ";
        }
        if (!(dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) {
            score += 2;
            missingCount++;
            missingList += "DEP ";
        }
        if (!(dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)) {
            score += 1;
            missingCount++;
            missingList += "CFG ";
        }
         //检查 HIGH_ENTROPY_VA
        if (!(dllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)) {
            score += 8;
            result.warnings.push_back("High entropy ASLR (IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) not set - 64-bit ASLR weaker");
            result.info.push_back("Added 8 points for missing HIGH_ENTROPY_VA");
        }
        if (missingCount == 3) {
            score += 1;
            missingList += "(all missing)";
        }
        if (missingCount > 0) {
            result.warnings.push_back("Missing security mitigations: " + missingList);
        }
    }

     //G-1: 编译器安全Cookie（GS）完整性校验
    {
        bool hasSecurityCheckCookie = false;
        if (importedApisSet.find("__security_check_cookie") != importedApisSet.end()) {
            hasSecurityCheckCookie = true;
        }

        if (hasSecurityCheckCookie) {
            bool foundCookie = false;
            bool dataSectionWx = false;

            for (const auto& sec : sections) {
                std::string lowerName = sec.name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                if (lowerName == ".data") {
                    if (sec.rawSize > 0 && sec.rawStart != 0 &&
                        sec.rawStart <= baseSize - sec.rawSize) {
                        const BYTE* data = base + sec.rawStart;
                        const char* pattern = "___security_cookie";
                        size_t patLen = strlen(pattern);

                        for (DWORD i = 0; i + patLen <= sec.rawSize; ++i) {
                            if (memcmp(data + i, pattern, patLen) == 0) {
                                foundCookie = true;
                                for (WORD si = 0; si < numSections; ++si) {
                                    if (pSection[si].VirtualAddress == sec.rvaStart) {
                                        DWORD ch = pSection[si].Characteristics;
                                        if ((ch & IMAGE_SCN_MEM_WRITE) && (ch & IMAGE_SCN_MEM_EXECUTE)) {
                                            dataSectionWx = true;
                                        }
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                    break;
                }
            }

            if (!foundCookie) {
                score += 5;
                result.warnings.push_back("GS cookie variable ___security_cookie not found in .data section despite __security_check_cookie import");
                result.info.push_back("Added 5 points for missing GS cookie");
            } else if (dataSectionWx) {
                score += 5;
                result.warnings.push_back("GS cookie variable in .data section which is writable and executable");
                result.info.push_back("Added 5 points for GS cookie in W^X section");
            }
        }
    }

    //64位异常处理目录（.pdata）缺失
    if (is64bit) {
        DWORD exceptionSize = dataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        if (exceptionSize == 0) {
            bool isDll = (pNt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
            if (isDll) {
                score += 6;
                result.warnings.push_back("64-bit DLL missing exception handling directory (.pdata) - violates Windows x64 ABI");
                result.info.push_back("Added 6 points for missing .pdata in 64-bit DLL");
            }
        }
    }

    // 加壳综合（重定位表缺失精细判断已内联)
    int packScore = 0;

    // 重定位表异常检测（驱动不额外加分，已在前面处理）
    if (!isDriver && !isDotNet) {
        if (relocFound) {
            if (relocSize < 0x200) {
                score += 4;
                result.warnings.push_back("Medium: .reloc section present but very small (" + std::to_string(relocSize) + " bytes) - likely invalid/stub after packing");
                result.info.push_back("Added 4 points for small .reloc");
            }
        } else {
            if (!is64bit) {
                bool combo = (entryPointSectionEntropy > 6.5 && totalImported < 10);
                if (combo) {
                    score += 8;
                    result.warnings.push_back("HIGH: Missing .reloc section combined with high entry entropy (>6.5) and few imports (<10) - strong packer/loader indicator");
                    result.info.push_back("Added 8 points for missing .reloc + combo");
                } else {
                    score += 2;
                    result.warnings.push_back("Low: No .reloc section in 32-bit PE (common in packed or old executables)");
                    result.info.push_back("Added 2 points for missing .reloc");
                }
            }
        }
    }

    // 入口点分析（仅非驱动）
    if (!isDriver) {
        if (entrySecRawOff != 0 && entrySecRawSize > 0) {
            DWORD offsetInSec = entryRVA - entrySecRVAStart;
            if (offsetInSec < entrySecRawSize) {
                DWORD entryRawOffset = entrySecRawOff + offsetInSec;
                DWORD bytesToRead = 32;
                if (entryRawOffset > baseSize - bytesToRead) {
                    bytesToRead = baseSize - entryRawOffset;
                }
                if (bytesToRead >= 6) {
                    const BYTE* entryData = base + entryRawOffset;
                    bool signatureDetected = false;

                    if (entryData[0] == 0x60 && (entryData[1] == 0x61 || entryData[1] == 0xE9)) {
                        packScore += 3;
                        result.warnings.push_back("Packer signature detected in entry point bytes: UPX-like (pushad/popad or pushad+jmp)");
                        signatureDetected = true;
                    }

                    if (!signatureDetected && entryData[0] == 0xE8 && entryData[5] == 0xE9) {
                        packScore += 3;
                        result.warnings.push_back("Packer signature detected in entry point bytes: MPRESS-like (call+jmp)");
                        signatureDetected = true;
                    }

                    if (!signatureDetected) {
                        int pushCount = 0, movCount = 0;
                        for (int i = 0; i < 32 && i < static_cast<int>(bytesToRead); ++i) {
                            if (entryData[i] == 0x68) pushCount++;
                            else if (entryData[i] == 0xB8) movCount++;
                        }
                        if (pushCount >= 3 || movCount >= 3) {
                            packScore += 2;
                            result.warnings.push_back("Packer signature detected in entry point bytes: Themida/VMProtect-like (many push/mov immediate)");
                            signatureDetected = true;
                        }

                        if (!signatureDetected && textFound) {
                            for (int i = 0; i < static_cast<int>(bytesToRead) - 5; ++i) {
                                if (entryData[i] == 0xE8 || entryData[i] == 0xE9) {
                                    int32_t offset = *(int32_t*)(entryData + i + 1);
                                    DWORD targetRVA = entryRVA + i + 5 + offset;
                                    if (!(targetRVA >= textRVAStart && targetRVA < textRVAEnd)) {
                                        packScore += 2;
                                        result.warnings.push_back("Packer signature detected in entry point bytes: call/jmp to non-.text section");
                                        signatureDetected = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    //  高级模式检测 
                    DWORD maxRead = 64;
                    if (entryRawOffset > baseSize - maxRead) maxRead = baseSize - entryRawOffset;
                    if (offsetInSec > entrySecRawSize - maxRead) maxRead = entrySecRawSize - offsetInSec;
                    if (maxRead >= 8) {
                        const BYTE* entryData2 = base + entryRawOffset;

                        bool foundEIP = false;
                        for (int i = 0; i <= static_cast<int>(maxRead) - 5; ++i) {
                            if (entryData2[i] == 0xE8 && entryData2[i+1] == 0x00 &&
                                entryData2[i+2] == 0x00 && entryData2[i+3] == 0x00 && entryData2[i+4] == 0x00) {
                                int next = i + 5;
                                if (next < static_cast<int>(maxRead)) {
                                    BYTE nextByte = entryData2[next];
                                    if ((nextByte >= 0x58 && nextByte <= 0x5F) || nextByte == 0x8B || nextByte == 0x89) {
                                        foundEIP = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if (foundEIP) {
                            packScore += 3;
                            result.warnings.push_back("EIP/GetPC stub detected (shellcode/packer)");
                        }

                        for (int i = 0; i <= static_cast<int>(maxRead) - 4; ++i) {
                            if (entryData2[i] == 0x31 && entryData2[i+1] == 0xC0 &&
                                entryData2[i+2] == 0xEB && entryData2[i+3] >= 0x80) {
                                packScore += 4;
                                result.warnings.push_back("Short jump decryption loop detected (xor eax,eax; jmp short -x) - likely decryption stub");
                                break;
                            }
                        }

                        if (maxRead >= 64) {
                            int pushCnt = 0, callCnt = 0;
                            for (int i = 0; i < static_cast<int>(maxRead); ++i) {
                                if (entryData2[i] == 0x68) pushCnt++;
                                else if (entryData2[i] == 0xE8) callCnt++;
                            }
                            if (pushCnt >= 4 && callCnt >= 2) {
                                packScore += 2;
                                result.warnings.push_back("IAT obfuscation stub detected");
                            }
                        }

                        std::vector<int> xorPositions;
                        for (int i = 0; i < static_cast<int>(maxRead); ++i) {
                            if (entryData2[i] == 0x31 || entryData2[i] == 0x33) {
                                xorPositions.push_back(i);
                            }
                        }
                        if (!xorPositions.empty()) {
                            for (int i = 0; i < static_cast<int>(maxRead); ++i) {
                                if (entryData2[i] == 0xEB || entryData2[i] == 0x75) {
                                    if (i + 1 < static_cast<int>(maxRead)) {
                                        signed char offset = static_cast<signed char>(entryData2[i+1]);
                                        if (offset < 0 && abs(offset) <= 0x10) {
                                            int target = i + 2 + offset;
                                            for (int pos : xorPositions) {
                                                if (target == pos) {
                                                    packScore += 3;
                                                    result.warnings.push_back("Short loop with xor and jump detected (decryption stub)");
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
            }
        }

        //  间接调用密度统计 
        if (entrySecRawSize > 0 && entrySecRawOff <= baseSize - entrySecRawSize) {
            const BYTE* secData = base + entrySecRawOff;
            int indirectCount = 0;
            for (DWORD i = 0; i + 1 < entrySecRawSize; ++i) {
                if (secData[i] == 0xFF) {
                    BYTE next = secData[i+1];
                    if ((next >= 0xD0 && next <= 0xD7) || (next >= 0xE0 && next <= 0xE7)) {
                        indirectCount++;
                    }
                }
            }
            if (indirectCount > static_cast<int>(entrySecRawSize / 60)) {
                packScore += 3;
                result.warnings.push_back("High density of indirect call/jump instructions (indirect " + std::to_string(indirectCount) +
                                          " in " + std::to_string(entrySecRawSize) + " bytes) - possible dynamic API obfuscation");
            }
        }

        // 入口点节熵检查 
        if (entryPointSectionEntropy > 6.5) {
            packScore += 4;
            result.warnings.push_back("[Medium] High entropy in entry-point section (" + std::to_string(entryPointSectionEntropy) + ")");
        }

        if (totalImported < 10) { packScore += 1; result.warnings.push_back("Very few imported functions (" + std::to_string(totalImported) + ")"); }
        if (numSections > 8) { packScore += 1; result.warnings.push_back("Many sections (" + std::to_string(numSections) + ")"); }
        if (suspiciousSectionCount >= 3) { packScore += 1; result.warnings.push_back("Multiple sections with raw/virtual size mismatch"); }
        if (dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == 0) { packScore += 1; result.warnings.push_back("No debug directory (common in packed files)"); }
        if (hasPackedSectionName) { packScore += 2; }

        if (packScore >= 5) { score += 4; result.warnings.push_back("Strong packing indicators (score " + std::to_string(packScore) + ")"); }
        else if (packScore >= 3) { score += 2; result.warnings.push_back("Moderate packing indicators (score " + std::to_string(packScore) + ")"); }
    } // end if (!isDriver)

    // 全局节区熵值统计模型（对驱动也适用）/
    int entropyScore = 0;
    if (totalRawSize > 0) {
        double weightedAvg = weightedSum / totalRawSize;
        if (weightedAvg > 6.8) {
            entropyScore += 6;
            result.warnings.push_back("[High] Weighted average entropy across sections is " + std::to_string(weightedAvg) +
                                      " (>6.8) - strong encryption/packer");
            result.info.push_back("Added 6 points for high weighted average entropy");
        }
        if (textEntropy >= 0.0 && rdataEntropy >= 0.0) {
            if (textEntropy < 2.0 && rdataEntropy > 7.5) {
                entropyScore += 4;
                result.warnings.push_back("[Medium] Code/data separation encryption: .text entropy " + std::to_string(textEntropy) +
                                          " (<2.0) and .rdata entropy " + std::to_string(rdataEntropy) +
                                          " (>7.5) - typical of VMProtect/Themida");
                result.info.push_back("Added 4 points for .text/.rdata entropy separation");
            }
        }
        result.info.push_back("Weighted average section entropy: " + std::to_string(weightedAvg));
        if (textEntropy >= 0.0) result.info.push_back(".text section entropy: " + std::to_string(textEntropy));
        if (rdataEntropy >= 0.0) result.info.push_back(".rdata section entropy: " + std::to_string(rdataEntropy));
    }
    score += entropyScore;

   
    //指令级反调试/反虚拟机扫描（仅非驱动）
   
    if (!isDriver && !isDotNet) {
        std::unordered_set<std::string> detectedPatterns;
        int rawHitCount = 0;

        for (size_t i = 0; i < numSections; ++i) {
            const auto& sec = sections[i];
            if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            if (sec.rawSize == 0 || sec.rawStart == 0) continue;
            if (sec.rawStart > baseSize - sec.rawSize) continue;

            const BYTE* data = base + sec.rawStart;
            scan_section_for_antidebug(data, sec.rawSize, sec.name, detectedPatterns, rawHitCount);
        }

        int uniqueCount = (int)detectedPatterns.size();
        if (uniqueCount > 0) {
            int addScore = uniqueCount * 3;
            if (uniqueCount >= 3) {
                addScore += 5;
                result.warnings.push_back("Strong anti-debug/anti-VM indicators (unique pattern types: " + std::to_string(uniqueCount) + ")");
            }
            score += addScore;
            result.info.push_back("Added " + std::to_string(addScore) + " points for anti-debug/anti-VM instruction patterns (" +
                                  std::to_string(uniqueCount) + " unique types, raw hits: " + std::to_string(rawHitCount) + ")");
        }

        // D-1 & D-2: 反调试模式
        for (size_t i = 0; i < numSections; ++i) {
            const auto& sec = sections[i];
            if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            if (sec.rawSize == 0 || sec.rawStart == 0) continue;
            if (sec.rawStart > baseSize - sec.rawSize) continue;

            const BYTE* data = base + sec.rawStart;
            scan_peb_anti_debug_pattern(data, sec.rawSize, is64bit, result, score);
            scan_seh_anti_debug_pattern(data, sec.rawSize, result, score);
        }
    }


    //动态控制流检测（对驱动适用，但权重可调） 

    if (!isDotNet){
        std::vector<std::pair<DWORD, DWORD>> execRanges;
        for (const auto& sec : sections) {
            if (pSection[&sec - sections.data()].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                execRanges.push_back({sec.rvaStart, sec.rvaEnd});
            }
        }

        DWORD iatRVA = 0, iatSize = 0;
        if (numberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT) {
            iatRVA = dataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            iatSize = dataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        }

        int abnormalCount = 0;
        std::vector<std::string> abnormalDetails;

        for (size_t i = 0; i < numSections; ++i) {
            const auto& sec = sections[i];
            if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            if (sec.rawSize == 0 || sec.rawStart == 0) continue;
            if (sec.rawStart > baseSize - sec.rawSize) continue;

            const BYTE* data = base + sec.rawStart;
            scan_section_for_control_flow(data, sec.rawSize, sec.rvaStart, sec.rawStart,
                                          sec.name, execRanges, iatRVA, iatSize,
                                          abnormalCount, abnormalDetails);
        }

        result.dynamicCallCount = abnormalCount;
        if (abnormalCount > 0) {
            int showCount = std::min(abnormalCount, 5);
            for (int i = 0; i < showCount; ++i) {
                result.abnormalCalls.push_back(abnormalDetails[i]);
            }
            if (abnormalCount > 5) {
                result.abnormalCalls.push_back("... and " + std::to_string(abnormalCount - 5) + " more.");
            }

            int add = std::min(abnormalCount * 5, 20);
            if (isDriver) {
                add = add / 2;
                if (add < 2) add = 2;
            }
            score += add;
            result.info.push_back("Added " + std::to_string(add) + " points for abnormal control flow instructions (E8/FF15)");
        }
    }


    // OEP 节名深度检测（适用于所有）

    if (!isDotNet){
        int entrySectionIndex = -1;
        for (WORD i = 0; i < numSections; ++i) {
            const auto& sec = pSection[i];
            DWORD vaStart = sec.VirtualAddress;
            DWORD vaEnd = vaStart + sec.Misc.VirtualSize;
            if (entryRVA >= vaStart && entryRVA < vaEnd) {
                entrySectionIndex = i;
                break;
            }
        }

        if (entrySectionIndex != -1) {
            const auto& sec = pSection[entrySectionIndex];
            char name[9] = {0};
            memcpy(name, sec.Name, 8);
            std::string oepSecName = name;
            std::string lowerName = oepSecName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            bool isReloc = (lowerName == ".reloc");
            bool isStandard = false;
            for (int s = 0; s < STANDARD_SECTION_COUNT; ++s) {
                std::string stdLower = standard_sections[s];
                std::transform(stdLower.begin(), stdLower.end(), stdLower.begin(), ::tolower);
                if (lowerName == stdLower) {
                    isStandard = true;
                    break;
                }
            }
            bool isExecutable = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

            if (!isStandard) {
                score += 10;
                result.warnings.push_back("OEP in non-standard section: " + oepSecName);
                result.info.push_back("Added 10 points for non-standard OEP section");
            }
            if (!isExecutable) {
                score += 5;
                result.warnings.push_back("OEP section is not executable: " + oepSecName);
                result.info.push_back("Added 5 points for non-executable OEP section");
            }

            std::string oepInfo = "OEP section: " + oepSecName +
                                  ", isReloc=" + (isReloc ? "true" : "false") +
                                  ", isStandard=" + (isStandard ? "true" : "false") +
                                  ", isExecutable=" + (isExecutable ? "true" : "false");
            result.info.push_back(oepInfo);
        } else {
            result.warnings.push_back("Cannot locate OEP section (entry RVA not in any section)");
        }
    }


    // 动态 API 解析链 + 注入链组合检测（仅非驱动） 

    if (!isDriver) {
        bool hasLoadLibrary = (allDetectedApis.find("loadlibrarya") != allDetectedApis.end() ||
                               allDetectedApis.find("loadlibraryw") != allDetectedApis.end());
        bool hasGetProcAddress = (allDetectedApis.find("getprocaddress") != allDetectedApis.end());
        bool hasInjectionApi = (allDetectedApis.find("virtualallocex") != allDetectedApis.end() ||
                                allDetectedApis.find("writeprocessmemory") != allDetectedApis.end() ||
                                allDetectedApis.find("createremotethread") != allDetectedApis.end() ||
                                allDetectedApis.find("ntcreatethreadex") != allDetectedApis.end());

        if (hasLoadLibrary && hasGetProcAddress && hasInjectionApi) {
            score += 15;
            result.warnings.push_back("Dynamic API + injection chain detected");

            std::vector<std::string> relatedApis;
            for (const auto& api : allDetectedApis) {
                if (api == "loadlibrarya" || api == "loadlibraryw" ||
                    api == "getprocaddress" ||
                    api == "virtualallocex" || api == "writeprocessmemory" ||
                    api == "createremotethread" || api == "ntcreatethreadex") {
                    relatedApis.push_back(api);
                }
            }
            std::string apiList = "Related APIs found: ";
            int count = 0;
            for (const auto& api : relatedApis) {
                if (count > 0) apiList += ", ";
                if (count < 10) {
                    apiList += api;
                } else {
                    apiList += "...";
                    break;
                }
                count++;
            }
            result.info.push_back(apiList);
            result.info.push_back("Combination: LoadLibrary + GetProcAddress + Injection API");
        }
    }


    // 动态 API 哈希检测扩展到所有可执行节（非驱动，但可对驱动也做） 
   // 对 .text 节已处理，此处处理其他可执行节
    if (!isDotNet) {
        for (size_t i = 0; i < numSections; ++i) {
            const auto& sec = sections[i];
            if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            std::string secName = sec.name;
            std::transform(secName.begin(), secName.end(), secName.begin(), ::tolower);
            if (secName == ".text") continue; // 已处理
            if (sec.rawSize == 0 || sec.rawStart == 0) continue;
            if (sec.rawStart > baseSize - sec.rawSize) continue;

            const BYTE* data = base + sec.rawStart;
            // 哈希检测
            scan_ror13_hashes(data, sec.rawSize, score, result.warnings, result.info);
            // push hash; call 检测
            scan_push_hash_call(data, sec.rawSize, score, result.warnings, result.info);
        }
    }

     //从 PE 头获取链接器时间戳
    DWORD linkerTimestamp = pNt->FileHeader.TimeDateStamp;

    //时间矛盾检测 
    if (result.hasSignature && (notBefore != 0 || notAfter != 0)) {
        const time_t DAY_SEC = 24 * 3600;

        if (notBefore > (time_t)linkerTimestamp &&
            (notBefore - (time_t)linkerTimestamp) > 30 * DAY_SEC) {
            score += 8;
            result.warnings.push_back("Certificate issued after linker timestamp (gap > 30 days)");
            result.info.push_back("Added 8 points for timestamp contradiction (NotBefore > LinkerTime)");
        }

        if ((time_t)linkerTimestamp > notAfter) {
            score += 8;
            result.warnings.push_back("Certificate timestamp contradiction detected: linker timestamp after certificate expiry");
            result.info.push_back("Added 8 points for timestamp contradiction (LinkerTime > NotAfter)");
        }
    }

    //空字符截断伪造
    if (nameSpoofed) {
        score += 15;
        result.warnings.push_back("Certificate name spoofing via null-byte truncation detected (e.g., 'Micro\\x00soft')");
        result.info.push_back("Added 15 points for null-byte truncation in certificate name");
    }

    // 签名深度信息处理（驱动逻辑）
    if (result.hasSignature) {
        std::wstring lowerSigner = signerCN;
        std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::towlower);
        std::wstring lowerIssuer = issuerCN;
        std::transform(lowerIssuer.begin(), lowerIssuer.end(), lowerIssuer.begin(), ::towlower);
        bool isMicrosoftSigner = (lowerSigner.find(L"microsoft") != std::wstring::npos);
        bool isTrustedMicrosoftIssuer = false;
        if (lowerIssuer.find(L"microsoft code signing pca") != std::wstring::npos ||
            lowerIssuer.find(L"microsoft root authority") != std::wstring::npos ||
            lowerIssuer.find(L"microsoft corporation") != std::wstring::npos) {
            isTrustedMicrosoftIssuer = true;
        }

        if (isMicrosoftSigner && !isTrustedMicrosoftIssuer) {
            score += 10;
            result.warnings.push_back("Forged Microsoft signature detected (subject contains 'Microsoft' but issuer not trusted Microsoft CA)");
            result.info.push_back("Added 10 points for forged Microsoft signature");
        } else {
            if (expired) {
                if (isDriver) {
                    score += 15;
                    result.warnings.push_back("Driver certificate is expired - will not load on Windows 10/11 (critical)");
                    result.info.push_back("Added 15 points for expired driver certificate");
                } else {
                    score += 10;
                    result.warnings.push_back("Certificate is expired");
                    result.info.push_back("Added 10 points for expired certificate");
                }
            }
            if (selfSigned) {
                if (isDriver) {
                    score += 10;
                    result.warnings.push_back("Self-signed certificate - driver may not load on secure boot systems");
                    result.info.push_back("Added 10 points for self-signed driver");
                } else {
                    score += 5;
                    result.warnings.push_back("Self-signed certificate");
                    result.info.push_back("Added 5 points for self-signed certificate");
                }
            }
            if (!expired && !selfSigned && !validSig) {
                if (isDriver) {
                    score += 15;
                    result.warnings.push_back("Driver signature present but WinVerifyTrust failed (certificate not trusted or tampered) - driver will not load");
                    result.info.push_back("Added 15 points for driver signature verification failure");
                } else {
                    score += 8;
                    result.warnings.push_back("Signature present but WinVerifyTrust failed (certificate not trusted or tampered)");
                    result.info.push_back("Added 8 points for signature verification failure");
                }
            }
            if (!expired && !selfSigned && validSig) {
                bool isKnown = false;
                std::string cnA(signerCN.begin(), signerCN.end());
                std::string issuerA(issuerCN.begin(), issuerCN.end());
                const char* knownCAs[] = {"Microsoft", "DigiCert", "VeriSign", "GlobalSign", "Comodo", "Symantec", "GoDaddy", "Let's Encrypt"};
                for (const char* ca : knownCAs) {
                    if (cnA.find(ca) != std::string::npos || issuerA.find(ca) != std::string::npos) {
                        isKnown = true;
                        break;
                    }
                }

                bool isMicrosoftPCA = false;
                std::wstring issuerLower2 = issuerCN;
                std::transform(issuerLower2.begin(), issuerLower2.end(), issuerLower2.begin(), ::towlower);
                if (issuerLower2.find(L"microsoft code signing pca") != std::wstring::npos) {
                    isMicrosoftPCA = true;
                }
/*
                if (isMicrosoftPCA) {
                    score = std::max(0, score - (isDriver ? 20 : 15));
                    result.info.push_back("Reduced score by " + std::string(isDriver ? "20" : "15") + " due to valid Microsoft Code Signing PCA signature");
                } else if (isKnown) {
                    score = std::max(0, score - (isDriver ? 6 : 3));
                    result.info.push_back("Reduced score by " + std::string(isDriver ? "6" : "3") + " due to valid known CA signature");
                } else {
                    score = std::max(0, score - (isDriver ? 3 : 2));
                    result.info.push_back("Reduced score by " + std::string(isDriver ? "3" : "2") + " due to valid signature from unknown entity");
                }
*/
                if (revocationCheckFailed) {
                    score += (isDriver ? 4 : 2);
                    result.warnings.push_back("Certificate revocation check failed (network/CRL unavailable) - " + std::string(isDriver ? "high risk for driver" : "mild risk"));
                    result.info.push_back("Added " + std::string(isDriver ? "4" : "2") + " points for revocation check failure");
                }
/*
                if (isEV) {
                    score = std::max(0, score - (isDriver ? 15 : 10));
                    result.info.push_back("Additional " + std::string(isDriver ? "-15" : "-10") + " points for EV certificate (high trust)");
                }
*/
            }
        }

        if (multiple && expired) {
            score += 4;
            result.warnings.push_back("Multiple signatures present with at least one expired or self-signed certificate (possible signature hijacking)");
            result.info.push_back("Added 4 points for multiple signature with issues");
        }
    } else {
        if (isDriver) {
            score += 20;
            result.warnings.push_back("No digital signature block found - 64-bit Windows will not load this driver");
            result.info.push_back("Added 20 points for missing driver signature");
        } else {
            result.info.push_back("No digital signature block found");
        }
    }
/*
    // 
    //路径上下文加权（对驱动调整）
    // 
    // 现代安全缓解措施联合检测 (CFG && RFG) -> 减分 20%
    {
        bool hasCFG = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        bool hasRFG = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_RF) != 0;
        if (hasCFG && hasRFG) {
            int oldScore = score;
            score = (int)(score * 0.8);
            result.info.push_back("CFG and RFG both enabled, score reduced by 20% from " + std::to_string(oldScore) + " to " + std::to_string(score));
        }
    }

    // 路径加权：先提取路径信息
    std::wstring dir = filePath;
    size_t pos = dir.find_last_of(L'\\');
    if (pos != std::wstring::npos) {
        dir = dir.substr(0, pos);
    } else {
        dir = L"";
    }
    std::wstring dirLower = dir;
    std::transform(dirLower.begin(), dirLower.end(), dirLower.begin(), ::towlower);
    std::wstring fileLower = filePath;
    std::transform(fileLower.begin(), fileLower.end(), fileLower.begin(), ::towlower);

    bool isSystemDir = false;
    bool isSystem32 = false;
    bool isSysWOW64 = false;
    // 检测系统目录
    if (dirLower.find(L"c:\\windows\\system32") == 0) {
        isSystemDir = true;
        isSystem32 = true;
    } else if (dirLower.find(L"c:\\windows\\syswow64") == 0) {
        isSystemDir = true;
        isSysWOW64 = true;
    } else if (dirLower.find(L"c:\\windows\\system32\\drivers") == 0) {
        isSystemDir = true;
        isSystem32 = true;
    }

    bool isTemp = false;
    bool isDownloads = false;
    bool isAppDataLocal = false;
    // 检测临时目录
    if (dirLower.find(L"\\temp") != std::wstring::npos ||
        dirLower.find(L"\\tmp") != std::wstring::npos) {
        isTemp = true;
    }
    if (dirLower.find(L"\\downloads") != std::wstring::npos) {
        isDownloads = true;
    }
    if (dirLower.find(L"\\appdata\\local") != std::wstring::npos ||
        dirLower.find(L"\\appdata\\locallow") != std::wstring::npos) {
        isAppDataLocal = true;
    }

    bool isUserDir = false;
    if (!isSystemDir) {
        wchar_t envBuf[MAX_PATH];
        DWORD len;
        std::wstring userDirs[3];
        len = GetEnvironmentVariableW(L"APPDATA", envBuf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) userDirs[0] = envBuf;
        len = GetEnvironmentVariableW(L"TEMP", envBuf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) userDirs[1] = envBuf;
        len = GetEnvironmentVariableW(L"USERPROFILE", envBuf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) userDirs[2] = envBuf;

        for (const auto& ud : userDirs) {
            if (!ud.empty()) {
                std::wstring udLower = ud;
                std::transform(udLower.begin(), udLower.end(), udLower.begin(), ::towlower);
                if (dirLower.find(udLower) == 0) {
                    isUserDir = true;
                    break;
                }
            }
        }
    }

    bool hasValidSig = result.hasSignature && result.certValid && result.hasSig;
    bool isMicrosoftSigner = false;
    if (hasValidSig) {
        std::wstring lowerIssuer = issuerCN;
        std::transform(lowerIssuer.begin(), lowerIssuer.end(), lowerIssuer.begin(), ::towlower);
        if (lowerIssuer.find(L"microsoft code signing pca") != std::wstring::npos ||
            lowerIssuer.find(L"microsoft root authority") != std::wstring::npos ||
            lowerIssuer.find(L"microsoft corporation") != std::wstring::npos) {
            isMicrosoftSigner = true;
        }
    }

    // 应用路径加权
    if (isSystemDir && isMicrosoftSigner) {
        // 系统目录且有微软签名 -> 乘以0.5
        int oldScore = score;
        score = (int)(score * 0.5);
        result.info.push_back("Path context: System directory with valid Microsoft signature, score reduced from " + std::to_string(oldScore) + " to " + std::to_string(score) + " (*0.5)");
    } else if (isSystemDir) {
        // 系统目录但无微软签名 -> 原有调整 (0.8/0.7)
        if (isDriver) {
            int oldScore = score;
            score = (int)(score * 0.7);
            result.info.push_back("Path context: System driver directory without Microsoft signature, score reduced from " + std::to_string(oldScore) + " to " + std::to_string(score) + " (*0.7)");
        } else {
            int oldScore = score;
            score = (int)(score * 0.8);
            result.info.push_back("Path context: System directory without Microsoft signature, score reduced from " + std::to_string(oldScore) + " to " + std::to_string(score) + " (*0.8)");
        }
    } else if ((isTemp || isDownloads || isAppDataLocal) && !hasValidSig) {
        // 临时/下载/AppData且无有效签名 -> 乘以1.5
        int oldScore = score;
        score = (int)(score * 1.5);
        std::string loc;
        if (isTemp) loc = "Temp";
        else if (isDownloads) loc = "Downloads";
        else if (isAppDataLocal) loc = "AppData\\Local";
        result.info.push_back("Path context: " + loc + " directory with no valid signature, score increased from " + std::to_string(oldScore) + " to " + std::to_string(score) + " (*1.5)");
    } else if (isUserDir && !hasValidSig) {
        // 其他用户目录无签名 -> 原有加分（与之前保持一致）
        if (isDriver) {
            score += 8;
            result.info.push_back("Path context: User directory with unsigned driver, added 8 points");
        } else {
            score += 5;
            result.info.push_back("Path context: User directory with no valid signature, added 5 points");
        }
    } else {
        result.info.push_back("Path context: No adjustment applied");
    }
*/
     //最终赋值
    scan_rootkit_indicators(base, baseSize, sections, importedDlls, importedApisSet,
                        score, result.warnings, result.info);
    result.score = score;
    return true;
}

//  主函数
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <PE_file>" << std::endl;
        return 1;
    }

    //  解析 UI 选项（原逻辑） 
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

    //  检测 --XML 参数（必须为第4个参数） 
    bool writeXML = false;
    if (argc >= 4 && strcmp(argv[3], "--XML") == 0) {
        writeXML = true;
    }

    strcpy(filepath, argv[1]);
    std::string filePathA(argv[1]);
    int len = MultiByteToWideChar(CP_ACP, 0, filePathA.c_str(), -1, NULL, 0);
    std::wstring filePathW(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, filePathA.c_str(), -1, &filePathW[0], len);
    filePathW.pop_back();

    HANDLE hFile = CreateFileW(filePathW.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Cannot open file: " << argv[1] << std::endl;
        return 1;
    }
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        std::cerr << "Invalid file size" << std::endl;
        CloseHandle(hFile);
        return 1;
    }
    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        std::cerr << "ReadFile failed" << std::endl;
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    AnalysisResult result;
    if (!AnalyzePE(buffer.data(), buffer.size(), filePathW, result)) {
        std::cerr << "Analysis failed" << std::endl;
        return 1;
    }

    std::cout << "\n= Analysis Report =" << std::endl;
    for (const auto& info : result.info) std::cout << "[*] " << info << std::endl;
    for (const auto& warn : result.warnings) std::cout << "[!] " << warn << std::endl;

    if (result.dynamicCallCount > 0) {
        std::cout << "\n[+] Dynamic Control Flow Anomalies: " << result.dynamicCallCount << " abnormal call(s) detected." << std::endl;
        for (const auto& detail : result.abnormalCalls) {
            std::cout << "    " << detail << std::endl;
        }
    }

    std::cout << "\n Signature Details " << std::endl;
    std::cout << "  Has signature block: " << (result.hasSignature ? "Yes" : "No") << std::endl;
    if (result.hasSignature) {
        std::wcout << L"  Issuer: " << result.issuerName << std::endl;
        std::cout << "  Certificate valid: " << (result.certValid ? "Yes" : "No") << std::endl;
        std::cout << "  Self-signed: " << (result.isSelfSigned ? "Yes" : "No") << std::endl;
    }

    std::cout << "\nTotal score: " << result.score << std::endl;
    std::cout << "Risk level: ";
    if (result.score >= 80) std::cout << "HIGH";
    else if (result.score >= 60) std::cout << "MEDIUM";
    else if (result.score >= 40) std::cout << "SAFE";
    else std::cout << "LOW";
    std::cout << std::endl;

    if (result.score >= 80) std::cout << ">>> The file is LIKELY MALICIOUS." << std::endl;
    else if (result.score >= 60) std::cout << ">>> The file is SUSPICIOUS, further analysis recommended." << std::endl;
    else std::cout << ">>> The file appears BENIGN (no strong indicators)." << std::endl;

    //  管道通信（原逻辑） 
    if (result.score >= 90) {
        std::wstring cmd = L"cmd /c del /f /q /a \"" + filePathW + L"\"";
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            std::wcout << L"File deleted due to high risk score (" << result.score << L")" << std::endl;
        } else {
            std::wcerr << L"Failed to delete file (error " << GetLastError() << L")" << std::endl;
        }
    }

    return 0;
}