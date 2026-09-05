/*
TaskScheduler.cpp
端点层

监控任务计划修改，报告无微软有效签名的任务

g++编译:
cd %g++Path%
g++.exe -std=c++17 -fdiagnostics-color=always -g "%SourceCodePath%\TaskScheduler.cpp" -o "%ExecutablePath%\TaskScheduler.exe" -lole32 -loleaut32 -luuid -ltaskschd -lwintrust -lcrypt32 -mwindows

运行权限：管理员权限
*/
#define UNICODE
#define _UNICODE
#define _WIN32_DCOM
#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <taskschd.h>
#include <iostream>
#include <fcntl.h>
#include <io.h>
#include <fstream>
#include <string>
#include <vector>
#include "nlohmann/json.hpp"
#include <filesystem>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <wchar.h>          // for _wcsicmp
// 签名校验所需头文件
#include <wintrust.h>
#include <softpub.h>
#include <cryptuiapi.h>
#include <wincrypt.h> 
#include <atomic>
#include <winternl.h>
#include "shutdown_handler.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

#pragma comment(lib, "taskschd.lib")   // 任务计划程序 API
#pragma comment(lib, "wintrust.lib")   // WinVerifyTrust
#pragma comment(lib, "crypt32.lib")    // CryptQueryObject

#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_TaskScheduler"
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_TaskScheduler"

#pragma pack(push, 1)
struct MessagetoControlCenter_by_TaskScheduler {
    char type[256];
    wchar_t taskName[512];
    wchar_t taskPath[512];
    int taskEnabled;
};
#pragma pack(pop)

#define PIPE_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_TaskScheduler)

struct CommandFromUser_UI {
    int command;   // 1 = 退出
};

std::atomic<bool> g_bExit{false};
HANDLE g_hExitEvent = nullptr;

bool isFirstRun = false;

//  辅助函数 

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

static time_t FileTimeToUnixTime(const FILETIME& ft) {
    ULARGE_INTEGER ul;
    ul.LowPart  = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    const uint64_t EPOCH_DIFFERENCE = 116444736000000000ULL;
    uint64_t seconds = (ul.QuadPart - EPOCH_DIFFERENCE) / 10000000;
    return static_cast<time_t>(seconds);
}

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
    // 初始化输出参数
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
    wvtData.fdwRevocationChecks = WTD_REVOKE_NONE;     // 不主动检查吊销（后续通过证书链检查）
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
    // 关闭状态
    wvtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &wvtData);

    bool valid = (trustStatus == ERROR_SUCCESS);

    // 提取证书详细信息
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

            // 自签名检测
            wchar_t issuerBuf[256] = {0}, subjectBuf[256] = {0};
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               CERT_NAME_ISSUER_FLAG, NULL, issuerBuf, 256);
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0, NULL, subjectBuf, 256);
            if (wcscmp(issuerBuf, subjectBuf) == 0) {
                outSelfSigned = true;
            }

            // 名称欺骗检测（空字节截断）
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

            // 证书链检查（吊销、有效期等）
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

                // EV 检测（OID 或 Issuer 关键字）
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

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

bool wstring_icase_equal(const std::wstring& a, const std::wstring& b) {
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
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
        } else if (err == ERROR_PIPE_BUSY) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        } else {
            std::cerr << "Connecting to pipe encountered an unknown error, code: " << err << std::endl;
            return INVALID_HANDLE_VALUE;
        }
    }
}

void ClientThread_to_ControlCenter(MessagetoControlCenter_by_TaskScheduler* msg) 
{
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Process TaskScheduler: Always failed to connect to pipe, exiting send thread" << std::endl;
        return;
    }

    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
        std::cerr << "Process TaskScheduler: Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}

//  控制接口线程：接收退出命令 
void ServerThread_from_User_UI() {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    while (!g_bExit.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_FROM_CONTROLCENTER_NAME,      // 已定义
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(CommandFromUser_UI),
            sizeof(CommandFromUser_UI),
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::wcerr << L"CreateNamedPipe failed, error: " << GetLastError() << std::endl;
            break;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::wcerr << L"ConnectNamedPipe failed, error: " << GetLastError() << std::endl;
            CloseHandle(hPipe);
            continue;
        }

        std::wcout << L"Control client connected." << std::endl;

        CommandFromUser_UI msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            if (msg.command == 1) {   // 退出命令
                std::wcout << L"Received exit command, shutting down..." << std::endl;
                g_bExit.store(true);
                if (g_hExitEvent) SetEvent(g_hExitEvent);
                // 断开并关闭管道，使 ReadFile 返回失败，跳出内层循环
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

static const wchar_t* GetStateString(TASK_STATE state) {
    switch (state) {
        case TASK_STATE_UNKNOWN:    return L"未知";
        case TASK_STATE_DISABLED:   return L"已禁用";
        case TASK_STATE_QUEUED:     return L"排队中";
        case TASK_STATE_READY:      return L"就绪";
        case TASK_STATE_RUNNING:    return L"运行中";
        default:                    return L"其他";
    }
}

//任务信息结构 
struct TasksInfo {
    std::wstring taskname;
    std::wstring taskpath;
    TASK_STATE taskstate;
    bool taskenabled;
    std::wstring xmlContent;          // 保留但不用于比较
    std::vector<std::wstring> exePaths; // 所有可执行文件完整路径
};

//  JSON 序列化特化
namespace nlohmann {
    template<>
    struct adl_serializer<TasksInfo> {
        static void to_json(json& j, const TasksInfo& t) {
            // 将所有宽字符串转为 UTF-8 标准字符串
            std::vector<std::string> utf8ExePaths;
            utf8ExePaths.reserve(t.exePaths.size());
            for (const auto& wpath : t.exePaths) {
                utf8ExePaths.push_back(wstring_to_utf8(wpath));
            }

            j = json{
                {"taskname", wstring_to_utf8(t.taskname)},
                {"taskpath", wstring_to_utf8(t.taskpath)},
                {"taskstate", t.taskstate},
                {"taskenabled", t.taskenabled},
                {"exePaths", utf8ExePaths}
            };
        }

        static void from_json(const json& j, TasksInfo& t) {
            // 安全读取每个字段，类型不符则赋予默认值
            if (j.contains("taskname") && j["taskname"].is_string()) {
                t.taskname = utf8_to_wstring(j["taskname"].get<std::string>());
            } else {
                t.taskname = L"";
            }

            if (j.contains("taskpath") && j["taskpath"].is_string()) {
                t.taskpath = utf8_to_wstring(j["taskpath"].get<std::string>());
            } else {
                t.taskpath = L"";
            }

            if (j.contains("taskstate") && j["taskstate"].is_number_integer()) {
                t.taskstate = j["taskstate"].get<TASK_STATE>();
            } else {
                t.taskstate = TASK_STATE_UNKNOWN;
            }

            if (j.contains("taskenabled") && j["taskenabled"].is_boolean()) {
                t.taskenabled = j["taskenabled"].get<bool>();
            } else {
                t.taskenabled = false;
            }

            // exePaths 应为字符串数组
            t.exePaths.clear();
            if (j.contains("exePaths") && j["exePaths"].is_array()) {
                for (const auto& item : j["exePaths"]) {
                    if (item.is_string()) {
                        t.exePaths.push_back(utf8_to_wstring(item.get<std::string>()));
                    }
                }
            }
        }
    };
} 

//  保留原有函数 
std::wstring sanitize_filename(const std::wstring& name) {
    std::wstring result = name;
    for (auto& ch : result) {
        if (ch == L'/' || ch == L'\\' || ch == L':' || ch == L'*' || ch == L'?' ||
            ch == L'"' || ch == L'<' || ch == L'>' || ch == L'|') {
            ch = L'_';
        }
    }
    return result;
}

bool IS_KNOWN_TASKS(const fs::path& filepath, const TasksInfo& info) {
    if (fs::exists(filepath)) {
        std::ifstream inFile(filepath);
        if (!inFile.is_open()) {
            std::wcerr << L"无法打开文件进行读取!" << std::endl;
            return false;
        }
        json j2;
        try {
            inFile >> j2;
        } catch (const json::parse_error& e) {
            std::wcerr << L"JSON解析错误: " << e.what() << std::endl;
            return false;
        }
        inFile.close();

        TasksInfo configIn = j2.get<TasksInfo>();
        return (wstring_icase_equal(info.taskname, configIn.taskname) &&
                wstring_icase_equal(info.taskpath, configIn.taskpath) &&
                info.taskenabled == configIn.taskenabled);
    }
    return false;
}

//  签名校验函数 
bool HasMicrosoftSignature(const std::wstring& filePath) {
    if (filePath.empty() || GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    std::wstring subjectCN, issuerCN;
    bool expired = false, selfSigned = false, multiple = false;
    int signerCount = 0;
    time_t notBefore = 0, notAfter = 0;
    bool nameSpoofed = false;
    bool revocationCheckFailed = false;
    bool isEV = false;
    bool timeStampWarning = false;

    bool valid = GetSignatureStatus(filePath,
                                    subjectCN,
                                    issuerCN,
                                    expired,
                                    selfSigned,
                                    multiple,
                                    signerCount,
                                    notBefore,
                                    notAfter,
                                    nameSpoofed,
                                    revocationCheckFailed,
                                    isEV,
                                    timeStampWarning);

    // 签名必须有效（WinVerifyTrust 通过且证书链可信）
    if (!valid) {
        return false;
    }

    // 检查主题或颁发者是否包含 "Microsoft"
    std::wstring lowerSubject = subjectCN;
    std::wstring lowerIssuer = issuerCN;
    std::transform(lowerSubject.begin(), lowerSubject.end(), lowerSubject.begin(), ::towlower);
    std::transform(lowerIssuer.begin(), lowerIssuer.end(), lowerIssuer.begin(), ::towlower);

    return (lowerSubject.find(L"microsoft") != std::wstring::npos ||
            lowerIssuer.find(L"microsoft") != std::wstring::npos);
}

bool AllExeHaveMicrosoftSignature(const std::vector<std::wstring>& exePaths) {
    if (exePaths.empty()) {
        return false;   // 无 EXE 文件时视为无签名，上报
    }
    for (const auto& path : exePaths) {
        if (!HasMicrosoftSignature(path)) {
            return false;
        }
    }
    return true;
}

//  全局缓存 
std::unordered_map<std::wstring, TasksInfo> g_taskCache;

//  递归枚举所有任务 
void CollectTasks(ITaskFolder* folder, std::vector<TasksInfo>& outTasks) {
    if (!folder) return;

    IRegisteredTaskCollection* pTasks = NULL;
    HRESULT hr = folder->GetTasks(0, &pTasks);
    if (SUCCEEDED(hr)) {
        LONG count = 0;
        pTasks->get_Count(&count);
        wprintf(L"=== 计划任务列表 (Scheduler 2.0) ===\n共 %d 个任务\n\n", count);

        for (LONG i = 1; i <= count; i++) {
            IRegisteredTask* pRegTask = NULL;
            VARIANT varIdx;
            VariantInit(&varIdx);
            varIdx.vt = VT_I4;
            varIdx.lVal = i;
            if (FAILED(pTasks->get_Item(varIdx, &pRegTask))) {
                VariantClear(&varIdx);
                continue;
            }
            VariantClear(&varIdx);

            TasksInfo taskInfo;
            BSTR name = NULL;
            if (SUCCEEDED(pRegTask->get_Name(&name))) {
                wprintf(L"任务名称: %S\n", name);
                taskInfo.taskname = name;
                SysFreeString(name);
            }

            BSTR path = NULL;
            if (SUCCEEDED(pRegTask->get_Path(&path))) {
                wprintf(L"  路径: %S\n", path);
                taskInfo.taskpath = path;
                SysFreeString(path);
            }

            TASK_STATE state;
            if (SUCCEEDED(pRegTask->get_State(&state))) {
                wprintf(L"  状态: %S\n", GetStateString(state));
                taskInfo.taskstate = state;
            }

            VARIANT_BOOL enabled;
            if (SUCCEEDED(pRegTask->get_Enabled(&enabled))) {
                wprintf(L"  启用: %S\n", enabled == VARIANT_TRUE ? L"是" : L"否");
                taskInfo.taskenabled = enabled == VARIANT_TRUE;
            }

            DATE lastRun;
            if (SUCCEEDED(pRegTask->get_LastRunTime(&lastRun))) {
                SYSTEMTIME st;
                if (VariantTimeToSystemTime(lastRun, &st)) {
                    wprintf(L"  上次运行: %04d-%02d-%02d %02d:%02d:%02d\n",
                            st.wYear, st.wMonth, st.wDay,
                            st.wHour, st.wMinute, st.wSecond);
                } else {
                    wprintf(L"  上次运行: (无法转换)\n");
                }
            }
            DATE nextRun;
            if (SUCCEEDED(pRegTask->get_NextRunTime(&nextRun))) {
                SYSTEMTIME st;
                if (VariantTimeToSystemTime(nextRun, &st)) {
                    wprintf(L"  下次运行: %04d-%02d-%02d %02d:%02d:%02d\n",
                            st.wYear, st.wMonth, st.wDay,
                            st.wHour, st.wMinute, st.wSecond);
                } else {
                    wprintf(L"  下次运行: (无法转换)\n");
                }
            }

            ITaskDefinition* pDef = NULL;
            if (SUCCEEDED(pRegTask->get_Definition(&pDef))) {
                ITriggerCollection* pTriggers = NULL;
                if (SUCCEEDED(pDef->get_Triggers(&pTriggers))) {
                    LONG trigCount = 0;
                    pTriggers->get_Count(&trigCount);
                    wprintf(L"  触发器数量: %d\n", trigCount);
                    for (LONG j = 1; j <= trigCount; j++) {
                        ITrigger* pTrig = NULL;
                        if (SUCCEEDED(pTriggers->get_Item(j, &pTrig))) {
                            TASK_TRIGGER_TYPE2 type;
                            if (SUCCEEDED(pTrig->get_Type(&type))) {
                                wprintf(L"    触发器 %d 类型: ", j);
                                switch (type) {
                                    case TASK_TRIGGER_EVENT:      wprintf(L"事件\n"); break;
                                    case TASK_TRIGGER_TIME:       wprintf(L"时间\n"); break;
                                    case TASK_TRIGGER_DAILY:      wprintf(L"每日\n"); break;
                                    case TASK_TRIGGER_WEEKLY:     wprintf(L"每周\n"); break;
                                    case TASK_TRIGGER_MONTHLY:    wprintf(L"每月\n"); break;
                                    case TASK_TRIGGER_MONTHLYDOW: wprintf(L"每月周\n"); break;
                                    case TASK_TRIGGER_IDLE:       wprintf(L"空闲\n"); break;
                                    case TASK_TRIGGER_REGISTRATION: wprintf(L"注册\n"); break;
                                    case TASK_TRIGGER_BOOT:       wprintf(L"启动\n"); break;
                                    case TASK_TRIGGER_LOGON:      wprintf(L"登录\n"); break;
                                    case TASK_TRIGGER_SESSION_STATE_CHANGE: wprintf(L"会话状态变化\n"); break;
                                    default: wprintf(L"未知 (%d)\n", type);
                                }
                            }
                            BSTR start = NULL;
                            if (SUCCEEDED(pTrig->get_StartBoundary(&start))) {
                                wprintf(L"      开始: %S\n", start);
                                SysFreeString(start);
                            }
                            pTrig->Release();
                        }
                    }
                    pTriggers->Release();
                }

                IActionCollection* pActions = NULL;
                if (SUCCEEDED(pDef->get_Actions(&pActions))) {
                    LONG actCount = 0;
                    pActions->get_Count(&actCount);
                    wprintf(L"  操作数量: %d\n", actCount);
                    for (LONG j = 1; j <= actCount; j++) {
                        IAction* pAction = NULL;
                        if (SUCCEEDED(pActions->get_Item(j, &pAction))) {
                            TASK_ACTION_TYPE actType;
                            if (SUCCEEDED(pAction->get_Type(&actType))) {
                                wprintf(L"    操作 %d 类型: ", j);
                                switch (actType) {
                                    case TASK_ACTION_EXEC:          wprintf(L"执行程序\n"); break;
                                    case TASK_ACTION_COM_HANDLER:   wprintf(L"COM 处理器\n"); break;
                                    case TASK_ACTION_SEND_EMAIL:    wprintf(L"发送邮件\n"); break;
                                    case TASK_ACTION_SHOW_MESSAGE:  wprintf(L"显示消息\n"); break;
                                    default: wprintf(L"未知\n");
                                }
                                if (actType == TASK_ACTION_EXEC) {
                                    IExecAction* pExec = NULL;
                                    if (SUCCEEDED(pAction->QueryInterface(__uuidof(IExecAction), (void**)&pExec))) {
                                        BSTR prog = NULL;
                                        if (SUCCEEDED(pExec->get_Path(&prog))) {
                                            wprintf(L"      程序: %S\n", prog);
                                            taskInfo.exePaths.push_back(prog);
                                            SysFreeString(prog);
                                        }
                                        pExec->Release();
                                    }
                                }
                            }
                            pAction->Release();
                        }
                    }
                    pActions->Release();
                }

                pDef->Release();
            }

            BSTR xml = NULL;
            if (SUCCEEDED(pRegTask->get_Xml(&xml))) {
                wprintf(L"  XML 定义: %S\n", xml);
                taskInfo.xmlContent = xml;
                SysFreeString(xml);
            }

            outTasks.push_back(taskInfo);
            pRegTask->Release();
            wprintf(L"\n");
        }
        pTasks->Release();
    }

    ITaskFolderCollection* pFolders = NULL;
    hr = folder->GetFolders(0, &pFolders);
    if (SUCCEEDED(hr)) {
        LONG folderCount = 0;
        pFolders->get_Count(&folderCount);
        for (LONG i = 1; i <= folderCount; i++) {
            ITaskFolder* pSubFolder = NULL;
            VARIANT varIdx;
            VariantInit(&varIdx);
            varIdx.vt = VT_I4;
            varIdx.lVal = i;
            if (SUCCEEDED(pFolders->get_Item(varIdx, &pSubFolder))) {
                CollectTasks(pSubFolder, outTasks);
                pSubFolder->Release();
            }
            VariantClear(&varIdx);
        }
        pFolders->Release();
    }
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_SHUTDOWN_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT) {
        // 在系统强制终止前，立即解除关键状态
        SetProcessCritical(false);
        return TRUE;
    }
    return FALSE;
}

//  主函数 
int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    _setmode(_fileno(stdout), _O_U16TEXT);

    EnableDebugPrivilege();
    SetProcessCritical(true);
    SetProcessShutdownParameters(0x100, 0);
    InstallShutdownHandler();
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    g_hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hExitEvent) {
        wprintf(L"Failed to create exit event.\n");
        SetProcessCritical(false);
        return 1;
    }

    // 启动控制接口线程（detach 让其在后台运行）
    std::thread controlThread(ServerThread_from_User_UI);
    controlThread.detach();

    fs::path configDir = L"./taskscheduler_config";
    if (fs::is_directory(configDir)) {
        wprintf(L"目录存在: %S\n", configDir.c_str());
    } else {
        wprintf(L"目录不存在，正在创建: %s\n", configDir.c_str());
        if (fs::create_directories(configDir)) {
            wprintf(L"目录创建成功: %s\n", configDir.c_str());
        } else {
            wprintf(L"目录创建失败: %s\n", configDir.c_str());
        }
    }
    isFirstRun = fs::is_empty(configDir);
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"CoInitializeEx failed: 0x%x\n", hr);
        SetProcessCritical(false);
        return 1;
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                              RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, 0, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        wprintf(L"CoInitializeSecurity failed: 0x%x\n", hr);
        CoUninitialize();
        SetProcessCritical(false);
        return 1;
    }

    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        wprintf(L"CoCreateInstance failed: 0x%x\n", hr);
        CoUninitialize();
        SetProcessCritical(false);
        return 1;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        wprintf(L"Connect failed: 0x%x\n", hr);
        pService->Release();
        CoUninitialize();
        SetProcessCritical(false);
        return 1;
    }

    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        wprintf(L"GetFolder failed: 0x%x\n", hr);
        pService->Release();
        CoUninitialize();
        SetProcessCritical(false);
        return 1;
    }

    while (!g_bExit.load()) {
        std::vector<TasksInfo> currentTasks;
        CollectTasks(pRootFolder, currentTasks);

        g_taskCache.clear();
        for (auto& entry : fs::directory_iterator(configDir)) {
            if (entry.path().extension() == L".json") {
                std::ifstream inFile(entry.path());
                if (inFile.is_open()) {
                    json j;
                    try {
                        inFile >> j;
                        TasksInfo info = j.get<TasksInfo>();
                        g_taskCache[info.taskpath] = info;
                    } catch (const std::exception& e) {
                        wprintf(L"加载 JSON 文件失败: %S, 错误: %S\n", entry.path().c_str(), e.what());
                        // 损坏的文件可考虑删除，下次重新生成
                    }
                    inFile.close();
                }
            }
        }

        // 检测删除
        std::vector<TasksInfo> deletedTasks;
        for (const auto& pair : g_taskCache) {
            bool found = false;
            for (const auto& cur : currentTasks) {
                if (wstring_icase_equal(pair.first, cur.taskpath)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                deletedTasks.push_back(pair.second);
            }
        }

        for (const auto& delInfo : deletedTasks) {
            fs::path jsonPath = configDir / (sanitize_filename(delInfo.taskname) + L".json");
            if (fs::exists(jsonPath)) {
                fs::remove(jsonPath);
                wprintf(L"删除JSON文件: %S\n", jsonPath.c_str());
            }
            bool hasMsSig = AllExeHaveMicrosoftSignature(delInfo.exePaths);
            if (!isFirstRun && !hasMsSig) {
                MessagetoControlCenter_by_TaskScheduler msg = {};
                lstrcpyA(msg.type, "TaskScheduler");
                lstrcpyW(msg.taskName, delInfo.taskname.c_str());
                lstrcpyW(msg.taskPath, delInfo.taskpath.c_str());
                msg.taskEnabled = delInfo.taskenabled ? 1 : 0;
                std::thread sendThread(ClientThread_to_ControlCenter, &msg);
                sendThread.join();
                wprintf(L"删除任务已上报（无微软签名）\n");
            } else {
                wprintf(L"删除任务未上报（有微软签名或首次运行）\n");
            }
        }

        // 检测新增或修改
        for (const auto& info : currentTasks) {
            bool found = false;
            TasksInfo cachedInfo;
            for (const auto& pair : g_taskCache) {
                if (wstring_icase_equal(pair.first, info.taskpath)) {
                    found = true;
                    cachedInfo = pair.second;
                    break;
                }
            }

            bool isNew = !found;
            bool isModified = false;
            if (!isNew) {
                if (!wstring_icase_equal(cachedInfo.taskname, info.taskname) ||
                    cachedInfo.taskenabled != info.taskenabled ||
                    cachedInfo.exePaths != info.exePaths) {
                    isModified = true;
                }
                if (!wstring_icase_equal(cachedInfo.taskpath, info.taskpath)) {
                    isModified = true;
                }
            }

            if (isNew || isModified) {
                fs::path outfilename = configDir / (sanitize_filename(info.taskname) + L".json");
                json j = info;
                std::ofstream outFile(outfilename);
                if (outFile.is_open()) {
                    outFile << j.dump(4) << std::endl;
                    outFile.close();
                    wprintf(L"JSON 文件写入成功: %S\n", outfilename.c_str());
                } else {
                    wprintf(L"无法打开文件进行写入: %S\n", outfilename.c_str());
                }

                bool hasMsSig = AllExeHaveMicrosoftSignature(info.exePaths);
                if (!isFirstRun && !hasMsSig) {
                    MessagetoControlCenter_by_TaskScheduler msg = {};
                    lstrcpyA(msg.type, "TaskScheduler");
                    lstrcpyW(msg.taskName, info.taskname.c_str());
                    lstrcpyW(msg.taskPath, info.taskpath.c_str());
                    msg.taskEnabled = info.taskenabled ? 1 : 0;
                    std::thread sendThread(ClientThread_to_ControlCenter, &msg);
                    sendThread.join();
                    wprintf(L"新增/修改任务已上报（无微软签名）\n");
                } else {
                    wprintf(L"新增/修改任务未上报（有微软签名或首次运行）\n");
                }
            }
        }

        wprintf(L"等待 30 秒后进行下一次扫描...\n");
        DWORD waitResult = WaitForSingleObject(g_hExitEvent, 30000);
        if (waitResult == WAIT_OBJECT_0) {
            // 事件被触发，退出循环
            wprintf(L"Exit event signaled, breaking loop.\n");
            SetProcessCritical(false);
            break;
        }
    }

    pRootFolder->Release();
    pService->Release();
    CoUninitialize();

    if (g_hExitEvent) {
        CloseHandle(g_hExitEvent);
        g_hExitEvent = nullptr;
    }
    return 0;
}