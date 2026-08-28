/*
SystemService.cpp
端点层

监控系统服务修改，报告无微软有效签名的服务

g++编译:
cd %g++Path%
g++ -fdiagnostics-color=always -g "%SourceCodePath%\systemservice.cpp" -o "%ExecutablePath%\SystemService.exe" -lwbemuuid -lole32 -loleaut32 -lws2_32 -ladvapi32 -mwindows -lwintrust -lcrypt32

运行权限：管理员权限
*/
#define UNICODE
#define _UNICODE
#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <fstream>
#include "nlohmann/json.hpp"
#include <filesystem>
#include <thread>
#include <chrono>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <atomic>
#include <winternl.h>
#include "shutdown_handler.h"

// 签名校验所需头文件
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <cryptuiapi.h>

using json = nlohmann::json;
namespace fs = std::filesystem;

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wintrust.lib")   // WinVerifyTrust
#pragma comment(lib, "crypt32.lib")    // 证书操作

#define PIPE_FROM_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_FROM_CONTROLCENTER_BY_SystemService"
#define PIPE_TO_CONTROLCENTER_NAME L"\\\\.\\pipe\\Pipe_TO_CONTROLCENTER_BY_SystemService"

#pragma pack(push, 1)
struct MessagetoControlCenter_by_SystemService {
    char type[256];
    wchar_t serviceName[512];
    wchar_t displayName[512];
    wchar_t binaryPath[512];
    DWORD currentState;
};
#pragma pack(pop)

#define PIPE_MESSAGE_SIZE sizeof(MessagetoControlCenter_by_SystemService)

struct CommandFromUser_UI {
    int command;   // 1 = 退出
};

// 全局控制变量
std::atomic<bool> g_bExitControl{false};
HANDLE g_hExitEvent = nullptr;

bool isFirstRun = false;

//  UTF-8 与宽字符转换 
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

//  服务信息结构 
struct ServiceInfo {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring binaryPath;
    DWORD currentState;
    std::wstring startMode;
};

//  JSON 序列化 
namespace nlohmann {
    template<>
    struct adl_serializer<ServiceInfo> {
        static void to_json(json& j, const ServiceInfo& info) {
            j = json{
                {"serviceName", wstring_to_utf8(info.serviceName)},
                {"displayName", wstring_to_utf8(info.displayName)},
                {"binaryPath", wstring_to_utf8(info.binaryPath)},
                {"currentState", info.currentState}
            };
        }

        static void from_json(const json& j, ServiceInfo& info) {
            info.serviceName = utf8_to_wstring(j.at("serviceName").get<std::string>());
            info.displayName = utf8_to_wstring(j.at("displayName").get<std::string>());
            info.binaryPath = utf8_to_wstring(j.at("binaryPath").get<std::string>());
            info.currentState = j.at("currentState").get<DWORD>();
        }
    };
}

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

//  状态描述 
std::wstring GetStateDescription(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED:          return L"已停止";
        case SERVICE_START_PENDING:    return L"启动中";
        case SERVICE_STOP_PENDING:     return L"停止中";
        case SERVICE_RUNNING:          return L"运行中";
        case SERVICE_CONTINUE_PENDING: return L"正在继续";
        case SERVICE_PAUSE_PENDING:    return L"暂停中";
        case SERVICE_PAUSED:           return L"已暂停";
        default:                       return L"未知状态";
    }
}

//  文件名消毒 
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

//  从服务镜像路径中提取可执行文件路径（去除参数、展开环境变量） 
std::wstring ExtractExecutablePath(const std::wstring& serviceImagePath) {
    if (serviceImagePath.empty()) return L"";

    std::wstring path = serviceImagePath;

    // 1. 处理引号：如果以双引号开头，取第一个和第二个引号之间的内容
    size_t start = 0;
    if (path.front() == L'"') {
        start = 1;
        size_t end = path.find(L'"', start);
        if (end != std::wstring::npos) {
            path = path.substr(start, end - start);
        } else {
            // 格式错误，尝试去除首引号
            path = path.substr(1);
        }
    } else {
        // 2. 无引号：截取到第一个空格（参数分隔）
        size_t spacePos = path.find(L' ');
        if (spacePos != std::wstring::npos) {
            path = path.substr(0, spacePos);
        }
    }

    // 3. 展开环境变量（如 %SystemRoot%）
    wchar_t expanded[MAX_PATH * 2] = {0};
    DWORD len = ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH * 2);
    if (len > 0 && len <= MAX_PATH * 2) {
        path = expanded;
    }

    return path;
}

//  验证文件是否具有微软有效数字签名 
bool IsMicrosoftSigned(const std::wstring& filePath) {
    if (filePath.empty()) return false;

    // 提取真实可执行路径（保留原有逻辑）
    std::wstring exePath = ExtractExecutablePath(filePath);
    if (exePath.empty() || !fs::exists(exePath)) {
        return false;
    }

    // 调用 GetSignatureStatus 获取完整签名状态
    std::wstring subjectCN, issuerCN;
    bool expired = false, selfSigned = false, multiple = false;
    int signerCount = 0;
    time_t notBefore = 0, notAfter = 0;
    bool nameSpoofed = false;
    bool revocationCheckFailed = false;
    bool isEV = false;
    bool timeStampWarning = false;

    bool valid = GetSignatureStatus(exePath,
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

//  管道连接 
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

//  同步发送（枚举上报） 
void ClientThread_to_ControlCenter(MessagetoControlCenter_by_SystemService* msg) {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Process SystemService: Always failed to connect to pipe, exiting send thread" << std::endl;
        return;
    }

    DWORD bytesWritten;
    if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
        std::cerr << "Process A: Failed to send message" << std::endl;
    }
    CloseHandle(hPipe);
}

//  异步发送线程 
void SendEventThread(MessagetoControlCenter_by_SystemService* msg) {
    SetConsoleOutputCP(CP_ACP);
    SetConsoleCP(CP_ACP);

    HANDLE hPipe = ConnectToPipe(PIPE_TO_CONTROLCENTER_NAME);
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        if (!WriteFile(hPipe, msg, PIPE_MESSAGE_SIZE, &bytesWritten, NULL) || bytesWritten != PIPE_MESSAGE_SIZE) {
            std::cerr << "Event send: Failed to write pipe" << std::endl;
        }
        CloseHandle(hPipe);
    }
    delete msg;
}

void SendServiceEventAsync(const MessagetoControlCenter_by_SystemService* msg) {
    MessagetoControlCenter_by_SystemService* copy = new MessagetoControlCenter_by_SystemService;
    memcpy(copy, msg, PIPE_MESSAGE_SIZE);
    std::thread t(SendEventThread, copy);
    t.detach();
}

void ControlThreadFunc() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (!g_bExitControl.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_FROM_CONTROLCENTER_NAME,          // 已定义的管道名
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(CommandFromUser_UI),
            sizeof(CommandFromUser_UI),
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateNamedPipe failed, error: " << GetLastError() << std::endl;
            // 严重错误时短暂休眠后重试
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }

        std::wcout << L"控制客户端已连接" << std::endl;

        CommandFromUser_UI msg;
        DWORD bytesRead;
        while (ReadFile(hPipe, &msg, sizeof(msg), &bytesRead, NULL) && bytesRead == sizeof(msg)) {
            if (msg.command == 1) {   // 退出命令
                std::wcout << L"收到退出命令，正在关闭程序..." << std::endl;
                g_bExitControl.store(true);
                if (g_hExitEvent) {
                    SetEvent(g_hExitEvent);   // 唤醒主循环
                }
                // 断开并关闭管道，使 ReadFile 退出
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

//  上报事件（仅当无微软签名） 
void ReportServiceEventIfNotMicrosoft(const ServiceInfo& info, const std::wstring& eventType) {
    // 检查二进制文件是否具有微软有效签名
    if (IsMicrosoftSigned(info.binaryPath)) {
        // 有微软签名，跳过上报
        wprintf(L"[跳过] 服务 %s 具有微软签名，不触发上报\n", info.serviceName.c_str());
        return;
    }

    // 无微软签名，构造消息并上报
    MessagetoControlCenter_by_SystemService msg = {};
    std::string typeStr = wstring_to_utf8(eventType);
    strncpy_s(msg.type, typeStr.c_str(), _TRUNCATE);
    wcsncpy_s(msg.serviceName, info.serviceName.c_str(), _TRUNCATE);
    wcsncpy_s(msg.displayName, info.displayName.c_str(), _TRUNCATE);
    wcsncpy_s(msg.binaryPath, info.binaryPath.c_str(), _TRUNCATE);
    msg.currentState = info.currentState;
    SendServiceEventAsync(&msg);
}

//  检查已知服务（用于首次枚举） 
bool IS_KNOWN_SERVICE(const fs::path& filepath, const ServiceInfo& info) {
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

        ServiceInfo configIn = j2.get<ServiceInfo>();
        return (info.serviceName == configIn.serviceName &&
                info.displayName  == configIn.displayName &&
                info.binaryPath   == configIn.binaryPath );
    }
    return false;
}

//  枚举所有服务（返回向量） 
std::vector<ServiceInfo> EnumerateServices() {
    std::vector<ServiceInfo> services;
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        wprintf(L"OpenSCManager 失败，错误码: %lu\n", GetLastError());
        return services;
    }

    DWORD dwBytesNeeded = 0, dwServicesReturned = 0, dwResumeHandle = 0;
    EnumServicesStatusEx(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_TYPE_ALL,
        SERVICE_STATE_ALL,
        NULL, 0,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL
    );
    if (dwBytesNeeded == 0) {
        CloseServiceHandle(hSCManager);
        return services;
    }

    std::vector<BYTE> buffer(dwBytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESS pServices =
        reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESS>(buffer.data());

    if (!EnumServicesStatusEx(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_TYPE_ALL,
        SERVICE_STATE_ALL,
        buffer.data(),
        dwBytesNeeded,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL
    )) {
        CloseServiceHandle(hSCManager);
        return services;
    }

    for (DWORD i = 0; i < dwServicesReturned; ++i) {
        const auto& status = pServices[i];
        ServiceInfo info;
        info.serviceName = status.lpServiceName;
        info.displayName = status.lpDisplayName ? status.lpDisplayName : L"";
        info.currentState = status.ServiceStatusProcess.dwCurrentState;
        info.startMode = L"";

        SC_HANDLE hService = OpenService(hSCManager, status.lpServiceName, SERVICE_QUERY_CONFIG);
        if (hService == NULL) {
            info.binaryPath = L"<无法打开服务>";
        } else {
            DWORD dwConfigBytes = 0;
            QueryServiceConfig(hService, NULL, 0, &dwConfigBytes);
            if (dwConfigBytes == 0) {
                info.binaryPath = L"<无法获取配置大小>";
            } else {
                std::vector<BYTE> configBuffer(dwConfigBytes);
                LPQUERY_SERVICE_CONFIG pConfig =
                    reinterpret_cast<LPQUERY_SERVICE_CONFIG>(configBuffer.data());
                if (QueryServiceConfig(hService, pConfig, dwConfigBytes, &dwConfigBytes)) {
                    info.binaryPath = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"<空路径>";
                } else {
                    info.binaryPath = L"<查询配置失败>";
                }
            }
            CloseServiceHandle(hService);
        }
        services.push_back(info);
    }

    CloseServiceHandle(hSCManager);
    return services;
}

//  检测服务变化 
void DetectServiceChanges(const std::vector<ServiceInfo>& oldList,
                          const std::vector<ServiceInfo>& newList,
                          std::vector<ServiceInfo>& created,
                          std::vector<ServiceInfo>& deleted,
                          std::vector<std::pair<ServiceInfo, ServiceInfo>>& modified) {
    std::map<std::wstring, ServiceInfo> oldMap;
    for (const auto& s : oldList) {
        oldMap[s.serviceName] = s;
    }
    std::map<std::wstring, ServiceInfo> newMap;
    for (const auto& s : newList) {
        newMap[s.serviceName] = s;
    }

    for (const auto& pair : newMap) {
        if (oldMap.find(pair.first) == oldMap.end()) {
            created.push_back(pair.second);
        }
    }

    for (const auto& pair : oldMap) {
        if (newMap.find(pair.first) == newMap.end()) {
            deleted.push_back(pair.second);
        }
    }

    for (const auto& pair : newMap) {
        auto itOld = oldMap.find(pair.first);
        if (itOld != oldMap.end()) {
            const ServiceInfo& oldInfo = itOld->second;
            const ServiceInfo& newInfo = pair.second;
            if (oldInfo.serviceName != newInfo.serviceName ||
                oldInfo.binaryPath != newInfo.binaryPath) {
                modified.push_back(std::make_pair(oldInfo, newInfo));
            }
        }
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

//  轮询间隔（毫秒） 
const int POLL_INTERVAL_MS = 2000;

//  主函数 
int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    EnableDebugPrivilege();
    SetProcessCritical(true);
    SetProcessShutdownParameters(0x100, 0);
    InstallShutdownHandler();
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    g_hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hExitEvent) {
        wprintf(L"创建退出事件失败\n");
        SetProcessCritical(false);
        return 1;
    }
    std::thread controlThread(ControlThreadFunc);
    controlThread.detach();

    //  创建配置目录 
    fs::path configDir = L"./system_service_config";
    if (!fs::is_directory(configDir)) {
        if (!fs::create_directories(configDir)) {
            wprintf(L"目录创建失败: %s\n", configDir.c_str());
            SetProcessCritical(false);
            return 1;
        }
    }
    isFirstRun = fs::is_empty(configDir);
    //  首次枚举并上报所有“新”服务 
    std::vector<ServiceInfo> currentServices = EnumerateServices();
    if (currentServices.empty()) {
        wprintf(L"未获取到任何服务，请确保以管理员身份运行。\n");
        _wsystem(L"pause");
        SetProcessCritical(false);
        return 1;
    }

    wprintf(L"首次枚举到 %zu 个服务。\n", currentServices.size());

    for (const auto& info : currentServices) {
        std::wstring safeName = sanitize_filename(info.serviceName);
        fs::path outfilename = configDir / (safeName + L".json");

        if (!IS_KNOWN_SERVICE(outfilename, info)) {
            // 写入 JSON 配置
            json j = info;
            std::ofstream outFile(outfilename);
            if (outFile.is_open()) {
                outFile << j.dump(4) << std::endl;
                outFile.close();
            }
            // 【修改】仅当非首次运行且无微软签名时才上报
            if (!isFirstRun) {
                // 这里使用新的上报函数，内部会校验签名
                ReportServiceEventIfNotMicrosoft(info, L"SystemService");
            }
        }
    }

    //  轮询监控 
    wprintf(L"开始轮询监控服务变化（间隔 %d 毫秒），按 Ctrl+C 退出。\n", POLL_INTERVAL_MS);

    while (!g_bExitControl.load()) {
        DWORD waitResult = WaitForSingleObject(g_hExitEvent, POLL_INTERVAL_MS);
        if (waitResult == WAIT_OBJECT_0) {
            // 收到退出事件，立即退出循环
            break;
        }

        std::vector<ServiceInfo> newServices = EnumerateServices();
        if (newServices.empty()) {
            wprintf(L"警告：轮询枚举服务失败，跳过本次检查。\n");
            continue;
        }

        std::vector<ServiceInfo> created, deleted;
        std::vector<std::pair<ServiceInfo, ServiceInfo>> modified;

        DetectServiceChanges(currentServices, newServices, created, deleted, modified);

        // 【修改】上报创建（仅无微软签名）
        for (const auto& info : created) {
            ReportServiceEventIfNotMicrosoft(info, L"Created");
            wprintf(L"[轮询] 服务 %s 被创建\n", info.serviceName.c_str());
        }

        // 【修改】上报删除
        for (const auto& info : deleted) {
            ReportServiceEventIfNotMicrosoft(info, L"Deleted");
            wprintf(L"[轮询] 服务 %s 被删除\n", info.serviceName.c_str());
        }

        // 【修改】上报修改
        for (const auto& pair : modified) {
            const ServiceInfo& newInfo = pair.second;
            ReportServiceEventIfNotMicrosoft(newInfo, L"Modified");
            wprintf(L"[轮询] 服务 %s 状态/路径发生变化\n", newInfo.serviceName.c_str());
        }

        currentServices = std::move(newServices);
    }

    SetProcessCritical(false);

    if (g_hExitEvent) {
        CloseHandle(g_hExitEvent);
        g_hExitEvent = nullptr;
    }

    return 0;
}