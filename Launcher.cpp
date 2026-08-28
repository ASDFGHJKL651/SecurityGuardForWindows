#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <iostream>
#include <shlwapi.h>        // 用于 PathRemoveFileSpec / PathAppend

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "shlwapi.lib")

bool CreateStartupTask(const wchar_t* taskName, const wchar_t* programPath, const wchar_t* workingDir = L"", const wchar_t* arguments = L"") {
    HRESULT hr;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    ITaskDefinition* pTask = NULL;
    IPrincipal* pPrincipal = NULL;
    ITriggerCollection* pTriggers = NULL;
    ITrigger* pTrigger = NULL;
    IActionCollection* pActions = NULL;
    IAction* pAction = NULL;
    IExecAction* pExecAction = NULL;

    // 1. 初始化 COM
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::cerr << "CoInitializeEx failed: " << hr << std::endl;
        return false;
    }

    // 2. 创建任务服务
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        std::cerr << "CoCreateInstance failed: " << hr << std::endl;
        CoUninitialize();
        return false;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        std::cerr << "ITaskService::Connect failed: " << hr << std::endl;
        pService->Release();
        CoUninitialize();
        return false;
    }

    // 3. 获取根任务文件夹
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        std::cerr << "ITaskService::GetFolder failed: " << hr << std::endl;
        pService->Release();
        CoUninitialize();
        return false;
    }

    // 4. 创建任务定义
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        std::cerr << "ITaskService::NewTask failed: " << hr << std::endl;
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return false;
    }

    // 5. 设置任务主体（以最高权限运行）
    hr = pTask->get_Principal(&pPrincipal);
    if (SUCCEEDED(hr)) {
        pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);   // 以管理员权限运行
        pPrincipal->Release();
    }

    // 6. 创建登录触发器（用户登录时触发）
    hr = pTask->get_Triggers(&pTriggers);
    if (SUCCEEDED(hr)) {
        hr = pTriggers->Create(TASK_TRIGGER_LOGON, &pTrigger);
        pTriggers->Release();
        if (FAILED(hr)) {
            std::cerr << "ITriggerCollection::Create failed: " << hr << std::endl;
        }
        if (pTrigger) pTrigger->Release();
    }

    // 7. 创建执行操作
    hr = pTask->get_Actions(&pActions);
    if (SUCCEEDED(hr)) {
        hr = pActions->Create(TASK_ACTION_EXEC, &pAction);
        pActions->Release();
        if (SUCCEEDED(hr)) {
            hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
            pAction->Release();
            if (SUCCEEDED(hr)) {
                // 设置要执行的程序路径和参数
                pExecAction->put_Path(_bstr_t(programPath));
                if (wcslen(arguments) > 0) {
                    pExecAction->put_Arguments(_bstr_t(arguments));
                }
                // 设置工作目录（防止相对路径失效）
                if (wcslen(workingDir) > 0) {
                    pExecAction->put_WorkingDirectory(_bstr_t(workingDir));
                }
                pExecAction->Release();
            }
        }
    }

    // 8. 注册任务
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(taskName),                     // 任务名称
        pTask,                                 // 任务定义
        TASK_CREATE_OR_UPDATE,                 // 如果存在则更新
        _variant_t(),                          // userId（空，使用当前用户）
        _variant_t(),                          // password（空）
        TASK_LOGON_INTERACTIVE_TOKEN,          // 登录类型
        _variant_t(),                          // sddl（空）
        NULL
    );

    // 清理资源
    if (pTask) pTask->Release();
    if (pRootFolder) pRootFolder->Release();
    if (pService) pService->Release();
    CoUninitialize();

    if (FAILED(hr)) {
        std::cerr << "ITaskFolder::RegisterTaskDefinition failed: " << hr << std::endl;
        return false;
    }

    std::wcout << L"Task '" << taskName << L"' created successfully." << std::endl;
    return true;
}

int main() {
    // 1. 获取当前 exe 所在目录（绝对路径）
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    PathRemoveFileSpec(exePath);                 // 去掉文件名，只留目录

    // 2. 拼接目标程序路径和工作目录
    wchar_t programPath[MAX_PATH];
    wcscpy_s(programPath, exePath);
    PathAppend(programPath, L"Verification.exe");

    // 3. 任务参数（可按需修改）
    const wchar_t* taskName = L"SecurityGuardStartupTask";;
    const wchar_t* arguments = L"";              // 如果需要参数，填写在这里

    // 4. 创建任务（工作目录设置为同一目录，确保相对路径操作正确）
    if (!CreateStartupTask(taskName, programPath, exePath, arguments)) {
        std::cerr << "Failed to create startup task." << std::endl;
        return 1;
    }

    return 0;
}
