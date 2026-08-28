/*
系统补丁
修复问题:被设置为系统关键进程的控制台程序,在系统广播CTRL_SHUTDOWN_EVENT,CTRL_LOGOFF_EVENT后无法在系统强制结束前解除系统关键进程状态,从而触发蓝屏
受影响组件:ControlCenter FileSystemMonitor MemoryGuard NetworkGuard RegistryMonitor SystemService TaskScheduler
修复方法:为被设置为系统关键进程的组件强行附加一个隐形窗口获取系统广播WM_QUERYENDSESSION,WM_ENDSESSION并解除系统关键进程状态以避免蓝屏
修复原理:系统会优先向所有GUI程序广播WM_QUERYENDSESSION,WM_ENDSESSION;向控制台程序广播CTRL_SHUTDOWN_EVENT,CTRL_LOGOFF_EVENT在向所有GUI程序广播之后,因此GUI程序有更多时间执行退出
*/
#pragma once

#include <windows.h>
#include <winternl.h>
#include <atomic>
#include <thread>

//  私有定义 
typedef NTSTATUS (NTAPI *RtlSetProcessIsCritical_t)(BOOLEAN, BOOLEAN*, BOOLEAN);

static RtlSetProcessIsCritical_t g_pRtlSetProcessIsCritical = nullptr;
static std::atomic<bool> g_shutdownRequested{false};

// 获取 RtlSetProcessIsCritical 函数指针
static bool InitCriticalFunction() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_pRtlSetProcessIsCritical = (RtlSetProcessIsCritical_t)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
    }
    return (g_pRtlSetProcessIsCritical != nullptr);
}

// 解除系统关键状态
static bool UnsetProcessCritical() {
    if (!g_pRtlSetProcessIsCritical) return false;
    NTSTATUS status = g_pRtlSetProcessIsCritical(FALSE, NULL, FALSE);
    return (status == 0);
}

//  隐藏窗口过程 
static LRESULT CALLBACK ShutdownWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_QUERYENDSESSION:
            // 系统即将关机，立即解除关键状态
            UnsetProcessCritical();
            g_shutdownRequested = true;
            return TRUE;    // 同意关机

        case WM_ENDSESSION:
            // 会话结束，清理后退出消息循环
            UnsetProcessCritical();
            g_shutdownRequested = true;
            PostQuitMessage(0);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

//  消息循环线程 
static DWORD WINAPI MessageLoopThread(LPVOID) {
    // 注册窗口类（显式使用宽字符版本）
    const wchar_t CLASS_NAME[] = L"ShutdownHandlerClass";
    WNDCLASSW wc = {};
    wc.lpfnWndProc = ShutdownWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = CLASS_NAME;
    RegisterClassW(&wc);   // 若已注册则忽略错误

    // 创建隐藏窗口（显式使用宽字符版本）
    HWND hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"ShutdownHandler",
        0,          // 无样式（完全隐藏）
        0, 0, 0, 0,
        NULL, NULL,
        wc.hInstance,
        NULL
    );

    if (!hwnd) {
        return 1;
    }

    // 消息循环
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // 收到 WM_QUIT，清理窗口
    DestroyWindow(hwnd);
    return 0;
}

//  对外接口 
static bool g_handlerInstalled = false;

// 安装关机处理器（线程独立，非阻塞）
void InstallShutdownHandler() {
    if (g_handlerInstalled) return;
    if (!InitCriticalFunction()) {
        // 无法获取 API（极少发生），可忽略
        return;
    }

    // 创建消息循环线程（分离状态，自动回收）
    HANDLE hThread = CreateThread(NULL, 0, MessageLoopThread, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);   // 线程分离
        g_handlerInstalled = true;
    }
}