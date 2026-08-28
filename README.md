================================================================================
                        Security Guard for Windows
                          端点检测与响应系统（EDR）
                       版本：1.0-test | 最后更新：2026-08-28
================================================================================

**** 重要提示 ****
本版本为测试版（TEST），仅供安全研究与功能验证使用，不建议在生产环境中部署。
测试过程中可能存在未知缺陷、误报或系统不稳定性，使用者应自行承担全部风险。
请务必在测试环境中充分验证后再考虑生产使用。

1. 概述
-------------------------------------------------------------------------------
Security Guard for Windows 是一套面向 Windows 10/11（x64）的轻量级端点检测与
响应（EDR）系统。它通过多层监控（文件系统、内存、注册表、服务、计划任务、网络）
实时发现恶意行为，并集成了静态/动态分析引擎、自动响应机制与 WinPE 救援环境，
能够有效防御已知与未知威胁。

核心特性：
  - 文件实时监控（USN Journal）与恶意文件分析（PE、脚本、Office、PDF、LNK、压缩包）
  - 进程内存注入检测（反射注入、进程镂空、APC、Doppelgänging 等）
  - 内核层 RootKit 检测（SSDT/IDT/GDT 钩子、隐藏驱动）
  - 持久化监控（注册表、系统服务、计划任务）
  - 网络流量监控（DGA、恶意 IP/域名、TLS 指纹、C2 信标）
  - 自动响应（挂起进程、终止进程、沙箱隔离、加密隔离、删除文件、禁用服务/任务、WFP 网络阻断）
  - 自保护机制（启动时哈希校验、关键进程保护、异常关机安全处理）
  - WinPE 救援模式（对抗顽固 RootKit）


2. 系统要求
-------------------------------------------------------------------------------
操作系统：  Windows 10/11（x64），建议 20H2 及以上
权限：      管理员权限（所有组件均需以管理员身份运行）
依赖工具：  需安装 7-Zip，并将 7z.exe 置于 AppDir\7-zip\ 目录
编译器：    MinGW-w64 8.1+ 或 MSVC（推荐 MinGW）
第三方库：  nlohmann/json.hpp（需自行下载并放置于包含路径）


3. 快速开始（5 分钟部署）
-------------------------------------------------------------------------------
初次部署步骤：
  1. 准备目录：将编译好的所有 .exe、依赖 .dll 及 7z.exe 按下方「目录结构」放置于 AppDir。
  2. 启动系统：以管理员身份运行 Verification.exe（或先运行 Launcher.exe 创建计划任务实现开机自启）。
  3. 查看界面：运行 User_UI.exe（或等待 Verification 自动启动），系统托盘将出现图标，表示系统已就绪。

验证运行状态：
  - 右键点击托盘图标 → 显示主窗口，可查看各监控模块状态（CPU / 内存 / PID）。
  - 若某项显示“未运行”，可点击对应的“启动”按钮手动启动。

提示：所有模块默认以隐藏窗口运行，无需额外配置。


4. 目录结构说明
-------------------------------------------------------------------------------
AppDir\
├── 7-zip\
│   └── 7z.exe                     # 解压工具（需手动放置）
├── Backup\                        # 程序备份（恢复被篡改的文件）
├── ISOL\                          # 加密隔离文件存储（自动创建）
├── Logs\                          # XML 分析日志（自动创建）
├── system_service_config\         # 系统服务快照（SystemService 组件创建）
├── taskscheduler_config\          # 计划任务快照（TaskScheduler 组件创建）
├── Temp\                          # 临时文件（自动创建）
├── Verification\
│   ├── Configuration\
│   │   └── HashValue.json         # 加密存储的 SHA‑256 哈希（由 CreateHash.exe 生成）
│   ├── CreateHash.exe             # 哈希生成工具（生成后建议删除）
│   ├── Launcher.exe               # 创建开机计划任务（仅需运行一次）
│   └── Verification.exe           # 开机自启动校验程序（系统入口）
├── WhiteList\
│   └── HighTrustWhiteList.json    # 高信任白名单（文件及目录）
├── WinPE\
│   ├── WinPE.iso                  # WinPE 镜像（需自行准备）
│   └── Executable\                # WinPE 环境下运行的工具
│       ├── CMDanalyzer_forWinPE.exe
│       ├── PEanalyzer_forWinPE.exe
│       └── traverseallfiles.exe
├── CMDanalyzer.exe                # 脚本（.bat/.cmd/.ps1）分析器
├── ControlCenter.exe              # 消息汇聚与路由中枢（必需）
├── DelFromZip.exe                 # 从压缩包中删除指定文件
├── Fileanalyzer.exe               # 文件类型识别与路由
├── FileSystemMonitor.exe          # 文件系统监控（USN Journal）
├── isol.exe                       # AES‑256 文件加密隔离工具
├── Lnkanalyzer.exe                # LNK 快捷方式分析器
├── MemoryGuard.exe                # 内存行为监控与检测（核心）
├── NetworkGuard.exe               # 网络流量监控
├── OLEanalyzer.exe                # OLE2 文档分析（旧版 Office）
├── PDFanalyzer.exe                # PDF 文件分析
├── PEanalyzer.exe                 # PE 可执行文件深度分析（核心）
├── RegistryMonitor.exe            # 注册表变更监控
├── RestartInWinPE.exe             # 配置下次重启进入 WinPE（用户手动启动）
├── SandBox.exe                    # 进程沙箱（受限令牌 + 作业对象）
├── SystemService.exe              # 系统服务变更监控
├── TaskScheduler.exe              # 计划任务变更监控
├── User_UI.exe                    # 用户决策界面（系统托盘 + 告警弹窗）
├── ZIPanalyzer.exe                # 压缩包分析（解压后调用 Fileanalyzer）
└── ...（运行所需的 .dll 文件）

核心文件说明：
  Verification.exe      启动入口 + 完整性校验          必须
  ControlCenter.exe     消息总线，协调各组件            必须
  User_UI.exe           用户交互界面                    必须
  MemoryGuard.exe       内存恶意行为检测                必须（核心防护）
  FileSystemMonitor.exe 文件写入/修改监控              必须
  NetworkGuard.exe      网络流量检测                    推荐
  RegistryMonitor.exe   注册表持久化监控                推荐
  SystemService.exe     服务变更监控                    推荐
  TaskScheduler.exe     计划任务监控                    推荐
  CreateHash.exe        一次性哈希生成工具              仅部署/更新时使用
  RestartInWinPE.exe    WinPE 救援（按需）              按需使用


5. 编译指南
-------------------------------------------------------------------------------
5.1 环境准备
  - 安装 MinGW-w64（建议 8.1.0 以上），并将 g++ 所在目录加入系统 PATH。
  - 下载第三方头文件：将 nlohmann/json.hpp 放入 C:\mingw64\include\nlohmann\（或项目 include\ 目录）。
  - 所有 Windows SDK 依赖库已通过 #pragma comment(lib, ...) 链接，无需额外配置。

5.2 编译单个模块
  编译命令已在每个源码文件头部注释中给出。以 PEanalyzer.cpp 为例：
    cd %G++_PATH%
    g++ -fdiagnostics-color=always -g "%SourceCodePath%\PEanalyzer.cpp" -o "%ExecutablePath%\PEanalyzer.exe" -lwintrust -lcrypt32 -lws2_32 -mwindows
  请将 %SourceCodePath% 替换为源代码实际目录，%ExecutablePath% 替换为输出目录（即 AppDir）。

5.3 推荐编译顺序
  1. CreateHash.exe（仅用于生成哈希配置文件）
  2. Verification.exe（自校验启动器）
  3. Launcher.exe（计划任务创建器）
  4. 其余模块（无严格顺序，但建议先编译 ControlCenter.exe 和 User_UI.exe）
  5. WinPE 专用版本（PEanalyzer_forWinPE.exe、CMDanalyzer_forWinPE.exe、traverseallfiles.exe）

5.4 批量编译脚本（示例）
  将以下内容保存为 build_all.bat（置于项目根目录）：
  -------------------------------------------------------------------------------
  @echo off
  set SRC=.\SourceCode
  set OUT=.\AppDir
  set GPP=g++

  for %%f in (
      CMDanalyzer ControlCenter DelFromZip Fileanalyzer FileSystemMonitor
      Lnkanalyzer MemoryGuard NetworkGuard OLEanalyzer PDFanalyzer PEanalyzer
      RegistryMonitor RestartInWinPE SandBox SystemService TaskScheduler User_UI ZIPanalyzer
  ) do (
      %GPP% -g "%SRC%\%%f.cpp" -o "%OUT%\%%f.exe" -mwindows
  )

  rem WinPE 专用
  %GPP% -g "%SRC%\PEanalyzer_forWinPE.cpp" -o "%OUT%\WinPE\Executable\PEanalyzer_forWinPE.exe"
  %GPP% -g "%SRC%\CMDanalyzer_forWinPE.cpp" -o "%OUT%\WinPE\Executable\CMDanalyzer_forWinPE.exe"
  %GPP% -g "%SRC%\TraverseAllFiles.cpp" -o "%OUT%\WinPE\Executable\traverseallfiles.exe"

  echo Build completed.
  -------------------------------------------------------------------------------
  注意：部分模块需额外链接库，请根据源码头部注释调整编译参数。


6. 配置详解
-------------------------------------------------------------------------------
6.1 白名单（WhiteList\HighTrustWhiteList.json）
  该文件用于指定永不触发告警的文件或目录，适合系统文件或可信应用程序。
  - Files：精确匹配文件完整路径（大小写不敏感），JSON 中反斜杠需转义为 \\。
  - Paths：目录路径（以 \\ 结尾），该目录下所有文件均被信任。

  示例：
  {
      "Files": [
          "C:\\Windows\\System32\\notepad.exe",
          "D:\\MyApp\\trusted.exe"
      ],
      "Paths": [
          "C:\\Program Files\\Microsoft\\"
      ]
  }
  修改后无需重启，FileSystemMonitor 和 MemoryGuard 每 5 分钟自动重载。

6.2 恶意 IP/域名黑名单（malicious.txt）
  每行一个 IP（支持 CIDR，如 192.168.1.0/24）或域名（支持 *.example.com 通配符），
  由 NetworkGuard.exe 加载。
  示例：
      5.5.5.5
      6.6.6.6/28
      *.malware.com
      evil.org

6.3 TLS 指纹库（tls_fingerprints.txt）
  每行一个 JA3/MD5 指纹，用于匹配恶意 TLS Client Hello（由 NetworkGuard 使用）。
  示例：
      e3b0c44298fc1c149afbf4c8996fb924
      5d7c5b1b2c3d4e5f6a7b8c9d0e1f2a3b

6.4 隔离密码修改（高级）
  隔离文件使用的 AES‑256 密码硬编码为 @pASs7W#Ord，如需修改：
  1. 修改 IsolationFolder.cpp 和 IsolationFoldermain.cpp 中的密码字符串；
  2. 重新编译 isol.exe；
  3. 注意：旧密码隔离的文件将无法解密，需先全部提取再更换。


7. 日常运维
-------------------------------------------------------------------------------
7.1 启动与停止
  - 开机自启：由 Launcher.exe 创建的计划任务 SecurityGuardStartupTask 在用户登录时
    启动 Verification.exe，后者负责拉起所有模块。
  - 手动停止：在 User_UI 主窗口点击「退出」按钮，所有子模块会收到退出命令并终止。
  - 单独启动/停止模块：在主窗口的进程列表中点击对应“启动”或“退出”按钮即可。

  **严重警告**：切勿通过任务管理器、taskkill 命令或其他方式手动终止监控进程
  （ControlCenter.exe、MemoryGuard.exe、FileSystemMonitor.exe 等），因为这些进程
  被设置为系统关键进程（RtlSetProcessIsCritical），强行终止将立即触发系统蓝屏
  （BSOD）。请始终通过 User_UI 主窗口的「退出」按钮或对应的「停止」按钮来正常
  关闭系统，这是唯一安全的方式。

7.2 查看日志
  - 各分析器（PEanalyzer、CMDanalyzer 等）生成的详细报告以 XML 格式保存在 Logs\ 目录。
  - 每个监控模块的控制台输出（默认隐藏）可通过附加启动参数 --withoutUi 或 --onlywithUi
    临时调整（需手动从命令行启动）。

7.3 更新程序
  1. 停止所有模块（通过 User_UI 退出）。
  2. 用新编译的 .exe 覆盖 AppDir 中的旧文件。
  3. 运行 CreateHash.exe 重新生成 Verification\Configuration\HashValue.json。
  4. 将新程序复制到 Backup\ 目录（以便下次校验恢复）。
  5. 重新启动 Verification.exe。

7.4 性能调优
  若系统资源紧张，可调整以下源码宏（需重新编译）：
    模块           宏                        默认值      说明
    MemoryGuard    COOLDOWN_SECONDS          15         同一进程两次扫描最小间隔（秒）
    MemoryGuard    LIGHT_SCAN_COOLDOWN_SEC   300        轻量扫描冷却时间
    FileSystemMonitor PROCESS_INTERVAL_MS    200        后台分析器限速间隔（毫秒）
    NetworkGuard   抓包超时                  1000 ms    setsockopt(SO_RCVTIMEO) 值


8. 故障排查
-------------------------------------------------------------------------------
8.1 开机后 Verification.exe 未启动
  检查计划任务：schtasks /query /tn "SecurityGuardStartupTask"
  若不存在，以管理员身份运行 Launcher.exe 重新创建。

8.2 托盘图标消失
  - 确认 User_UI.exe 正在运行（任务管理器 → 进程）。
  - 若未运行，手动启动；若已运行，尝试重启资源管理器（explorer.exe）。

8.3 部分模块显示“管道连接失败”
  - 确保 ControlCenter.exe 已优先启动（它是管道服务器）。
  - 检查防火墙是否阻止本地管道通信（通常不会）。

8.4 MemoryGuard 无法检测内核钩子
  - 若系统启用了 HVCI（虚拟化代码完整性），内核钩子检测功能会降级，此为正常行为。
  - 可通过 msinfo32 查看“基于虚拟化的安全性”状态。

8.5 更新程序后 Verification 提示哈希不匹配
  - 运行 CreateHash.exe 重新生成 HashValue.json。
  - 将新生成的 HashValue.json 复制到 AppDir\Verification\Configuration\。
  - 将新程序文件复制到 AppDir\Backup\ 目录（作为恢复源）。

8.6 NetworkGuard 无法抓取网络包
  - 在 Windows 10 1703 以后，原始套接字（SIO_RCVALL）可能受组策略限制。
  - 可尝试以管理员身份执行 netsh 相关设置（需自行研究）。
  - 或考虑改用 WFP 回调模式（需二次开发）。


9. 卸载说明
-------------------------------------------------------------------------------
1. 在 User_UI 主窗口点击「退出」按钮，等待所有子进程退出（约 2~3 秒）。
2. 删除 AppDir 目录下的所有文件。
3. （可选）删除计划任务：
   schtasks /delete /tn "SecurityGuardStartupTask" /f
4. （可选）清除 WFP 阻断规则（若 NetworkGuard 曾添加过阻断规则）：
   - 查看：netsh wfp show filters
   - 找到对应过滤 ID（filterId），然后执行：netsh wfp delete filter id=<ID>


10. 常见问题（FAQ）
-------------------------------------------------------------------------------
Q：启动后为何某些模块 CPU 占用较高？
A：首次启动时，MemoryGuard 会进行全进程扫描，完成后 CPU 会回落。若持续高占用，
   可调整冷却时间（见“性能调优”）。

Q：隔离文件后如何恢复？
A：使用命令：
   isol.exe extract <隔离文件夹路径> <文件名> <目标路径> @pASs7W#Ord
   例如：isol.exe extract .\ISOL malware.exe C:\恢复目录\ @pASs7W#Ord

Q：如何临时禁用某个监控模块？
A：在主窗口的进程列表中点击对应“退出”按钮即可。该模块被终止后，系统防护会降级，
   请谨慎操作。

Q：可以同时运行多套该程序吗？
A：不建议。管道名称、文件锁等设计为单例模式，多实例会导致冲突。

Q：WinPE 救援模式是否会影响系统数据？
A：traverseallfiles.exe 会直接删除被判定为恶意的 PE/脚本文件，可能误删系统文件。
   使用前请务必备份重要数据。

Q：如何获取当前运行状态摘要？
A：在 User_UI 主窗口可看到各模块的 PID、CPU、内存占用，以及最后一条告警信息。


11. 免责声明与许可证
-------------------------------------------------------------------------------
AI 生成声明：
  本程序部分源代码由 AI 编程助手（大语言模型）辅助生成，并经过人工审查、整合与测试。
  尽管已尽力确保代码的正确性和可靠性，AI 生成的代码仍可能存在逻辑缺陷、边界条件处理不当或安全漏洞。
  本程序涉及系统底层操作（包括但不限于进程保护、内核检测、文件系统修改、注册表操作等），
  误用或代码缺陷可能导致系统不稳定、数据丢失或蓝屏崩溃。使用者应在充分理解代码功能的前提下谨慎部署，
  并在非生产环境中充分测试。开发者不对因使用本程序产生的任何直接或间接损失承担责任。
  
免责声明：
  本软件仅供安全研究和防御实践使用。使用者应自行承担因部署和使用本软件带来的
  一切风险，开发者不对任何直接或间接损失负责。

许可证：
  本程序仅供安全研究与内部使用，未经授权不得用于商业用途。

================================================================================
              Security Guard for Windows — 为您的 Windows 系统筑起坚实防线。
================================================================================
