# Claude Studio Control Plane (Phase 5–8)

轻量原生 Windows x64 WPF 双空间控制面，直接基于 Windows 内置 `.NET Framework 4.x` (`csc.exe` `/warn:4` 零警告) 与原生 C 构建，运行期零 Electron、零 Node.js、零外部工具链依赖。

## 核心能力

- **全局顶栏**：独立上游代理配置（硬保护宿主保留端口 `10810`）、实时上游健康灯、宿主网络对照检测、一键全部急停离线（Kill-Switch）。
- **双空间高对比度卡片**：`Space A`（蓝色 · `zh-CN` · `Asia/Shanghai` · `Ctrl+Alt+1`）与 `Space B`（琥珀色 · `en-US` · `America/Los_Angeles` · `Ctrl+Alt+2`），独立展示 PSEC Container SID、WFP 规则状态与清单哈希、专属代理口与实时命中/活跃隧道数、系统 DNS 代发计数（`0`），支持单空间临时断网、独立停止回滚以及一键启动高保真模拟桌面窗（`ClientAdapter`）。
- **纯 C# 内嵌双空间代理与自动断流看门狗（`EmbeddedProxyRelay.cs`）**：内建 A/B 独立 IPv4 回环入口监听（禁止子进程继承套接字句柄），持续监测上游健康与 `ProxyOwner` 存活；共享上游故障时实测 **`569.5 ms`** 内并行速杀双方 `ProxyOwner`、撤除动态 WFP 例外并将控制面双空间自动切至 `FaultCutoff`。
- **真实三层 PSEC 1.1 后端（`RealDesktopPsecBackend.cs`）**：配合预编译原生辅助二进制（`StudioLayer1Psec.exe`、`StudioLayer2DesktopHost.exe`、`StudioProxyOwner.exe`），已实机 12/12 验证直驱双空间真实官方 Claude Desktop（`v6.6395.0.0`）同桌面并存且零宿主改动。
- **项目单写者、NTFS ACL 执行器与防别名冲突**：通过 Win32 `GetFinalPathNameByHandleW` 规范化真实路径，拦截经目录联接（Junction）/符号链接绕过的写冲突，强制要求先停止原写者空间再交接写权；`NtfsSingleWriterEnforcer.cs` 负责在受控目录切换单写者 `Modify` / 只读 `ReadAndExecute`；只读静态模板同步默认关闭且硬拦截 `.credentials.json`、`.claude.json`、`claude-code-sessions`、`projects` 等身份/会话文件。
- **纯文本 Handoff 抽屉 & 5 项语言/时区脱敏诊断**：读取项目只读 Git 状态生成脱敏 `HANDOFF.md`；分项展示 5 类语言/时区读数（含 Win32 原生时区边界）并内置宿主机用户名 PII 脱敏自检。

## 构建与运行

```powershell
# 编译原生 x64 WPF 控制面及 3 个原生辅助二进制
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1

# 启动桌面控制面（含系统托盘与全局热键）
.\bin\ClaudeStudioControlPlane.exe

# 运行 Phase 5 自动化自测（9/9）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase5-control-plane.ps1

# 运行 Phase 6A 实机双空间引擎联调验收（9/9，自动全量回滚）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase6-live-engine.ps1

# 运行 Phase 8 控制面直驱双空间真实官方 Claude Desktop + 内嵌代理看门狗验收（12/12，零账号/零宿主改动/自动全量回滚）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase8-control-plane-real-desktop.ps1
```
