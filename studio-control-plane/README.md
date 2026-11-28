# Claude Studio Control Plane (Phase 5–9)

轻量原生 Windows x64 WPF 双空间控制面，直接基于 Windows 内置 `.NET Framework 4.x` (`csc.exe` `/warn:4` 零警告) 与原生 C 构建，运行期零 Electron、零 Node.js、零外部工具链依赖。

## 核心能力

- **全局顶栏 & 脱敏配置持久化（`StudioConfig.cs`）**：独立上游代理配置（硬保护宿主保留端口 `10810`，持久化与加载阶段均强制拦截）、实时上游健康灯、宿主网络对照检测、保存脱敏配置（不含任何凭据/密码/私有代理认证）、一键临时实机双空间演练入口（UAC · 零改动宿主 · 关闭窗口 100% 自动回滚）与一键全部急停离线（Kill-Switch）。
- **双空间高对比度卡片与 1s 无闪烁遥测刷新**：`Space A`（蓝色 · `zh-CN` · `Asia/Shanghai` · `Ctrl+Alt+1`）与 `Space B`（琥珀色 · `en-US` · `America/Los_Angeles` · `Ctrl+Alt+2`），独立展示 PSEC Container SID、WFP 规则状态与清单哈希、专属代理口与实时命中/活跃隧道数、系统 DNS 代发计数（`0`），支持单空间临时断网、独立停止回滚以及一键启动高保真模拟桌面窗（`ClientAdapter`）。
- **容器内 `claude://` OAuth 回调定向路由（`OAuthCallbackRouter.cs` + `l2_desktop_host.c`）**：解决 Windows 全局 `claude://` 协议注册无法区分 Space A 与 Space B 的问题；严格校验 `claude://` 协议头并拒绝非法协议/引号注入，经纯 `KERNEL32.dll` 第 2 层守卫原子 IPC 在目标空间精确 PSEC 1.1 容器内拉起回调承接进程，同时自动将审计日志中的 `code`/`state`/`token` 参数值脱敏为 `[REDACTED]`。
- **纯 C# 内嵌双空间代理与自动断流看门狗（`EmbeddedProxyRelay.cs`）**：内建 A/B 独立 IPv4 回环入口监听（禁止子进程继承套接字句柄），持续监测上游健康与 `ProxyOwner` 存活；共享上游故障时实测 **`569.5 ms`** 内并行速杀双方 `ProxyOwner`、撤除动态 WFP 例外并将控制面双空间自动切至 `FaultCutoff`。
- **真实三层 PSEC 1.1 后端（`RealDesktopPsecBackend.cs`）**：配合预编译原生辅助二进制（`StudioLayer1Psec.exe`、`StudioLayer2DesktopHost.exe`、`StudioProxyOwner.exe`），已实机 12/12 + 10/10 验证直驱双空间真实官方 Claude Desktop（`v6.6395.0.0`）同桌面并存且零宿主改动。
- **项目单写者、实时 NTFS ACL 联动与防别名冲突**：通过 Win32 `GetFinalPathNameByHandleW` 规范化真实路径，拦截经目录联接（Junction）/符号链接绕过的写冲突，强制要求先停止原写者空间再交接写权；在实机模式下注册或双向交接写权会自动调用 `NtfsSingleWriterEnforcer.cs` 切换单写者 `Modify` / 只读 `ReadAndExecute` 并同步更新 PSEC 挂载表；只读静态模板同步默认关闭且硬拦截 `.credentials.json`、`.claude.json`、`claude-code-sessions`、`projects` 等身份/会话文件。
- **纯文本 Handoff 抽屉 & 5 项语言/时区脱敏诊断**：读取项目只读 Git 状态生成脱敏 `HANDOFF.md`；分项展示 5 类语言/时区读数（含 Win32 原生时区边界）并内置宿主机用户名 PII 脱敏自检。

## 构建与运行

```powershell
# 编译原生 x64 WPF 控制面及 3 个原生辅助二进制
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1

# 启动桌面控制面（安全预览模式，含系统托盘与全局热键）
.\bin\ClaudeStudioControlPlane.exe

# 启动一键临时双空间实机交互 GUI 演练（UAC；默认零公网测试上游；关闭窗口即 100% 回滚账户与 WFP）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\launch-ephemeral-real-desktop-gui.ps1

# 运行 Phase 5/9 自动化自测（11/11）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase5-control-plane.ps1

# 运行 Phase 6A 实机双空间引擎联调验收（9/9，自动全量回滚）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase6-live-engine.ps1

# 运行 Phase 8 控制面直驱双空间真实官方 Claude Desktop + 内嵌代理看门狗验收（12/12，零账号/零宿主改动/自动全量回滚）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase8-control-plane-real-desktop.ps1

# 运行 Phase 9 容器内 OAuth 回调定向路由 + 实机 NTFS 单写者联动 + 实机 WPF 窗口退出回滚验收（10/10，自动全量回滚）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase9-interactive-product.ps1
```
