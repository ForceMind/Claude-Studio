# Claude Studio Control Plane (Phase 5–7)

轻量原生 Windows x64 WPF 双空间控制面，直接基于 Windows 内置 `.NET Framework 4.x` (`csc.exe` `/warn:4` 零警告) 构建，无需安装额外 SDK 或 Electron 运行时。

## 核心能力

- **全局顶栏**：独立上游代理配置（硬保护宿主保留端口 `10810`）、实时上游健康灯、宿主网络对照检测、一键全部急停离线（Kill-Switch）。
- **双空间高对比度卡片**：`Space A`（蓝色 · `zh-CN` · `Asia/Shanghai` · `Ctrl+Alt+1`）与 `Space B`（琥珀色 · `en-US` · `America/Los_Angeles` · `Ctrl+Alt+2`），独立展示 PSEC Container SID、WFP 规则状态与清单哈希、代理端口、系统 DNS 代发计数（`0`），支持单空间临时断网（仅撤动态例外、不影响对端）、独立停止回滚以及一键启动高保真模拟桌面窗（`ClientAdapter`）。
- **实机双空间引擎接入（`LivePsecBackend.cs`）**：通过 `ISpaceRuntimeBackend` / `LivePsecWfpBackend` 直接驱动三层硬化 PSEC + 4 条静态 `ALE_PACKAGE_ID` BLOCK WFP + 独立动态 `ProxyOwner` 与幂等故障重连。
- **可插拔客户端适配器（`ClientAdapter.cs`）**：统一 `SyntheticTwin`（`ClaudeDesktopTwin.exe` + `ClaudeCliTwin.exe`）与未来官方客户端的启动参数/环境变量隔离契约。
- **项目单写者与防别名冲突**：通过 Win32 `GetFinalPathNameByHandleW` 规范化真实路径，拦截经目录联接（Junction）/符号链接绕过的写冲突，强制要求先停止原写者空间再交接写权；只读静态模板同步默认关闭且硬拦截 `.credentials.json`、`.claude.json`、`claude-code-sessions`、`projects` 等身份/会话文件。
- **纯文本 Handoff 抽屉**：读取项目只读 Git 状态并生成人工审阅的脱敏 `HANDOFF.md`，明示原生会话与凭据按 OS 账户物理隔离、不跨号迁移。
- **5 项语言/时区透明读数与脱敏诊断导出**：分项展示窗口语言、渲染器时区、请求语言、子进程偏好与 Win32 `GetTimeZoneInformation` 宿主机原生时区边界；导出诊断 JSON 内置宿主机用户名脱敏自检。

## 构建与运行

```powershell
# 编译原生 x64 WPF 可执行文件
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1

# 启动桌面控制面（含系统托盘与全局热键）
.\bin\ClaudeStudioControlPlane.exe

# 运行 Phase 5 自动化自测（9/9：状态机 + 真实 Git 仓库 + Junction 冲突 + 静态模板拦截 + WPF 渲染 + 急停清理）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase5-control-plane.ps1

# 运行 Phase 6A 实机双空间 PSEC + WFP 引擎联调验收（9/9，需提权，结束自动全量回滚）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-phase6-live-engine.ps1
```
