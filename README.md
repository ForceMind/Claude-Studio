# Claude-Studio

本项目要让同一 Windows 桌面的两个独立空间共用指定代理。代理故障时，两个空间离线，宿主仍能收发。开发验收使用模拟应用和合成资料。

- [项目官网](https://forcemind.github.io/Claude-Studio/)
- [下载 Windows 便携版 0.3.1（ClaudeBrowser.exe）](https://github.com/ForceMind/Claude-Studio/releases/download/v0.3.1/ClaudeBrowser.exe)
- [完整路线图与逐步验收](ROADMAP.md)
- [项目记忆与接手约定](AGENTS.md)

## 最新进展与交接入口（2026-11-27）

已完成 **Phase 0–Phase 8** 全部底层隔离引擎、纯 C# 内嵌双代理与自动断流看门狗、原生 WPF 控制面（含预编译原生辅助二进制）、高保真模拟客户端套件（`ClaudeDesktopTwin` + `ClaudeCliTwin`），以及 **控制面直驱两份真实官方 Claude Desktop (`v6.6395.0.0`) 双空间同桌面并行隔离与故障自动断流实机验收**（全程零真实账号、零改动宿主 `WindowsApps`/`C:\`/桌面 ACL/`10810`/系统 DNS，并全部 100% 回滚）：

- **双标准用户 + PSEC 1.1 启动前零竞态封网**：三层架构（Layer-1 PSEC 1.1 创建器含内核态 `fs_enumerate` → Layer-2 纯 `KERNEL32.dll` 硬化守卫 → Layer-3 客户端多进程树），在 `ResumeThread` 前单事务安装并独立读回 4 条静态 `ALE_PACKAGE_ID` BLOCK WFP 规则；普通同账户/跨账户 6 视角句柄审计 `0` 违例。
- **内嵌双代理与看门狗秒级自动断流**：控制面内建 `EmbeddedDualProxyRelay`（A/B 各自独立 `127.0.0.1:Pa/Pb`，禁止子进程继承套接字句柄），上游故障时实测 **`569.5 ms`** 内并行撤除双方动态 WFP 例外并自动切入 `FaultCutoff`；主进程与派生子进程全协议（直连 TCP/UDP、`127.0.0.2`、QUIC、DoT、DoH、系统 DNS ETW）零旁路零泄露；宿主持续在线。
- **控制面直驱真实官方 Claude Desktop 双空间（Phase 8 · 12/12 通过）**：`ClaudeStudioControlPlane.exe` 直接驱动两份真实官方 `claude.exe`（A `zh-CN / Asia/Shanghai`、B `en-US / America/Los_Angeles`）在 `WinSta0\Default` 同桌面并存两个可见 `Chrome_WidgetWin_1:Claude` 窗口、共 12 个真实进程全落各自 AppContainer，冷启动零命中、在线态各自路由 `CONNECT claude.ai:443`、单空间断网与共享上游自动断流均通过，全量 20 个观测 PID 的 DNS ETW 代发为 `0`、`CoworkVMService` 未触发。

| 入口 | 用途 |
| --- | --- |
| [完整路线图与逐步验收](ROADMAP.md) | Phase 0–7 及真实官方 Claude Desktop 双空间实测脱敏记录与报告哈希 |
| [项目记忆](AGENTS.md) | 已批准边界、回滚要求和原始证据位置 |
| [原生 WPF 控制面](studio-control-plane/) | 纯 `.NET 4.x` 原生 x64 控制面、系统托盘、`LivePsecWfpBackend`、单写者租约、`HANDOFF.md` 与 `ClientAdapter` |
| [高保真模拟客户端套件](studio-twin-clients/) | 模仿官方接口的 `ClaudeDesktopTwin`、`ClaudeCliTwin`、本地 TLS 1.2 OAuth/SSE 模拟 API 与 Phase 7 双空间端到端验收 |
| [启动权限与 PSEC 实测夹具](mock-desktop/fixtures/startup-permissions/) | Phase 0–4、Phase 6B 合成 MSIX、及真实官方 Claude Desktop 单/双空间 PSEC 1.1 实测脚本 |
| [早期模拟器源码](mock-desktop/) | 早期 Electron 双窗口、合成邮箱、测试仓库及 Windows WFP/DNS 探针 |

本分支包含可审查的控制面、模拟客户端及实测夹具源码。路线图中 `.prototype` 下的原始报告以原实机工作区为根，机器标识、用户资料、凭据、代理私有配置与原始 ETW 均留在本机不入库。

## 合成模拟器

进入 mock-desktop 安装锁定依赖后，运行 npm run spaces 可演示两个独立窗口。两个窗口各自保存模拟资料、语言和时区。模拟邮箱可以先完成 B 再完成 A，测试仓库支持读写授权、只读及写权限交接。

| 命令 | 测试内容 |
| --- | --- |
| npm run verify:spaces | 双窗口、资料重开、独立停止与配置 |
| npm run verify:workflows | 合成登录、会话归属与合成目录写回 |
| npm run verify | 独立窗口和回环代理 |
| npm run verify:drop | 临时代理退出后的旧流、新流和直连对照 |
| npm run verify:recover | 临时代理故障、恢复及换端口 |

以上命令使用合成资料。前台聚焦和 Windows 网络、ACL、模拟包等实机实验按各自批准范围执行。历史 Sandboxie 与真实客户端资料留在原工作区。
