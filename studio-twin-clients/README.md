# Claude Studio High-Fidelity Twin Clients (Phase 7)

在不触碰真实官方 Claude Desktop / Claude Code CLI 与真实账号的前提下，完整模拟官方客户端的命令行契约、环境变量、本地存储结构、OAuth PKCE 流程、多进程树与 SSE 流式代理交互。

## 组成文件

- `src/TwinShared.cs`：PSEC 容器令牌读取、Win32 原生时区读数、`127.0.0.1:<proxyPort>` 显式 `HTTP CONNECT` + TLS 1.2（叶证书 SHA-256 指纹校验、零意外系统 DNS 调用）、SSE 流句柄、反符号链接重解析点检查、Claude Code 路径编码器与防旁路探针。
- `src/ClaudeDesktopTwin.cs` → `bin/ClaudeDesktopTwin.exe`：模仿 Claude Desktop（Electron 多进程 GUI）
  - 契约参数：`--user-data-dir`、`--proxy-server`、`--lang`、`--tz`、`--space`、`--project-dir`、`--cli-exe`、`--cli-config-dir`、`--type=mcp-helper`、`--config-file`、`--automation-dir`
  - 存储结构：`<user-data-dir>/claude-code-sessions/<accountUuid>/<orgUuid>/local_*.json`、`local-agent-mode-sessions/<accountUuid>/<orgUuid>/cowork_*.json`、`claude_desktop_config.json`、`account-session.json`
  - 行为：单实例 Mutex（热启回执）、派生 `--type=mcp-helper` 子进程、内嵌拉起 `ClaudeCliTwin.exe`、独立中英文/时区深色窗口与实时 SSE 流。
- `src/ClaudeCliTwin.cs` → `bin/ClaudeCliTwin.exe`：模仿 Claude Code CLI
  - 环境变量：`CLAUDE_CONFIG_DIR`（硬拦截符号链接）、`HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`、`LANG`、`TZ`
  - 子命令：`auth status`、`auth start-oauth`、`auth complete-oauth`、`-p "<prompt>" [--cwd ...] [--resume ...] [--read-file ...] [--write-file ... --content ...]`、`doctor`
  - 存储结构：`<CLAUDE_CONFIG_DIR>/.credentials.json`、`.claude.json`、`projects/<encoded-cwd>/<sessionUuid>.jsonl`
- `mock-claude-api.cjs`：本地仅监听 `127.0.0.1` 的 TLS 1.2 模拟 API/OAuth 服务（PKCE S256、单次/过期校验、Bearer 与 Account/Org UUID 强绑定防伪造 `403 IDENTITY_MISMATCH`、真实 SSE 流及 `/n3/<marker>` 健康探针）。

## 构建与实机双空间验收

```powershell
# 1. 编译模拟客户端二进制（纯内置 .NET 4.x csc.exe，/warn:4 零警告）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\studio-twin-clients\build.ps1

# 2. 运行 Phase 7 双标准用户实机 PSEC + WFP + NTFS 单写者全链路验收（含自动全量回滚）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\studio-twin-clients\test-phase7-realistic-twins.ps1
```

也可直接启动 `studio-control-plane\bin\ClaudeStudioControlPlane.exe`，点击 Space A / Space B 卡片上的 **“打开模拟桌面窗”** 交互体验双空间独立模拟窗口。
