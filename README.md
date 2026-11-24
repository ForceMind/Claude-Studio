# Claude-Studio

本项目要让同一 Windows 桌面的两个独立空间共用指定代理。代理故障时，两个空间离线，宿主仍能收发。开发验收使用模拟应用和合成资料。

- [项目官网](https://forcemind.github.io/Claude-Studio/)
- [下载 Windows 便携版 0.3.1（ClaudeBrowser.exe）](https://github.com/ForceMind/Claude-Studio/releases/download/v0.3.1/ClaudeBrowser.exe)
- [完整路线图与逐步验收](ROADMAP.md)
- [项目记忆与接手约定](AGENTS.md)

## A/MXC 沙盒交接

[当前验收状态与下一步](ROADMAP.md#a-模拟器启动前封网方案)记录了 A 的启动权限预检。宿主能够以标准 A 的令牌挂起创建合成进程，但普通 A 仍然可以取得其主线程的恢复权限。下一次实机验证需要先获准，范围为新建 A 令牌副本的默认 DACL，合成进程全程保持挂起。

[容器复测](ROADMAP.md#a-的-mxc-容器绑定复测)记录了按用户 SID 和映像路径拒绝 IPv4 绑定的负结果。[N3 实测](ROADMAP.md#n3-实测结果与清理)记录了按容器 SID 限制连接的正结果。N3 覆盖合成 HTTP、HTTPS、代理故障和两项 DNS 调用。启动前封网和 B 的同等覆盖仍需验证。

| 入口 | 用途 |
| --- | --- |
| [项目记忆](AGENTS.md) | 已批准边界、回滚要求和原始证据位置 |
| [模拟器源码](mock-desktop/) | Electron 双窗口、合成邮箱、测试仓库及 Windows 探针 |
| [N4 启动权限实验源码](mock-desktop/fixtures/startup-permissions/) | 使用现有宿主权限挂起创建 A、比较窗口站与桌面权限、核对句柄及退出 |
| [A 的 MXC 绑定实验源码](mock-desktop/fixtures/mxc-bind/) | 合成 TCP/UDP 调用和独立的 WFP 条件读回 |

本分支包含可审查的模拟器及实验夹具源码。路线图中 .prototype 下的路径以原实机工作区为根。原始日志、实验凭据、代理配置、SDK 暂存内容和具体运行清单都保留在该机器。复核源码可以用独立检出。复现实机需要符合路线图的夹具、专用标准账户及用户确认。

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
