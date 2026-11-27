# Windows 同桌面双空间路线图

2026-11-27 更新。目标是在一台 Windows 电脑的同一桌面上运行两个独立空间 A、B。每个空间使用自己的标准用户、应用资料、邮箱、语言和时区。两者共用指定上游代理。代理故障时，两个空间的已有外联应中断，新外联应失败，宿主机仍能解析域名、维持已有连接并建立新连接。

**最新里程碑（2026-11-27）：Phase 0–Phase 7 与真实官方 Claude Desktop 双空间同桌面并行隔离实机验收已全部通过并 100% 回滚。** 涵盖：一次性硬化 `TokenDefaultDacl` 与 6 视角跨账户句柄闸口、PSEC `SchemaVersion 1.1`（含内核态 `fs_enumerate`，零磁盘 ACL 修改）+ 4 条静态 `ALE_PACKAGE_ID` BLOCK WFP 启动前零竞态封网、单端口动态 `ProxyOwner` 故障 `< 3s` 断流（实测 `51ms–1392ms`）、全协议与派生子进程防旁路审计、原生 x64 WPF 控制面（`studio-control-plane/`，含实机引擎 `LivePsecWfpBackend` 与可插拔适配器 `ClientAdapter`）、高保真模拟客户端套件（`studio-twin-clients/`）、合成离线签名 MSIX 5 进程承接，以及**两份真实官方 `claude.exe`（`v6.6395.0.0`）同桌面并行运行、冷启动零命中、专属代理路由、单空间断流隔离、全量 DNS ETW 零泄露与零宿主改动实测**（报告哈希 `520B06D1AE76`）。[完整实测记录](#启动权限预检结果)

*(以下四段保留 2026-11-23 至 2026-11-25 早期阶段交接摘要以便追溯)*

**P 阶段离线准备已验收，当前宿主的 A 预阻断方案未放行。** 两条权重 `65535` 的 `sing-tun` 硬放行匹配现有 `sing-box.exe` 的精确应用 ID。A 的 Authz 静态模型对该映像没有读或执行权限，实际运行令牌和持续互斥仍未证明，保守优先级检查继续拒绝执行。M/F/X 的运行及恢复入口、审阅清单、离线取证和宿主合成对照均已交付。实机下一步需解决优先级证据，再单独确认系统改动和 A 模拟器运行范围。[最新批次与诊断](#最新批次与-wfp-优先级结论) · [Sol 执行方案](#sol-接手执行方案)

**A 的合成 IPv4 绑定实验已完成并回滚。** 精确匹配 A 和指定映像的一条临时规则阻止了所测 TCP/UDP 显式与隐式绑定。A 的另一映像、宿主运行相同映像以及宿主新旧回环连接均通过对照。[实测与回滚](#a-的合成-ipv4-绑定实验)

**同一绑定拒绝在 A 的 MXC 容器内未生效。** 规则安装并经独立读回后，同一容器进程的四项 IPv4 操作均成功。宿主新旧连接正常，临时规则、子层和 MXC 运行时条目均已回收。[容器复测](#a-的-mxc-容器绑定复测)

**A 的启动前封网权限闸口及两层挂起创建链已通过无 PSEC/无 WFP 实机验证。** 一次性 A 令牌副本 `TokenDefaultDacl`（含 `OWNER RIGHTS = 0`）结合纯 `KERNEL32.dll` 第 1 层原生启动器，在恢复运行第 1 层并由其经 `CreateProcessW(STARTUPINFOEX + Job + CREATE_SUSPENDED)` 创建挂起第 2 层后，普通 A（异/同 Logon SID）对第 1、2 层的 20 项句柄权限均被拒，桌面 ACL 未改动，临时账户与目录已清理。下一步待确认将第 2 层接入 PSEC 容器创建与 `ALE_PACKAGE_ID` Static BLOCK WFP 实测。[方案与实测进展](#a-模拟器启动前封网方案)

## 已有证据

2026-11-22，按用户要求清理旧 Sandboxie 后台。`SbieSvc` 服务与 `SbieDrv` 驱动均已停止并设为 Disabled，控制程序、服务进程及维护工具均已退出，未发现相关注册表自启动项、启动文件夹入口或计划任务。驱动通过已安装的官方 `KmdUtil.exe stop SbieDrv` 正常卸载，无需重启。安装文件和沙盒资料保留，原始状态及最终核验保存于本机 `.prototype/mock-results/sandboxie-disabled.json`。后续实验不得重新启用 Sandboxie；本轮 A 容器实验结束后再次确认服务和驱动仍为 Stopped / Disabled，相关进程为零。10810、系统 DNS、网卡和 TUN 未改动。

下表取自原实机工作区的 `.prototype/mock-results/`。本分支的独立检出包含模拟器及近期夹具源码，文中的本机证据与运行清单仍以原实机工作区为根。文件名用于本机复核，两个关键报告附有 SHA-256 前 12 位。公开仓库保留实测摘要。原始报告含机器标识和网络信息，保存在本机。

| 已测条件 | 观察到的结果 | 本机报告 |
| --- | --- | --- |
| 双窗口与偏好 | 两个模拟窗口同桌面并存。重复打开能回到原窗口，停一边后另一边仍可收发。重开后各自资料保留。A 默认 `zh-CN / Asia/Shanghai`，B 默认 `en-US / America/Los_Angeles`。上海冬夏均 UTC+8，洛杉矶冬季 UTC−8、夏季 UTC−7。两边的 Windows 原生 API 均读到宿主时区。 | `spaces.json` |
| 登录与目录 | 合成登录先完成 B 再完成 A，两个窗口分别得到自己的身份。合成仓库在原目录出现 Git 差异。标准用户下另测了双方私有资料、只读和写者交接，NTFS 权限已回滚。 | `workflows.json`、`windows-acl.json` |
| 初版代理与账户规则 | 模拟器用临时代理演练了停机、拒转、恢复和换端口。按账户加 WFP 规则时，受控直连目标零命中，宿主的新旧回环连接正常。Windows DNS Client 仍为两个账户发出查询。 | `proxy-recovery.json`、`windows-network-windows.json`、`windows-ipv6-dns.json` |
| A，MXC v1.1.0 代理模式，上游从启动时就未监听 | HTTP 失败，容器内 IPv4 TCP、UDP 直连目标各 0 次。两种系统解析调用合计产生 **4 次 DNS 发送、2 次回复**。本轮未接入健康代理。 | `windows-psec-stopped.json` · `CC3EFF7A552A` |
| A，同机同探针，关闭容器入站、出站、宿主回环，省略代理 | 窗口和子进程的三项网络能力均为空。`DnsQuery_W` 返回 5，`GetAddrInfoW` 返回 11001，合计 **0 次发送、0 次回复**。容器外 TCP、UDP 对照各命中 1 次，容器内各 0 次。宿主 DNS 和受控回环 TCP 新旧连接正常，跟踪零丢失，容器过滤器退出后为 0。 | `windows-psec-networkless.json` · `4ED6C1737DD9` |
| A，仅 `networkLoopback` 网络能力，入站/出站默认拒绝，无 MXC 代理配置 | 显式 HTTP 代理收到 1 次请求并返回匹配标记。两项 DNS API 被拒，服务发送和回复均为 0。但非代理宿主回环 TCP/UDP 各命中 1 次，触发停止条件；代理停机未测。宿主对照正常，本轮容器规则、进程、监听和跟踪均已回收。 | `windows-psec-hostloopback.json` · `1D5FE486D689` |
| 原生 IPv6 | 加实验规则前，现有 TUN 策略已阻断 `::1`。IPv4 映射地址有独立结果。原生 IPv6 缺少可达的正对照，按用户决定暂缓。 | `windows-ipv6-diagnosis.json` |

与最后两次容器实验对应的环境是 Windows 11 26H2 build `26300.9974` 和 Microsoft MXC SDK `1.1.0`。升级后应先核对系统能力和实际令牌。MXC 的代理模式要求授予 `privateNetworkClientServer`。零网络能力模式把容器内部回环列在外部网络策略范围之外，两个独立进程在本机能否互通仍需 S1 取证。[微软版本表](https://github.com/microsoft/mxc/blob/v1.1.0/docs/backends/process-container/os-version-support.md) · [微软网络模型](https://github.com/microsoft/mxc/blob/v1.1.0/docs/backends/process-container/networking.md)

### A 的合成 IPv4 绑定实验

2026-11-23，Windows 11 26H2 build `26300.9974`。用普通 A 标准用户和字节相同、WFP 应用 ID 不同的两个合成映像建立对照。先验证网络基线，再在一个新的动态子层中只加一条 `ALE_RESOURCE_ASSIGNMENT_V4` BLOCK 规则，条件为 A 的精确 `ALE_USER_ID` 与指定映像的精确 `ALE_APP_ID`。规则不按端口匹配。独立 WFP 会话在规则提交后、回滚前两次读回了活动规则 `176969` 及其完整条件。所有测试流量使用数字 IPv4 回环地址和系统分配的临时端口。[微软 ALE 层说明](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)

| 对照 | 加规则前 | 规则生效时 | 回滚后 |
| --- | --- | --- | --- |
| A 运行指定映像 | 四项通过，TCP/UDP 目标各收到 1 个标记 | TCP/UDP 显式 `Bind()` 和 TCP 隐式 `Connect()` 返回 `10013`。UDP 隐式 `SendTo()` 返回 `10022`，发送字节数为 0。TCP/UDP 目标各收到 0 个标记 | 四项通过，TCP/UDP 目标各收到 1 个标记 |
| A 运行另一映像，宿主运行指定映像 | 各四项通过 | 各四项通过，两组 TCP/UDP 目标各收到 1 个标记 | 各四项通过 |
| 宿主回环 TCP 连接 | 旧连接和新连接双向通过 | 原有连接继续双向收发，新连接可建连并双向收发 | 同一旧连接和新连接双向通过 |

首次提升进程启动失败，后续独立读回确认该次的规则和子层均不存在。正式实验的原始报告保留了把所有拒绝预期写为 `10013` 导致的 UDP 断言失败。随后基于原始报告分别复核了 36 项 API 操作、目标标记、两种身份对照和连接连续性，功能结果符合本轮验收。正式实验结束后立即关闭动态会话，独立查询确认规则及子层 GUID 均已消失，随后复测并确认无合成进程或监听残留。本轮仅添加该临时规则及其子层，已有 WFP、ACL 和 10810 均未改动，真实客户端未启动。

结果范围是普通 A 的合成映像和宿主 IPv4 回环对照。MXC 容器、实际 `sing-tun` 硬放行、代理故障隔离和原生 IPv6 需要各自的证据。原始报告在本机 `.prototype/mock-results/windows-a-ipv4-bind-d1abb51d47814670871d248c8447aec4.json`，SHA-256 前 12 位为 `B675B373A26D`。

### A 的 MXC 容器绑定复测

2026-11-23，Windows 11 26H2 build `26300.9974`，MXC `1.1.0`。使用入站和出站默认拒绝、仅 `networkLoopback`、无代理的 A 临时 PSEC。通过宿主独立读取两个合成进程的实际令牌，确认同属 A 标准用户和同一 PSEC，只有预期的回环网络能力，且进程与映像在前、中、后三段连续。首次启动的只读令牌核对遇到缓冲区不足，规则未添加，容器正常退出。临时探针改为按系统返回长度分配缓冲区后复测。[微软令牌读取 API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)

四项基线均通过后，只在独立动态子层加一条 `ALE_RESOURCE_ASSIGNMENT_V4` BLOCK，保留普通 A 实验的两个条件：精确 A 用户 SID 与精确合成 AppID。独立会话两次读回过滤器 `179254`，子层权重 `65533`。规则生效时，目标映像的 TCP、UDP 显式 `Bind()` 和 TCP 隐式 `Connect()`、UDP 隐式 `SendTo()` 均成功，两个目标各收到 1 个 32 字节标记。容器内另一个映像与宿主执行同一映像也正常。宿主同一条旧 TCP 回环连接在容器启动前至退出后五个检查点均可双向收发，每次新建 TCP 回环连接也通过。

关闭 WFP 动态会话后独立读回规则及子层均已消失，随后在同一容器复测，四项操作依然成功。容器退出码为 0。按容器 SID 找到的 6 条 MXC 条目全部回收，无合成进程或监听残留。现有 WFP、ACL、10810 保持原样，真实客户端未启动。该规则未阻止所测 MXC 容器的新 IPv4 绑定，本轮没有分类事件能够定位具体未命中的条件，不能用作代理故障封网依据。

本机原始报告为 `.prototype/mock-results/windows-a-mxc-ipv4-bind-fe6062953a074618b222be505f99f642.json`，SHA-256 前 12 位为 `1945B9286D7F`。

### A 模拟器启动前封网方案

2026-11-23，方案经既有 Astra 代理只读审查，待用户确认。执行范围为现有标准账户 A、MXC v1.1.0 的一次性实验启动器、合成探针和宿主对照。容器保留进出站默认拒绝和仅 `networkLoopback` 的已测基线。首个成果是启动权限预检回执。可信闸口或 WFP 仲裁无法证实时，交付停止点及清理记录。

1. 复用 MXC 挂起创建及 Job 归属流程，在 `ResumeThread` 前加入实验闸口。用宿主独立持有的进程、主线程句柄核验 PID、创建时间、实际 A 标准令牌、PSEC SID、映像、令牌能力和 Job。验证普通 A 无法改写启动器、取得或复制可恢复主线程的句柄，或自行走另一条恢复路径。底层 API 不可用、同账户权限门槛失败或出现未预期进程时，保持挂起并回收，WFP 写入数为零。[MXC 启动源码](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L930-L1034) · [Windows 挂起创建](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
2. 用一次性同配置 A 合成正对照确认相同的 IPv4 TCP、UDP 回环目标原本可达。正式受测实例始终保持挂起。复查四层的现有硬放行和 callout，特别是两条 `sing-tun` 规则。仅在能证明其规范 AppID 与本轮实际合成映像互斥时排除。此证据限于本轮固定映像。任何竞争关系未决都不安装、不恢复。[WFP 过滤仲裁](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
3. 写入前保留恢复清单及五个 GUID，并确认独立清理器在线。计划在一个新子层内用单个事务新增四条非持久的 Static BLOCK，分别位于 IPv4/IPv6 的 `ALE_AUTH_CONNECT` 和 `ALE_AUTH_RECV_ACCEPT`。唯一筛选条件是独立读到的本轮 `ALE_PACKAGE_ID`，无代理放行。独立会话逐条读回层、完整条件、动作、权重和状态。Static 在规则管理器退出后仍保留，因此控制器失联时不会因会话退出直接放通。原生 IPv6 暂缓实测，对其只核对规则读回。[WFP 对象生命周期](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
4. 宿主与目标端提前开始观测。用同一台机器的单调时钟关联 `事务提交 → 独立读回通过 → 宿主调用 ResumeThread → 探针首个套接字调用`，核对实际线程句柄及恢复返回的前一挂起计数为 1。探针从入口直接尝试 IPv4 TCP 和 UDP，不等待应用内放行信号。两个受控目标都必须零命中，并保留 API 返回值和唯一标记。另用独立 DNS 跟踪按唯一名称、探针 PID 和 Dnscache PID 复核两项解析调用，要求零代发且采集无丢失。未授权或缺规则读回的对照必须保持挂起、零业务执行。IPv4 入站规则本轮只核对读回。[ResumeThread 返回语义](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)

**宿主影响。** 预期阻断仅匹配本轮 A 容器。ALE 加规则和撤规则可能触发现有流重新授权，因此用相同的宿主旧 TCP 回环连接、每阶段的新连接及正常 DNS 贯穿验证，观察实际收发和解析结果。保持现有 WFP、系统 DNS、网卡、TUN、ACL 和 10810。需要额外文件 ACL、提权授权、常驻服务或其他隔离变更时，停在该步骤另行确认。[ALE 重授权](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)

**回滚。** 正常结束、预检失败或控制器失联时，先禁止恢复，使用受信 Job 或原始句柄停止本轮 A 进程树并确认 PSEC 已退出。随后由独立清理器按清单核验并事务性删除本轮四条过滤器和一个子层，再用新会话确认五个 GUID 及 PSEC 自有条目均已消失。关闭临时监听和跟踪，清理临时启动器，再复测宿主旧连接、新连接及 DNS。残留或归属不能确认时保持本轮 A 停止，保留清单。

本轮验收限于 A 合成探针的启动时序、所测 IPv4 出站与两项 DNS 调用，及宿主对照和清理。代理、B、真实客户端及产品启动链的验收各自独立。

#### 启动权限预检结果

2026-11-23，宿主当前提升令牌与交互用户同身份、同会话，现有 `SeImpersonatePrivilege` 已启用。未发现 `SeAssignPrimaryTokenPrivilege`，`SeIncreaseQuotaPrivilege` 已禁用。替代创建接口 `CreateProcessWithTokenW` 显式指定现有 `WinSta0\Default`，避开桌面参数留空时自动授权的行为。两个实验前后窗口站与桌面的所有者、组及 DACL 指纹均相同。[微软创建接口](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)

- 将 Job 放入创建属性的调用返回 `87`，无受测进程。改用标准挂起参数，创建成功后立即加入清理 Job。独立核对了标准 A 实际令牌、映像、会话和 Job，主线程用户态运行时间和恢复调用次数均为零。
- 用 A 的实际令牌请求句柄权限后立即关闭，未恢复线程。对提升宿主的已测关键权限均被拒。对挂起探针，9 项进程和 5 项线程权限全部获准，包含 `THREAD_SUSPEND_RESUME` 和 `WRITE_DAC`。因此默认对象权限无法建立宿主独占的恢复闸口。
- 挂起探针由原始句柄回收，进程、线程退出信号和退出码均匹配，无测试进程或暂存二进制残留。未创建 PSEC、添加 WFP 或修改已有 ACL，10810 和真实客户端均未参与。

**2026-11-25 一次性 `TokenDefaultDacl`、两层挂起链与 PSEC 启动前 WFP 封网实测（均已回滚）。** 在 Windows 11 build `26300.9974` 上分三轮完成，均临时新建标准账户 A（仅属 `Users`）、零真实客户端、不触碰 `10810`/系统 DNS/网卡/TUN、全程不修改 `WinSta0` 与 `WinSta0\Default` ACL，并在结束时删除临时目录、测试账户及配置目录核验无残留。

- **挂起创建闸口（`passed-token-default-dacl-gate`）**：对 `LogonUserW` 原始令牌经 `DuplicateTokenEx(..., 0, ...)` 复制一次性主令牌副本（注：先前缩窄句柄掩码 `0x008B` 时 `CreateProcessWithTokenW` 返回 `5`），仅对副本设置 `TokenDefaultDacl = [Host(GA), SYSTEM(GA), OWNER RIGHTS S-1-3-4(0)]`。经 `CreateProcessWithTokenW`（显式 `WinSta0\Default`、`CREATE_SUSPENDED`）创建的受测进程与主线程实读 DACL 仅含上述 3 条 ACE，不含 A 用户 SID 与 Logon SID。异 Logon SID 与同 Logon SID 两组 A 模拟探测均对普通 A 正对照 20/20 获准（含 9 项进程、5 项线程关键权限及终止/查询/`READ_CONTROL`），对受测挂起目标和提升宿主负对照均 20/20 返回拒绝（`error = 5`）；受测进程全程挂起（`resumeCalls = 0`），桌面与 `WinSta0\Default` 指纹不变。同期附带的独立 `.NET` A 进程因不改桌面 ACL 在 DLL 初始化阶段以 `0x8007045A` 退出。本机报告为 `.prototype/mock-results/windows-a-token-default-dacl-120dac77e5f1471b.json`，哈希前 12 位 `425864019665`（前置排障记录 `c972ce5f82b1420b`、`799995573cf54e19` 均已回滚留档）。
- **第 1 层恢复运行 → 第 2 层挂起创建（`passed-layer1-resumed-to-layer2-suspended`）**：以纯 `KERNEL32.dll` 导入（无 `USER32.dll`、`/SUBSYSTEM:WINDOWS`）的原生 x64 合成第 1 层启动器替代受 `0x8007045A` 影响的 `.NET` 入口。宿主验证挂起态后调用 `ResumeThread`（返回前一挂起计数 `1`），第 1 层正常运行，完成内部线程与事件同步，并经同用户 `CreateProcessW` + `STARTUPINFOEX`（`PROC_THREAD_ATTRIBUTE_JOB_LIST`）+ `CREATE_SUSPENDED` 挂起创建第 2 层合成子进程（`layer2ResumeCalls = 0`）。宿主直读确认第 2 层从创建起继承相同 3 条 ACE 的硬化 DACL 且处于挂起态（`threadUserTime = 0`）。异/同 Logon SID 两组 A 探测对普通正对照 20/20 获准，对**运行中的第 1 层**、**挂起中的第 2 层**及宿主负对照全部 20/20 返回 `error = 5`（120 项拒绝检查 0 违例）。发送停止信号后第 1 层终止第 2 层并退出 0，桌面与 `WinSta0\Default` 指纹不变，临时目录与账户均已回收。本机报告为 `.prototype/mock-results/windows-a-layer1-resumed-852cbc1220414253.json`，哈希前 12 位 `3EE3D7B46219`。
- **PSEC + 4 条静态 BLOCK `ALE_PACKAGE_ID` WFP 启动前封网（`passed-a-psec-startup-network-guard`）**：原生 x64 第 1 层（仅导入 `KERNEL32.dll`、`ADVAPI32.dll`）与第 2 层合成网络/DNS 探针（仅导入 `KERNEL32.dll`、`WS2_32.dll`、`DNSAPI.dll`）。通过挂起不恢复（0 CPU 时间、立即终止）的 `seclogon` 种子获取自带当前交互会话 Logon SID 的标准 A 主令牌，复制一次性副本并将 `TokenDefaultDacl` 硬化为 `[Host(GA), SYSTEM(GA), OWNER RIGHTS S-1-3-4(0x00121400)]`；第 1 层挂起创建后仅恢复其主令牌对象 DACL（保持第 1 层进程/线程 SD 与 `TokenDefaultDacl` 均硬化），使第 1 层经原生 `processmodel.dll!CreateProcessSecurityEnvironment`（仅 `networkLoopback` 能力、出站默认拒绝、`MXC-Loopback`、无代理）挂起创建第 2 层时，第 2 层自出生即继承硬化 Process/Thread DACL（仅含 Host、SYSTEM、`S-1-3-4` 及系统追加的本容器 AppContainer SID，不含 A 用户 SID 与任何 Logon SID）。
  - **正对照**：同配置 PSEC 不装 WFP 规则时，第 2 层直连临时回环哨兵 TCP=1/1、UDP=1/1（唯一标记精确命中），退出后该容器 SID 残留 WFP 条目数为 `0`。
  - **闸口与仲裁**：受测第 2 层保持挂起（`threadUserTime = 0`、`threadKernelTime = 0`、`inJob = true`、独立新容器 SID、仅 `networkLoopback`）；异/同 Logon SID 两组 A 探测对普通正对照 20/20 获准，对第 1 层和挂起中的第 2 层全部 16/16 返回 `error = 5`（0 违例）。仲裁遍历 `679` 条现有过滤，2 条 `sing-tun` 规则均按 `ALE_APP_ID` 与本轮固定合成映像互斥排除，选用子层权重 `65533`。
  - **规则安装、读回与单调时序**：写入前落盘恢复清单，单事务提交 4 条非持久 Static BLOCK（IPv4/IPv6 `ALE_AUTH_CONNECT` 与 `ALE_AUTH_RECV_ACCEPT`，唯一条件为本轮 `ALE_PACKAGE_ID`，无代理放行），独立会话逐条读回确认存在且无例外规则；随后由宿主直接对第 2 层调用 `ResumeThread`（返回前一挂起计数 `1`）。同一单调时钟严格满足 `wfpCommitStart <= wfpCommitEnd <= wfpReadbackStart <= wfpReadbackEnd <= hostResumeBefore <= probeEntry <= probeFirstSocket`。
  - **阻断、DNS 与宿主连续性**：受测第 2 层 TCP `connect` 同步返回 `WSAEACCES (10013)`（发送 0 字节），无连接 UDP 由内核在 `ALE_AUTH_CONNECT_V4` 丢弃，临时哨兵实收 TCP=`0`、UDP=`0`；`DnsQuery_W` 返回 `5`、`GetAddrInfoW` 返回 `11001`；独立 DNS ETW 确认 `Dnscache` PID 稳定、零丢包、容器代发/回包为 `0`、未知角色为 `0`、宿主发送 `12` 次。阻断前/中/后宿主旧 TCP 回环连接、新连接与公网 DNS 全部正常。
  - **清理与局限**：结束时进程树退出、5 个 WFP GUID 独立核验消失、容器 SID 残留过滤数为 `0`，`WinSta0`/当前桌面/`WinSta0\Default` 指纹全程未变（0 次桌面 ACL 写入），临时目录、测试账户及用户配置目录全部删除。本机报告为 `.prototype/mock-results/windows-a-psec-startup-guard-6c4929304d714ae9.json`，哈希前 12 位 `6A3A515019C3`（原生 IPv6 与 IPv4 入站本轮仅核对规则读回；代理放行例外、B 账户、真实客户端/MSIX 激活及原生时区尚未进入本轮实测）。
- **2026-11-26 Phase 1 · 启动前封网 + 仅单端口动态代理例外 + 4 类故障 3 秒内断流闭环（`passed-a-phase1-proxy-guard`）**：在同一台 Windows 11 build `26300.9974` 上，于 Phase 0 启动前硬化 PSEC + 4 条静态 BLOCK `ALE_PACKAGE_ID` 基线上，接入纯原生 x64 Winsock + Schannel TLS 1.2 客户端（`layer2_phase1_client.c`，无 `.NET`/无 `WinHTTP`）与独立提升进程 `Phase1ProxyOwner`（仅持有 `FWPM_SESSION_FLAG_DYNAMIC` 动态例外规则 `E`：仅放通该 `containerSid` 的 `TCP 127.0.0.1:Pa`），复用 N3 合成转发链 `Entry(Pa, entry-n4 监视 ProxyOwner PID/StartTicks 与 Upstream) → Upstream(Pu) → HTTP/HTTPS Target`（全部使用独立临时端口，不触碰 `10810`/系统 DNS/网卡/TUN，零真实客户端）。
  - **关键发现与最小收口**：Windows 对 AppContainer 令牌执行 `SeAccessCheck` 时对“用户/所有者检查”与“AppContainer SID 检查”取交集；在 Layer-2 挂起态（A1/A2 句柄审计前）同步将 Layer-2 自身 `TokenDefaultDacl` 与自身主令牌对象 DACL 设为 `[Host, SYSTEM, S-1-3-4(仅只读 TOKEN_READ|TOKEN_QUERY_SOURCE = 0x00020018), containerSid(TOKEN_ALL_ACCESS)]`，使容器内 Schannel/SSPI 可查询自身令牌而不授予普通 A 任何修改/复制/冒充/`WRITE_DAC` 权限，进程与线程对象 DACL 保持 100% 不变（A1/A2 对普通正对照 20/20 获准，对第 1 层与挂起中第 2 层仍全部 16/16 返回 `error = 5`，0 违例）。
  - **冷启动封网与单调时序**：冷启动未开例外 `E`，仲裁遍历 `683` 条规则（2 条 `sing-tun` 按 `ALE_APP_ID` 互斥排除，选用子层权重 `65533`），4 条静态 BLOCK 安装与独立读回完成后由宿主独占调用 `ResumeThread`，单调 QPC 严格递增（`wfpCommitStart <= wfpCommitEnd <= wfpReadbackStart <= wfpReadbackEnd <= hostResumeBefore <= probeEntry <= probeFirstSocket`）；冷启动阶段直连 `Pa`、`Pu`、哨兵 TCP/UDP 与两项 DNS 全部零命中/被拒。
  - **健康期仅走单端口代理**：开启例外 `E` 后，经 `healthy1`–`healthy4` 四轮核验，HTTP 与 HTTPS（`CONNECT` + Schannel TLS 1.2 + 严格叶证书 SHA-256 指纹校验）均 `200` 且全链路三端日志精确匹配，同时直连哨兵 TCP/UDP、`Pu`、HTTP/HTTPS Target 及两项 DNS 均保持 100% 阻断。
  - **四类故障注入与 3 秒内收敛**：每轮注入前均在活跃 HTTP/TLS 长流上实收至少 2 条增量标记；四类故障均远低于 `3000 ms` 阈值完成断流、独立读回确认例外 `E` 消失、活跃旧流全部转 `io-error` 且离线探针失败：
    - `refuse`：`232.45 ms`（`upstream-unhealthy`），恢复后旧流无重放（`oldNoReplayAfterRecovery = true`）；
    - `silent`：`1224.65 ms`（`upstream-unhealthy`），恢复后旧流无重放；
    - `owner-exit`（强杀 `ProxyOwner` 进程）：`71.61 ms`（`exception-owner-exit`，Windows BFE 自动撤销动态会话且 `entry-n4` 立即停服），重启 `ProxyOwner` 恢复后旧流无重放；
    - `upstream-exit`（强杀 `Upstream`）：`1185.03 ms`（`upstream-unhealthy`），离线探针全部阻断。
  - **DNS ETW、宿主连续性与全量回滚**：独立 DNS ETW 确认 `Dnscache` PID 稳定、`lossZero = true`、`psecSendReplyCount = 0`、`unknownSendReplyCount = 0`、`hostSendCount = 20`；宿主 5 阶段（`baseline`/`blocked`/`healthy1`/`fault2`/`restored`）公网 DNS、旧 TCP 回环连接与新连接全部正常；`WinSta0`/当前桌面/`WinSta0\Default` 指纹全程未变（0 次桌面 ACL 写入）；结束时 0 残留进程、5 个 WFP GUID 独立核验消失、容器 SID 残留过滤数 `0`、临时目录与 `ClaudeStudioLabA` 账户及配置目录全部删除。本机报告为 `.prototype/mock-results/windows-a-phase1-proxy-guard-e5a6f57e908d43ad.json`，哈希前 12 位 `5627754005AA`（原生 IPv6、IPv4 入站本轮仅核对规则读回；标准账户 B 与 A/B 双空间并发隔离、真实桌面客户端/CLI、时区语言矩阵及托管 UI 尚未进入本轮实测）。
- **2026-11-26 Phase 2 · 标准账户 B 与 A/B 双空间并发隔离 + 共享上游故障验证（`passed-ab-phase2-dual-space`）**：在 Windows 11 build `26300.9974` 上同时临时新建两个标准本地账户 `ClaudeStudioLabA` 与 `ClaudeStudioLabB`（均仅属 `Users`），各自独立部署硬化两层 PSEC 容器（`containerSid_A != containerSid_B`）、独立 4 条非持久 Static BLOCK WFP（A 选用子层权重 `65533`、B 选用 `65532`，各自仲裁 2 条 `sing-tun` 按 `ALE_APP_ID` 互斥排除）、独立动态例外所有者 `ProxyOwner_A` / `ProxyOwner_B` 与独立入口 `Entry_A(Pa)` / `Entry_B(Pb)`，共用同一独立临时上游 `Upstream(Pu)` → 合成 HTTP/HTTPS Target（全部独立临时端口，不触碰 `10810`/系统 DNS/网卡/TUN，零真实客户端，0 次桌面 ACL 修改）。
  - **6 视角跨账户句柄闸口与双冷启动封网**：同用户异 Logon、同用户同 Logon、跨用户（B 查 A、A 查 B）共 6 视角审计，普通正对照全部 20/20 获准，对 A/B 的第 1 层与挂起中第 2 层（含跨用户查对方普通进程）全部返回 `error = 5`（`0` 违例）；A、B 均严格满足单调 QPC 时序，冷启动对自有入口、对端入口（`crossPort` `WSAEACCES 10013`）、`Pu`、哨兵与两项 DNS 全部零命中/阻断。
  - **并发健康态与跨端口互斥**：15 轮分空间探针全部通过；健康期 A 仅走 `Pa`（HTTP/TLS 1.2 均 `200` 且仅命中 `entry-a`+`upstream`+`target`，`entry-b` 交叉命中为 `0`），B 仅走 `Pb`（`entry-a` 交叉命中为 `0`）；A 直连 `Pb` 与 B 直连 `Pa` 全程返回 `WSAEACCES (10013)`。
  - **独立空间隔离（仅强杀 `ProxyOwner_A`）**：强杀 `ProxyOwner_A` 后，A 在 **`209.3 ms`** 内收敛断流（`exception-owner-exit`、`E_A` 独立读回消失、离线探针零命中、恢复后旧流无重放）；同一时段 **B 100% 不受影响**（`E_B` 保持存在、B 活跃 HTTP/TLS 长流从 `2` 条连续推进至 `14` 条增量标记、B `healthy2` 新探针持续 `200`）。
  - **共享上游三类故障全收敛**：向共同 `Upstream(Pu)` 注入三类故障，A/B 均远低于 `3000 ms` 同步断流、各自例外消失、活跃旧流关闭、离线探针零命中，宿主持续在线：
    - `shared-refuse`：A **`218.8 ms`**、B **`406.13 ms`**（`upstream-unhealthy`），恢复后 A/B 均回 `200` 且旧流无重放；
    - `shared-silent`：A **`1182.16 ms`**、B **`1366.0 ms`**（`upstream-unhealthy`），故障期宿主公网 DNS 与旧/新 TCP 全部正常，恢复后 A/B 均回 `200` 且旧流无重放；
    - `shared-upstream-exit`：A **`1230.01 ms`**、B **`1391.52 ms`**（`upstream-unhealthy`），A/B 离线探针全阻断。
  - **DNS ETW、宿主连续性与全量回滚**：独立 DNS ETW 确认 `Dnscache` PID 稳定、`lossZero = true`、`psecSendReplyCount = 0`、`unknownSendReplyCount = 0`、`hostSendCount = 20`；宿主 5 阶段（`baseline`/`blocked`/`healthy1`/`fault3`/`restored`）全部正常；`WinSta0`/当前桌面/`WinSta0\Default` 指纹全程未变；结束时 0 残留进程、A/B 全部 10 个 WFP GUID 独立核验消失、双方容器 SID 残留过滤数均为 `0`，临时目录与 `ClaudeStudioLabA`/`ClaudeStudioLabB` 账户及用户配置目录全部删除。本机报告为 `.prototype/mock-results/windows-ab-phase2-dual-space-7af629cb7cf74765.json`，哈希前 12 位 `98064AD777D8`（前三次脚本修障运行 `9f1373cf59ed44eb`、`c56336f9a4984f2c`、`9539e34686994e4e` 均已全量回滚留档；原生 IPv6 与 IPv4 入站本轮仅核对读回）。
- **2026-11-26 Phase 3 · 新硬化 PSEC 容器下的日常双空间工作流验证（对应 S6，`passed-ab-phase3-dual-workflow`）**：在 Windows 11 build `26300.9974` 上沿用 Phase 2 双标准用户硬化 PSEC + 4 条静态 BLOCK + 单端口动态 `ProxyOwner` + 共享上游基线，新增多路径 PSEC 构建（`BuildLoopbackOnlyPsecV1Multi`）与纯原生 Win32 工作流客户端（`layer2_phase3_workflow.c`，含真实可见 Win32 空间窗口与子进程派生，零真实客户端、零真实邮箱、0 次桌面 ACL 写入、不改动宿主仓库与 `10810`），完成 4 次容器实例生命周期（A/B 首启 + 重启交接，累计 16 条临时静态 WFP 写入，结束全部归零）：
  - **资料物理隔离与跨重启保留**：A、B 各自读写独立资料目录，A↔B 跨资料目录读/写 4 项均被操作系统拒绝（`error = 5`）；重启进入全新容器 SID 后，双方各自资料与已登录状态均完整保留。
  - **交错模拟登录回调**：按“B 发起 → A 发起 → 交叉投递拒收 → 过期边界拒收 → B 先完成且重放拒收 → A 后完成且重放拒收 → A 重启后旧回调拒收（`NO_PENDING_LOGIN`）”全项通过，且已认证身份跨重启不丢失、不串号。
  - **共享合成 Git 仓库单写者与受控交接**：临时目录 `C:\ProgramData\ClaudeStudioABPhase3-*` 下建合成仓库、未授权目录与目录联接别名（`shared-alias`）。阶段 1（A `fs_read_write`/NTFS `Modify`，B `fs_read_only`/NTFS `RX`）：A 写入并经宿主 `git diff` 验证差异，B 可读但覆写与新建均返回 `error = 5`，A/B 访未授权目录均被拒，对直接路径与 Junction 别名申请 B 写锁均报 `WRITE_CONFLICT`；停止 A 后差异保留，交接单写者至 B 并重启双容器后（B `rw`、A `ro`），B 写入并经宿主 `git diff` 核验，A 可读但写入返回 `error = 5`，交接后双空间代理与防旁路探针继续通过。
  - **5 类语言与时区读数（严格分项）**：
    - 窗口语言：A `zh-CN`（可见窗口 `Claude Studio | Space A | zh-CN | Asia/Shanghai`），B `en-US`（可见窗口 `Claude Studio | Space B | en-US | America/Los_Angeles`）；
    - 渲染器/应用层时区：A `Asia/Shanghai`（固定 UTC 基准格式化 `2026-07-01T20:00:00+08:00`），B `America/Los_Angeles`（`2026-07-01T05:00:00-07:00`）；
    - 请求语言（HTTPS 隧道经代理直达目标实读）：A 目标实收 `zh-CN,zh;q=0.9`，B 目标实收 `en-US,en;q=0.9`；
    - 子进程偏好（真实派生 AppContainer 子进程实读）：A `LANG=zh_CN.UTF-8`、`TZ=Asia/Shanghai`（`appContainer=true`），B `LANG=en_US.UTF-8`、`TZ=America/Los_Angeles`（`appContainer=true`）；
    - Windows 原生时区（`GetTimeZoneInformation`）：A/B 主进程与子进程均如实读到宿主机全局时区（`Bias = +480 / UTC-8`、`太平洋标准时间` / `Pacific Standard Time`），明确记录 Win32 系统原生时区为机器级边界、不作伪装。
  - **DNS ETW、宿主连续性与全量回滚**：`Dnscache` PID 稳定、`lossZero = true`、`psecSendReplyCount = 0`、`unknownSendReplyCount = 0`、`hostSendCount = 20`；宿主 5 阶段（`baseline`/`blocked`/`healthy1`/`healthy2`/`restored`）公网 DNS 与旧/新 TCP 全部正常；`WinSta0`/当前桌面/`WinSta0\Default` 指纹全程未变；结束时 0 残留进程、全部 4 个退役容器 SID 的残留 WFP 过滤数均为 `0`，临时目录、合成项目目录与 `ClaudeStudioLabA`/`ClaudeStudioLabB` 账户及配置目录全部删除。本机报告为 `.prototype/mock-results/windows-ab-phase3-dual-workflow-7ada76d572e040ee.json`，哈希前 12 位 `E816C1127630`（首次时区本地化名称修障运行 `f2ade6108ae94287` 已全量回滚留档）。
- **2026-11-27 Phase 4 · 协议与派生子进程覆盖审计（对应 S7，`passed-ab-phase4-protocol-audit`）**：在 Windows 11 build `26300.9974` 上，沿用 Phase 2 双标准用户硬化 PSEC + 4 条静态 BLOCK + 单端口动态 `ProxyOwner` + 共享上游基线，新增纯原生三模式审计器 `layer2_phase4_audit.c` 与编排器 `run-phase4-protocol-audit.ps1`（不新增任何常驻规则、0 次桌面 ACL 写入、不触碰 `10810`/系统 DNS/网卡/TUN，零真实客户端）。
  - **关键架构发现与收口（Layer-3 子进程 TLS 兼容）**：首轮实测（`fed86c3b62444eaf`，已回滚）发现主进程全协议通过、子进程 HTTP 与直连/DNS 阻断均通过，但子进程内 Schannel TLS 1.2 报 `CredFail`，根因是 Layer-3 令牌对象 DACL 继承了 Layer-2 的 `TokenDefaultDacl`（原带 `S-1-3-4(0x00121400)` 缺少 `TOKEN_QUERY`）。在 `PsecStartupGuard.cs` 中保持 Layer-1/Layer-2 进程与线程对象 DACL 及 Layer-2 自身令牌对象 DACL 完全硬化不变（6 视角启动句柄闸口仍 0 违例）的前提下，将 Layer-2 的 `TokenDefaultDacl` 调整为 `[Host(GA), SYSTEM(GA), tokenUserSid(GA), containerSid(GA)]`，既确保 Layer-3 派生辅助进程（Schannel/Chromium/Node）可正常建立 TLS 1.2，又维持跨空间严格隔离与启动前零竞态。
  - **容器外正对照**：普通 A 在容器外命中全部 6 类本地哨兵（`sentinelTcp=1`、`sentinelUdp=1`、`quicUdp=1`、`dotTcp=1`、`dohTcp=1`、`altLoopback 127.0.0.2=1`）。
  - **全协议与派生子进程实测覆盖表（A/B 双空间 × 主进程/真实派生子进程 × 在线/离线双态）**：

| 协议 / 路径 | 角色范围 | 在线态结果（仅开 `Pa`/`Pb`） | 离线态结果（撤除 `E_A`/`E_B`） | 归属与依据 |
| --- | --- | --- | --- | --- |
| HTTP 正向代理（`127.0.0.1:Pa/Pb`） | A/B 主进程 + 子进程 | 均 `200`，三端链路匹配，对端入口交叉命中 `0` | 均 `ConnectFailure`，目标命中 `0` | 动态例外 `E` + `Entry/Upstream/Target` 日志 |
| HTTPS `CONNECT` + Schannel TLS 1.2 | A/B 主进程 + 子进程 | 均 `200`（严格叶证书 SHA-256 校验），交叉命中 `0` | 均 `ConnectFailure`，目标命中 `0` | 动态例外 `E` + 端到端 TLS 目标日志 |
| HTTP / TLS 长连接流（`/hold/`） | A/B 主进程 | 均实收 `>= 2` 增量标记 | 已由 Phase 1/2 复验 `<= 3000 ms` 断流 | 代理隧道流控制 |
| 直连 TCP 哨兵 / `Pu` / Target / 对端代理口 | A/B 主进程 + 子进程 | 均 `WSAEACCES (10013)`，哨兵 `0` 命中 | 均 `WSAEACCES (10013)`，哨兵 `0` 命中 | Static BLOCK `D4`（`ALE_PACKAGE_ID`） |
| 备用回环地址 `127.0.0.2` 直连 TCP | A/B 主进程 + 子进程 | 均 `WSAEACCES (10013)`，哨兵 `0` 命中 | 均 `WSAEACCES (10013)`，哨兵 `0` 命中 | 验证 `E` 严格锚定 `127.0.0.1` 而非 `127.0.0.0/8` |
| 原生 UDP 哨兵 & 代理口 UDP | A/B 主进程 + 子进程 | 内核丢包，哨兵 `0` 命中（`E` 仅限 TCP） | 内核丢包，哨兵 `0` 命中 | Static BLOCK `D4` + 仅 TCP 例外 |
| 模拟 QUIC（本地 UDP 哨兵 & `192.0.2.1:443`） | A/B 主进程 + 子进程 | 本地哨兵 `0` 命中；容器无公网能力且无 UDP 例外 | 本地哨兵 `0` 命中 | `networkLoopback` 单能力 + `D4` |
| 加密 DNS 旁路：DoT（本地哨兵 & `192.0.2.1:853`） | A/B 主进程 + 子进程 | 均 `WSAEACCES (10013)`，本地哨兵 `0` 命中 | 均 `WSAEACCES (10013)`，本地哨兵 `0` 命中 | Static BLOCK `D4` |
| 加密 DNS 旁路：DoH（本地哨兵 & `192.0.2.1:443`） | A/B 主进程 + 子进程 | 均 `WSAEACCES (10013)`，本地哨兵 `0` 命中 | 均 `WSAEACCES (10013)`，本地哨兵 `0` 命中 | Static BLOCK `D4` |
| 系统 DNS（`DnsQuery_W` + `GetAddrInfoW`） | A/B 主进程 + 子进程 | `DnsQuery_W=5`、`GetAddrInfoW=11001`；ETW 容器代发 `0` | `DnsQuery_W=5`、`GetAddrInfoW=11001`；ETW 容器代发 `0` | 无 `internetClient`/`privateNetwork` 能力 + DNS ETW |
| 原生 IPv6（`D6`/`I6`）与 IPv4 入站（`I4`） | A/B 独立子层 | 规则存在性与动作独立读回通过 | 规则存在性与动作独立读回通过 | **边界标注**：原生 IPv6 流量按约定暂缓实测，仅读回核验 |
| 真实外部浏览器与 MSIX 客户端 | 未纳入本轮 | 未验证（留待 Phase 6 专项批准） | 未验证（留待 Phase 6 专项批准） | 遵循开发阶段仅用合成程序约定 |

  - **DNS ETW、宿主连续性与全量回滚**：`Dnscache` PID 稳定、`lossZero = true`、`psecSendReplyCount = 0`、`unknownSendReplyCount = 0`、`hostSendCount = 20`；宿主 5 阶段（`baseline`/`blocked`/`healthy1`/`fault1`/`restored`）公网 DNS 与旧/新 TCP 全部正常；`WinSta0`/当前桌面/`WinSta0\Default` 指纹未变；结束时 0 残留进程、A/B 全部 10 个 WFP GUID 独立核验消失、双方容器 SID 残留过滤数均 `0`，临时目录与 `ClaudeStudioLabA`/`ClaudeStudioLabB` 账户及配置目录全部删除。本机报告为 `.prototype/mock-results/windows-ab-phase4-protocol-audit-40ad4a836cea4de5.json`，哈希前 12 位 `D374F8DE2515`。
- **2026-11-27 Phase 5 · 轻量原生 Windows 控制面 UI 与守护状态机产品化（`passed-phase5-control-plane-selftest`）**：在仓库独立目录 `studio-control-plane/` 中以纯 Windows 内置 `.NET Framework 4.x` (`csc.exe` `/warn:4` 零警告) 构建原生 x64 WPF 桌面控制面与系统托盘应用（`ClaudeStudioControlPlane.exe`，集成实时 PSEC/WFP 后端后仅 `174,080` 字节，零 Electron 开销、零外部依赖，不新增常驻服务、不触碰 `10810`/桌面 ACL/系统策略，零真实客户端）：
  - **核心模块**：`ControlPlaneModels.cs`（强类型状态与 5 类语言/时区模型）、`ProjectLeaseManager.cs`（基于 Win32 `GetFinalPathNameByHandleW` 规范化真实路径的单写者租约、Junction/符号链接别名写冲突拦截、受控交接门禁及默认关闭且硬拦截 `.credentials.json`/`.claude.json`/会话目录的静态模板单向同步）、`HandoffGenerator.cs`（只读 Git 摘要 + 脱敏纯文本 `HANDOFF.md` 生成器）、`StudioEngine.cs`（Fail-Closed 状态机：`Stopped → ColdBlocked → ProxyOnline → FaultCutoff → Stopped`、保留端口 `10810` 硬拦截、单空间临时断网、一键全部急停、宿主连续性探针与内置宿主机用户名 PII 脱敏校验的诊断包导出）、`LivePsecBackend.cs`（实时 PSEC/WFP 后端实现 `ISpaceRuntimeBackend`）、`MainWindow.cs`（双空间高对比度蓝/琥珀卡片、系统托盘、`Ctrl+Alt+1`/`2` 全局热键与 4 标签页控制面板）。
  - **自动化端到端自测（9/9 全通过，合入实机后端后复验通过）**：在 Windows 11 build `26300.9974` 上运行 `studio-control-plane/test-phase5-control-plane.ps1`，验证：`reservedPort10810Protected`、`failClosedColdStartWhenUpstreamOffline`、`dualOnlineAndSoftDisconnectIsolation`、`singleWriterJunctionAndControlledHandoff`（真实临时 Git 仓库 + `mklink /J` 目录联接别名冲突 + 未停写者拒交接 + 停写者后交接成功）、`staticTemplateOptInAndIdentityBlocked`（默认关闭 + `.credentials.json` 硬拦截 + 只读 `CLAUDE.md` 同步）、`sanitizedHandoffBriefGenerated`、`wpfWindowAndTrayLifecycleClean`（真实 WPF 窗口实例化与渲染及托盘/热键释放）、`killSwitchRollbackAndSanitizedDiagnostics`（一键急停归零、宿主连续在线、导出 JSON 含 5 类语言/时区读数且零宿主机用户名 PII）与 `selfTestTempCleanup`（临时目录清零、`ClaudeStudioLabA`/`B` 均不存在）。初版报告 `windows-phase5-control-plane-0a3634e0a1e84336.json`（`330D18006B9D`），合入实机后端后复验报告 `windows-phase5-control-plane-223ebc471dda4b94.json`（哈希前 12 位 `500266E63245`）。
- **2026-11-27 Phase 6A · 控制面接入实机双空间 PSEC + WFP 引擎闭环验证（`passed-phase6a-live-control-plane`）**：通过 `studio-control-plane/src/LivePsecBackend.cs`（`LivePsecWfpBackend`）将 `StudioEngine` 直接接入实机两层硬化 PSEC 容器、`ALE_PACKAGE_ID` 4 条静态 BLOCK WFP、独立动态 `ProxyOwner` 与 N3 转发链，并以 `studio-control-plane/test-phase6-live-engine.ps1` 在 Windows 11 build `26300.9974` 上驱动真实 `ClaudeStudioLabA`（子层权重 `65533`）与 `ClaudeStudioLabB`（子层权重 `65532`）完成 9/9 全实机验收（不触碰 `10810`/系统 DNS/网卡/TUN/桌面 ACL，零真实客户端）：
  - `liveFailClosedColdStart`：上游离线时双空间冷启动严格停在 `ColdBlocked`，直连/代理/DNS 全部阻断；
  - `liveDualProxyOnline`：接入临时上游后双空间均进 `ProxyOnline`，各自经独立单端口实现 HTTP/TLS 1.2 `200`，对端入口交叉命中为 `0`；
  - `liveSoftDisconnectIsolatesAOnly`：经 `StudioEngine.DisconnectSpaceNetwork("A")` 仅撤销 A 的动态 `ProxyOwner` 与入口监听，A 立即转 `FaultCutoff` 且实测离线，同一时段 B 维持 `ProxyOnline` 且 HTTP/TLS 1.2 持续 `200`；
  - `liveReconnectAndSanitizedDiag`：经 `StudioEngine.ReconnectSpaceNetwork("A")` 恢复 A 至 `ProxyOnline` 且 HTTP/TLS `200`，导出诊断包确认包含 5 类语言/时区读数且零宿主机用户名 PII；
  - `liveKillSwitchZeroResidual`：经 `StudioEngine.EmergencyKillAll()` 一键急停，A/B 进程树全退、全部 WFP 过滤器清零（`residualFiltersA = 0`、`residualFiltersB = 0`）；
  - `dnsZeroLeak`、`desktopUnchanged`、`hostContinuous`、`cleanup` 全部通过（临时目录、`ClaudeStudioLabA`/`ClaudeStudioLabB` 账户及配置目录均清零）。本机报告为 `.prototype/mock-results/windows-phase6a-live-control-plane-62b6383d8b4b4bf2.json`，哈希前 12 位 `1C0F55340239`。
- **2026-11-27 Phase 6B · 合成离线签名 MSIX 激活与 5 进程同容器 PSEC 承接实测（对应 S8 合成范围，`passed-a-phase6b-msix-activation`）**：在 Windows 11 build `26300.9974` 上运行 `mock-desktop/fixtures/startup-permissions/run-phase6-msix-activation.ps1`，经 `mock-desktop/n4-activation-mock/build.ps1 -SignForTest` 离线构建并自签名 `Studio.N4.ActivationMock.msix`（`v1.0.0.0`，SHA-256 前 12 位 `9BBFF0B6129E`，`signerMatches = true`，**零系统证书库写入、零全局 Appx 注册**），解包后由硬化两层 PSEC + 4 条静态 BLOCK `ALE_PACKAGE_ID` WFP 容器拉起冷启主窗口、热启单实例第二窗口及 3 个辅助进程（`StudioActivationHelperOne`/`HelperTwo`/`MediumHelper`）：
  - 6/6 全项通过：`signedMsixBuiltOffline = true`、`allFiveMsixBinariesContainedInPsec = true`（5 个 `.NET WinForms` 进程退出码全为 `0x00000000`，5 份回执均落在同一标准用户 `ClaudeStudioLabA` SID 与同一硬化 PSEC `containerSid` 内，冷启 `warm=False` 与热启单实例 `warm=True` 互斥语义均成立）、`dnsZeroLeak = true`（`Dnscache` PID 稳定、`lossZero = true`、`psecSendReplyCount = 0`、`unknownSendReplyCount = 0`、`hostSendCount = 12`）、`desktopUnchanged = true`、`hostContinuous = true`、`cleanup = true`（0 残留进程、0 残留 WFP 过滤器、临时目录与构建产物及 `ClaudeStudioLabA` 账户/配置目录全删）。本机报告为 `.prototype/mock-results/windows-a-phase6b-msix-activation-47e57065c5f849f8.json`，哈希前 12 位 `B194748962F9`。
- **2026-11-27 Phase 7 · 高保真模拟客户端双胞胎（Desktop + MCP Helper + CLI + OAuth/SSE API）与控制面可插拔适配器全链路实机验收（`passed-ab-phase7-realistic-twins`）**：按用户要求在开发阶段继续不碰真实官方客户端，新建独立目录 `studio-twin-clients/` 构建完全模仿官方接口与工作方式的高保真模拟套件：`ClaudeDesktopTwin.exe`（支持 `--user-data-dir`/`--proxy-server`/`--lang`/`--tz`、单实例互斥、身份绑定目录 `claude-code-sessions/<accountUuid>/<orgUuid>/local_*.json` 与 `local-agent-mode-sessions/`、`claude_desktop_config.json`、Electron 风格 `--type=mcp-helper` 子进程及内嵌 CLI 调用）、`ClaudeCliTwin.exe`（支持 `CLAUDE_CONFIG_DIR` 物理隔离与防符号链接校验、`HTTPS_PROXY`/`LANG`/`TZ`、`auth start-oauth/complete-oauth/status`、`-p` 编码工作目录 `projects/<encoded-cwd>/<session>.jsonl` 与 `doctor`）以及本地 TLS 1.2 `mock-claude-api.cjs`（PKCE `S256` 单次校验、Bearer Token 与 `X-Account-Uuid`/`X-Org-Uuid` 绑定、`403 IDENTITY_MISMATCH` 防冒用、真实 SSE 流式响应）；同时在控制面新增 `ClientAdapter.cs` 可插拔适配器并将 `LivePsecWfpBackend` 升级为三层架构（Layer-1 PSEC 创建器 → Layer-2 纯 C 硬化守卫 → Layer-3 Desktop/MCP Helper/CLI 全进程树同容器受控）及幂等故障重连：
  - **12/12 全项通过**（`studio-twin-clients/test-phase7-realistic-twins.ps1`，Windows 11 build `26300.9974`，零真实客户端、零证书库/桌面 ACL 修改、不触碰 `10810`）：
    - `desktopAndCliColdBlocked`：上游离线时 A/B 均停在 `ColdBlocked`，双模拟桌面窗可见且均在各自 AppContainer 内，Desktop 与 CLI 均无法访问 API/直连哨兵/对端代理口/系统 DNS；
    - `oauthPkceAndUuidIsolation`：B 先 A 后交错 PKCE 登录，交叉投递拒收（`STATE_MISMATCH`）、重放拒收、各自生成独立的 `claude-code-sessions/<acct>/<org>/` 与无符号链接 `CLAUDE_CONFIG_DIR/.credentials.json`，A↔B 跨资料读取均被 OS 拒绝，A 携带 B 的 UUID 调 API 被服务端返回 `403 IDENTITY_MISMATCH`；
    - `multiProcessTreeContained`：A/B 各自派生的 `mcp-helper` 与 `ClaudeCliTwin` 全部与各自 Desktop 共享同一 `userSid` 与 `containerSid`（A≠B），且均只能走各自代理、直连与 DNS 全部阻断；
    - `dualProxyApiAndStreaming`：双空间并发调用 `POST /v1/messages` 与真实 SSE 流式响应，服务端实读 `zh-CN,zh;q=0.9` vs `en-US,en;q=0.9` 与各自账户/组织 UUID；
    - `faultCutoffAndSingleSpaceIsolation`：经 `StudioEngine.DisconnectSpaceNetworkOnly(A)` 仅断开 A 时，A 的活跃 SSE 流在 **`290.5 ms`** 内断流且后续对话失败，同一时段 B 的 SSE 流保持开启（`4 → 8` chunks）且新对话持续 `200`；恢复 A 后重连 `ProxyOnline` 正常；随后强杀共享上游，A 在 **`50.9 ms`**、B 在 **`81.4 ms`** 内双双断流；
    - `sharedRepoSingleWriterAndHandoff`：共享合成 Git 仓库阶段 1（A NTFS `Modify` + PSEC `RW`，B NTFS `RX` + PSEC `RO`），B 并发写权租约报 `WRITE_CONFLICT`，A 的 CLI 改写 `app.txt` 并生成编码 JSONL（`git diff` 核验），B 的 CLI 可读但写入被 OS 拒绝；控制面生成脱敏 `HANDOFF.md`（零 Token/UUID/宿主用户名）；A 未停时交接报 `WRITER_STILL_RUNNING`；停 A 后受控交接给 B 并切换 NTFS/PSEC 写权，B 的 CLI 读入 `HANDOFF.md` 完成后续编辑并写入自有独立 JSONL；
    - `localeFiveReadingsHonest`、`killSwitchAndZeroBypass`（TCP/UDP 哨兵命中均为 `0`、退役容器残留 WFP 为 `0`）、`dnsZeroLeak`（`Dnscache` PID 稳定、`lossZero = true`、`psecSendReplyCount = 0`、`unknownSendReplyCount = 0`、`hostSendCount = 20`）、`desktopUnchanged`、`hostContinuous`、`cleanup` 全部通过（临时账户、配置目录、合成仓库与临时目录全删）。本机报告为 `.prototype/mock-results/windows-ab-phase7-realistic-twins-91f24d46c3f84dc5.json`，哈希前 12 位 `C0F2990DC678`（前置排障运行 `601829adcffc4faa`、`34e2711b7d364df5`、`834a71af05d04535`、`381cbb4d227a4715`、`61ce20f42ae345b8`、`8294bb947ecc4240`、`3d8c70a2f6224950`、`fc2c0ecfb7a54c80` 均已全量回滚留档）。
- **2026-11-27 真实官方 Claude Desktop 离线冷启动冒烟实测（用户专项批准，零账号/零联网/不动宿主安装，`passed-a-real-claude-offline-smoke`）**：针对本机已装官方 MSIX 版 `Claude`（`v6.6395.0.0`，`Claude_pzs8sxrjxfjjc`），在不修改 `WindowsApps` ACL、不重装/不注册 MSIX、不碰 `10810` 与宿主资料的前提下，将 `app\` 只读复制到临时标准用户 `ClaudeStudioLabA` 的临时隔离目录，经三层硬化 PSEC + 4 条静态 BLOCK `ALE_PACKAGE_ID` WFP（零代理放行）冷启动真实官方 `claude.exe`（[run-real-claude-offline-smoke.ps1](mock-desktop/fixtures/startup-permissions/run-real-claude-offline-smoke.ps1)）：
  - **关键适配突破（全部零宿主改动）**：① Electron/Chromium 内核在 AppContainer 内初始化嵌套沙箱触发 `0x80000003`，需传入 `--no-sandbox --disable-gpu-sandbox`（由外层硬化 PSEC + WFP 提供 OS 级隔离）；② Layer-2 显式注入 `ClaudeStudioLabA` 独立的 `USERPROFILE`/`APPDATA`/`LOCALAPPDATA`/`TEMP`；③ Node.js `fs.realpathSync` 向上 `lstat('C:\')` 触发 `EPERM`，通过将 PSEC 升级至 **`SchemaVersion 1.1` 并启用内核态 `fs_enumerate`**（对父级路径分量放行元数据枚举，零磁盘 ACL 修改，实测 `C:\` 与 `WindowsApps` ACL 前后一致）彻底打通。
  - **8/8 全项通过**：真实官方 `claude.exe` 成功在 `WinSta0\Default` 渲染出可见主窗口（`Chrome_WidgetWin_1:Claude`）并在隔离 `userdata` 写入 25+ 初始文件；全部 **6 个真实多进程**（`browser`、`utility/NetworkService`、`gpu-process`、2 个 `renderer`、`crashpad-handler`）均落入同一 `ClaudeStudioLabA` + 同一硬化 PSEC `containerSid`；Chromium 网络服务尝试发起外联且读取 `DnsConfig` 被拒后，全量 DNS ETW 核验 8 个观测 PID 的系统 DNS 尝试与代发均为 **`0`**、`CoworkVMService` 未触发（PID 不变）、宿主资料/`WindowsApps`/`C:\`/桌面 ACL 零变化、宿主网络持续正常、结束时 0 残留 WFP 与账户。本机报告为 `.prototype/mock-results/windows-a-real-claude-offline-smoke-bb031e7a1e0d4612.json`，哈希前 12 位 `55DECBE4687A`（前置排障运行 `1f53a9a637a1495b`、`c5adc9e2c7364fb6`、`977e9c38bcb742a1`、`77e147bbc6b44b16`、`d163d603d09c4c0b`、`af318897cd974984`、`f766f839ad864a0a`、`49c7b4290cd14601`、`fe44557f07c44850` 均已全量回滚留档）。
- **2026-11-27 选项 A · 双空间并行真实官方 Claude Desktop（`v6.6395.0.0`）实机隔离与代理路由验收（零真实账号/零外网/零宿主改动，`passed-ab-real-claude-dual-space`）**：在 Windows 11 build `26300.9974` 上运行 [run-real-claude-dual-space.ps1](mock-desktop/fixtures/startup-permissions/run-real-claude-dual-space.ps1)，将官方 `app\` 单份只读暂存至临时共享目录，同时在两个临时标准用户 `ClaudeStudioLabA`（`zh-CN / Asia/Shanghai`，WFP 子层权重 `65533`）与 `ClaudeStudioLabB`（`en-US / America/Los_Angeles`，权重 `65532`）的独立硬化 PSEC 1.1 容器内拉起两份真实官方 `claude.exe`，并接入本地零外网双入口合成代理（`Entry_A(Pa)` / `Entry_B(Pb)` → `Upstream(Pu)` 返回本地合成 `502`，不触碰 `10810` 与真实公网）：
  - **12/12 全项通过**：
    - `dualColdStartZeroProxyHits`：双容器 SID 互异；未开动态例外前冷启动 `Entry_A = 0`、`Entry_B = 0`、`Upstream = 0`；
    - `bothWindowsCoexistSimultaneously` & `allMultiProcessTreesContained` & `isolatedUserDataCreatedSeparately`：两份真实官方 `claude.exe` 在 `WinSta0\Default` **同时并存两个可见 `Chrome_WidgetWin_1:Claude` 窗口**（零单实例互斥冲突），A、B 各自 6 个真实 Chromium/Electron 进程全部 100% 落入各自 AppContainer（共 12 个 `claude.exe` + 4 个守护进程），各自独立写入 `83` 份隔离 `userdata` 文件；
    - `dualProxyTrafficRoutedToDedicatedPorts`：开启 `ProxyOwner_A` / `ProxyOwner_B` 后，真实 `claude.exe` A 经 `127.0.0.1:Pa` 发出 `2` 次 `CONNECT claude.ai:443`，B 经 `127.0.0.1:Pb` 发出 `2` 次 `CONNECT claude.ai:443`（`Upstream = 4`）；
    - `singleSpaceCutoffIsolatesAOnly`：仅退出 `ProxyOwner_A` 撤除 `E_A` 后，独立读回确认 `E_A` 消失且 `E_B` 保持开启，`Entry_A` 保持 `0` 新增命中，B 窗口与进程树维持存活；
    - `coworkServiceUntriggered`、`hostClaudeAndSystemUnchanged`（`WindowsApps`、`C:\`、宿主 Claude 资料目录零变化）、`dnsZeroLeak`（全量 16 个观测 PID 的系统 DNS 尝试与代发均为 **`0`**、宿主 `20` 次、零丢包）、`desktopUnchanged`、`hostContinuous`（5 阶段全过）、`cleanup`（0 残留 WFP/进程、共享暂存目录与双临时账户/配置目录全删）。本机报告为 `.prototype/mock-results/windows-ab-real-claude-dual-space-cebab25ea4204a52.json`，哈希前 12 位 `520B06D1AE76`。
- **2026-11-27 Phase 8（选项 B）· 原生 WPF 控制面直驱双空间真实官方 Claude Desktop + 内嵌纯 C# 双代理与看门狗自动断流验收（`passed-ab-phase8-control-plane-real-desktop`）**：在 `studio-control-plane/` 新增纯 C# 内嵌双入口代理与看门狗 [EmbeddedProxyRelay.cs](studio-control-plane/src/EmbeddedProxyRelay.cs)（强制 `SetHandleInformation(..., HANDLE_FLAG_INHERIT, 0)` 防子进程继承监听套接字）、真实三层 PSEC 1.1 后端 [RealDesktopPsecBackend.cs](studio-control-plane/src/RealDesktopPsecBackend.cs)、纯 `KERNEL32.dll` 守卫 [l2_desktop_host.c](studio-control-plane/native/l2_desktop_host.c) 与 NTFS 单写者执行器 [NtfsSingleWriterEnforcer.cs](studio-control-plane/src/NtfsSingleWriterEnforcer.cs)；[build.ps1](studio-control-plane/build.ps1) 一次性无警告预编译全部 4 个原生二进制（`ClaudeStudioControlPlane.exe` `205,312` 字节 + `StudioProxyOwner.exe` + `StudioLayer1Psec.exe` + `StudioLayer2DesktopHost.exe`），运行期**零外部 `node.exe`、零编译工具链依赖**。经 [test-phase8-control-plane-real-desktop.ps1](studio-control-plane/test-phase8-control-plane-real-desktop.ps1) 在 Windows 11 build `26300.9974` 上由 `ClaudeStudioControlPlane.exe` 自身驱动两份真实官方 `claude.exe`（`v6.6395.0.0`）完成 **12/12 全项通过**：
  - `controlPlaneColdStartBlocked`：硬拦 `10810`，上游离线时双空间停在 `ColdBlocked` 且冷启动内嵌代理命中 `A=0 / B=0`；
  - `dualRealDesktopContainedAndRouted`：重启进在线态后双官方可见窗口同桌面并存，A/B 各 6 个真实 Chromium/Electron 进程全落各自 AppContainer，内嵌代理实收 `A=1 / B=12` 次 `CONNECT claude.ai:443`（零外网本地测试上游）；
  - `softDisconnectAAndReconnect`：经 `StudioEngine.DisconnectSpaceNetworkOnly(A)` 仅断 A（命中冻结、`E_A` 撤除），B 维持 `ProxyOnline`，随后 A 幂等重连成功；
  - `watchdogAutoCutoffOnUpstreamFault`：停掉本地共享上游后，内嵌看门狗在 **`569.5 ms`** 内并行速杀双方 `ProxyOwner`、撤除动态 WFP 例外并将 `StudioEngine` 双方状态自动切回 `FaultCutoff`（`relayUpstreamHealthy = false`）；
  - `ntfsSingleWriterAndSanitizedDiag`、`killSwitchZeroResidual`（4 次容器生命周期结束残留 WFP 均为 `0`）、`coworkServiceUntriggered`、`hostClaudeAndSystemUnchanged`、`dnsZeroLeak`（全量 20 个观测 PID 的系统 DNS 尝试与代发均为 **`0`**、宿主 `20` 次、零丢包）、`desktopUnchanged`、`hostContinuous`、`cleanup` 全部通过。本机报告为 `.prototype/mock-results/windows-ab-phase8-control-plane-real-desktop-a567e4ef42894b8b.json`，哈希前 12 位 `067834CE9375`（前置排障运行 `a6c23f5bacdb4c88`、`4b2a32b869d44527`、`32b866d6a53140b5`、`8476873c8eb542b1` 均已全量回滚留档）。

**当前接手状态（Phase 0–Phase 8 全部核心引擎、内嵌双代理与自动断流看门狗、原生 WPF 控制面及真实官方 Claude Desktop 双空间直驱验收已全部收官并全量回滚）。** 整套控制面与原生辅助二进制已具备零外部依赖的独立运行能力；后续只需在用户批准日常长期标准账户名与真实上游代理端口后即可直接投入日常使用。

本机前期证据位于 `.prototype/mock-results/`。令牌权限报告为 `windows-a-startup-privileges-3ff4986b005149d085975fb0ab1db4bf.json`，哈希前 12 位为 `7A4F186EE1E6`。两次挂起实验分别为 `windows-a-suspended-token-0c788df8c5fa40a981ee07b90e679205.json` 与 `windows-a-suspended-token-1232c400bcdf40938bcefa0b6cd47844.json`，哈希前 12 位为 `7D15124AE75E` 与 `5563C153957A`。

## 拟验证的结构

以下为早期零网络能力、容器内代理方案，S1 的容器内连接未通过；保留用于追溯，不作为当前已实现结构。已验证的替代入口是“仅回环能力的 A 容器 → 受 WFP 限制的宿主代理端口”，其下一轮设计见下文 N1–N4。是否采用替代结构及其新增规则须按该轮确认范围实施。

```text
A 的应用 → A 容器内的 HTTP 代理 → A 专用 IPC ┐
                                          ├→ 宿主转发进程 → 指定上游代理 → 目标
B 的应用 → B 容器内的 HTTP 代理 → B 专用 IPC ┘
```

应用使用自身网络栈支持的代理设置，入口是本容器内的数字回环地址。容器内代理和业务进程都保持零网络能力。只有壳子自己编写的代理组件使用 IPC（本机进程间通信）。宿主转发进程以普通用户运行，连接配置里固定的上游地址，把目标域名交给上游。测试上游仅做合成域名到受控目标的固定映射。HTTP 使用正向代理，HTTPS 使用 CONNECT，TLS 由客户端和目标建立。[HTTP CONNECT 语义](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)

每条业务链路必须通过指定上游到达，或在本空间内失败。未支持代理的原生子进程、UDP 和 QUIC 允许返回失败。若产品必需功能依赖其中一条，该项记为兼容性阻塞。容器策略约束实际进入容器的进程树。同一用户名下的容器外进程和接受委托的系统服务要另查归属。宿主、启动器、转发进程和用户指定的上游属于受信范围。

实验只使用独立临时端口。PSEC 管理容器生命周期内的过滤器，宿主持续在线并沿用日常代理、原有系统 DNS、网卡和 TUN。若下一步需要新增系统规则、持久权限或改变隔离方式，先说明原因、影响和撤销方法，再按确认范围实施。

## 分步计划

| 步骤 | 前置条件 | 用户可查看的交付物 | 放行依据 |
| --- | --- | --- | --- |
| S1 · A 的容器内回环 | 已有零网络能力基线 | 窗口显示另一进程返回的随机标记，附双方身份和反向对照 | 同一容器两进程互通，容器与普通宿主监听器隔离 |
| S2 · A 的专用 IPC | S1 通过 | 宿主转发进程和容器内代理双向收发标记，记录未授权方的结果 | 通道归属可证，关闭即断，双方端点均回收 |
| S3 · A 的标准代理 | S2 通过 | 普通模拟窗口经临时上游完成 HTTP、HTTPS 请求 | 上游收到原始域名，目标收到同一请求的标记，直连和系统 DNS 代发为零 |
| S4 · A 的故障与恢复 | S3 通过 | 已有流、重试、换端口及宿主健康的逐阶段报告 | 故障期间零旁路，恢复仅经新确认的上游 |
| S5 · A、B 同时联网 | S4 通过 | 两个可操作的模拟窗口及并发请求归属记录 | 共用一个上游，不能跨用入口，停一个不影响另一个，共同故障只影响 A、B |
| S6 · 日常双空间工作流 | S5 通过 | 在新容器下可演示资料、登录、项目、语言和时区 | 在各自标准用户及容器身份下重验业务结果 |
| S7 · 网络覆盖与回滚 | 已有可用的双空间原型 | 每条协议、辅助进程和代发服务的覆盖表，含缺口及恢复记录 | 每个必需路径都有归属、出口或阻断证据，并能安全撤回 |
| S8 · 官方兼容与交付 | 必需路径通过，用户另行批准真实客户端范围 | 适用版本、逐项验收结果、启动与恢复入口 | 真正的桌面程序及其辅助进程满足约定的 A1–A7 |

### S1 · 两个进程能否在 A 容器内通信

1. 复用 A 的零能力策略。固定本轮运行号，在同一次 ProcessContainer 实例中启动可见的模拟客户端和独立监听进程。记录用户 SID、容器 SID、Job 归属、PID 和窗口。读回两个令牌，核对 `internetClient`、`internetClientServer`、`privateNetworkClientServer` 均未授予。给普通宿主另设对照端口。
2. 监听进程独占绑定 `127.0.0.1` 的临时端口。模拟窗口把该端口设为标准 HTTP 代理，向一个新的合成域名发请求。监听进程收到含域名的代理请求后，直接返回本次标记。分别记录绑定、监听、连接、收发的结果。该步无需宿主转发或外部网络。
3. 从容器连接宿主对照监听器，再从普通宿主连接容器监听器。要求跨边界的标记均未送达。与此同时让宿主成功访问自己的对照监听器。用原生子进程复核两项 DNS 探针，按下文规则取证。
4. 窗口读回正确标记、身份与令牌一致、跨边界零命中、DNS 和宿主对照通过并完成清理，才进入 S2。若绑定或连接被拒，报告首个失败调用、错误码、双方令牌与有效对照，在此停下。保留零能力基线，提交其他有系统支持的应用接入方式及其影响供评审。

原工作区的 `mock-desktop/` 下已有 `windows-lab-psec-probe.cs`、`windows-lab-psec-stopped.ps1`、`windows-lab-psec-observe.ps1` 和 `windows-lab-psec-result.ps1`。从这些入口扩展新的实验模式，给 S1 分配独立报告名，保留已有两份对照报告。当前公开文档批次未分发模拟器源码，换机接手时需先取得对应源码和已验证版本的 SDK。

#### S1 结果与候选方案

实测使用 Windows 11 build `26300.9974`、MXC SDK `1.1.0` 和 `base-container`。复验入口是 `mock-desktop/windows-lab-psec-stopped.ps1 -Stage <已校验的实验目录> -Loopback`，使用 Windows PowerShell 5.1。报告单独保存在 `.prototype/mock-results/windows-psec-s1-loopback.json`，SHA-256 前 12 位为 `E5A336692872`。前两份 ProcessContainer 对照报告仍可复核。

| 验收项 | 实测 |
| --- | --- |
| 标准代理正对照 | 普通宿主进程运行同一监听器。标准 `HttpWebRequest` 经数字回环代理得到正确标记，两端正常退出。 |
| 容器归属 | 模拟窗口可见，监听器和原生 DNS 子进程占用各自独立的 PID。三个进程的用户 SID、容器 SID、会话均相符，都处于 Job，所查的三项网络能力均未授予。 |
| 容器内连接 | 监听器在动态端口成功执行 `Bind` 和 `Listen`。窗口显式使用该 HTTP 代理，`HttpWebRequest.GetResponse` 在连接阶段返回 `ConnectFailure`，内层套接字错误为 `10013 / AccessDenied`。监听器接受 0 条连接。具体执行阻断的系统组件尚未定位。 |
| 双向跨边界对照 | A 容器外 TCP、UDP 目标各命中 1 次，容器内各 0 次。普通宿主连接容器监听器超时，监听器收到 0 条宿主请求。 |
| 系统 DNS 和宿主 | `DnsQuery_W` 返回 5，`GetAddrInfoW` 返回 11001。两项探针各 0 次发送、0 次回复，采集零丢失。宿主测试前、运行中、结束后的新旧 TCP 对照及 DNS 均通过。宿主 TCP 对照限于回环。 |
| 清理 | 实验进程、端口、SDK 暂存目录和原始 ETL 已回收。按实验容器 SID 匹配的 WFP 条目从运行时 4 条降至 0 条。 |

判定为 `failed-container-loopback-http`。

##### 官方文档和源码核对

2026-11-20 查阅时，MXC 最新正式发布仍是 `v1.1.0`。同时检查主线提交 `cfc27d9e7e627ba1ed7d978e9727cac7023a4f36` 的代理校验和能力生成逻辑，两者的约束相同。[发布记录](https://github.com/microsoft/mxc/releases/tag/v1.1.0) · [主线代理校验](https://github.com/microsoft/mxc/blob/cfc27d9e7e627ba1ed7d978e9727cac7023a4f36/src/mxc-sdk/src/core/mxc_common/network_parser.rs#L361-L395)

- **Model 3 符合现有隔离要求。** 官方文档规定它没有代理配置和宿主或对端回环授权。文档提到的容器内监听，以及容器内回环排除在外部网络策略之外，均未承诺无网络能力的客户端能连接该监听器。S1 已分别实测到监听成功、客户端连接被拒。微软的另一组实验性 `CreateProcessInSandbox` API 说明了代理配置字段，未给出零能力令牌能使用该代理的支持条件，不能据此替换现行启动方案。[MXC Model 3](https://github.com/microsoft/mxc/blob/v1.1.0/docs/backends/process-container/networking.md#model-3-externally-blocked-most-restrictive) · [Windows 实验性沙盒 API](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox#network_policy-table-networkpolicy-default-empty)
- **MXC 标准代理走 Model 2。** 校验器要求 `runtimeConfig.networkProxy` 配合 `ingress.default=allow`，能力生成代码随即授予 `privateNetworkClientServer`。通过 `allowedProxyPeer` 能限制代理身份和端点，但保留私网能力。此前 A 的 Model 2 冷启动探针仍观察到 4 次系统 DNS 发送和 2 次回复。[配置校验](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/core/mxc_common/network_parser.rs#L361-L395) · [能力生成](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/network_policy_helpers.rs#L68-L91) · [Model 2 范围](https://github.com/microsoft/mxc/blob/v1.1.0/docs/backends/process-container/networking.md#model-2-proxy-only-egress-recommended)
- **单独开放宿主回环也会改变隔离。** 即使 `ingress.default=deny`，开启 `hostLoopback` 仍会授予 `networkLoopback`，并请求通用宿主回环授权。官方回环正例还设置了 `egress.default=allow`，测试目标是宿主的 HTTP 监听器。这个正例无法证明当前拒绝出站策略下的零能力标准代理。S1 运行时读取了前三项常见网络能力，`networkLoopback` 的缺省状态来自本轮对策略和源码的核对。以后若比较回环授权，令牌检查须覆盖第四项能力。[PSEC 策略生成](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs#L24-L43) · [官方回环测试](https://github.com/microsoft/mxc/blob/v1.1.0/tests/scripts/run_processcontainer_network_loopback_test.ps1#L23-L64)

##### 需要评审的变更

| 接入方式 | 原因与影响 | 回滚 |
| --- | --- | --- |
| 使用有身份约束的 Model 2 外部代理 | 让现有 HTTP 客户端使用标准代理。仅对 A 的临时容器授予私网能力并指定独立测试代理。系统 DNS 代发已有失败证据。新增可验证的 DNS 控制前，这条路线无法满足原验收要求。注册测试包或添加防火墙授权要分别确认。 | 先停止 A 的测试进程和子进程，再关闭测试代理并释放 PSEC。若经批准新增包或规则，按对象清单撤除。恢复 Model 3，用原探针复核 A 的零代发、容器过滤器清理和宿主对照。 |
| 单独开放宿主回环 | 可作为研究回环连通性的变更。它为 A 放开通用宿主回环关系，授权粒度超过指定代理。实际允许的方向和连接还受 Windows 构建与出站策略影响。现有验收目标下暂不选用。 | 退出 A 的临时容器和所有测试监听器，恢复禁止宿主回环的策略。重新检查跨边界连接和 DNS。 |
| 应用主动使用专用 IPC | 保持零网络能力，需要应用文档支持自定义传输，或由我们控制客户端代码。普通 Windows 管道句柄可继承，跨 PSEC 启动链仍待证明。只支持标准 HTTP 代理设置的应用依然需要可连接的 TCP 入口。[微软管道句柄说明](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-handle-inheritance) | 关闭本轮两端句柄并退出测试进程。若需要新的 ACL 或命名对象授权，先确认对象、主体和恢复原权限的方法。 |

上述代理入口的源码核对未放行 S2。

##### 系统 DNS 本机调用取证

在 Windows build `26300.9974` 上，用普通标准用户 A 和宿主分别运行 `DnsQuery_W` 与 `GetAddrInfoW(AF_INET)`，每次使用独立合成名称。四次调用均在探针线程记录 RPC 客户端事件 5，在同一 `Dnscache` 进程记录服务端事件 6。两端的接口 UUID、`DNSResolver` 端点、`LRPC` 协议以及操作号 4 一致。对应的服务端事件位于客户端事件和该名称的首个 DNS 发送之间。每个名称随后在相同服务 PID 下记录 2 次 DNS 发送和 1 次回复，载荷中的客户端 PID 与探针一致。报告保存在 `.prototype/mock-results/windows-dns-rpc-observation.json`，SHA-256 前 12 位为 `3D6E9B1AC866`。[微软本地 RPC 协议说明](https://learn.microsoft.com/en-us/windows/win32/rpc/protocol-sequence-constants)

现有 RPC 规则查询成功，返回的列表里没有规则 GUID。本次未安装规则，ETW 未见探针或 `Dnscache` 的 RPC 防火墙阻断事件。RPC 调用开始事件表明服务收到了请求，缺少能证明该调用经过 `FWPM_LAYER_RPC_UM` 的分类证据。Windows 11 build `26100` 上已有同接口规则未阻止系统代发的公开实测。目前继续把这条方案视为未放行。会话、原始跟踪、模拟进程和临时文件已清理。[微软 WFP 层说明](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/run-time-filtering-layer-identifiers) · [Windows 11 公开失败实测](https://github.com/fmuecke/wfp-lock/issues/1)

2026-11-22 直接回读 WFP 引擎的过滤器表。共读到 872 条过滤器，其中 IPv4 连接授权层 69 条，`FWPM_LAYER_RPC_UM` 为 0 条。同期查询 `Dnscache` 的模块列表，共读到 42 项，包含 `RPCRT4.dll` 和 `dnsrslvr.dll`，未见 `RpcRtRemote.dll`。这两项都是时点快照，不能推断安装过滤器后本地调用是否会被分类。现行规则没有可用的匹配观测点，S1 继续停在评审。临时状态文件和目录已清理，本机摘要为 `.prototype/mock-results/windows-dns-rpc-wfp-readback.json`，SHA-256 前 12 位为 `EF8EB6BE9A58`。[微软 WFP 查询文档](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wfp)

##### A 的临时 RPC 过滤验证

**已完成，A 的两项查询均未被阻断。** 本次只验证本机构建上的 `DnsQuery_W` 和 `GetAddrInfoW(AF_INET)`，以及宿主 DNS 是否正常。复用 `mock-desktop/windows-lab-dns-rpc.ps1` 的合成探针和 ETW 取证方式。试验使用 A 和宿主两种身份、现有系统解析器和每次独立的 `.test.` 名称。B 不参加，真实客户端不启动。全程无代理监听、代理请求或 `10810` 操作。

**计划中的系统变更。** 仅由短时管理员进程在 WFP 动态会话中创建一个专用子层和一条 `FWPM_LAYER_RPC_UM` 阻断规则，分别分配唯一 GUID。两个条件必须同时满足，接口 UUID 为本机已验证的 `DNSResolver` 接口，调用者令牌匹配 A 的标准账户 SID。规则作用于 A 对该接口的调用，实验窗口内可能影响 A 的其他进程和该接口的其他方法。应用前重新读回现有 RPC 层和 A 的身份。若任一条件不能确认、发现 A 正在运行其他业务进程、或已有 RPC 规则使结果无法归因，就暂停并保持基线。现行系统 DNS、网卡、TUN、审计策略和服务配置不纳入变更。动态会话保证本轮 WFP 对象可回收，运行时模块是否立即卸载另行记录，无需重启系统服务。[微软过滤条件](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer#fwpm_layer_rpc_um) · [条件数据类型](https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers-) · [WFP 动态会话](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0#remarks)

| 阶段 | 操作与观测 | 进入下一步的条件 |
| --- | --- | --- |
| 基线 | 启动临时 DNS Client 和 RPC 元数据 ETW，记录 `Dnscache` PID、RPC 层现有规则。依次让 A 和宿主用两项 API 各解析一个新名称。 | 四次均能把探针 PID、RPC 调用和 `Dnscache` 的 3010 发送及 3011 回复对应起来。任何一项缺少正对照就不加载规则。 |
| 装载 | 在同一动态会话中提交专用子层及规则。按 GUID 回读层、动作、接口条件及 A 的 SID 条件。 | 两个条件都存在且完全相符。回读只确认装载。先让宿主用两个新名称复测，任一查询失败就退出并回滚。 |
| 命中 | A 两项 API 依次运行，各用新名称、独立探针 PID 和分开的时间窗。在本机已核实的 `Microsoft-Windows-RPC` 事件 2 中找目标接口和本轮过滤器 GUID。用 A 探针的调用窗、探针或服务 PID 及可用的 RPC 关联字段归因，每个时间窗只运行一个 A 探针。 | 每项 API 都须有可归因的实际阻断事件。安装成功、应用返回拒绝访问、DNS 零发送、普通 RPC 调用开始事件均不能单独证明命中。无法唯一归因时记为证据不足。`netsh rpc` 的规则审计只支持 `permit`，本试验不以开启全局审计获取阻断证据。[微软 `netsh rpc` 文档](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-rpc) |
| DNS 与宿主 | 规则仍在时，宿主再使用两项 API 和独立新名称，核对成功状态、3010、3011 和客户端 PID。同时持续跟踪 A 两个名称至规则退出后的收尾，排除迟发和重试。 | A 两项均确实命中且没有对应 3010，宿主两项均成功并有发送、回复。服务 PID 保持一致，ETW 无丢失。如果 A 仍有任一 3010，本实验未阻止代发。即使看见 RPC 阻断，也要记录 DNS 仍发出的事实。 |
| 回滚 | 停止本轮 A 探针，关闭专用动态会话。按两个 GUID 回读规则及子层均已消失，核对 RPC 层回到基线。用新名称复跑 A 与宿主各两项 API，再关闭 ETW、确认会话已结束并清理原始跟踪和暂存文件。 | A 与宿主重新观察到发送、回复，且本轮 WFP 对象、跟踪和文件均已回收。保留脱敏计数和必要事件关联。 |

规则激活期间设独立超时，最长 60 秒。宿主 DNS 异常、规则回读不符、服务 PID 改变或观察器异常时，立即关闭规则会话。正常关闭、进程异常退出和回滚读回都围绕同一份对象清单。若发现残留，由管理员仅按记录的 GUID 删除本轮对象，再重复回滚对照。任一必要观察缺失时，记录具体缺口；两项 API 全部达到命中、零代发和宿主对照标准后，结论也只覆盖本次 A 的两项已测调用。

2026-11-22 在 Windows `26300.9974` 完成实测。规则的接口和 A 的 SID 条件均已回读，从规则进程启动到确认对象消失不超过 1.892 秒。A 两项调用在规则验证成功和撤除之间均返回 0，各有一对可对应的 `DNSResolver` 本地 RPC 客户端和服务端事件，各记录 2 次系统 DNS 发送、1 次回复。本轮规则 GUID 的阻断事件为 0。宿主在基线、加规则后以及回滚后共 8 次查询均成功。两次 ETW 跟踪均为零丢失，`Dnscache` PID 一致。

规则与子层按 GUID 验证已移除，RPC 层回到 0 条过滤器。回滚后 A 两项查询和宿主两项查询均复测通过。临时跟踪、原始 ETL、助手进程和暂存目录已清理。未取得实验期间的模块快照，回滚后普通宿主令牌无法读模块清单。本轮确认该规则未阻止这两项代发，无法区分本地调用未进入分类器或进入后未匹配。该规则不能放行 S1 或 S2。

本机证据位于 `.prototype/mock-results/windows-dns-rpc-filter-baseline.json` 与 `windows-dns-rpc-filter-test.json`，SHA-256 前 12 位分别为 `EE0C61591A2E` 和 `E69AED07DAC9`。

##### 本地调用是否进入 RPC 分类层

2026-11-22 只读复核同一份报告及本机事件定义。规则生效时，A 的两项 API 各产生一次可关联的 DNSResolver 服务端调用。在各自 API 起止时间内，`Dnscache` 进程发起的 RPC 客户端事件 5 均为 0；整段跟踪中同一进程有 52 条这类事件。RPC 事件 5、6 记录接口、操作号和传输协议，均没有分类层和用于条件匹配的令牌。事件 2 携带阻断规则 GUID。RPC-Audit 事件 2 有 `IsBlockedByWFP`，模板没有逐条件比较结果。管理员只读查询原实验 UTC 18:05:19 至 18:05:24 的 Security 日志成功，5712 共 0 条，5152、5156、5157 中与本轮规则运行 ID 对应的记录为 0。此次查询没有启用审计或重跑探针。

复核后保留“本地路径可能未进入 RPC 分类”作为文献支持的假设。本机的零 RPC 客户端事件和零安全日志均不能区分分类未发生与观测不完整。采集器只启用指定 RPC 关键字和级别，随后按探针及服务 PID 筛选；整段出现 52 条其他 RPC 客户端事件、ETW 零丢失，均不能证明该分类路径必然产生可见事件。5712 的产生另有审计前提，上轮没有建立其正对照。5152、5156、5157 也没有经过本机 RPC 层覆盖验证。两项 API 分别在管理接口回读成功约 1.334 秒和 1.608 秒后启动；回读只能确认对象存在，服务端策略已就绪仍需证据。当前可靠结论为这条规则在本次窗口内未阻止两项 DNS 代发，根因未定。[RPC 运行时研究](https://www.akamai.com/blog/security/guide-rpc-filter) · [另一 Windows 版本对同接口移除 SID 条件的实测](https://github.com/fmuecke/wfp-lock/issues/1) · [微软 RPC 审计策略](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-rpc-events)

待确认的实验须先验证观测能力。原阻断实现使用自建子层；微软将 RPC 审计过滤器指定在内置的 `FWPM_SUBLAYER_RPC_AUDIT`。此差异尚不能证明原阻断规则错误，但允许审计实验须核实专用子层、审计上下文、当前审计策略和实际事件通道，不能仅更换 action。先让 A 的模拟器访问专用模拟 RPC 接口，以同一套规则安装和采集代码验证命中、SID 条件和事件归属，并比较受支持的网络传输与本地传输。正对照必须验证对应的过滤动作及审计，单纯 RPC 调用成功不算通过。该结果只适用于模拟服务，不能替代 Dnscache 的就绪或分类证据。[微软 RPC 审计子层](https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-sublayer-identifiers) · [微软 RPC 规则审计说明](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-rpc)

只有观测能力成立，才评审对 DNSResolver 依次使用接口条件、接口加 A 令牌条件的两组 permit 审计规则。需采用相同采集设置并在各组前后取得正对照，核实服务端策略传播、连接复用和事件归属。两组都出现可归因的匹配证据，才能证明测试时进入分类并匹配 A；仅接口组命中仍需排除组间状态变化才可归因于令牌条件；两组均零保留未知。原先“只用模拟器”的描述指主动工作负载；仅接口规则实际覆盖宿主对该接口的调用，必须单独批准该范围。permit 的裁决效果需结合子层、权重和 action rights 审核，不能仅凭动作名保证零影响。需要开启全局审计时另行说明影响并等待批准。

本段 DNSResolver 鉴别规则仍待确认。后续回滚按各阶段关闭限时动态会话，按 GUID 验证仅本轮过滤器及自建对象消失，保留系统内置子层，核对基线并复测 A。若范围扩至宿主 DNS 接口，验收还须包括宿主 DNS 对照。S1 未放行。

##### A 的专用模拟 RPC 正对照

2026-11-22（用户时区），用户批准仅对专用模拟接口添加临时规则。在 Windows `26300.9974` 完成实测，接口为 `fd53aacc-6237-4a11-a9dc-093b984145af`。A 标准账户同时运行短时模拟服务和每次新建的客户端，唯一方法收发合成整数，服务安全回调校验 A 的身份。TCP 客户端指定 `127.0.0.1`，服务通过 RPC 运行时分配的临时端口监听，端口授权依赖既有系统策略及服务的身份检查；本地传输使用本轮独立端点。未安装 Windows 服务。未更改 DNSResolver、10810、系统网络规则或全局审计策略；本轮仅增加该测试接口的四条短时 WFP RPC 规则及其子层。

每种传输依次验证无规则、接口加不匹配的合成账户 SID、撤除、接口加 A SID、撤除。规则的条件、动作与上轮 DNS 试验相同，使用自建子层和动态会话；更换测试接口 UUID。四次均读取规则及条件并在结束时按 GUID 验证规则和子层消失。

| 传输 | 无规则与不匹配 SID | 匹配 A SID | 撤除后 |
| --- | --- | --- | --- |
| TCP RPC | 合成整数往返成功 | 服务进程记录事件 2，FilterKey 精确匹配本轮 A 规则，服务方法未接收标记 104。底层客户端在 6 秒截止时仍未返回，由测试器终止，未将其记为返回拒绝访问。 | 同一服务进程内再次往返成功 |
| 本地 RPC | 合成整数往返成功 | 调用成功，服务方法收到标记 109；本轮规则的阻断事件为 0。 | 再次往返成功 |

完整复测共 10 个调用，RPC ETW 零丢失。TCP 证据证明本机这套自建子层阻断规则、A SID 条件和事件 2 观察链可工作，因此自建子层本身不能解释上轮 DNS 阻断失败。本地模拟路径表现出不同结果。模拟服务与 Dnscache 的实现和状态不同，此结果仍未直接定位 Dnscache 内部分类入口；下一步停在证据评审，DNSResolver 新规则仍需用户批准。该轮没有验证 permit 审计或 5712。

预检修正了带认证 RPC 缓冲区长度的处理。首次阻断已产生准确 GUID 的事件，但客户端等待超时且跟踪丢失事件，因此另存为不完整记录；增大临时跟踪缓冲区并直接管理客户端生命周期后完成上述复测。报告为 `.prototype/mock-results/windows-rpc-fixture.json`，SHA-256 前 12 位 `233E8D1CD13D`。四条规则及子层已消失，服务均退出 0，模拟器与规则助手进程数为 0，各次测试端口无监听，跟踪会话、原始 ETL、私有暂存目录和编译的两个助手均已清理。源码入口为 `mock-desktop/windows-lab-rpc-fixture.ps1`，其运行会申请管理员权限并实际安装该测试接口的临时规则。

##### 只读机制核验与仅回环能力候选

用户要求建立目标并持续推进。当前主目标为明确 DNS 代发隔离的可行机制和证据边界，按批准范围推进最小验证。已完成 RPC 正对照和本轮只读分析。下一项涉及隔离变化，维持待确认状态。采用本机 `rpcrt4.dll` 与 `dnsrslvr.dll` 文件版本 `10.0.26100.9949`，核对 PE 调试标识与微软 PDB 的 GUID、DBI age 均匹配。公开符号和离线解码结果仅保存在 `.prototype/windows-lab/rpc-symbols/`，详细摘要在 `.prototype/mock-results/windows-rpc-static-review.json`。

- 本机 `LRPC_SCALL::HandleRequest` 的直接调用包含接口安全描述符检查和服务安全回调。`OSF_SCALL::DoSecurityCallbackAndAccessCheck` 调用 `OSF_SCALL::FwFilter`，再进入 `FwExtFilter`。已枚举运行时函数表范围内的相关直接调用，间接调用和实际执行分支仍有边界。这项静态证据与本机两种传输的正对照、公开运行时研究一致，支持本地 RPC 路径未触发同一种 WFP RPC 过滤的解释。[运行时研究](https://www.tiraniddo.dev/2021/08/how-windows-firewall-rpc-filter-works.html)
- `dnsrslvr!Rpc_Initialize` 将接口 `45776b01-5956-4485-9f80-f428f7d60129` 注册到 `ncalrpc` 的 `DNSResolver`，调用 `RpcServerRegisterIf3` 并传入 DLL 静态描述符。安全回调 `Rpc_SecurityCallback` 调用 `Rpc_IsProtoLpc`，按绑定协议是否等于 `ncalrpc` 返回结果。该注册路径没有读取可供外部替换接口描述符的配置。仍未找到受支持的外部按 A 调整接口 ACL 入口，不能由此断言系统其他路径绝不存在此能力。[接口注册 API](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3)
- 描述符包含 `S-1-15-3-1`、`S-1-15-3-2`、`S-1-15-3-3`。本机 `DeriveCapabilitySidsFromName` 确认它们对应 `internetClient`、`internetClientServer`、`privateNetworkClientServer`。`networkLoopback` 对应独立的长 SID，未列在该描述符中。SID 比对提供候选依据，完整令牌访问判定和 DNS 实测仍需验证。[SID 推导 API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-derivecapabilitysidsfromname)
- MXC v1.1.0 在 `hostLoopback=allow` 时单独添加 `networkLoopback` 并使用 `MXC-Loopback` 宿主回环授权。保持入站默认拒绝、出站默认拒绝且无出站允许规则时，常规能力生成不会添加上述三个能力。注意网络拒绝捕获选项可能额外添加 `internetClient`，此候选须关闭该选项并以实际令牌为准。[能力生成源码](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs) · [默认网络能力源码](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/network_policy_helpers.rs)

**已批准的最小验证。** 只启动 A 的空白模拟器容器，使用 MXC 1.1.0，策略为 `egress.default=deny`、`ingress.default=deny`、`ingress.hostLoopback=allow`，省略 MXC 的 `runtimeConfig.networkProxy` 和专用代理 peer。由模拟客户端显式选择临时数字回环 HTTP 代理，代理仅返回合成响应。运行前读回策略，并读取窗口与子进程的完整网络能力列表，要求三个常见网络能力均不存在、仅回环网络能力存在。若需要添加出站 allow 才能连通，则停止，因为 MXC 该分支会增加 `internetClient`。

验证顺序如下。先复用零能力结果作为对照并确认版本适用性，再核验新的数字回环 HTTP 请求、两项系统 DNS 调用及现有 IPv4 TCP/UDP 直连诱饵。每个 DNS 调用分配新名称，按 A 探针 PID、服务 PID、3010 和 3011 关联，配宿主 DNS 正对照和跟踪丢失计数。代理停止后 A 的代理请求须失败，两项 DNS 仍零代发；恢复后再次得到合成响应。宿主 DNS、受控已有连接和新连接在测试期间保持正常。原生 IPv6 延续暂缓。任何意外能力、DNS 代发、直连命中、宿主异常或缺少正对照，均结束并回收，不放行 S1。

**必要性与影响。** 此方案给标准代理提供一个可能可达的宿主回环入口，同时检验 DNS 能力限制。它会扩大 A 容器对宿主回环的可达范围，MXC 的此选项没有按端口限制，不能据此保证 A 只能访问指定代理。主动探针仅访问本轮合成监听器，10810 保留。当前阶段若通过，下一阶段仍需单独评审按容器限定回环端口和代理故障收敛；本轮通过不能当作产品的强制代理验收。

**回滚与交付。** 结束模拟器进程树、PSEC 和本轮代理，验证容器过滤器退出、全部本轮监听和进程消失，停止 ETW、删除原始跟踪与暂存文件，再复测宿主对照。只复用本机已有实验暂存区权限；若需要额外 ACL、注册包或调整宿主配置则停止报告。实现复用 `windows-lab-psec-stopped.ps1`、`windows-lab-psec-run.ps1`、`windows-lab-psec-probe.cs`，通过独立模式和报告保留既有实验入口。当时的批准仅覆盖回环能力候选；回环端口规则的后续批准及实测另记于下文。

等待确认期间，已补齐 `windows-lab-psec-probe.cs` 的只读令牌报告。新增 `capabilitySids` 保留所有能力 SID，原 `networkCapabilities` 继续识别三个常见网络能力，并加入本机 API 已核实的 `networkLoopback` SID。因此旧零能力验收也能发现意外的回环授权。编译通过，空列表、三个常见能力、单独回环能力及混合无关能力四项合成筛选检查通过，临时编译文件已删除。这些检查没有启动模拟器或容器，尚未构成回环候选的实机验收。启动脚本和策略尚未变更。

##### 仅 A 回环能力实验结果

2026-11-22，用户明确批准本轮候选。入口为 `mock-desktop/windows-lab-hostloopback.ps1`，使用 Windows PowerShell 5.1。它先跑同一执行器的零网络能力对照，再运行 `windows-lab-psec-stopped.ps1 -HostLoopback` 的健康代理阶段。候选窗口及原生子进程均属于标准账户 A、同一 AppContainer 和桌面会话，均处于 Job 中。令牌未含 `internetClient`、`internetClientServer`、`privateNetworkClientServer`，网络能力只有 `networkLoopback`；完整能力列表另含系统生成的容器能力，不能把“一个网络能力”写成“令牌只有一个能力”。

执行器来自微软 v1.1.0 官方发布 ZIP 的 `x64/wxc-exec.exe`，文件版本为 1.1.0，Authenticode 验证有效，签名者为 Microsoft Corporation。其 SHA-256 为 `CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D`，不同于旧实验固定的 `6D466C6B…`，首次启动因此被校验拦下，未运行容器。旧哈希差异来源尚未查明，没有声称两个二进制相同。确认当前官方签名后增加该明确哈希，并重跑同二进制对照，未覆盖旧报告。同版本对照全部通过，报告 `windows-psec-hostloopback-baseline.json` 的 SHA-256 前 12 位为 `83BB3FF27571`。下载使用直连且未使用 10810，最终通过 HTTP 字节范围读取 ZIP 索引和所需条目，没有安装 SDK 或其他平台组件。

| 验收项 | 实测结果与边界 |
| --- | --- |
| 显式数字回环 HTTP 代理 | 模拟窗口收到匹配的随机标记。临时代理记录 1 次窗口请求、1 次响应、0 次读取错误，随后由父进程关闭。仅测 HTTP 合成响应，没有真实上游、HTTPS CONNECT 或已有代理流。 |
| `DnsQuery_W` / `GetAddrInfoW` | 分别返回 5 / 11001。按唯一名称、A 探针 PID 和 Dnscache PID 关联，两项 API 各 0 次服务发送和 0 次回复；健康阶段所有 A 测试名称也没有 3010/3011。跟踪的三项丢失计数均为 0，服务 PID 前后一致。 |
| 非代理目标 | 本轮两个目标均为 **127.0.0.1 的其他临时端口**，TCP 和 UDP 在容器内各命中 1 次。它们证明宿主回环没有被限制到代理端口，不能据此声称外部 IPv4 已泄漏。外部非回环 IPv4 本轮未测，原生 IPv6 继续暂缓。 |
| 代理停机与恢复 | 健康阶段命中非代理回环目标后，按已批准的停止条件结束。**未执行停机、恢复或故障期间已有流测试，不能宣称代理故障即全面断网。** |
| 宿主对照 | 实验前、运行中、容器结束后的三次宿主 DNS 均有响应，ETW 发送和回复正对照成立；受控回环 TCP 的原有连接与新建连接均双向收发成功。没有用这些有限对照代替对宿主所有外部连接的证明。 |
| 回滚 | 候选运行时按容器 SID 读到 6 条 WFP 过滤器，结束后为 0。窗口、子进程、代理以及暂存区内其他进程均已退出，无强制杀进程。实验 TCP/UDP 监听、ETW 会话、原始 ETL、私有取证目录和暂存目录均已清理；没有新增用户资料目录。下载分段、未完成的整包和临时执行器亦已删除。 |

本轮结果为 `failed-nonproxy-host-loopback-isolation`，报告是 `.prototype/mock-results/windows-psec-hostloopback.json`，SHA-256 前 12 位为 `1D5FE486D689`。报告的 `policy.networkless=true` 是既有运行器“省略 MXC 原生代理配置”的内部标志，此模式不代表没有网络能力，实际状态以策略的 `hostLoopback=allow` 和两个令牌为准。结果分类已改成明确指出非代理宿主回环问题，避免把已成功的代理连接写成代理失败。原始观测未改变。

下一步需要单独评审并取得授权，才能增加按 **A 的容器身份和目标端口** 匹配的临时限制。目标是在本轮代理端口以外拒绝回环 TCP/UDP，同时维持两项 DNS 拒绝；需要验证本机 WFP 层的回环覆盖和与 PSEC 规则的优先级，不能只凭静态规则认定有效。限制不得按宿主或 Dnscache 服务身份匹配，不修改 10810。新的最小实验须包含仅 A 断流、宿主正对照和动态会话退出后的规则零残留，批准后再实施。本轮没有添加这些规则，也没有放行 S2。

此前只读符号分析的工具下载最初沿环境默认代理尝试连接 10810，被执行沙箱拒绝。后续成功下载显式使用 NoProxy 直连微软与 NuGet；系统代理配置未改。离线分析使用 Iced 1.21.0，依赖位于本机实验目录，未安装到系统。该只读分析轮次没有启动真实客户端、模拟器或附加系统服务进程，没有新增过滤器或全局审计设置；它与上面的已批准模拟器实测是不同轮次。

##### 仅 A 容器的回环端口限制方案（已执行）

2026-11-22 最初形成方案，后获准实施，结果另见下节。目标是在上轮已证明可达的代理入口前补上限制：A 本次容器只能主动连接 `TCP 127.0.0.1:P`；其他目的地址、端口及 UDP 不可用。P 是本轮独占的临时动态端口，不是 10810。不改系统代理、DNS、网卡、TUN、全局防火墙配置或全局审计，不启动真实客户端、B 容器、Sandboxie 或虚拟机。代理只提供合成数据，不连接真实上游。通过本轮不能代替真实代理、所有系统代发路径或产品故障保护的验收。

**1. 精确匹配身份，不按整个账户封网。** 在 A 的模拟器引导进程就绪、尚未放行测试请求时，通过进程句柄读取实际 `TokenAppContainerSid`，同时核对标准用户 A、进程创建时间、会话和 Job。过滤条件使用 `FWPM_CONDITION_ALE_PACKAGE_ID == 本次容器 SID`，类型为 `FWP_SID`，不用程序路径、PID、自报 A 标签或宽泛的用户 SID 代替。A 的窗口及同容器原生子进程应匹配；宿主进程、临时代理、Dnscache、同一账户在容器外的探针应不匹配。每次新建容器重新取 SID，禁止复用旧 SID。微软定义了该 AppContainer SID 条件，并在 ALE 连接及接收授权层提供支持；PSEC 在本机实际分类时是否带入该 SID，仍由本轮正反对照证明。[身份条件](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers) · [各层支持的条件](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer)

**2. 规则集合。** 以下每条都必须带上述精确 SID 条件，所有动作均为 `FWP_ACTION_BLOCK`。不添加通用放行、不修改 PSEC 或其他软件的现有过滤器。三条 IPv4 出站规则组成唯一端点以外的拒绝集合；同一条规则内条件为 AND，多条规则的阻断范围合起来才是 OR。

| 编号 | WFP 层 | SID 之外的条件 | 作用 |
| --- | --- | --- | --- |
| R1 | `ALE_AUTH_CONNECT_V4` | IP 协议不等于 TCP | 拒绝 A 的 UDP 等非 TCP 出站，包括到 P 的 UDP。 |
| R2 | `ALE_AUTH_CONNECT_V4` | 远端地址不等于 `127.0.0.1` | 拒绝其他 IPv4 目标，也拒绝其他回环地址或宿主网卡地址上的同号端口。 |
| R3 | `ALE_AUTH_CONNECT_V4` | 协议为 TCP，远端端口不等于 P | 拒绝所有其他 TCP 端口，包括访问宿主既有服务；不向 10810 发测试流量。 |
| R4 | `ALE_AUTH_CONNECT_V6` | 无其他条件 | A 的 IPv6 出站全部拒绝，不设置映射地址例外。IPv4 映射连接若归类到 V4，受 R1–R3 管理；归类到 V6 则拒绝。 |
| R5–R6 | `ALE_AUTH_RECV_ACCEPT_V4/V6` | 无其他条件 | 拒绝以 A 容器为接收端的新入站流，防止其他本机进程反向连接 A 的监听器。正常代理响应属于 A 发起的出站流，须在健康代理测试中确认仍可返回。 |
| G（离线闸门） | `ALE_AUTH_CONNECT_V4` | 无其他条件 | 启动校验及受控代理停机期间，临时连 P 也拒绝；V6 始终由 R4 拒绝。 |

上述 R4 是拟纳入本轮确认范围的 A 专属防御性拒绝规则，不是恢复 IPv6 连通性的实验。原生 IPv6 仍按约定暂缓，不改网卡或 TUN；缺少可达正对照时只能记录规则已安装，不能写成原生 IPv6 已实测通过。R2 同时收紧 A 的非回环 IPv4 出站，避免同端口被用于其他地址；不扩大到其他身份。

规则放入本轮新建的独立子层。添加前只读核对相关 PSEC/系统子层的权重、动作和权限位，为新子层选择可先于相关放行动作执行的权重，记录准确数值，不调整现有子层。不能把“BLOCK 一定压过所有 PERMIT”当作前提，硬放行和 callout 仲裁存在区别。若无法建立所需优先关系或实际探针仍能通过，停止并回滚，不自动升级到内核驱动或改动系统规则。[WFP 仲裁](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)

**3. 启动、停机与恢复顺序。** 复用 MXC `egress.default=deny`、`ingress.default=deny`、`hostLoopback=allow`，不启用 MXC 原生代理配置或会增加 `internetClient` 的拒绝捕获。引导进程仅读取身份并等待受控信号，不发网络请求；这只适用于本轮自有模拟器，不作为真实程序启动前隔离已完成的证明。

先启动本轮合成代理并独占 `127.0.0.1:P`，登记 PID、创建时间和绑定地址。以一个 WFP 事务安装 R1–R6 与 G，逐条原生读回 SID、层、动作、比较符、地址、端口、实际权重和 GUID/运行时 ID；任何差异均不放行模拟器。确认代理返回本轮标记后，事务删除 G，才允许 A 开始测试。只允许该明确端点，并不保证绕过现有策略仍然连得上它，代理可达性必须实测。

R1–R6 在健康、故障、恢复三个阶段始终保留。**其他端口从始至终被拒绝，不依赖“发现代理坏了才加规则”。** 受控停机先加 G 并读回，再关闭代理的监听及所有已接受连接；不把仅停止监听当作已关闭旧连接。恢复时保持 G，重建并核对本轮代理、确认无旧流，再删除 G。首轮固定 P，不顺带实现换端口。

另测一次不预先加 G 的代理进程退出。R1–R6 应仍阻止所有替代端口；管理器收到其持有的进程句柄退出信号后加 G，记录退出到闸门提交的时间。在这段检测间隔内，端点规则仍只识别 `127.0.0.1:P`，不能识别后来占用 P 的其他进程。因此，受控停机后使用假代理占 P 验证 G 阻断，但不能将其外推为突然崩溃时的同端口抢占已无竞态。若产品要求完全杜绝该竞态，还需单独设计端口保留或代理身份认证，不在本轮暗中扩大实现范围。

保留一条持续交换编号标记的代理连接，区分“监听停止但旧连接仍活着”和“代理整个进程退出”。对可控故障，代理管理器须关闭所有活动客户端及合成目标连接；对无响应，拟定 **3 秒检测期限**，超时加 G、关流并保持离线。这是拟验收阈值，不是瞬时断流承诺。记录故障注入、检测、G 提交、最后到达标记和连接关闭时间，分别报告检测窗口内的在途数据及离线确认后的送达计数，禁止用重试成功掩盖旧流继续传输。ALE 策略变更会引发已有流重授权，但发生在后续数据包分类时，不能仅凭加规则成功认定所有旧套接字立即断开。[ALE 重授权](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)

**4. 宿主影响和实验限制。** 新增配置只包含一个独立子层及最多七条临时规则，均限定 A 本次容器。规则写入需要本机管理员权限，实际代理仍用普通宿主身份。宿主和 A 容器外探针的 DNS、新旧连接，以及宿主正常使用 10810 的条件不应改变。既有连接可能遇到 WFP 政策更新触发的重授权，所以“宿主不受影响”仍要实测，不只靠 SID 条件推断。不主动连接、停止、绑定或修改 10810。A 的其他回环功能和作为 TCP/UDP 服务端的功能会受限，这是本轮有意的收紧。

采用 `FWPM_SESSION_FLAG_DYNAMIC`，不设持久或启动期过滤器，不安装驱动、服务或计划任务。动态会话结束会自动删除本轮对象，有利于回滚，但也意味着规则管理进程意外退出后保护会消失。本轮监督器须在管理器丢失、BFE 状态异常或证据不完整时终止 A 的整个实验进程树，并停止测试；**该响应的时序不构成零竞态的产品级保护**。本轮不故意杀规则管理器来宣称故障安全，生产级管理器崩溃保护需要后续独立方案。[动态会话生命周期](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0)

**5. 验证顺序与通过条件。** 每一步均记录本机版本、执行器及探针哈希、进程与容器身份、独立运行号和清理结果。整个测试设硬截止时间；某个等待超时立即进入回滚，不无限等用户关闭窗口。

| 步骤 | 操作与必须得到的证据 |
| --- | --- |
| 基线与身份对照 | 只用 A 的受控模拟器重验代理和两个非代理回环 TCP/UDP 诱饵原本可达。宿主及 A 容器外探针访问相同端点作为不匹配身份对照。新容器 SID 来自实际令牌，不使用另一个真实账户或 B 容器。 |
| 规则读回与身份匹配 | 原子安装并读回完整规则。相同探针、目标和 PSEC 策略下，A 容器请求应从可达变为被阻断，宿主及 A 容器外仍可达。先用 G 验证 A 连代理也被拒；去掉 G 后只恢复代理，不恢复其他端口。若连 G 都不能阻断，不能解释成其余规则已生效。 |
| 健康代理 | 窗口和原生子进程分别经 `127.0.0.1:P` 收到唯一标记；两个其他端口零命中。另测 UDP 到 P、其他 127/8 地址和可建立基线的宿主本地 IPv4 目标；所有未授权目标零命中。反向连接 A 合成监听器被拒。没有正对照的地址或协议标为未验证，不改系统设置补造基线。 |
| DNS | 健康、故障、恢复分别使用新域名调用 `DnsQuery_W` 和 `GetAddrInfoW`。按探针 PID、服务 PID 和名称核对 3010/3011 发送及回复均为零，并要求 API 返回失败。每阶段都有宿主及必要的容器外 DNS 正对照、服务 PID 稳定和跟踪零丢失。不封 Dnscache 服务本身。 |
| 故障与旧流 | 冷启动端口不监听；受控关闭全部代理连接；代理进程突然退出；代理保持旧流却停止应答。逐项验证 A 新请求失败、其他端口零命中、已确认离线后旧流的新标记零送达。记录实际检测和关闭耗时；观察到违规送达即失败。 |
| 同端口与恢复 | 保持 G 时，让本轮假代理占用 P，A 不得收到它的标记。清理假代理、核验正确代理并恢复，仅新请求恢复；不重放故障前排队的业务。此步骤不证明突然退出时的端口抢占竞态已解决。 |
| 宿主全程对照 | 保持一条宿主受控 TCP 连接持续双向发送编号数据，每阶段另建新连接并取得响应，同时解析新域名。检查成功率、错误与延迟，不只检查 TCP 状态。对照范围是受控连接及默认 DNS，不把它写成所有互联网连接的保证。 |
| 回滚复测 | 停 A 及代理，撤销本轮对象并读回零残留；宿主对照继续正常。若需证明撤销后 A 恢复原状态，只新建一个受控模拟器容器做短时非代理诱饵正对照，再立即关闭；不得在仍运行的旧 A 上先删规则让它自由联网。 |

规则归因先用完整读回与上述“同身份、同目标、只有规则不同”的对照建立证据。若本机已有的 WFP 网络事件采集可用，追加 `filterId → 本轮 GUID` 对应关系；未拿到该事件时明确写“行为对照成立，未取得直接命中事件”，不伪造命中计数。本轮不打开全局审计，也不改变全局 WFP 事件采集开关；如果后续必须开启才能取证，另行说明并请求确认。

**6. 回滚和异常处理。** 修改前保存本轮 GUID、A 容器 SID、P、管理器/代理/模拟器句柄、跟踪名和暂存路径，准备只接受该清单的独立回滚入口。正常或异常退出均先加 G（管理器尚可用时），停止 A 整个进程树并确认退出，关闭代理全部连接及监听，随后在事务中只删除本轮 R1–R6/G 和新子层，关闭动态会话。再用独立只读句柄按 GUID 确认过滤器与子层不存在，核对 PSEC 自有过滤器随容器退出而清零、实验端口及进程消失、ETW 停止、临时文件删除、宿主对照成功。禁止使用全局 firewall reset、删除其他软件规则或改动 10810。撤销失败就保持 A 停止，保留清单继续清理，不宣布回滚完成。

**7. 获批后的最小文件范围。** 新增 `mock-desktop/windows-lab-wfp-container.cs`，复用既有 ABI、事务和读回方式，但不得直接复用旧 `windows-lab-wfp.cs` 的“两账户持久规则”安装入口。扩展 `windows-lab-hostloopback.ps1`、`windows-lab-psec-stopped.ps1`、`windows-lab-psec-probe.cs`、`windows-lab-psec-observe.ps1` 和结果判定，仅为本轮增加受控握手、规则生命周期、连续流及故障阶段。保留上轮报告，新增独立的 `windows-psec-hostloopback-portguard.json` 本机报告，公开文档只存脱敏结论。先检查 ABI、规则构造/拒绝宽泛身份、解析和编译，再运行上表中的必要实测；不启动浏览器。若 SDK 入口或暂存区权限要求扩大到新 ACL、包注册、系统设置或其他隔离方案，停止实施并补充确认。

用户已确认继续本方案。实施范围为上述 A 专属六条基础拒绝规则、临时离线闸门、普通宿主合成代理、仅 A 模拟器及现有 DNS ETW 取证与回滚，未转为常驻配置。实验通过最多证明本机所测端点和协议下的限制成立；同端口恶意抢占的全时序防护、规则管理器崩溃保护、未测原生 IPv6及其他系统服务代发仍保留为后续验收项。

##### A 容器端口限制与故障矩阵实测

2026-11-22（America/Los_Angeles），Windows `26300.9974`、MXC SDK `1.1.0`。仅使用 A 标准账户、WinForms 模拟器及普通宿主合成 HTTP 代理。窗口、监听子进程和原生探针读回相同的容器 SID，网络能力仅有 `networkLoopback`。没有启动真实客户端、B 或 Sandboxie，没有访问或修改 10810，也没有改变系统 DNS、网卡、TUN 或全局审计。

健康门槛报告为 `.prototype/mock-results/windows-psec-hostloopback-portguard.json`，SHA-256 前 12 位 `6BA4C15BD090`。完整故障报告为 `.prototype/mock-results/windows-psec-hostloopback-portguard-flows.json`，SHA-256 前 12 位 `985E092045BC`，判定 `passed-container-portguard-fault-matrix`。完整报告保存源码哈希、执行器哈希、逐阶段读数、进程身份、带时刻的编号标记和清理结果。运行时间记录为 UTC，日期展示采用客户端时区。

| 验收项 | 本次证据 |
| --- | --- |
| 身份和规则 | 精确使用本次 A 的 `ALE_PACKAGE_ID`。首次安装读回七条 BLOCK，打开闸门后读回六条，之后各次切换均核对完整条件。相同 A 用户但不在容器中的探针仍可访问全部五个合成端点，未变成账户范围或宿主范围规则。 |
| 健康代理和其他端口 | 同一容器加规则前，非代理 TCP/UDP、代理端口上的 UDP、`127.0.0.2:P` 及本机网卡 IPv4 合成端点各命中一次。加规则后，窗口及原生子进程 HTTP 经 `127.0.0.1:P` 收到正确标记，其余五个端点均为零。故障及恢复各阶段仍为零。 |
| 反向连接 | 加规则前宿主可以连接容器监听子进程；加入仅 A 的 RECV_ACCEPT 阻断后连接超时。结论是本次受控反向 TCP 连接被阻断。 |
| 停听与旧流 | 只停止监听后，原连接仍收到六个成功响应，证明“停听”不能替代“断开旧流”。之后先关闸门，再关闭全部活动连接，约 144ms 确认离线。离线后的五次原连接发送尝试均未收到成功响应。 |
| 代理进程退出 | 不预先加闸门，终止持有句柄对应的合成代理进程。退出到闸门确认约 133ms；原连接不能继续收发，新请求失败，离线后五次尝试零成功响应。此间没有实施同端口抢占攻击，不能据此消除检测竞态。 |
| 无响应代理 | 保持旧连接但停止回复，健康探针超时后加闸门并关掉全部活动连接。故障注入到确认离线约 **1.829 秒**，在预定 3 秒内。离线后五次原连接尝试零成功响应。 |
| 不监听端口和假代理 | 代理退出、闸门关闭时，在相同容器中新建原生子进程，HTTP 失败，两项 DNS 被拒。然后假代理占用原端口，A 的新请求仍失败，假代理请求数为零。冷启动证据限于新子进程，未重建全新容器。 |
| 恢复 | 三次恢复均在闸门关闭期间创建并校验新的合成代理进程，宿主健康探针返回正确标记后才开闸。A 的新请求随后成功；三条旧流各自只使用一个 socket，自动重连计数均为零，未以重试成功冒充旧流恢复。 |
| DNS | 健康、离线、不监听、假代理、进程退出、无响应和三次恢复中，已测 `DnsQuery_W=5`、`GetAddrInfoW=11001`，对应探针 PID 的服务发送与回复均为零。宿主及普通 A 的正对照出现可归属的发送和回复，ETW 三项丢失计数均为零，Dnscache PID 不变。 |
| 宿主与清理 | 各阶段宿主 DNS 正常，预先建立的受控回环 TCP 连接和新建连接均能往返标记。实验过滤器及子层按记录 GUID 确认消失，容器 SID 对应条目归零。监听、测试进程、ETW、私有交接目录、SDK 暂存目录及下载片段已回收，无强制清理残留进程。 |

实现入口是 `mock-desktop/windows-lab-hostloopback.ps1 -FlowChecks`，需要原工作区的 A 标准账户条件和经校验的官方 SDK ZIP 片段；片段已按本轮清理要求删除，脚本不会自行下载。WFP 原生接口在 `windows-lab-wfp-container.cs`，规则所有者和独立回滚入口在 `windows-lab-portguard-control.ps1`，故障顺序在 `windows-lab-portguard-scenarios.ps1`，连续流和合成代理在 `windows-lab-portguard-flow.cs`。回滚入口只接受本轮私有证据目录及其中受校验的对象清单，不执行全局重置。

源码已静态编译，PowerShell 已解析校验。对保存的报告重算判定仍通过；另在内存中分别注入直连命中、DNS 代发、宿主连接失败、规则缺失、离线后成功响应、超时和清理残留七种合成反例，判定器均拒绝通过。首次连续流运行因离线后下一个 100ms 发送周期尚未到达就取样而停止，旧连接当时已报 `10053`，没有发现离线后成功响应；已保留 `windows-psec-hostloopback-portguard-flow-sampling-preflight.json`，补足取样窗口后才取得完整结果。更早的优先级及读回预检报告同样保留，没有覆盖原始证据。

**结论边界与下一步。** 本轮证明这个入口在所测模拟器、端点、HTTP 和系统版本下可用，并完成了本次批准的临时规则验收。它还没有转发到真实上游，也没有验证 HTTPS CONNECT、真实外网长连接、B、原生 IPv6、全新容器从创建起的冷启动保护或其他系统服务代发。宿主新旧 TCP 对照限于受控回环，不能表述为所有宿主外网连接均已实测。未开启全局审计，阻断依据是精确条件读回及同容器、容器外正反对照，没有宣称取得每条规则的丢包事件。

规则优先级检查按本次模拟器实际可执行文件排除其他 AppId 的规则，再选择足够优先且未占用的子层权重；当前二进制检查不能替代任意辅助程序的检查。只允许端点不等于认证该端口的进程，动态规则所有者退出也会撤除保护。下一轮应先明确受信代理入口与指定上游的关系、同端口身份校验和规则所有者失效时的保护，再列出新的系统写入及回滚范围交用户确认。不得直接从本轮结果启动真实客户端，或自动部署常驻网络规则。

### 下一轮：上游接入与失效保护设计

2026-11-22。本节先作为设计交付，随后用户批准执行 N1 和 N2。两轮实测另记于下文。旧入口 `CreateContainerGuard()` 将全部拒绝规则放进动态会话；原控制器的正常清理负责退出 A 后撤销它们。突然终止管理器不会执行 PowerShell 的正常清理路径，不能靠 `finally` 保证 A 先退出。N1 为此增加独立的 Static 基础拒绝与 Dynamic 例外模式，保留旧入口和证据。沿用 C#、Windows PowerShell 和现有模拟器，不引入虚拟机、Sandboxie、驱动或常驻服务。

**目标数据路径。**

```text
A 容器中的标准代理客户端
  → TCP 127.0.0.1:P_A（A 的宿主入口）
  → 固定配置的上游 U（首测为独立合成 HTTP 代理）
  → 合成 HTTP / HTTPS 目标
```

后续 B 使用自己的 `P_B`、规则和连接表，共用 U；本节不启动 B。容器仍只授予已测的 `networkLoopback`，不恢复 MXC 原生代理模式的私网能力。管理组件有写规则权限，转发组件以普通宿主身份运行。应用不支持标准代理的路径保持失败，不承诺壳子能透明接管所有协议。

**采用的依据与限制。**

| 机制 | 官方资料能确认什么 | 本项目决定 |
| --- | --- | --- |
| WFP Static / Dynamic 生命周期 | Dynamic 随所属会话结束而消失；Static 不随会话结束删除，但会在 BFE 停止或系统关机时消失。Persistent 才跨 BFE 重启保留。 | N1 用 Static 基础拒绝和 Dynamic 精确放行，先不引入跨重启持久配置。该组合是待测设计，不能拿文档替代本机行为。 |
| 同子层仲裁 | 同一子层按权重匹配，遇到 Permit 或 Block 后不再评估该子层余下规则；其他子层仍参与仲裁。 | 精确放行在同一子层高于默认拒绝，不用新增硬放行压过其他安全产品。 |
| 独占监听与共享 socket | 独占选项在 bind 前设置；复制 socket 描述符可延长底层 socket 生命周期。 | 普通崩溃可用保留监听减小暴露，但不把它当成所有持有者退出后的代理身份认证。 |
| 端口预留 | 运行时预留依赖持有 socket；持久预留可由能取得预留的进程使用。 | 不仅凭一个预留 token 宣称实现独占进程身份，也不在本轮创建全局持久端口预留。 |
| Job 退出联动 | `KILL_ON_JOB_CLOSE` 取决于最后一个 Job 句柄关闭，嵌套 Job 有顺序和兼容约束。 | 作为后续进程清理机制，先核查 MXC 与句柄继承；不能代替网络默认拒绝，也不能从 `inJob=true` 推出已具有此保护。 |

来源：[WFP 对象生命周期](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[子层仲裁](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)、[过滤器标志与权重](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)、[独占端口](https://learn.microsoft.com/en-us/windows/win32/winsock/so-exclusiveaddruse)、[共享 socket](https://learn.microsoft.com/en-us/windows/win32/winsock/shared-sockets-2)、[预留生命周期](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-associate-port-reservation)、[Job 退出](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)。这些资料不承诺控制进程死亡、动态规则撤销、已建立流重授权和 socket 关闭在同一瞬间发生；本项目仍须记录各自时刻及在途数据。

**N1 · 已批准并完成：管理器退出后默认断网。**

交付一个独立模拟实验模式、原生规则读回、独立回滚入口和 `windows-psec-static-guard.json` 报告。仅使用 A、普通宿主合成代理和动态端口 P，不连接真实上游。旧报告及旧动态规则入口保留。本轮最多新增一个 Static 子层、四条 Static 拒绝规则和一条 Dynamic 放行规则，不同时安装旧 R1–R6/G。

| 对象 | 作用层与匹配 | 生命周期与次序 |
| --- | --- | --- |
| D4 | `ALE_AUTH_CONNECT_V4`，精确本次 A 的 `ALE_PACKAGE_ID`，BLOCK | Static；同子层低于 E，拒绝所有未被 E 匹配的 A 出站。 |
| D6 | `ALE_AUTH_CONNECT_V6`，相同 SID，BLOCK | Static；无 IPv6 放行，仍不做原生 IPv6 连通实验。 |
| I4 / I6 | `ALE_AUTH_RECV_ACCEPT_V4/V6`，相同 SID，BLOCK | Static；保留对 A 入站的限制。 |
| E | `ALE_AUTH_CONNECT_V4`，相同 SID AND TCP AND 远端 `127.0.0.1:P`，PERMIT | Dynamic，只有健康校验后才创建；使用高于 D4 的明确权重，不设置 `CLEAR_ACTION_RIGHT`。离线时删除 E，管理器退出时由会话生命周期撤除 E。 |

先用普通非动态会话原子安装子层和 D4/D6/I4/I6，读回后关闭安装会话，确认对象仍存在。随后另起短时管理器持有动态 E。只在自有子层内调整匹配次序，不能把另一子层的 D4 与 E 混用后期待“高权重 Permit 总能覆盖 Block”。继续核对现有硬放行/callout 的实际优先关系。新增软放行若无法与本机 PSEC 策略兼容，停止并回滚，不提升为硬放行、不改其他子层。读回要检查原始与有效权重、条件、SID、生命周期相关标志及运行时 ID。

**宿主影响与新风险：**规则身份范围仍只有 A 容器，宿主、Dnscache、同账户容器外进程及 10810 不应匹配；WFP 策略变化仍需宿主对照。与上轮不同，安装器或管理器退出后，Static 拒绝可能留在 BFE，必须主动清理。因此这轮必须重新确认，不能沿用“动态会话退出就全部回滚”的结论。不安装开机规则，不停止或重启 BFE，不修改 ACL、系统 DNS、网卡、TUN、全局审计或系统代理。

实施顺序和验收：

1. 先完成纯规则构造、精确 SID 拒绝校验、生命周期模式检查及判定器反例；编译通过后才准备实机。保存预分配 GUID、源文件哈希、A 实际身份、进程句柄及创建时间、P、暂存路径。独立回滚进程必须先就绪，并与故意终止的动态管理器分开。
2. A 的受控引导进程等待放行。安装四条 Static 拒绝、关闭安装会话后，用独立句柄确认它们仍在；A 到 P 及其他合成端点全部失败，宿主及容器外正对照正常。
3. 添加 E 并读回，只恢复 A 到 P。窗口、原生子进程各完成标记往返；其他 TCP/UDP 端点仍零命中，两项 DNS 零代发。建立同一 socket 的连续编号流。
4. 只终止持有 E 的管理器，保留独立观察器、A 模拟器和代理。按真实进程句柄退出信号计时，读回 E 消失、四条拒绝及子层仍在。A 新连接失败；继续尝试旧流，记录最后成功数据、重授权/断流和离线确认时刻。不得为了得到通过结果而先杀 A 或先关代理。拟验收期限为退出信号后 3 秒内完成 E 消失和离线验证；观察到离线确认后的成功送达即失败，超时即停止，不改大阈值掩盖失败。
5. 在持续默认拒绝下，新管理器校验同一运行清单和代理健康后再创建 E，仅新请求恢复。分别重测 DNS、受控目标、宿主旧 TCP 流、新 TCP 流和新域名解析。记录管理器退出到 E 消失之间的数据，不能将检测间隔描述成零竞态。
6. 正常结束或任一失败都执行独立回滚：先撤 E、停止 A 全部实验进程并确认退出，再关闭代理全部连接，然后在非动态会话中按清单删除四条拒绝及子层。独立读回全部 GUID 不存在，PSEC 条目、进程、监听和 ETW 清零；**规则撤除之后**再复测宿主 DNS、新连接及从规则安装前保留到此时的旧连接。实验工作上限 90 秒，独立清理器最迟在第 120 秒开始收尾；清理未证实时保存清单并保持 A 停止，不能宣布完成。

清单写入宿主私有目录，不信任 A 可写的配置来选择删除对象。回滚器必须先核对 GUID、SID、规则内容和本轮子层归属，发现不符不删除。若回滚器启动或就绪确认失败，禁止安装 Static 对象。规则创建前先写清单，事务失败只撤本轮已提交对象；全部控制进程都异常退出时，Static 对象可能残留，恢复入口须允许在下一次独立调用中安全清理，不能静默重开 A。BFE 重启和宿主重启保护本轮未验证，也不得靠重启清理代替验收。

拟改文件限定为：`windows-lab-wfp-container.cs` 增加独立 Static/动态例外接口；新建 `windows-lab-static-guard-control.ps1` 及独立回滚模式；`windows-lab-psec-stopped.ps1`、`windows-lab-psec-run.ps1` 增加严格限定的新模式与时限；复用 `windows-lab-portguard-flow.cs` 的流证据；新建 `windows-lab-static-guard-result.ps1`；本路线图更新结果。不得调用旧账户级持久规则安装入口。具体调用名可调整，作用范围不能扩大。报告需区分“退出到 E 消失”“退出到旧流中断”“离线后新尝试送达数”，保留正反对照及回滚后宿主读数。

#### N1 实测结果与清理

2026-11-22（America/Los_Angeles），仍为 Windows `26300.9974`、MXC `1.1.0`、仅 A 标准用户模拟器和普通宿主合成 HTTP 代理。主智能体集成并操作实机；两个 `gpt-6.1-sol / high` 子智能体分别实现原生接口和判定器，原生接口负责人另做控制器清理路径的只读复核。没有启动真实客户端、B、Sandboxie 或浏览器，没有改动 10810、系统 DNS、网卡、TUN、全局审计、开机规则或服务配置。

入口为 `mock-desktop/windows-lab-hostloopback.ps1 -StaticGuard`。本机最终报告 `.prototype/mock-results/windows-psec-static-guard.json` 的 SHA-256 前 12 位为 `DBCF5B172207`，判定 `passed-static-guard-n1`。报告含源码/执行器哈希、精确规则及身份、编号流、DNS ETW、阶段时间和清理结果。SDK 下载片段已删除，复验需按既有固定版本和哈希重新准备。

| 验收项 | 本次结果 |
| --- | --- |
| Static 生命周期 | 安装 D4/D6/I4/I6 后关闭安装会话，独立会话仍读回四条拒绝及子层。首次无 E 时 A 到代理及其他合成端点均失败，宿主和容器外 A 正对照正常。 |
| Dynamic 例外 | 在相同子层创建高权重 E，只匹配本次 A SID、TCP、`127.0.0.1:P`；未设置硬放行标志。窗口和原生子进程恢复标记往返，其他 TCP、UDP、同端口 UDP、另一回环地址和本机 IPv4 合成端点均零命中。 |
| 管理器退出 | 只终止持有 E 的管理器。实际进程退出到独立读回 E 缺席约 **57ms**，四条 Static 拒绝仍在。A 窗口、容器监听子进程及普通宿主代理当时均存活，没有先关闭代理来制造断流结果。 |
| 旧流与新请求 | 同一条连接约在实际退出后 **85ms** 出现 `ConnectionAborted / 10053`。从收到进程退出信号到核对新旧请求均离线约 **303ms**，在预定 3 秒内。离线确认后的四次原 socket 发送尝试零成功响应，自动重连为零。 |
| 恢复 | 新动态管理器重新核验同一清单、Static 对象和代理健康后创建 E。新窗口请求和新原生子进程成功；原失效 socket 未复活，也没有自动重放旧请求。 |
| DNS | 容器内已测 `DnsQuery_W=5`、`GetAddrInfoW=11001`，对应发送/回复均为零。全部 A 标签 DNS 发送/回复仅来自两个明确的容器外正对照 PID，分别位于 baseline 和 stopped 阶段。服务 PID 不变、ETW 三项丢失计数均为零。 |
| 撤规则后宿主 | 正常停止 A 和代理，再删除本轮 E、四条拒绝及子层并独立确认不存在；约 52ms 后开始宿主复测。安装规则前建立并一直保留的 TCP 对照、新建 TCP 对照和新域名 DNS 均成功，ETW 仍在采集。 |
| 回收 | 本轮 Static 与 Dynamic GUID、PSEC 条目、测试进程、监听、ETW、私有清单目录和 SDK 暂存目录均已回收；没有强制清理残留进程。保留历史失败报告与脱敏交接内容。 |

实现扩展 `windows-lab-wfp-container.cs` 的独立 N1 接口；新增 `windows-lab-static-guard-control.ps1`、`windows-lab-static-guard-scenarios.ps1`、`windows-lab-static-guard-result.ps1` 和纯判定自测。控制器的 `-Rollback -EvidenceDirectory <本轮宿主私有目录>` 是独立恢复入口：按已保存的 SID、GUID、内容和子层成员核验后清理，不执行全局重置。规则和私有目录正常回收后不再保留可重复删除的活动清单。若再次实验中异常留存清单，必须先清理再重启 A。

权限相关自查修复了“CIM 路径快照后仅凭 PID 终止”的复用窗口：先取得进程句柄，再核对实际路径和创建时间；历史 owner 的 PID 已复用时跳过，继续处理仍匹配的 owner，最后仍要求 E 缺席和实验进程清零。源码 x64 编译通过，原生规则/生命周期纯内存测试拒绝 72 个错误变体；判定器在 PS7 和 Windows PowerShell 5.1 下接受正例、拒绝 21 个反例及空报告。反例包含错 SID、缺 Static、E 未消失、超时、离线后送达、代理提前被杀、容器 DNS 代发、伪造容器外 PID、宿主失败及清理残留。

保留三份预检记录：`windows-psec-static-guard-powershell-preflight.json` 记录 PS5.1 不识别 `ushort` 别名和失败报告 UTF-8 回读问题，发生在写规则前；`windows-psec-static-guard-manifest-preflight.json` 记录 PowerShell 空字符串绑定导致的原子清单替换失败，也未提交规则；`windows-psec-static-guard-time-preflight.json` 记录 UTC 与本地 DateTime 比较误报超时，该次原始流已经报错且规则已回滚。分别改为 `uint16`、明确 UTF-8、可验证的原子替换，以及 UTC 截止时间后才取得完整实测。

最终完整运行的首次判定还把 stopped 阶段容器外 A 的 DNS 正对照误计入容器结果。原始完整报告保存在 `windows-psec-static-guard-before-dns-attribution-review.json`；修正仅豁免已核验且不属于任何已记录容器 PID 的该正对照后，对同一份保存证据重算通过，未再运行或改动系统。主报告保留旧判定、旧/新判定器哈希和重算说明；新增容器 PID、未知 PID 和伪造正对照 PID 三项反例均拒绝，未放宽零代发要求。

本轮结论仍限于合成 HTTP、当前模拟器和 Windows 版本。它证明本次管理器退出后会恢复基础拒绝，不证明终止的瞬间没有在途数据，也不认证代理端口的持有者。Static 规则不跨 BFE 停止或重启，尚未验证 BFE/宿主重启、全部控制组件同时故障、全新容器执行业务前的保护、B、真实上游、原生 IPv6 或所有系统服务代发。宿主 TCP 对照仅为受控回环。120 秒独立清理监督是有界实验收尾机制，不是硬实时调度保证。下一步只细化 N2 的准确规则/权限作用范围和回滚方案，未自动授权实施 N2。

**N2 · 入口被别的进程冒用：已单独获批，A 模拟器实测通过并回滚。**

#### N2 机制与可信边界

本轮选择验证“受信代理先独占绑定，随后禁止任何进程新绑定该端口”。先由控制器启动并核验代理实例，代理在 bind 前设置 `SO_EXCLUSIVEADDRUSE`，绑定 `127.0.0.1:P` 并监听；再加 Static 绑定拒绝规则，读回和健康检查通过后才为 A 开 E。不设置程序路径、用户或 PID 放行例外：代理退出后，即使另起同一个程序也不能重新绑定 P。恢复使用新端口 Q，旧 P 在 A 停止前一直封住。

微软文档确认 `ALE_RESOURCE_ASSIGNMENT_V4/V6` 检查显式及隐式 bind；`ALE_AUTH_LISTEN` 检查 listen。地址未指定时分类字段可能为 `FWP_EMPTY`，所以端口规则不加本地地址条件。现有流重授权发生在 AUTH_CONNECT/RECV_ACCEPT；据此推断，新绑定规则可能保留已绑定的受信监听，但**必须先实测确认**，文档没有替本方案保证这一组合。[绑定层](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers) · [支持的过滤条件](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer) · [流重授权](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)

独占绑定必须在 bind 前设置；已有连接可能在关闭监听后继续占有端口。因此“冒用者绑定失败”不能单独证明 WFP 生效，验收必须含关闭全部旧连接、绑定前正对照、撤规则后恢复及原始错误码。[Winsock 独占与复用语义](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse)

威胁范围是无权改 WFP、无权改受信文件的其他普通进程，包括容器外标准用户 A 启动的冒用程序。宿主管理员、内核、对受信控制器的注入或窃取其句柄不在本轮保证内。控制器记录进程句柄、创建时间、实际用户、文件哈希和监听归属；不把 AppId 路径相等当成进程实例认证，不用业务请求携带的随机字符串来认证服务端。TLS 代理认证保留为后续候选，本轮不安装根证书或更改全局验证。

#### N2 准确写入范围与宿主影响

| 对象 | 拟实施的范围 | 影响与限制 |
| --- | --- | --- |
| A 基础保护 | 重新安装 N1 的 4 条 Static 默认拒绝及最多 1 条 Dynamic E，精确匹配本轮 A 容器 SID；E 只允许 TCP → `127.0.0.1:当前端口` | N1 旧规则已回滚，不能当成现行配置；B 不参与。 |
| P 绑定保护 | 新子层内 2 条 Static BLOCK：RESOURCE_ASSIGNMENT_V4/V6，条件仅 TCP 与本地端口 P | **作用于所有用户、所有程序和所有本地地址**的新绑定。没有身份白名单，不能把作用范围描述为只限 A。 |
| Q 恢复保护 | 同一新子层内另 2 条同构规则，仅端口换成 Q；准备 Q 时才安装 | 全程最多 9 条本轮过滤器、2 个本轮子层。无 Persistent、Boot、驱动或常驻服务。 |
| 受信文件 | 宿主 TEMP 下一个全新本轮私有目录，放代理副本、控制配置和恢复清单；关闭继承，仅宿主控制账户、SYSTEM、Administrators 有完全控制 | 先确认父目录不允许 A/B 修改、替换或删除该目录，再创建；不改父目录、仓库、A/B 资料或其他既有 ACL。无法满足则停止。 |

2026-11-22 只读核对发现 `.prototype/windows-lab` 与 `mock-desktop` 均继承了 `Authenticated Users` 的修改权限，不能直接用来承载可信代理副本。实施时由控制器从已审阅构建产物固定哈希，在私有目录中核验复制结果；还需拒绝 A 读取/替换私有配置及写入代理文件，核验实际进程打开的映像。该目录 DACL 是本轮新增批准项，不能沿用“N1 已批准”来跳过确认。A 的模拟器继续使用实验目录，不能访问代理控制通道。

只读查询当前 TCP 动态端口范围、排除范围及占用后，选择两个不在动态范围、不在保留/排除范围、没有现存 TCP 占用的高位临时端口 P/Q；排除 10810 和宿主已用代理。不能找到符合条件的端口就停止，不改系统端口分配设置。绑定成功仍以实际独占 bind 为准，预检查不消除竞争。第一轮只监听回环；规则的地址范围必须覆盖通配绑定。

宿主普通 DNS及使用其他端口的连接不在新规则条件内；但宿主程序**显式使用 P/Q 作监听端口或 TCP 源端口会被拒绝**，这是有意的局部影响。选择动态范围之外的端口减少自动源端口冲突，不能保证所有宿主软件永远不会显式选择它们。验收仍只证明实际宿主对照通过；局域网/外网所有连接不据此宣称全面验证。10810 不连接、不停止、不改配置；系统 DNS、网卡、TUN、全局审计保持原状。

绑定子层的优先级必须依据相关层现有 hard permit/callout 做只读核对；未知优先级或无法解释的竞争规则使本轮停止，不调整第三方规则。所有新增规则须独立读回层、条件、动作、权重、GUID 和生命周期。Static 在所有本轮控制进程退出后仍可能存在，但不跨 BFE 停止/系统重启，这部分仍属于 N4。

#### N2 执行顺序与验收

获批后分为以下门槛，前一项失败就收尾，不进入下一项。不提前接真实上游；所有响应和邮箱仍为合成数据。

1. **构建与可恢复准备。** 在现有 N1 代码上实现绑定保护、P/Q 清单和独立回滚入口；先做不写系统的参数、规则归属、恢复状态和判定器反例检查。写入前保存运行号、GUID、端口、私有目录权限、进程身份及已知清理步骤。启动独立有界清理监督，不依赖拥有 E 的管理器收尾。
2. **先验证原监听能保留。** A 仍关闭 E。普通宿主及容器外 A 的绑定探针分别在没有保护规则时成功绑定 P 后关闭；受信代理独占监听，再安装 P 两条规则。确认代理可继续接新连接且已有连接可收发、其他未用测试端口可绑定。失败立即回滚，不能靠加程序白名单或弱化规则继续。
3. **健康与冒用。** 打开 E 后 A 窗口/原生子进程获得合成响应，非代理 TCP/UDP 和两项 DNS 仍不放行。分别使用默认选项、REUSEADDR、EXCLUSIVEADDRUSE，在 `127.0.0.1` 和 `0.0.0.0` 尝试绑定 P；记录 bind/listen 原始结果。冒用者包括容器外标准用户 A、普通宿主探针和宿主启动的同一受信二进制第二实例；A 另用可读的同内容副本，不能为了该测试放宽私有目录 ACL。所有冒用监听不得接到业务标记。
4. **退出组合与归因。** 分别测试代理退出而 E 管理器仍活着、E 管理器退出而代理仍活着、两者退出。代理退出场景确认所有已接受 socket 和持有者已关闭，再重复绑定探针；规则仍在，旧业务流失效，新请求失败，冒用者零业务命中。只看到端口占用错误、旧连接仍存活或缺少可达正对照时，不能判为绑定保护通过。无需开启全局审计；不能可靠归因就保留为未证实。
5. **新端口恢复。** 保持 P 规则不动，关闭 E 和所有旧业务流；受信代理在 Q 独占监听，安装并读回 Q 规则，健康检查通过后仅打开指向 Q 的新 E。清单以代际和 GUID 记录切换，任何中间失败保持 A 拒绝。新请求只到 Q，旧 P 无新业务、无法重新绑定，旧请求不自动重放。不得短时解锁 P 来恢复服务。
6. **贯穿与收尾对照。** 健康、每个退出组合、Q 恢复及回滚后均验证宿主 DNS、同一条旧 TCP 流上的新标记及一条新 TCP 连接；TCP 仍为受控回环范围。容器两项 DNS 与已核验 PID 的容器外 A 正对照使用不同唯一域名，DNS ETW 零丢失；容器发送/回复均应为零，未知归属不能豁免。出现泄漏或宿主对照异常立即停止业务并回滚。

V6 绑定规则仅安装和读回以避免配置只覆盖 V4；原生 IPv6 绑定/连通正对照和双栈运行行为仍按既定决定暂缓。N2 即便通过，也只能称当前 IPv4 模拟器证据通过，不能把 V6 规则存在等同于 IPv6 已验证。运行期限与各步骤超时在实施入口固定，超时进入失败清理，不能无限重试。

#### N2 回滚与交付

回滚顺序：撤 E → 停止并验证本轮 A 进程树已退出 → 关闭代理及全部接受连接 → 按清单逐项验证并删除本轮 P/Q 绑定规则和 N1 基础规则/子层 → 独立枚举确认均不存在。随后用普通宿主探针重新绑定 P/Q，保持原宿主旧连接并复测 DNS、新连接。若 P/Q 因 TIME_WAIT 或其他占用尚不能恢复，记录原因并等待有界复测，不能把它直接记为回滚通过，也不改 TCP 系统参数。

最后仅删除本轮私有目录和临时实验产物；新建私有目录没有需要恢复的旧文件 ACL，父目录与既有目录 ACL 应保持原值。删除前核对绝对路径与本轮清单一致。任何规则归属不明、清理失败或宿主异常都保留恢复清单和证据，不删掉独立恢复入口；A 保持停止。全局重置防火墙、重启 BFE、释放他人监听或启用 Sandboxie 均不属于回滚手段。

实机入口为 `mock-desktop/windows-lab-hostloopback.ps1 -BindGuard`。只在对应范围获批且具备本机 A 实验账户、已校验的 MXC 1.1.0 启动器和 WFP 写权限时使用。入口 `mock-desktop/windows-lab-bind-gate.ps1` 单独验证地址绑定和撤除。`mock-desktop/windows-lab-bind-result.ps1` 可对保存报告离线重算。`-StaticGuard` 仍用于 N1。

#### N2 实测结果与清理

2026-11-23，Windows 11 build `26300.9974`、MXC `1.1.0`。完整运行 `studio-ee0290c647d240f7`，结果 `passed-bind-guard-n2`。本机报告 `.prototype/mock-results/windows-psec-bind-guard.json`，SHA-256 `DF28B8EBFC976ADA9F11E82FE0F252B2A61A3BA1063A81C3F6B90C4BF46B5242`。

| 检查 | 实测结果 |
| --- | --- |
| 原监听和宿主权限 | 单端口 WFP 门槛确认安装后原监听的新旧连接正常。完整轮中普通 A 无法读或删除私有配置样本，也无法以写权限打开代理文件。受信代理两代均从私有目录启动，核验了进程、端口和哈希。 |
| 防止接管 | P 活跃时 18 项绑定尝试均失败，其中 `10013` 和 `10048` 各 9 项。P 代理退出后、两者退出后和 Q 恢复后，共 54 项在 `bind` 返回 `10013`。覆盖普通宿主、容器外 A 和同一代理二进制的新实例，以及默认、复用、独占选项和两个 IPv4 地址形式。 |
| 故障和恢复 | 从代理退出确认到 A 旧流失效、新请求失败并通过宿主对照，用时约 2.65 秒。两者均退出及仅放行管理器退出的对应检查分别用时约 385 ms、280 ms。Q 在 E 关闭时无法从 A 访问。Q 健康后放行，窗口和原生子进程均取得合成响应。旧 P 流未重连，也未在恢复后收到响应。 |
| DNS 和宿主 | 容器中两项系统解析 API 分别返回 5 和 11001，服务代发与回复均为零。容器外 A 的两个阶段均出现 4 次发送、2 次回复，ETW 零丢失。宿主 DNS、同一条回环旧连接及新回环连接在测试各阶段和回滚后均通过。 |
| 回滚 | 两个子层和本轮过滤器均确认消失，P/Q 均可重新绑定。宿主回滚后对照在规则确认撤除约 33 ms 后开始。临时目录、实验进程、监听、ETW 和 SDK 片段缓存均已清理。 |

两次早期集成预检均在启动 A 容器前停止并完成回滚。`windows-psec-bind-guard-probe-array-preflight.json` 记录 PowerShell 5.1 多条 JSON 结果的计数差异。`windows-psec-bind-guard-live-socket-preflight.json` 记录原监听存在时的端口占用。后续判定仅在原监听仍活跃时把 `10048` 接受为绑定被拒。退出后要求 `10013`，并以撤规则后正对照排除端口持续占用。保存报告的判定器通过 6 项反例复核。N1 的 21 项离线反例仍通过。

本次验收覆盖 IPv4 合成 HTTP 和两项已测 DNS API。IPv6 仅核对两代绑定规则读回。真实代理协议、B、官方客户端、全新进程启动竞态以及 BFE 或系统重启属于后续验收。

**N3 · 实际代理协议：先合成上游，再评审真实上游。**

#### N3 获批步骤与进度

2026-11-23，Astra 已完成只读方案审查，用户批准两步合成实验。交付停在 A 的试验报告与回滚核验。宿主使用指定范围之外的 TCP 端口保持联网。原生 IPv6、10810、真实上游、真实客户端、B 及浏览器继续按既定边界处理。

| 步骤 | 验收 | 状态 |
| --- | --- | --- |
| 独立协议 | 本机回环 P → U → 独立目标。HTTP、CONNECT 内 TLS 和标记往返有目标端证据，错证书/域名、缺少 TLS 往返、畸形及越界请求被拒，TCP 半关闭可完成反向传输。 | 已通过，进程、监听和证书临时目录已清理。无系统规则。 |
| A 故障与恢复 | A 的业务只能经 P 发起。P/U 各独占一个非动态、非排除临时端口，再按 N2 结构封住新绑定。实验最多 9 条过滤器、2 个子层和一个新增宿主私有 TEMP 目录。宿主不能新绑定 P/U，包括显式作 TCP 源端口。冷启动、拒绝、静默、退出和可恢复故障分别取证。静默注入起 3 秒内停止接收业务、撤 E 且关闭成对旧流，截止后无新标记送达，恢复无重放。U 进程退出留在最后，旧 U 保持封住至 A 停止，进程重启恢复另议。撤除后重新绑定 P/U，复测宿主 DNS 与新旧回环连接。 | 八个阶段已通过，系统规则及临时目录已回滚。 |

独立协议报告 `.prototype/mock-results/windows-psec-n3-protocol-920b0e9e71a946d9.json`，SHA-256 `025F39589EDE303939266F305A41DF12222F0EFF2EDBADC158D4D882045F022E`。HTTP、TLS、半关闭以目标标记和 P/U 连接端口逐跳关联。错误主机名和错误证书为 `TrustFailure`，畸形和非预置目标收到 400，无 TLS 的 CONNECT 200 没有目标请求。预检记录了多个 Node 路径、旧 .NET 默认 TLS、普通拒绝需正常关流，以及客户端可能重试 CONNECT，复测核实了结果。

N1、N2 达到各自门槛后，入口 P_A 才从“本地返回标记”改为“只向固定 U 转发”。首轮 U 和 HTTP/TLS 目标仍为本机独立合成监听器。U 以数字地址配置，目标主机名原样放入 HTTP 请求或 CONNECT，不由 A 或入口进程调用宿主 DNS 解析；合成上游通过测试清单映射到受控目标。禁止自动使用系统代理/PAC、环境变量、DIRECT 回退或把业务 URL 当成新上游配置。HTTP 首版只接受测试所需的明确报文格式；歧义长度、超限、非法 authority 等直接失败，不把最小解析器包装成生产通用代理。

HTTPS 的成功标准是在 CONNECT 成功后由客户端与目标完成 TLS 和标记往返，入口只搬运隧道字节。证书验证限定测试目标和测试客户端，其他目标继续执行正常验证。上游认证凭据保留在宿主转发组件，不能复制给 A 或写入日志；同时区分入口认证与上游认证，不能盲目透传 `Proxy-Authorization`。[CONNECT 语义](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)

每条下游连接必须登记对应的上游连接；上游拒绝、退出或无响应时撤 E、关两端旧连接、丢弃排队业务。健康检测须穿过 U 到受控目标，不以 P 仍监听或 U 返回 CONNECT 200 作为健康结论。恢复先完成新的目标往返才允许新业务，不重放旧请求。测试窗口、原生子进程、入口、上游、目标和 DNS ETW 按运行号关联，额外检查入口进程没有目标域名代发。主机默认 DNS 及受控旧、新 TCP 对照保留到规则回滚之后。HTTP、CONNECT、TLS、半关闭、连接拒绝、3 秒静默期限和错误恢复分别记录，原生 IPv6 仍暂缓。

真实 U 的协议、数字地址、认证和远端解析行为到真实接入阶段再核实；如果 U 就是保留端口 10810，需要用户对“使用该端口”作新的明确授权，之前的保护约定不会自动失效。即便自有转发代码仅连接 U，也不能据此宣称宿主转发进程已被系统规则限制只能访问 U；这类按身份限定转发进程的额外规则另行设计批准。首轮将该组件列为受信边界。

#### N3 实测结果与清理

2026-11-23，Windows 11 build `26300.9974`、MXC `1.1.0`、本机 Node `26.13.1`。运行 `studio-0f0ed3ff20544b91` 结果为 `passed-n3-a`。完整本机报告 `.prototype/mock-results/windows-psec-n3-a-0f0ed3ff20544b91.json`，SHA-256 `9B7CC5DB276A47229807EB76235F3E324A26495D625E234215157D425BD7FDC5`。

| 验收 | 实测 |
| --- | --- |
| 协议和身份 | A 窗口与同容器原生子进程分别通过 HTTP 和 HTTPS。健康与两次恢复的 8 条成功路径可凭标记、连接端口和 PID 逐跳还原。P/U 读回 4 条绑定规则。A 的基础拒绝和仅到 P 的动态例外均按容器 SID 读回。标准 A 对临时私有配置的读、删和代理文件的写入均被拒。 |
| 故障时间 | 从注入到入口停收、成对 socket 已关且 WFP 例外确认撤除，U 拒绝、静默、退出分别约 303 ms、1.30 s、1.38 s。八个运行阶段内 A 共 8 条离线请求全部连接失败，合成目标未收到其标记。 |
| 旧流和恢复 | 三次故障前均持有实际 HTTP 和 TLS 响应流，关断后未再收到旧标记。解除拒绝和静默后，健康探针先完成 HTTP、TLS 目标往返，才放行新的业务，两次恢复均无旧请求重放。U 退出后宿主绑定探针返回 `10013`。另一次宿主到旧 U 的连接在 1200 ms 内未完成，原样记为超时。 |
| DNS 和宿主 | A 的 `DnsQuery_W` 和 `GetAddrInfoW` 返回 5、11001。按测试域名追踪未观察到容器或入口 P 的系统 DNS 代发。容器外 A 正对照有 4 次发送、2 次回复，ETW 零丢失。TCP/UDP 直连诱饵零命中。宿主 DNS、原有回环 TCP 和新回环 TCP 在所有对照及撤规则后均成功。 |
| 回滚 | 两组规则和两个子层确认移除，P/U 恢复可绑定，宿主的回滚后对照在确认移除约 23 ms 后开始。测试进程正常退出，私有目录、证书、暂存目录、ETW 及临时 SDK 片段已清理。 |

入口为 `mock-desktop/windows-lab-n3-protocol.ps1` 和 Windows PowerShell 5.1 下的 `mock-desktop/windows-lab-n3-run.ps1`。`mock-desktop/windows-lab-n3-result.ps1` 可离线重算。18 项报告检查通过，6 项篡改反例均被拒绝。早期实机报告分别保存了 PowerShell 变量类型冲突、对 U 退出后错误码的错误预期，以及容器退出时文件确认不稳定。最终确认由实际窗口进程的输出、命令序号及退出码共同验证，三次预检均核对了规则和目录清理。

本轮范围为本机 IPv4 合成流量和受信 P/U 夹具。U 退出后的原位重启、真实上游及其认证、B、真实客户端、原生 IPv6 和 BFE/系统重启均未实测。

**N4 · 启动前保护与双空间产品化。**

#### N4 获批首轮

方案经 Astra 只读审查。用户批准先以 A 模拟器做闭网预检，权限通过才加 4 条临时规则。MXC v1.1.0 在将进程加入 Job 后自行恢复线程，再交回句柄。首轮保留官方 MXC，用受信引导程序等待宿主核验。普通 A 的进程和线程权限用实际打开句柄的结果判断，已有标准用户和 AppContainer 的读数仍需单独核验。[MXC 启动源码](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L988-L1110)

| 步骤 | 验收和停止条件 | 状态 |
| --- | --- | --- |
| A 闭网预检 | 只运行引导程序和权限探针。临时可信目录对 A 可读、不可改写或替换。核验真实令牌、进程身份和 Job。容器外普通 A 无法取得引导程序或其创建器的关键改写、复制句柄或线程控制权限。同账户普通进程作权限正对照。有关键权限成立或证据无法归因时清理并停止。 | 已测。文件通过，进程与线程权限不通过，已清理。 |
| 四条拒绝规则与启动顺序 | 在实际回环配置重验权限。先以本轮真实 A 容器 SID 安装并读回四条临时 CONNECT/RECV_ACCEPT 拒绝，随后才由可信引导程序挂起创建业务模拟器。子令牌和 Job 归属确认后恢复。使用独立进程启动证据验证缺少授权时未创建，另验证恢复后直连和系统 DNS。先确认进程退出，再撤规则和临时 ACL，复测宿主。 | 前置权限门槛未通过。无 WFP 写入，无业务进程启动。 |

本轮只使用合成模拟器和独立测试端点。P/U、10810、宿主网络配置、B、真实客户端和 BFE 重启不在授权内。

#### N4 闭网预检结果与清理

2026-11-23，Windows 11 build `26300.9974`，官方 MXC `1.1.0` 的 `base-container`，运行 `studio-8934d094fac84ab6`。本机报告 `.prototype/mock-results/windows-psec-n4-preflight-8934d094fac84ab6.json`，SHA-256 `B280A498D3247FA7EFF2C4915DCE04D66ED06223EFCA28695B7DC4EF4DBB14D8`，结果 `stopped-n4-critical-right-granted`。

- **文件门槛通过。** 容器外标准 A 能读取授权样本并写结果目录，写入、删除、替换保护样本和在保护目录创建文件均被拒。容器内引导程序也能读样本，无法以写权限打开。两个程序的路径和编译源哈希保存在报告。
- **进程门槛失败。** 引导程序的真实令牌属于 A，位于 AppContainer 和 Job，已识别的网络能力为零。容器外标准 A 的独立探针核对了目标映像、PID、创建时刻与 TID。两个目标的进程对象和受测线程对象的所有者均为 A。引导程序与 MXC 创建器各有 9 项进程权限、5 项线程权限请求成功，共 28 项，包括写进程内存、改 DACL、复制句柄、修改线程上下文及挂起/恢复。普通 A 自有进程正对照也全部成功。每个句柄只打开和关闭，未使用权限改写或控制目标。当前文件 ACL 无法单独建立可信启动链。同在 Job 的标记不用于证明 Job 归属相同，进程树退出行为留待通过启动门槛后验证。
- **清理通过。** 测试进程正常退出，没有新增或残留的 AppContainer 资料目录。本轮临时目录、桌面进程和 SDK 下载片段已清除。宿主 DNS、新建回环连接与同一条旧回环连接在实验前、期间及清理后均正常。WFP 写入为零。

入口为 `mock-desktop/windows-lab-n4-preflight.ps1`。早期报告保留了令牌查询的权限错误以及默认禁用容器 UI 时的 CLR 初始化错误 `0x8007045A`。正式读数改用 `TOKEN_QUERY` 直接读取字段，容器 UI 选项与现有 A 模拟器对齐，闭网策略保持不变。恢复本项需先明确如何让容器外 A 无法取得足以改变可信创建器和启动决策的权限；新增隔离边界另行评审和批准。

#### N4 宿主创建预检

用户批准并经 Astra 只读审查。使用一次性宿主提升助手，取现有标准测试账户 A 的临时主令牌，以 `CreateProcessAsUserW` 挂起创建固定、无业务的本地测试程序。创建时分别为进程和主线程指定宿主所有者与受保护 DACL，原始句柄由宿主持有且不可继承。实测核对实际令牌、所有者、DACL 与句柄，复用同 A 账户的普通进程作正对照。外部 A 对受测创建器或对象的关键访问成功、归属不明、正对照失败或 API 返回 `1314` 等错误时，记录并停住。受测线程全程不恢复，用原句柄回收并复测宿主 DNS、同一条旧回环连接和新回环连接。

本轮只写本次临时目录 ACL，随后删除目录。不改用户权限、用户资料或系统网络设置。PSEC 接入、桌面与 WFP 启动验收另议。P/U、10810、B 与真实客户端不参与。**状态：一次性提升实测已命中原生 `1314` 停止条件。** 提升助手退出时回传了原生错误，受测进程未创建。临时目录已删除，宿主前后对照通过。控制端等待窗口先结束，漏记期间对照，原始报告保留该缺口。

- 2026-11-23 执行，Windows 版本号为 `10.0.26300.0`。回执 PID 与实际提升助手一致，读取到高完整性。`SeIncreaseQuotaPrivilege` 在令牌中存在且显示禁用，`SeAssignPrimaryTokenPrivilege` 不在令牌中。`CreateProcessAsUserW` 返回 `ERROR_PRIVILEGE_NOT_HELD (1314)`。进程和主线程所有者、DACL 与同 A 关键句柄矩阵无实测结果。[微软 Win32 API 文档](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- 清理复核确认助手退出码为 0、夹具进程数为 0、临时目录已删除，WFP 写入为 0。宿主在前后两次均解析到 DNS 记录，同一条已建立的 IPv4 回环连接与另开的回环连接均完成双向标记。
- 原始本机报告为 `.prototype/mock-results/windows-psec-n4-host-create-c21618f3620a48e0.json`，SHA-256 `D9CC66C941BC2541BAA3E50DD35DED3A81C3626CFB7BB3CDA73EEDA607B972F7`。报告总体标为 `inconclusive-n4-host-create` 以保留控制端超时和期间对照缺失，原生 1314 决策证据单列于 `broker.error`。
- 本轮入口为 `mock-desktop/windows-lab-n4-host-create.ps1`。新旧探针均已编译通过。启动器已调整为在初始等待结束后继续采集宿主对照，并在清理阶段核验迟到回执。修正后的回执校验已用原始回执和错误 PID 对照通过，本机提升实验仅执行原计划的一次。N4 在此停止，新的创建机制或权限变更须重新审批。

#### N4 集中复核

2026-11-23，**复核完成，现有方案不放行。** 本轮对既有模拟器实测重算判定，做 Windows 只读查询及官方源码核对。实际系统为 `26300.9974`，受测 MXC 为 `v1.1.0`。本轮工作区只更新本路线图，原始报告保留，WFP 写入、ACL 写入和实际客户端启动均为零。

| 项目 | 结论和证据边界 |
| --- | --- |
| 双窗口和资料 | 模拟器的双窗口、重复打开、独立启停、持久资料、合成回调、项目写回和 NTFS 对照报告通过。还需在同一条最终隔离启动链上重验 A、B。 |
| 语言和时区 | 已证实模拟器的窗口语言、请求语言和受控辅助进程时区能分别设置。两边 Windows 原生 API 均读到宿主时区。原生 API 所用的系统时区和应用层偏好需分别验收。现行双用户及容器机制没有实现进程级原生时区。 [微软系统时间说明](https://learn.microsoft.com/en-us/windows/win32/sysinfo/local-time) |
| A 强制代理及故障 | 原始 N1、N2、N3 用同一项目的离线判定器重算均通过。N3 八阶段只使用 A、合成 HTTP/CONNECT 和临时端口。拒绝、静默、退出约 303 ms、1.30 s、1.38 s 收口。原始报告的宿主 DNS、新旧 IPv4 回环连接、对象清理和端口恢复均通过。更早的端口限制故障报告重算仍有未确定项，其范围保留。 |
| DNS | MXC 内置代理的冷启动对照为 4 次代发、2 次回复，且其他 HTTP 栈依赖明确的代理设置。零能力和仅回环能力两项已测 DNS API 均为 0 次代发。零能力容器内 HTTP 入口连接失败，仅回环能力本身允许访问非代理回环监听器。N1–N3 的端口限制和 DNS 对照仅适用于各自 A 夹具。 [MXC 网络模型](https://github.com/microsoft/mxc/blob/v1.1.0/docs/backends/process-container/networking.md) |
| 启动权限 | 原闭网回执重算得到同账户的运行器和引导程序各 9 项进程、5 项线程句柄请求成功。普通 Win32 宿主创建回执再次核对为原生 `1314`，无受测进程。两轮均无 N4 规则写入。后一轮只有实验前后宿主对照。 |
| 路线尚未覆盖 | 四条 N4 拒绝规则与首次业务进程执行的先后关系，A/B 并发及子进程、BFE 或系统重启时的故障关闭，真实客户端和 DNS 代发覆盖，均未验收。原生 IPv6 的已有正对照在加规则前已被 TUN 阻断，按约定暂缓。WFP Static 对象只活到 BFE 停止或系统关闭。 [WFP 对象生命周期](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) |

**启动接口判定**

- MXC `v1.1.0` 的 `base-container` 在 `CreateProcessW` 时通过创建属性挂上 PSEC，进程与主线程安全属性传空。SDK 内部挂起创建、加入 Job、恢复主线程，随后才交回进程句柄。SDK 的通用容器生命周期文档不能替代受测后端的具体接口。没有找到这个已发布后端支持把未恢复的句柄交给调用者，或先公开返回可供外部 WFP 使用的实际容器 SID 的接口。本机也读到同一标准账户两次归档运行的容器 SID 不同。 [创建调用](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L842-L904) · [恢复和交接](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L988-L1110) · [生命周期架构](https://github.com/microsoft/mxc/blob/v1.1.0/docs/development/architecture/container-lifecycle.md#4-lifecycle-model)
- `CreateProcessWithLogonW` 支持挂起启动，但签名没有创建时进程和线程安全描述符参数。事后改对象权限无法建立从创建起的权限保证。实验性的 `CreateProcessAsUserInSandbox` 同样明确要求两个安全属性为 `NULL`。单独补一个权限或替换启动函数均无法完成 N4。 [带凭据启动](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) · [实验性沙盒 API](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox)
- Windows 原生 AppContainer 可把身份设在创建属性中。本机只读探针调用 `QueryProcessSecurityEnvironmentSupport` 成功，能力标志为 `0x0000000F`。另用两个新生成名字调用 `DeriveAppContainerSidFromAppContainerName`，同名相同、异名不同，未创建配置或测试业务进程。标准 AppContainer 的名字到 SID 派生能力不能外推给当前 PSEC 运行时。用预先确定的身份安装策略，再由独立可信启动器创建进程，是可评估的新设计。它仍需实证能保留两个 Windows 标准用户身份、限定 DNS 和宿主代理出口、启动两个窗口并保持正式 MSIX 激活兼容。 [AppContainer 启动文档](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) · [WFP AppContainer SID 条件](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)

原始证据索引沿用 [双空间报告](.prototype/mock-results/spaces.json)、[N3 故障报告](.prototype/mock-results/windows-psec-n3-a-0f0ed3ff20544b91.json)、[N4 闭网回执](.prototype/mock-results/windows-psec-n4-preflight-8934d094fac84ab6.json) 和 [N4 宿主创建回执](.prototype/mock-results/windows-psec-n4-host-create-c21618f3620a48e0.json)。现有 A 结果可作为候选路线的对照。需要新权限、规则或隔离方式时，以新的明确作用范围和验收批准开始，当前 N4 仍未达到启动放行条件。

#### N4 新启动链研究

2026-11-23，用户要求继续研究。本轮完成官方文档、MXC v1.1.0 源码和现有模拟器的核对，并由既有 Astra 审查代理独立审查。当前批准范围到研究、内存权限对照与本路线图更新。以下启动链、系统对象和故障注入尚未实施。

**一次性助手有新的待测路径。** 上次 `CreateProcessAsUserW` 返回 1314，不能推出必须安装服务。`CreateProcessWithTokenW` 要求调用方具备 `SeImpersonatePrivilege`，可以使用已登录的 A 主令牌，并支持挂起创建。它没有进程或线程安全描述符形参。候选是在宿主内准备独立的一次性 A 令牌，研究其 `TokenDefaultDacl` 与 `OWNER RIGHTS`，让第一层 A 启动器从创建时就具有受限的对象权限。必须实测该 API 实际使用哪份 DACL、所有者、主线程和令牌对象权限、会话及原始句柄；仅凭参数或内存判定不能放行。权限缺失时记录原始失败，不自动授予账户权限。 [创建接口](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) · [令牌默认 DACL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_default_dacl) · [OWNER RIGHTS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)

本机只读 `AccessCheck` 对照使用宿主当前令牌的临时副本和三份内存描述符。所有者为当前用户，仅 SYSTEM 有显式授权时，所有者请求 `WRITE_DAC` 成功；增加只授予 `READ_CONTROL` 的 `OWNER RIGHTS` ACE 后，该请求被拒；再给用户显式授予 `WRITE_DAC` 后恢复成功。三项符合预期，副本与缓冲区均释放。首次在执行环境的受限令牌中三项均被拒，正对照无效，未采用该结果。宿主令牌对照没有修改真实对象 ACL，也没有修改原令牌。此证据只支持权限机制，不能证明 A 启动器、主线程或子进程已受保护。 [访问检查](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)

**优先保留 PSEC 的网络基线。** MXC 源码已有 `CreateProcessSecurityEnvironment` 和环境句柄，再通过 `SecurityEnvironmentStartupInfo` 附加到 `CreateProcessW`。因此可研究对这一原生启动段作局部修改，保留环境创建、策略编码与清理，延迟 `ResumeThread` 至宿主核对完成。起点必须是已经受保护的第一层 A 启动器。普通 A 能控制它时，延迟末端恢复仍不能建立可信链。WFP 写入留在宿主控制端，业务创建器保持标准 A 身份。是否能够设置并保留进程、线程与令牌对象权限，以及 Job 是否覆盖其全部后代，都要实测。 [PSEC 句柄和启动属性](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/secenv.rs) · [实际启动和恢复](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L842-L1110)

本次还纠正上一轮只读支持查询的声明。官方 MXC 绑定为 `QueryProcessSecurityEnvironmentSupport(UINT64*)`，上一轮临时命令使用了 32 位输出，ABI 声明不正确。现已用 64 位输出重查，HRESULT 为 0，完整值为 `0x000000000000000F`。以本次完整值为准，该查询只读取能力，未创建安全环境。

**拟定的有限实验批次**

| 顺序 | 可查看结果与放行条件 | 失败处置 |
| --- | --- | --- |
| 一次性 A 创建器 | 合成程序全程挂起。从宿主核对实际标准 A 令牌、登录/桌面会话、进程与线程 ACL、令牌访问和不可继承原始句柄。普通 A 正对照有效，关键修改权限均被拒，能可靠回收。 | 任何归属、权限或回收项失败，关闭句柄并清理，本批次给出否决报告。后段不启动。 |
| PSEC 与首次执行 | 同一受保护创建器挂起创建合成业务程序。保持 PSEC 句柄有效，取得实际包 SID，验证 Job 和对象权限，宿主事务安装并读回四条拒绝规则，才准许首次恢复。未授权、规则失败、宿主退出分别验证无业务标记及进程回收。 | 进程确认退出后按本轮 GUID 撤规则并清理，记录第一个失败步骤。 |
| 网络和恢复 | 恢复后的 A 首先闭网验证 IPv4 TCP/UDP 和两项 DNS API，继而复用 N3 代理故障证据设计。PSEC、代理和控制器异常退出时核对旧流、新流、DNS，以及宿主连续旧连接和新连接。 | 协议、DNS 或宿主对照缺口均不外推为成功。逐项复核规则和进程清理。 |

这是一份实验设计。实施前需明确该批次实际程序、临时目录 ACL、容器与四条规则的准确范围。批次内步骤可连续执行，最终统一提交通过或否决结果。服务仅在一次性助手路径被具体证据否决后再评估，需另列服务身份、用户资料加载、交互桌面访问、受限命令协议和卸载范围。

**MSIX 和原生时区分别影响最终可交付范围。** `ActivateApplication` 返回履行激活契约的实例 PID，可能复用已有实例，接口不提供挂起主线程和 PSEC 创建属性。因此后续必须用同类型的合成包覆盖冷启动、已有实例和辅助进程，并验证真实用户、包身份及窗口归属。直接启动包内 EXE 的结果不能覆盖包激活。原生 AppContainer 备选也要验证 A/B 使用不同身份或有效用户条件，不能仅凭两个用户配置目录假定包 SID 不同。 [应用激活接口](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iapplicationactivationmanager-activateapplication)

模拟器源码确实使用 `TZ`、`--lang` 以及请求语言配置，原生读数由独立 PowerShell 查询 `TimeZoneInfo.Local`。Windows CRT 的 `TZ` 语法和应用运行时的 IANA 时区支持不同，不能给所有子进程复制同一字符串就视为成功。Windows Server 容器有原生虚拟时区，但文档排除了需要交互桌面的 GUI 应用；RDS 时区重定向作用于远程会话。当前要求的同一本地桌面双原生时区仍未找到直接适用的系统接口。API 兼容层可以研究，但需覆盖 Win32、CRT、.NET/ICU 缓存及每个辅助进程，Detours 只能说明可拦截函数，不能证明完整时区隔离。它属于独立的应用兼容方案，不能用作网络强制策略的保证。 [CRT 时区](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/tzset?view=msvc-170) · [容器时区](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/virtual-time-zone) · [GUI 限制](https://learn.microsoft.com/en-us/virtualization/windowscontainers/quick-start/lift-shift-to-containers) · [RDS 重定向](https://learn.microsoft.com/en-us/windows/win32/termserv/win32-terminalservicesetting-settimezoneredirection) · [Detours](https://github.com/microsoft/Detours/wiki)

若保留原 N4 的验收条件，上述路线仍须在业务代码执行前取得容器 SID、装好默认拒绝且完成 Job/句柄交接。受控模拟器自愿等待文件信号不能证明任意程序都没有启动竞态。受保护创建器与延迟恢复保留为候选，不再认定它们是实现启动前网络阻断的唯一办法。N1 的 Static 规则不跨 BFE/重启，跨重启保护仍需另行设计与批准。

#### N4 启动前封网的前提复核

2026-11-23，用户要求重新思考。本轮读取既有报告、模拟器、multi-claude 与微软源码，并复用既有 GPT-6.2 Astra 审查代理完成只读方案审查。交付到有条件的修正结论与本路线图，不执行新实验。当前只有本节及接手位置等相关文字修改，无 WFP、ACL、包注册或客户端启动。

**需要分开判断两个问题。** 原 N4 的 28 项句柄请求成功，证明普通 A 有能力改动当时的 A 创建器和引导程序，因此它们不满足原设计的可信启动门槛。测试只打开和关闭句柄，没有演示绕过网络规则。取得这些句柄本身不等于能改写宿主 WFP 策略，也不等于容器令牌已经逃逸。句柄保护对抗同账户篡改仍有价值，但不能从该结果推导所有启动前封网方案均失败。N2 对宿主受信控制器的排除范围也不能自动取消 N4 已批准的权限验收。

**较简单的候选顺序如下，尚无组合实测。**

1. 在启动任何本轮 A 工作负载之前，由宿主事务安装并读回匹配 A 用户的四条默认拒绝规则，覆盖 `ALE_AUTH_CONNECT_V4/V6` 与 `ALE_AUTH_RECV_ACCEPT_V4/V6`。A 的用户身份预先已知，不必等待动态容器 SID。这里的 `ALE_USER_ID` 条件值是安全描述符，实际匹配 PSEC 受限令牌的行为仍需验证。[微软条件定义](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)
2. 保留原版 MXC 的 PSEC 创建路径，使用已测的仅 `networkLoopback` 能力配置，不开启 MXC 内置代理模式。应用开始运行时，直接网络应已受到第 1 步约束，系统 DNS 则依赖创建时即生效的容器限制。两者分别取证，不能互相替代。
3. 宿主根据自己启动的实例和持有的进程句柄，核对 A 用户、创建时刻、映像、会话、实际容器 SID 和能力。身份来自实际对象，不能只接受 A 自报的 PID。核验成功后，在同一自有子层安装更高权重的动态软允许，条件同时包含 A 用户、实际容器 SID、TCP、`127.0.0.1` 和经过 N2 机制核验的代理端口。代理不是仅凭一个端口号获得信任。跨子层仲裁仍须检查，不能套用普通防火墙中任意允许规则覆盖拒绝规则的假设。[微软过滤仲裁](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
4. 代理或控制端故障时撤去代理例外，保留 A 默认拒绝，并关闭业务旧流。规则重授权和旧流收口需要沿用 N3 的实际发送标记验证，不能只看管理界面或规则数量。控制端退出时动态例外消失、默认拒绝留下，也是本组合的独立验收项。[ALE 重新授权](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)

由此可提出一个有限推论。如果第 1 步确实匹配实际 PSEC 令牌，而且 DNS 限制从创建时生效，取得容器 SID 就只需早于“开放代理”，不必为了直接网络默认拒绝而早于“执行第一条业务指令”。这可以消除该网络目标对自定义挂起交接的依赖，不能据此宣告原 N4 的权限和启动时序验收通过。

| 边界 | 修正后的判断 |
| --- | --- |
| 规则作用范围 | 从一个容器扩大到 A 账户的直接连接，容器外 A 也会被阻断。与 N1/N2 保留容器外 A 联网的对照条件不同，需要明确批准此变化，旧规则授权不能直接沿用。B 留到 A 组合验证通过后。 |
| 系统 DNS 与其他代发 | A 账户规则不等于阻断以服务身份发出的流量。容器外 A 仍可能通过 Dnscache 代发。应用和辅助程序必须留在有证据支持的容器边界内。若要求连容器外恶意 A 的系统代发也全部禁止，此候选尚不能满足。 |
| 宿主影响 | 设计上只匹配专用 A，宿主控制器及转发组件须使用独立身份。仍须同时观察宿主 DNS、同一条旧连接和新连接。既有报告主要证明受控 IPv4 回环，不能外推为所有外网连接均已验证。10810、P/U、网卡、TUN 和系统 DNS 配置保持现状。 |
| 账户条件证据 | 旧账户规则实验测试普通 A/B，旧 PSEC 端口实验主要按容器 SID。二者不能拼成“账户条件已在 PSEC 中通过”。所查微软 WFPSampler 的 AppContainer 例子里，附加 `ALE_USER_ID` 的几行是未完成的注释，不能用作已实现的组合证据。[所查源码](https://github.com/microsoft/Windows-driver-samples/blob/d49bb7d72f3651952b2b6e4ad28d14fe2247eb69/network/trans/WFPSampler/svc/Scenarios_AppContainers.cpp#L303) |
| 回滚与异常 | 正常结束先停本轮 A 工作负载，确认退出后按本轮 GUID 删除例外和四条拒绝，读回无残留并复测。管理器崩溃时不能自动撤掉默认拒绝恢复 A 直连，须有宿主持有的独立清理入口。其他规则不动。BFE/系统重启保证仍未建立。 |

**下一轮应先回答三个能决定路线的问题。** 以下是后续建议，不是本轮实施授权。新增规则和合成包注册分别按准确作用范围确认。

| 问题 | 首个可查看成果与停止条件 |
| --- | --- |
| 账户封网是否真实覆盖 PSEC | 在相同的原本可达回环 TCP/UDP 目标上，比较普通 A 与仅回环 PSEC 的加规则前、阻断时、撤规则后，并设错误身份及宿主对照。能归因的阻断和恢复必须成立。另从首次业务调用开始记录两个 DNS API、唯一域名、客户端与服务 PID 及无丢失跟踪。若匹配或 DNS 边界失败，停止此候选。原生 IPv6 继续暂缓，不以本来不通作为成功。 |
| 包激活是否保留隔离归属 | 先核对启动源码，再用同激活类型的合成 MSIX 测冷启动、已有实例、别名与辅助进程。每个实际执行者都须核对用户与容器身份。multi-claude 的 Windows 脚本找到包后调用应用别名并传资料路径，它没有提供完整隔离边界。单测普通 EXE 不能回答包激活问题。[multi-claude 源码](https://github.com/thomasog/multi-claude/blob/main/src/windows/multi-claude.ps1) · [微软激活接口](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iapplicationactivationmanager-activateapplication) |
| 两套时区能覆盖哪些实际调用 | 先在模拟器分别列出窗口、请求语言、渲染器、原生 Win32、CRT、.NET 和辅助进程的冬夏读数。现有证据只有应用层可分开，Windows 原生读数仍随宿主。若必需功能依赖原生时区，应先评估最小应用兼容层及其边界，不能拖到全部网络工程完成后才发现阻塞，也不能承诺所有程序天然支持 `TZ`。 |

本轮研究结论是有条件优先验证账户预阻断的简化路线，同时提前检查包激活和时区兼容。原受保护创建器路线保留用于更强的同账户篡改防护需求。没有证明完整产品可交付，也没有撤销原 N4 的失败结果或 S5–S8 的验收目标。后续试验应以一个有明确停止条件的批次交付，失败就给出对应路线的否决依据。

#### Sol 接手执行方案

2026-11-23，按用户“给出清晰的方案让 sol 去执行”制定。已复用既有 GPT-6.2 Astra 审查代理进行只读审查，采纳规则峰值与累计数量、首次执行证据、端口影响、独立回滚和兼容性前置五项修正。本次只交付方案，没有把代码准备或实机执行标为已授权、已完成，也没有实际切换会话模型。

**本批次终点。** 给出 A 的账户预阻断候选是否成立、合成包激活是否保留隔离、各层语言与时区能否独立的分项结论，附证据及清理结果。A 网络通过后仍不自动扩展 B、真实上游或真实客户端。原 N4 的同账户句柄防护仍记为未通过。本候选验证的是“首次业务网络请求前已有默认拒绝，开放代理前身份已核验”，采用这个替代验收和扩大到整个 A 账户均须明确确认。

**授权与执行边界。**

| 范围 | Sol 应如何推进 |
| --- | --- |
| 计划交付 | 方案已完成。用户随后要求 Sol 接手，进入 P。 |
| P 准备阶段 | 用户已授权必要仓库代码、构建和不改变系统配置的离线检查。实际证据与未完成项见本节后续记录。 |
| A 网络实机批次 | P 通过后，集中展示准确清单及影响，核对用户是否已明确批准 M、F、X 的账户范围、规则预算和目录 ACL。尚未批准时一次确认三段，已有对应批准且清单符合范围时直接执行。获批后按门槛连续执行、逐段清理和更新本页，不为同一范围内的正常步骤重复询问。 |
| 合成 MSIX 注册 | 先构建并列出确切包身份、清单、目标用户、信任方式、涉及的证书存储或开发者设置以及撤销命令。可与已准备好的网络清单一并提交确认，但未明确的注册、证书或系统设置不能夹带。 |
| 更换隔离机制或扩展权限 | 不自动改为原生 AppContainer、注入、服务、驱动、持久规则或授予账户特权。确有需要时给原因、影响和回滚，再按确认推进。 |

P/U 历史保留资源与 10810 不连接、不停用、不改配置。所有新代理使用另行分配的临时端口。宿主保持联网，系统 DNS、网卡、TUN、系统语言/时区、全局审计维持原状，不重启 BFE。只用模拟器、合成身份、合成域名与测试目录，不启动 Sandboxie、真实客户端或浏览器。原生 IPv6 连通实验继续暂缓。默认不提交或推送 Git。

**P · 准备阶段，首个可查看成果。**

1. 核对当前路径、分支、差异和本页状态，保护现有修改。只读确认 A 是专用标准账户，宿主控制身份与 A 不同，列出 A 的现存进程。存在无法归属的 A 工作负载时不启动账户封网，也不杀掉它。核对 Windows/MXC 版本、可信执行器哈希、测试工具、旧实验清理状态及私有目录父级权限。缺少 SDK 或构建工具先列明，不能用旧实测版本的结论替代新版本。
2. 在改网络代码前，给出一页兼容性结论，记在本节状态表。只读检查已知包清单和启动源码的 `RuntimeBehavior`、`TrustLevel`、`EntryPoint`、别名与单实例行为，不激活真实包。设计同类型、独立名称及别名的无联网合成包。确认能否使用当前已有工具构建和在获批条件下注册，不默认开启开发者模式、安装系统证书或修改真实包。原生时区仍读宿主是已有缺口，不写成“时区通过”。若必需功能已被明确证据否决，先交付影响，不自行投入完整网络批次。未知或未实现不能冒充已证实不可行。
3. 实现独立的 AccountGuard 模式，默认仅准备，实机必须显式选择执行入口及已核对的清单。不要把已有账户规则安装器改个参数后直接运行，它在 `windows-lab-wfp.cs` 中使用 Persistent 标志、两个账户和 20 条规则，超出本方案。复用原生结构、身份核验、协议、跟踪与回滚代码，保留 N1–N3 旧入口和原始报告。
4. 准备私有本机清单，含运行号、实际 A SID、来源哈希、每个规则/子层 GUID、代际、层、条件、权重、生命周期、端口、进程身份、临时路径、超时、独立回滚命令和预期撤销结果。清单及恢复信息须在首次 WFP/ACL 写入前原子落盘于已确认 A 不可改的宿主位置。没有这样的目录就停在准备，不先改权限再补记录。敏感清单不提交仓库。
5. 编译并运行纯构造与判定器检查，覆盖错 A 身份、用户条件缺失、错误包 SID、过宽地址/端口、Persistent/Boot/硬允许标志、时序颠倒、代理未认证、DNS 漏发或归属不明、ETW 丢失、无正对照、旧流截止后送达及回滚残留。回滚选择器必须拒绝清单外 GUID、他人进程、越界路径和未知子层成员。不能导入有顶层副作用的旧实机脚本来做“自测”。

P 的验收是编译及纯检查通过，兼容性初评、准确操作清单、离线结果和可单独调用的恢复入口均可查看。最终报告要给出实际生成的执行、离线重算、回滚命令，不能把拟新增命令描述为已经存在。此阶段不通过就修复准备工作或交付确切阻塞，不请求用户批准一个尚未具备恢复条件的实机操作。

**代码范围与复用入口。** 接口的实际实现和可运行入口以本节末的准备结果为准。保持现有 C#、Windows PowerShell 5.1 与 Node/Electron 技术栈。

| 文件或模块 | 限定职责 |
| --- | --- |
| 新 `mock-desktop/windows-lab-n4-account-guard.cs` | 在 `StudioLabWfp` 的现有原生声明上扩展单账户 Static 拒绝和 Dynamic 例外，严格区分账户 SID 与容器 SID，独立读回安全描述符、条件、有效权重和生命周期，按清单撤销。 |
| 新 `mock-desktop/windows-lab-n4-account-guard.ps1` | 准备和实机入口分开。编排 M/F/X，保存清单、单调时序和进程身份，超时进入清理。不得默认提权或运行实验。 |
| `mock-desktop/windows-lab-n4-account-run.ps1` | M 的清单固化、租约、观测、安装/读回顺序、停止与恢复流程。目前可跑离线演练，真实操作由后续宿主适配器接入。 |
| `mock-desktop/windows-lab-n4-account-host.ps1` | 宿主回环哨兵、A 探针策略与流式回执、持句柄身份和父子关系、WFP 独立读回、退出监督及回滚。`-SelfTest` 是离线入口，`Invoke-N4StagedReviewedMatch` 需要已经封存且另获准的私有运行目录。 |
| `mock-desktop/windows-lab-n4-batch-prepare.ps1` | 只读本机核对、编译、准备 M/F/X 清单与精确规则对象预算。`-VerifyDraft` 只读复核总清单、阶段草案和包内文件。草案本身禁止执行。 |
| `mock-desktop/windows-lab-n4-proxy-run.ps1` | F/X 前置检查、宿主拓扑与规则准备、独立管理、故障取证和回滚编排。探针用标准输入输出，健康阶段使用 N3 三端日志，DNS 和恢复对照已接入运行入口。 |
| 新 `mock-desktop/windows-lab-n4-account-control.ps1` | 管理动态例外、独立观察与回滚入口。回滚进程不与故意终止的例外管理器共命运，不信任 A 可写的命令来选择删除对象。 |
| 新 `mock-desktop/windows-lab-n4-account-result.ps1` 及纯自测 | 从原始报告分别判定身份、规则、冷启动、协议、DNS、宿主与清理，缺字段不通过。合成正例不是实机证据。 |
| 现有 `windows-lab-wfp-container.cs`、`windows-lab-wfp-bind.cs` | 复用 Static/Dynamic 生命周期、绑定保护、读回和身份核验。不得改坏旧模式或复用仅认容器 SID 的校验去接受用户 SID。 |
| 现有 `windows-lab-psec-probe.cs`、`windows-lab-n3-simulator.cs`、`windows-lab-n3-protocol.*`、`windows-lab-n3-target.cjs` | 最小增加首条业务操作立即做网络/DNS 的探针模式，复用 HTTP、CONNECT/TLS、合成目标和原生子进程。其余旧实验无需重跑。 |
| 现有 `spaces.cjs`、`space-window.cjs`、`verify-spaces.cjs` | 复用偏好读数和旧报告。兼容性探针另设明确入口，不调用会顺带双开、联网或改用户配置的整套旧验收。 |

只有实际需要的直接依赖才作局部修改。合成包和无联网时区探针放入 `mock-desktop/` 的独立实验子目录，其产物与本机报告放 `.prototype/`。路线、状态和公开摘要仍只维护本页。当前仓库多项代码尚未跟踪，接手不能认为远端文档仓库已经包含这些文件。

**A 网络批次的准确范围。** M、F、X 依次运行，前一段的规则、进程、监听及跟踪全部回收并复测后才进入下一段。整批共用一个新增宿主私有临时根目录，仅该新目录设置保护 ACL，父级、仓库、账户资料及现有文件 ACL 不变。根目录与恢复清单是批次资源，保留到整批结束或提前停止且清理通过。没有满足权限的父级时不实施。A 可执行探针与宿主受信组件分开放置，A 不得读取私有配置或改写受信组件。

| 段 | 同时存在的本轮规则 | 单次完整批次累计成功添加上限 |
| --- | --- | --- |
| M · 账户条件与冷启动默认拒绝 | 4 条按 A 用户的 Static CONNECT/RECV_ACCEPT V4/V6 拒绝，1 子层，无代理例外 | 4 次过滤器添加，1 次子层创建 |
| F · 协议、故障与恢复 | 4 条账户拒绝 + 4 条新入口 `P′` 与合成上游 `U′` 的 V4/V6 TCP 绑定拒绝 + 至多 1 条动态 E，2 子层 | 8 条 Static 各添加一次，E 初次及三次恢复共至多添加 4 次，合计 12 次过滤器添加、2 次子层创建 |
| X · 入口代理退出 | 使用另一组新端口 `P″/U″`，与 F 同样最多 9 条过滤器、2 子层，退出后不恢复该端口 | 9 次过滤器添加，2 次子层创建 |

整批峰值为 **9 条过滤器、2 个子层**，成功过滤器添加累计最多 **25 次**，子层创建累计最多 5 次。清单预分配各段及 E 每代的 GUID，分别记录安装尝试、成功提交和撤销。不能拿峰值代替累计写入，也不得增加固定序列以外的故障或 F 的第四次恢复。失败后先清理并报告，不盲目重跑实机。

四个受保护的代理端口均须为新临时端口，避开旧 P/U、10810、动态分配范围、排除范围及现有占用。每个端口一对 V4/V6 TCP 绑定拒绝，没有地址条件，覆盖通配绑定。普通宿主进程显式把这些端口用于新监听或 TCP 源端口也会被拒，这是需要确认的局部宿主影响。TCP/UDP 哨兵、HTTP/TLS 目标、宿主新旧连接另外占用端口，逐项列入清单，它们不在这四条绑定规则的保护范围内。

E 只在同一账户拒绝子层中以更高权重软允许以下条件的交集：A 用户、核验过的实际容器 SID、TCP、远端 `127.0.0.1`、本段 P′ 或 P″。保留其他子层的裁决，不使用硬放行。代理先核验映像/进程/端口归属并独占绑定，再安装绑定保护并验证健康，最后才开 E。各控制/代理/目标的信任边界沿用 N2/N3，受信宿主转发器不是本轮被 WFP 限制出口的对象。

**M · 证明账户规则命中实际容器。**

1. 提前启动目标、DNS 跟踪和宿主对照。无新规则时，普通 A 和仅 `networkLoopback` 的 PSEC 分别访问同一组 IPv4 回环 TCP/UDP 目标，必须有成功标记。宿主身份作为不匹配对照，不为错 SID 另装一组规则，也不封锁其他真实账户。
2. 宿主事务安装四条 A 拒绝，从另一个 WFP 会话读回完整内容。在同协议、同地址、同端口重试，普通 A 与 PSEC 均须被拒，宿主仍成功。只有容器原本已不通的结果不算命中。若声称 RECV_ACCEPT 行为通过，须另有 A 监听端的可达基线、入站结果和发送端对照，否则只记入站规则读回，不能称已实测入站阻断。
3. 保持四条拒绝，创建全新的 MXC/PSEC 实例。用宿主单调时钟记录事务提交、独立读回结束、调用创建、进程创建时刻与首个探针事件。探针第一项业务行为就是直接连接及两项 DNS 调用，不等待宿主文件放行来制造安全时序。核验标准 A、会话、实际容器 SID、网络能力和活句柄。只记录 `inJob=true` 不能宣称 Job 归属及退出联动已证明。
4. 从首次调用开始，按唯一域名追踪 `DnsQuery_W`、`GetAddrInfoW` 的调用 PID、Dnscache 服务 PID 及发送/回复。容器内不得代发。普通 A 的容器外 DNS 正对照单列，不能假设账户规则会阻止它。服务归属不明、首个事件前未开始观测、ETW 丢失或未知调用者均为证据不足。
5. 执行共同回滚，重测普通 A 与相同配置新 PSEC 的原目标已恢复可达。前/中/后三组证据和宿主连续对照均成立，才放行 F。第一处身份、匹配或 DNS 差异出现后停止依赖实验。

**C · 提前给出包激活和时区结论。** 源码初评属于 P。获准注册后，使用无联网功能的合成 MSIX 检查冷激活、已有实例、执行别名与辅助进程，记录实际用户、包/容器身份、会话及进程关系，不调用真实别名。此项不增加 WFP 规则。普通 EXE 直启结果不能代替包激活，单纯返回一个 PID 不能证明它属于本轮容器。注册失败或激活转到容器外均须定位首个差异，不给该进程追加宽泛放行。清理按精确包身份与注册用户撤销，只移除本轮确实新增的信任对象，不能卸载别的包。

时区探针只用合成程序，分别以 `zh-CN / Asia/Shanghai` 和 `en-US / America/Los_Angeles` 两套启动配置运行，不能把配置名称冒充两个真实 Windows 账户。读取默认窗口/运行时语言、`Intl`、Win32、CRT、`.NET TimeZoneInfo.Local` 与辅助进程。固定比较 `2026-01-15T12:00:00Z`、`2026-07-15T12:00:00Z`，统一记录相对 UTC 的偏移，上海应为 +8/+8，洛杉矶应为 −8/−7。显式传目标时区的日期换算不算默认环境生效，`Date.getTimezoneOffset` 的反向符号单独转换。网络请求语言沿用旧证据，若没有在新链实际发送就标待测。宿主读数前后不变，原生读数仍随宿主就标未实现，不通过改系统时区、注入或隐去该行来过关。

C 的准确包注册/信任范围尚未确定，Sol 必须先在 P 准备完整。尽早执行已获批的 C，避免把明确的必需兼容性阻塞拖到完整网络验证之后。C 未获批或证据不足时可以交付其独立状态，不能据此宣称产品可行。若已证实必需功能在批准范围内无法实现，先汇报该影响，再由用户决定是否仍单独完成网络子目标。

**F · 真实时序下的合成代理与故障。**

新一段先布好观测并安装、独立读回四条账户拒绝，再启动全新 A 模拟器。无 E 时，包含代理未监听在内的所有直接连接均失败，首批 DNS 无代发。随后按 N2 方式保护新 P′/U′，宿主持活句柄核对实际实例与容器身份后开 E。原生客户端、受控辅助进程分别完成 HTTP 和 CONNECT 内 TLS 的目标标记往返，错误证书/主机名仍失败。P′和 U′监听或 CONNECT 200 本身不算业务成功，未支持的协议保持失败。

开放 E 前还必须有一次相同代理端点的有效反对照。P′已监听且宿主已完成健康往返，E 仍缺席时，PSEC 与容器外普通 A 均不能从该端点取得响应。开启 E 后，同协议、同端口的 PSEC 请求成功，容器外普通 A 仍被拒。这个差异用于检验用户条件和容器条件确实共同约束例外，不能用“无 E 时端口本来没有监听”代替。

按固定顺序执行健康 → U′拒转 → 同进程解除拒转并恢复 → U′静默 → 同进程解除静默并恢复 → 只退出 E 管理器、代理保持存活 → 新管理器核验后恢复 → U′进程退出。最后一步不重启 U′，不换 Q 端口。初次及三次恢复最多创建四代 E，核验每代均只含本段实际 A/容器/端口。每次故障前建立有编号的 HTTP/TLS 旧流，故障后继续尝试原流及新请求，保留最后成功标记与断开时刻。

代理拒转、静默及退出沿用 N3 的 **3 秒**验收期限，计入发现故障、停止接收业务、撤 E 和关闭成对旧连接。仅 E 管理器退出沿用 N1 的 3 秒期限，并要求代理和 A 在取证时仍存活，不能先杀代理制造通过。期限后不得送达新业务标记，旧请求不重放。拒转/静默的检测窗口内在途数据单列，不能声称故障发生瞬间全部停止。每个阶段检查直接 TCP/UDP、系统 DNS、入口目标域名是否代发，以及宿主 DNS、同一条旧 TCP 和新 TCP。宿主 TCP 证据限定受控 IPv4 回环，不外推全网。

U′退出后确认其全部已接受连接关闭，再用普通宿主和普通 A 的探针尝试冒用旧 U′，应被绑定规则拒绝，仍存活的 P′不得改用其他上游。回滚后验证绑定恢复，排除“只是端口仍被占用”的假通过。任何规则或身份异常、直连命中、容器 DNS 代发、宿主对照失败、超过期限或旧请求重放均立即撤 E、停止本段并清理。

**X · 单独验证入口代理退出。** F 通过并回滚后，用预列的新 P″/U″重复最小冷启动和健康往返，只退出 P″而保留 U″及 E 管理器供观察。要求 3 秒内 A 的旧流、新请求均失败，E 已撤除且账户拒绝仍在，冒用者不能重新绑定 P″或收到业务标记。全收尾后复测 A、端口与宿主。不恢复 P″，不添加第三代端口或额外规则。

**每段共同回滚和总报告。**

1. 第一次系统写入前，独立清理器必须就绪且清单已持久保存，不能只依赖主脚本 `finally`。准备阶段固定每段工作上限和清理启动时限，并校验所有单步等待有界，实测不能临时延长来掩盖超时。
2. 正常或失败都先撤 E，再停止并核验本轮 A 进程及全部业务连接，关闭代理与接受连接，最后按清单核验归属并删绑定规则、账户拒绝及子层。无法证明 A 工作负载已回收时，保留默认拒绝和独立恢复入口，不自动恢复其直连。
3. 独立枚举确认本轮 GUID/子层缺席、相关监听退出，保护端口重新可绑，普通 A 原本可达的 TCP/UDP 恢复，宿主 DNS、从加规则前一直保留的旧 TCP 和新 TCP 均正常。保留原始事件到回滚后对照完成，再关闭跟踪并核验其退出。
4. 段间只回收该段普通工作文件，保留批次私有根与清单。整批结束或提前停止后，确认全部段的清理证据通过，才删除唯一新建私有根及恢复清单。删除前验证解析后的绝对路径属于本批清单，永久报告移到本机结果目录。清理未通过就保留清单、入口及原始证据，记录具体残留，不重启 BFE、不全局重置网络、不删除别人的进程或规则。
5. 本机报告按 `windows-psec-n4-account-<run>.json` 保存，并记录阶段原始证据和哈希。结果字段分开为 `accountMatch`、`coldStart`、`proxy`、`dns`、`host`、`cleanup`、`packageActivation`、`timezone`，分别使用通过、失败、证据不足或未执行。不得用一个网络 `passed=true` 覆盖兼容性缺口。

**计划状态与交接。** 每完成一个可验收步骤，由主智能体先更新本表及成果入口，再继续下一步，不另建平行进度文档。

| 步骤 | 当前状态 | 下一动作或停止条件 |
| --- | --- | --- |
| 方案与复杂计划审查 | 已完成 | 已由 Sol 接手 |
| P · 源码/兼容初评、代码与离线准备 | 离线验收通过，实机门槛仍阻断 | M/F/X 入口已实现，当前权重为空的草案只可审阅。两条最高权重放行作用域的持续互斥未证明，当前算法无可用权重。 |
| M · 账户条件及首包前默认拒绝 | 判定器已过离线检查，实机待准备并确认 | 匹配、DNS、时序和回滚均通过才进入完整网络验证 |
| C · 合成包和时区 | 合成包已签名，注册未执行。时区子进程已测。 | 精确证书与包范围见下文，获准后验证激活归属。Win32/.NET 时区独立仍未实现。 |
| F · 协议与故障恢复 | 待 M 通过及批准 | 按固定八阶段执行，清理通过才进入 X |
| X · 入口代理退出 | 待 F 通过及批准 | 只验证退出，不扩展端口或恢复机制 |
| 总报告 | 待实测 | 分项结论与清理证据齐全即交付，B、真实客户端及生产部署另行决定 |

##### P 准备结果与接手位置

2026-11-23，Sol 接手。Windows `26300.9974`。独立只读查询确认 A 启用、属于 Users、非 Administrators，宿主身份不同，进程枚举未观察到匹配 A 的进程。IPv4/IPv6 动态 TCP 端口均从 49152 开始。此读数不代替启动当时的实际身份、端口排除/占用及私有目录复核。既有 N1–N4 回执保留。Microsoft MXC 1.1.0 发布资产重新分段读取，固定条目已缓存为本机 `.prototype/windows-lab/n4-mxc-v1.1.0-entry.bin`，解压后独立重算 SHA-256 为 `CB8F9253A2288BBB5E980D63216068EA3B640EBAF845BA3FCCC0D3FE822F7A0D`。本轮没有执行该二进制。[微软发布资产](https://github.com/microsoft/mxc/releases/tag/v1.1.0)

| 项目 | 结果与下一步 |
| --- | --- |
| WFP 规则及 M 判定器 | `mock-desktop/windows-lab-n4-account-guard.ps1 -SelfTest` 在 PS 7 和 Windows PowerShell 5.1 编译并验证四条账户拒绝、五条件软允许及 8 项参数反例。`mock-desktop/windows-lab-n4-account-result.ps1 -SelfTest` 在两版本接受 JSON 往返后的合成正例，拒绝 10 项反例。独立回滚与首请求探针的续做证据见下文。 |
| 本机网络预检 | 普通沙箱环境打开 WFP 会话返回 `0x00000005`。解除工具沙箱后的宿主普通令牌可打开会话，但 `FwpmFilterCreateEnumHandle0` 仍返回 `0x00000005`。该查询没有作用于基线，不能据此判断本机是否存在可用优先级。需要有权限的只读枚举与后续准确实验清单，当前不具备申请安装 M/F/X 的条件。 |
| 已安装包激活声明 | 主程序与两个 SSH 辅助入口声明 `Windows.FullTrustApplication`，另一辅助入口声明 `uap10:RuntimeBehavior=win32App`、`uap10:TrustLevel=mediumIL`。有 4 个执行别名。清单提供类型依据，单实例是否复用及运行时是否维持 PSEC 待测。无联网代码的合成包按这两种类型构建四个独立测试入口。合成程序记录实际用户、包、AppContainer SID、PID 与会话，再执行自己明确的单窗口逻辑。合成逻辑不能证明真实应用的单实例行为。 |
| 时区 | `mock-desktop/windows-lab-n4-timezone.ps1` 在独立合成子进程读取冬夏偏移。Node 上海 `+480/+480` 分钟，洛杉矶 `−480/−420`。Win32 与 .NET 两套配置均读出宿主 `−480/−420`。UCRT 直接读取 IANA `TZ` 时两套均为 `0/+60`，以 UCRT 格式 `CST-8`、`PST8PDT` 作正对照则分别得到 `+480/+480`、`−480/−420`。CRT 可单独配置，无法据此得到 Win32/.NET 进程级时区。宿主前后不变。本轮没有在 A/B 或 PSEC 中复测窗口和请求语言。 [微软 CRT 语法](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/tzset?view=msvc-170) |

本机准备报告保存在 `.prototype/mock-results/windows-psec-n4-prep-20261123.json`，SHA-256 `C511331CCDEE82E12A8F39788A50461165A3A6B24FBD7526CA2E6802F92D53EA`。本次所有测试是离线构建、自测或只读查询，未写入 WFP、修改系统 ACL、注册包或启动真实客户端。

**可以单独审阅的 C 注册范围。** 本机生成的 [签名合成包](.prototype/n4-activation-eaf7f3f6eec34bccae2c601673b203ed/Studio.N4.ActivationMock.msix) 为 `Studio.N4.ActivationMock` `1.0.0.0` x64，发布者 `CN=Studio N4 Simulation`，SHA-256 `0CC5119D85171C4E5B4778580AE9F4678104283F16A9B3278CFC19E7D566808C`。测试叶证书指纹 `7F9F3D9CC453915CA99881CE47B99AC766E796FB`，有效期至 `2026-11-30T16:51:47Z`。签名读取的证书与导出的公开 `.cer` 一致，信任校验因该证书尚未受信而返回错误。签名时生成的一次性 PFX 已删除，证书库未写入。重建入口是 `mock-desktop/n4-activation-mock/build.ps1 -SignForTest`，若重建须更新签名范围与确认内容。

建议 C 只批准导入这一枚公开测试证书到 `LocalMachine\TrustedPeople`，以 A 身份注册这一份包，并执行其合成冷、热、别名和辅助进程激活。证书信任作用到整台机器，包只向 A 注册。先确认该指纹、合成包和别名无既有同名对象，留存注册后实际 `PackageFullName`。结束时只停止本轮合成进程，在 A 内用 `Remove-AppxPackage -Package <本次读回的 PackageFullName>` 撤包，从 `Cert:\LocalMachine\TrustedPeople\7F9F3D9CC453915CA99881CE47B99AC766E796FB` 删除本轮导入项，再读回包、别名、证书、进程及合成回执目录。不得卸载其他包、增加根证书或切换开发者模式。此接受和撤销范围独立于 WFP。 [微软包签名和本机信任](https://learn.microsoft.com/windows/msix/package/sign-msix-package-guide)

**P 续做结果。** `windows-lab-n4-account-control.ps1 -SelfTest` 在 PS 7 和 Windows PowerShell 5.1 验证 M/F/X 三种清单，拒绝 10 种错误清单，包括保留端口、重复 GUID 和不符合阶段预算的例外。独立回滚命令由后续启动器从受保护的 `ClaudeStudioN4Account-<run>` 目录运行 `windows-lab-n4-account-control.ps1 -Rollback -Directory <同一目录> -ManifestSha256 <写入前记录的哈希>`。入口要求实际目录 ACL、当前宿主和 A 身份、清单及 DLL 哈希通过核对，并独占启动器共用的 `recovery.lease`。A 尚有进程、身份不明、端口仍有活跃连接或动态例外未消失时，保留默认拒绝。原生清理在同一个事务内核对和移除本段账户与端口规则，另开会话确认本段所有 GUID 消失。该入口未在实机撤过任何规则，仍需证明启动器持锁、工作负载回收和宿主回滚对照。

首请求探针在通过 `N4_ACCOUNT_MATCH` 编译开关构建的 `StudioProbe.exe` 中提供 `n4-account-match` 模式。它直接尝试带唯一标记的回环 TCP/UDP 和两项 DNS API，记录单调时钟、原生结果和进程身份。首请求前无等待信号，发出回执后才为宿主读回活进程留出短窗口。x64 探针与恢复 DLL 通过编译，错误运行号和 `10810` 参数在请求前被拒。后续要把探针回执与独立的进程、目标、WFP 和 DNS 事件关联，不能单用回执判过冷启动。构建和反例证据见本机 `.prototype/mock-results/windows-psec-n4-recovery-prep-f7ad6a90ab2148c0a18480c9927915a6.json`，SHA-256 `E8D575A88D53629484E4DD1195B8DAB44DDF647C16BE396295BE32BC3B9F470F`。

2026-11-23 17:03 UTC，IPv4/IPv6 TCP 动态区间均为 `49152–65535`，只读查询当时未列出 TCP 排除区间。`40000/40001`（F）与 `40002/40003`（X）是当时未见占用的候选端口，与历史 N2/N3 的测试端口不同，没有实际绑定。启动前按确认清单重读，并以真实独占绑定为准。M 段使用临时回环哨兵；宿主新旧连接及 TCP/UDP 哨兵的具体端口需要在启动编排中读回。此次续做仅写工作区，未安装 WFP、改变系统 ACL、注册包或启动真实客户端。

**M 编排续做。** `windows-lab-n4-account-run.ps1 -SelfTest` 在 PowerShell 7 与 Windows PowerShell 5.1 均通过一个合成正例与 10 个故障分支。启动前以独占运行锁固化 `recovery.json`，在写规则前再次校验哈希；基线、写入、两次独立读回、阻断探针与冷启动依次判定。实际安装回执丢失由独立回滚入口处理。若工作负载退出证据不足，则保留默认拒绝及清单。唯一运行锁用真实文件和独立合成子进程实测，子进程持锁期间回滚端无法获取，强制终止该子进程后能取锁，清单哈希不变。此处独立进程只持文件锁，没有运行任何账号或 WFP 实验。

旧 DNS 解析格式会丢弃 `psec/ordinary/host` 角色的新 canary 域名。`windows-lab-dns-trace.ps1` 现有 `-AccountMatch` 观测模式，保留同一运行前缀却无法归因的事件。M 编排基于四阶段 PSEC 的 DNS 回执、观测就绪时刻、已核对的 PID、ETW 丢失计数和独立 3010/3011 发送/回复判定。演练确认漏采、未知归因以及任一 PSEC 阶段的代发都不能通过。旧格式样例的解析结果一致。报告保存在 `.prototype/mock-results/windows-psec-n4-match-orchestration-prep-20261123.json`，SHA-256 `AE47D8E405B6BC3DBA190A8A9ED5C3B13EB3A3B519A5CF9FA6DE6B5A0CD16B8A`。待接实际宿主适配器后，规则读回须使用独立 WFP 会话，进程和时序须使用实际观察；当前 `-SelfTest` 属于离线证据，不能用作放行 F 的 M 实机结果。

**M 宿主接口续做。** `windows-lab-n4-account-host.ps1` 的 WFP 回调在写入和读回前验证已审阅清单字节、当前宿主与 A、私有目录及启动器租约，并验证控制脚本和 DLL 哈希。规则读回打开独立 WFP 会话。回滚通过单独 Windows PowerShell 子进程调用原保护目录内的控制脚本，要求正常退出且返回完整 M 撤销回执。该回调尚未运行 WFP 操作。新清单必须包含 `controllerSha256`，缺字段在两版 PowerShell 自测中被拒。启动编排按原字节固化已审阅清单，保留尾换行并读回同一 SHA-256。

宿主在两版 PowerShell 下用真实 `127.0.0.1` TCP/UDP 回环验证标记计数，测试前后复用同一条旧 TCP 流，每次另开新流，关闭后确认三个监听均已释放。普通工具沙箱阻止回环 `EndConnect`，该自测通过只允许本机回环的工具权限运行。回滚传输用真实子进程接受一条有效回执，拒绝 5 个失败场景。M 启动接口已构造 20 秒的只读夹具策略，解析带本轮标记、目标和单调时钟的流式回执，拒绝异轮标记。持活句柄复核 A SID、包 SID 和能力的代码已编译，尚无实际 A 令牌读回。还需可信启动器接上流式输出，核对其与候选进程的实际谱系，用独立观测关联创建时间和第一请求，并在首条规则前启动独立退出监督。未运行 A、真实客户端、包注册、ETW 实机或系统 WFP 写入。

本机报告 `.prototype/mock-results/windows-psec-n4-match-host-prep-20261123.json`，SHA-256 `2AB4CC28D8EB9BB2A7050DA89859523482383B233FBA9ECAF76400FF775D3F72`，包含两版 PowerShell 结果、x64 产物哈希和源文件哈希。该阶段还未产生可执行的已确认实机批次。

**M 启动与监督续做。** `Invoke-N4StagedReviewedMatch` 已接入 M 的实机调用链。它要求已提升的宿主、受保护的 TEMP 运行目录、精确 SHA-256 的 `reviewed-M.json`、独占运行锁文件、固定 DLL/控制脚本、只读夹具目录和经核验的 A 专用身份。清单中的 `fixtures.probeSha256` 必须和实际探针一致，`wxc-exec.exe` 必须匹配已固定的微软发布哈希。接口先核对规则优先级和当前 A 进程，再交给原 M 编排。当前没有自动建立或提权运行该目录的入口，实机仍需准备完整材料并确认范围。

A 启动复用原账户工具，新增的流式模式保留子进程标准输出供宿主抢在探针退出前读取，既有缓冲模式仍是默认。宿主用实际句柄验证用户 SID、会话、运行文件、AppContainer SID 和网络能力，再用 Windows 进程快照核验 `启动器 → MXC → 探针` 或 `启动器 → 普通探针` 的关系。限界事件使用单调时钟，独立的 Windows 创建时间用 UTC 验证在启动/观测区间内，不把两种时钟当作同一个时间轴。M 结果保留已解码的 DNS 原事件和探针回执，便于复核。真实 MXC 的 stdout 是否及时到达、运行时实际谱系和活令牌仍待实机。[微软进程快照结构](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w)

独立监督进程先按 PID 与创建时间持有真实启动器句柄，再返回绑定本轮清单的就绪回执。写入规则前复核监督仍在运行。启动器退出后监督尝试走相同的独立回滚入口；A 或其他受测资源仍存活时留存默认拒绝及恢复材料。监督最长等待 420 秒，确认规则已撤销后可提前解除。两版 PowerShell 的本机测试独立启动合成子进程，验证父子关系、进程退出通知、错误创建时间与已退出监督均被拒；结果自测另拒绝缺少谱系和创建时间越界，共 12 个反例。x64 编译与宿主回环复验通过。报告 `.prototype/mock-results/windows-psec-n4-match-wired-prep-20261123.json`，SHA-256 `3FF5816183ECA907345BE05C1C0C59B033551251AF03508BAF45259C6239FFE4`。本轮未运行 A/PSEC 实机、写入 WFP 或注册包。

**M/F/X 本机审阅草案。** `windows-lab-n4-batch-prepare.ps1 -Prepare` 已用本机 A 身份和最新 TCP 范围构建单批材料。草案为 `.prototype/n4-batch-0fec08fd31b5421f86df905411865a38/batch-review.json`，SHA-256 `D8B502050258589AB2D628673B52483D6FBEEF3EA4B7B609487151FCABF23558`。同目录的 `draft-M.json`、`draft-F.json`、`draft-X.json` 包含每段预分配 GUID 与本机身份，不公开。`bundle` 包含 x64 原生 DLL、同时支持 M/N3 协议模式的探针、编译好的合成代理、目标脚本、恢复脚本和固定 MXC 1.1.0 执行器；摘要列有每个文件的 SHA-256。候选端口仍是 F `40000/40001`、X `40002/40003`。绑定前要复核，临时宿主对照、直接连接哨兵和目标端口以实际本机回环绑定为准。私有 TEMP 运行目录只是提案，未创建；其中 A 仅读取/执行精确合成夹具，不授予它修改控制器、规则清单或代理的能力。

本机脚本以只读 API 为已计划的账户子层和两个代理子层候选核对仲裁，避免绑定候选与账户子层占用同一权重。查询仍在 `FwpmFilterCreateEnumHandle0` 返回 `0x00000005`，三个阶段的权重保持 `null`，清单不能作为回滚/启动文件接受。两版 PowerShell 验证了 M/F/X 的 4、12、9 条累计添加预算和阶段内 9 条峰值，拒绝重复 GUID、重用 F/X 端口、第四次额外恢复、保留端口和不同账户等 5 个反例。未绑定候选端口、执行 MXC、启动 A 或改变 WFP/ACL。

##### 最新批次与 WFP 优先级结论

更新后的本机草案位于 `.prototype/n4-batch-7d1a2ddba1cb4b479837e3c8a665c831/batch-review.json`，SHA-256 `F22B624287D1D5023F05C4000EF647A041CC980B75F5715E1FF1714DAC09F573`。已按清单重读每个文件与各段草案的哈希。F/X 代际编排在两版 PowerShell 中通过，F 按顺序验证拒转、静默、例外管理器退出、上游退出，使用四代例外。X 使用新端口和一代例外，只验证入口退出。六个反例被拒，包括无同端口正对照、容器外普通 A 意外获准、旧例外仍在、超过三秒、A 仍存活和 X 重用 F 端口。原生作用范围自测另验证入口端口、独立子层及运行时包身份，合计拒绝 12 个错误规则参数。原生 F/X 开放入口要求四条账户拒绝和四条 TCP 绑定保护已经在独立层读回，再允许动态例外。当前仍需把 N3 真实代理、故障注入和观察回执接到这些接口，离线测试没有启动代理或 A。

**管理员只读结果覆盖了上面的权限缺口。** 真正高令牌的第一次查询已经进入枚举，返回 `No unused higher priority available`。第二次只读核对定位到 `sing-tun` 子层的两条 `PERMIT`，`flags=0x48`、最高竞争权重 `65535`，每条各 1 个条件。当前账户级检查把它们视为可能与 A 竞争，不能分配更高权重。结果分别保存为上述批次目录的 `wfp-priority-read.json`（SHA-256 `29284CB2217A0CAA2BA3495EC8D2CD39CF829F2F33C1360B2752F959A6830C15`）和 `wfp-priority-explanation.json`（SHA-256 `E5109D2422AC5D167655726D19FFE20588B8490E9DCC797D399FB17DAF5B2D99`）。没有写入规则、修改 TUN 或触碰 10810。[微软 WFP 仲裁说明](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)

管理员按 GUID 读回两条已安装过滤器。在 `ALE_AUTH_CONNECT_V4/V6` 上各有一个 `ALE_APP_ID / FWP_MATCH_EQUAL / FWP_BYTE_BLOB_TYPE` 条件。两个条件值均与正在运行的 `sing-box.exe` 由 `FwpmGetAppIdFromFileName` 返回的规范标识逐字匹配。诊断读取器仅接受两条已知类型的规则，优先级判定逻辑未改。[微软 WFP 条件标识说明](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-) · [sing-tun Windows 上游源码](https://github.com/SagerNet/sing-tun/blob/dev/tun_windows.go)

对 A 的只读权限核对包含映像和 9 个上级路径，间接本地组查询只返回 Users。路径上的 7 个重解析点均为云文件标签，没有名称替代标志。以 `AUTHZ_SKIP_TOKEN_GROUPS` 建立 SID 上下文并显式加入已知的本地和常见交互组后，`AuthzAccessCheck` 对 A 的映像 `FILE_EXECUTE` 和 `FILE_READ_DATA` 均返回错误 5。宿主对同一映像、A 对公开系统程序的执行正对照均获准。未登录 A 或执行任何映像。结论适用于当前 DACL 和已建模组，实际运行令牌、由其他身份启动的辅助进程、路径及权限后续变化仍未覆盖。[微软 Authz SID 上下文说明](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzinitializecontextfromsid)

本机批次目录内保留 `wfp-appscope-read.json`（SHA-256 `793C9944AFE10CCFA56D4FB8E9BD51DE8DA943347C85CA444E0A8B27C3952911`）、`wfp-appscope-path-metadata.json`（`E2EC14029AAF0F40EC45D9492D304CBA634C5AB8620FDD183186EB0040AD5BD0`）及 `wfp-appscope-authz-model.json`（`BB36C74015D3FE77A8F9FE253B2C593ACD3D129A4CC4931359DEBC48F2D8BDE3`）。原生守卫在 PowerShell 7 和 Windows PowerShell 5.1 重跑离线自测，各拒绝 12 个错误范围。批次草案的权重仍为 `null`，禁止执行，未做 M/F/X 实机验收。本步没有写入 WFP、ACL、包注册或系统网络配置。

**F/X 协议证据续做。** 健康代际每次要求主进程和辅助进程各有 HTTP 与 CONNECT/TLS 目标回执，四个标记各自经入口、上游和目标唯一关联。错误证书与错误主机名各有同代 CONNECT 路径、`TrustFailure` 回执且零目标标记。两版 PowerShell 离线自测各通过 F 四代与 X 一代，拒绝 10 个反例。回放旧 N3 报告关联四条 A 路径，并独立核对宿主协议夹具的两项 TLS 拒绝。混用两个历史运行的记录会被拒绝。尚需接入实际代理、按代际采集日志、验证活进程归属及失效时序，历史回放不计作 F/X 实测。

**更新后的代码审阅包。** `.prototype/n4-batch-6913a4c49b2946deaaf95d319960e977/batch-review.json`，SHA-256 `C92E1CDED544F6A6D1EDFC09F27EB879C09A4269CD10330229BC20E399E0D907`。已重新编译并核对 14 个包内文件和 3 个阶段草案的 SHA-256。打包进程没有管理员高令牌，枚举返回 `0x00000005`。以上管理员只读取证仍适用，所有权重为空且 `executionAllowed=false`。F/X 候选端口未绑定，本轮未启动 A 或真实客户端。

**F/X 代际日志。** 调度器在每次例外精确读回后、健康请求前记下入口、上游、目标三个文件的字节边界和 SHA-256。它只使用之后追加的完整 NDJSON 行，并按各写入进程的 PID 验证归属。已送达的请求标记在后续代际出现即失败。PowerShell 7 和 Windows PowerShell 5.1 的文件夹具均通过 F 四代、X 一代与 15 个反例，新增旧路径补证、历史内容改写、写入 PID 不符、不完整记录和跨代重放。回滚仍为离线回调演练。实机需由受保护的拓扑启动器提供各角色日志与已核验的进程身份。

**固定代理产物和只读复核入口。** 现有 N3 拓扑启动器增加可选已审阅夹具参数，要求复用固定文件名和阶段清单 SHA-256 的代理及合成目标文件。遇到旧运行日志或文件内容变化，在创建证书、启动进程或绑定监听前拒绝。成功启动时将用实际就绪进程的 PID 构造三个日志来源描述。离线核对验证了两份夹具、旧运行文件与目标脚本被修改的两个拒绝分支。既有 N3 默认构建入口仍保留。

上一份审阅草案是 `.prototype/n4-batch-60cdd82b1f2c4485a1f6244a9a7015f4/batch-review.json`。PowerShell 7 和 Windows PowerShell 5.1 均核对 14 个产物和 3 个阶段草案，批次自测各拒绝 7 个错误清单，另以错误总清单哈希确认入口拒绝。

**F 的管理进程退出对照。** 已审阅的入口使用 `entry-n4` 模式。宿主通过私有控制通道传入管理进程 PID 及 UTC 创建时间，入口核对并持有实际进程句柄。它在上游仍健康时也会因该进程退出停止接入和关闭现存会话，状态回执记录关闭原因、原管理进程身份和单调时刻。F 的离线编排现在要求以同一代管理进程的回执通过，并拒绝 `controller-halt` 冒充进程退出。两版 PowerShell 各通过 F 四代、X 一代并拒绝 16 个反例。

本机在宿主上启用合成代理与合成目标，只绑定独立的临时 IPv4 回环端口。只退出占位管理进程后，入口在 **128.73 ms** 停止接入，客户端在 **143.50 ms** 观察到旧 HTTP 和 CONNECT/TLS 都已断开。两条新请求均失败且没有到达目标。入口和上游保持同一进程，换上新占位管理进程后两条新路线均恢复，并由三端日志确认。结束核对临时目录已移除、测试监听为零。报告 `.prototype/mock-results/windows-n4-owner-watch-7f4887288ce2495eb42f938c6c56b5a7.json`，SHA-256 `BC6CAC16677E0388CA1D7447D35816A526D86119241287504A5D23D4F6BC8690`。此测试覆盖代理侧断流，WFP 动态会话实际撤销、A 身份和 F/X 全段回滚仍待验证。

**独立例外管理和逐代清理。** 控制器的 `-ProxyOwner` 入口复用受保护宿主 TEMP 根、恢复清单 SHA-256、启动器独占租约、宿主和 A 身份检查。它只接受本段本代、已记录哈希的 `proxy-owner-<F|X>-<代次>.json` 请求。核对启动器与入口、上游的实际进程关系、两个精确回环监听、活 A 探针的标准账户令牌/实际容器及其回环能力。宿主只在入口成功监视该子进程后才发出打开指令。子进程核对入口的同代健康心跳，从动态会话安装单个预列 GUID，使用独立 WFP 读会话复核。控制管道 EOF、入口心跳失效、进程退出、命令错误或超时均触发释放路径。段内和回滚前的宿主清理要求独立读回例外缺席且原基础规则完整。即使例外读回失败，也尝试回收工作负载，保留静态默认拒绝与恢复清单。

两版 PowerShell 的回滚清单自测各接受 M/F/X，拒绝 11 个错误清单，另通过 8 项例外生命周期检查。Windows PowerShell 子进程通过真实标准输入输出验证关闭、EOF、入口健康失效及未打开时超时，WFP 回调使用合成操作。文件锁正对照读到实际冲突错误 32。没有启动已暂存的特权管理入口，尚无 BFE 自动撤销时间或 A 应用断网的实测结论。原始管道报告 `.prototype/mock-results/windows-n4-exception-transport-f5dbb54ae2294d0ba341ff73805f367e.json`，SHA-256 `12905CF27BB231C31CF07B9B4C1B6B0DA83FAD43728E3085CDBA03D00F702F3F`。[微软 WFP 动态会话语义](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0)

**F/X 故障取证。** 有受保护的实机上下文时，故障操作只作用于留有句柄、创建时间和映像记录的本轮目标进程。拒转和静默发送给原上游。进程退出只终止对应的入口、上游或例外所有者。独立 WFP 读会话检查例外缺席、四条账户拒绝及四条绑定规则完整。退出端口另要求宿主通配独占绑定返回 `10013`。X 的管理进程在释放例外后保留观察窗口，宿主必须读到同代释放回执，同时确认入口已退出且 A、上游和管理进程仍存活。

故障判定核对两条旧流的目标请求、连续标记、原有时间戳及三秒内的关闭状态，要求两条新请求失败且零目标命中。恢复期间保留前一代日志边界，检查重放。失败保留当时已采集的旧流、目标事件和故障结果。两版 PowerShell 均通过 F 四代、X 一代并拒绝 21 个反例。使用旧 N3 报告回放拒转、静默和退出，每项均关联两条旧流及两条新请求。另用 Windows PowerShell 子进程验证了 X 的释放后存活、正常关闭及重复打开被拒，报告 `.prototype/mock-results/windows-n4-fault-observation-a878c94ac13e4fef88465c459f5b7f57.json`，SHA-256 `2B5E167999208EF0C37A93D76C81AFD9B27AA7A2A4FC1D0E9BD6BB241C729009`。管道测试使用合成规则回调，未测实际 WFP 关闭时刻、实机监听重绑或 A。

**F/X 前置检查、宿主准备和回滚材料。** `Get-N4ReviewedProxyPreflight` 要求当前阶段清单、前一阶段的原始结果、保护目录和两份哈希。它重算 M 的验收，核对 F 四代故障与恢复回执，再检查当前账户及绑定权重。准备器取得独占租约后，先独立读回前一阶段对象已全部消失，再把上一份 `recovery.json` 原字节归档为 `recovery-M.json` 或 `recovery-F.json`。现用清单按已审阅字节落盘。归档后、下一份清单写入前若中断，可以按原哈希恢复交接。已有活动清单、歧义或静态读回异常会阻断交接。最终结果写入 `result-M.json`、`result-F.json` 或 `result-X.json`，提交时不覆盖。

内部准备器 `Invoke-N4PreparedProxyStage` 启动独立恢复监督后布置合成代理与宿主观测，核对端口归属，安装并独立读回本段四条账户拒绝和四条绑定规则，再允许 A 的首次业务探针。回滚先清理例外和工作负载，再由独立控制器撤销已准许对象并读回；随后复测宿主、普通 A 与受保护端口，最后结束 DNS 跟踪。出错留下现用清单和错误回执。独立手动恢复仍使用同一保护目录内的 `windows-lab-n4-account-control.ps1 -Rollback -Directory <保护目录> -ManifestSha256 <现用恢复清单哈希>`，按实际 M/F/X 段核对回执。A 的控制与测量回调还没有完整实机入口。

两版 PowerShell 均通过真实文件交接、哈希不符拒绝、归档后中断恢复和覆盖拒绝，另拒绝 8 种无效前序报告。Windows PowerShell 子进程传输接受模拟的 F/X 回执并拒绝错段和错误输出，修复了模块首次加载进度误判为错误的问题。新草案的 F/X 清单因权重为空，均在转换成实机计划时被拒绝。未运行真实规则操作、A 或真实客户端。

**MXC 探针控制通道。** 固定的 MXC v1.1.0 CLI 读取配置后调用选定后端的同步入口。ProcessContainer 的管道透传路径在输出被重定向时，从当前执行器取得标准输入、输出和错误句柄，标记为可继承并交给工作负载。现有 `Start-LabProbe` 会关闭自己的引导用 stdin。为持久在线合成探针，宿主直接在 A 的凭据下启动固定哈希的执行器并保持标准管道打开，通过 `--config-base64` 提供同一只读夹具与回环能力策略。没有增加网络能力、允许写入的共享目录或系统设置。[微软 v1.1.0 CLI 入口](https://github.com/microsoft/mxc/blob/v1.1.0/src/tools/wxc/src/main.rs#L1387-L1425) · [ProcessContainer 句柄透传](https://github.com/microsoft/mxc/blob/v1.1.0/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L558-L686)

受保护的阶段启动器在账户规则读回后创建探针，第一份回执来自无需宿主指令的直连和 DNS 尝试。后续往返校验本轮随机标识、递增序号、单调时刻与持有句柄所对应的进程。健康观测用主探针和辅助进程实际生成 HTTP/TLS、坏证书/主机名与旧流回执。辅助进程等宿主核对活令牌和父子关系再退出。故障后的旧流关闭和新请求回执共用三秒截止时刻。F/X 的 DNS 事件完整归因、普通 A 及宿主对照还需接入。

已编译的宿主合成模式测试通过直接标准管道、经父进程继承标准管道、EOF，并拒绝错误标识、重放序号和合成模式中的网络指令。报告 `.prototype/mock-results/windows-n4-probe-pipe-9a61194ef320491db600e6c841187ead.json`，SHA-256 `BB5DA95FDB1E4242D234933E003C55B5146EEB0BF4F3483A24CB861BE80B64AE`。宿主试验使用无网络的合成入口，验证了本项目的消息编解码和本机管道。MXC 发布二进制、A、代理和真实客户端均未启动，不能据此视为 A 的实际句柄继承、活令牌或网络效果已经通过。

**F/X DNS、普通 A 和宿主对照。** 已审阅运行入口使用固定回调，回环哨兵与 DNS 观测先于账户规则。普通 A 在写规则前与回滚后都要命中同一组 TCP/UDP 哨兵。规则阶段验证宿主在该代理出口往返且普通 A 与 E 不存在时的 PSEC 不能连接。E 存在时仍用普通 A 复查；退出端口的重绑分别记录宿主和普通 A 的原生错误。宿主各阶段使用同一旧 TCP 流、单独新流和唯一 DNS 查询。PSEC 两项系统 DNS API 按域名、来源进程和阶段归因；存在 3010/3011 代发、未知事件、缺正对照、服务 PID 变化或 ETW 丢失都不能通过。关闭与新请求的三秒记录基于原始时间戳，DNS ETW 最终判定在回滚后完成，本版本没有实时 ETW 代发告警。

两版 PowerShell 的账户库、回滚、判定器、M/F/X 编排及批次清单自测均通过。F/X 拒绝 21 项调度反例、9 项前序结果反例和 9 项 DNS 反例。宿主合成回环通过 TCP/UDP、旧流连续性、退出监督和临时监听清理。另以当前编译的普通探针在宿主合成拓扑上关联了 HTTP/TLS 两条三端路径，并验证应用 503 不会冒充 WFP 的传输拒绝。临时监听和目录清理通过。记录 `.prototype/mock-results/windows-n4-ordinary-proxy-bbe0791a2d904c28b15dd9748d90bc78.json`，SHA-256 `8350FC035EF02A4BABA417D3A592FC4999DA96187BEF94ECBFA2A597882A8C8C`。没有在 A 下运行，也没有改 WFP 或 ACL。

**本轮最新审阅草案。** `.prototype/n4-batch-4a79f7bbc9e645d6b52003182967cc88/batch-review.json` 包含固化夹具、M/F/X GUID、端口、同段规则关系和操作预算。两版 PowerShell 核对 14 个包内文件、3 个阶段草案及各自哈希。在仓库根目录运行：

```powershell
pwsh -NoProfile -File mock-desktop/windows-lab-n4-batch-prepare.ps1 -VerifyDraft -Directory .prototype/n4-batch-4a79f7bbc9e645d6b52003182967cc88 -ManifestSha256 6263566A9A05856FD8B813555EC752C4366B59A599EA0FD7290FEBD6C4C2801C
```

**实机运行与回滚的审阅材料。** 以下入口已存在。运行输入须来自另行确认的受保护 TEMP 工作目录，当前草案的 `null` 权重在 M、F、X 三段均被实际解析器拒绝，不能作为执行输入。真正的管理员只读报告确认无更高可用优先级。后续若能证明 A 的实际令牌和目标映像路径始终互斥，须先审阅是否能安全使用现有仲裁。若改隔离方式，另审对宿主、回滚和 A 启动范围的影响。当前无可提交批准的系统写入批次。

| 操作 | 入口及必要审阅输入 |
| --- | --- |
| M 冷启动验证 | 加载保护目录内的 `windows-lab-n4-account-host.ps1 -FunctionsOnly`，调用 `Invoke-N4StagedReviewedMatch -Directory $RunDirectory -ReviewedJournalHash $MHash`。仅使用获准的 `reviewed-M.json` 及对应哈希。 |
| F、X 故障验证 | 加载保护目录内的 `windows-lab-n4-proxy-run.ps1 -FunctionsOnly`，调用 `Invoke-N4PreparedProxyStage -Directory $RunDirectory -Segment F -ReviewedJournalHash $FHash -PreviousResultSha256 $MResultHash`。X 替换为本段哈希与通过并回滚的 F 结果哈希。 |
| 独立回滚 | `& (Join-Path $RunDirectory 'windows-lab-n4-account-control.ps1') -Rollback -Directory $RunDirectory -ManifestSha256 $ActiveJournalHash`。只使用未归档的 `recovery.json` 哈希。回滚器核对清单、租约、工作负载退出和规则范围，再独立读回缺席。 |

本轮未启动 A、MXC、Sandboxie 或真实客户端，未绑定草案候选端口，未修改系统规则、ACL、历史 P/U 或 10810。A 令牌下的管道透传、时序、DNS、回滚，以及 Win32/.NET 原生时区独立和真实客户端，均保留各自未实测或未实现状态。

| 当前顺序 | 用户可查看的交付物 | 执行门槛 |
| --- | --- | --- |
| N1（已完成） | 管理器退出后 A 默认断网及回滚报告 | 已批准、实测通过并回滚；原始证据和判定修正均已保存。 |
| N2（已完成） | A 模拟器端口冒用、P/Q 切换、宿主与回滚报告 | 已单独批准，IPv4 模拟实测通过并回滚。 |
| N3（已完成合成实验） | 独立协议报告与 A 的 HTTP/HTTPS、故障、恢复及回滚报告 | 两步均已批准并通过，真实上游另行明确。 |
| N4 | 启动前保护、双空间归属、系统故障与恢复报告 | 原闭网预检未通过。账户预阻断的替代前提已审查，未实施，作用范围与原验收变化须确认。真实客户端仍需专门批准。 |

N1–N4 是原 S1 替代入口通向 S3/S4 的设计分支，未把原 S2 的容器内 IPC 标为通过，也未取消 S5–S8 的原验收目标。最初设计轮只改路线图；随后获批的 N1 已增加实验代码并完成临时系统规则实测和回滚。没有部署常驻规则，未提交或推送仓库。

### S2 · 只给容器内代理一条宿主通道

1. 在当前 MXC 接口上核对受支持的双向 IPC 传递方式，首选只交给指定代理进程的成对管道句柄。宿主只交换合成标记。Win32 支持句柄继承，跨 PSEC 启动链的可用性需要单独证明。[微软管道句柄说明](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-handle-inheritance)
2. 由可信启动器绑定运行号、空间和实际代理进程，业务子进程不继承宿主通道。合法双向标记须到达。同一用户下的无关进程、普通宿主进程尝试加入或冒用 A 均须被拒。停止任一端后，对端能观察断开，重开后旧通道失效。
3. 如果只能通过新的 ACL、命名对象授权或包注册跨过边界，先列明对象、可访问主体、宿主影响和撤销方法，取得确认。不能把通道限定给指定进程时停止。保留 S1 报告，关闭本轮管道和进程。

### S3 · A 经临时上游完成真实的代理协议

1. 接上宿主转发进程、测试上游 P 和合成目标。上游地址由启动器固定，容器只能提交业务目标。转发进程仅连接 P，把主机名原样转交，不进行本地目标解析。给原生 HTTP 客户端和模拟窗口实际使用的 Electron 网络栈分别设置标准代理。
2. 让两套客户端分别请求唯一的合成域名。HTTP 核对目标响应，HTTPS 通过 CONNECT 后在隧道内完成 TLS 和带标记的响应校验。测试证书信任限定在模拟客户端及该测试目标。关联窗口、容器内代理、宿主转发、上游和目标的同一标记。上游的 CONNECT 成功码本身不足以通过。
3. 另用原生子进程尝试直接 TCP、UDP 及两项系统 DNS 调用。要求直连诱饵零命中，DNS 服务未替应用、探针或转发进程发出对应目标名，宿主对照正常。任一侧只有请求日志而无有效目标响应，均保留该链路待验证。清理时先停窗口，再关闭通道、上游和目标。

### S4 · 上游故障时关闭 A 的旧流和新流

| 情况 | 操作与通过条件 |
| --- | --- |
| 冷启动时无代理 | 预留且不监听临时端口。新请求在约定时限内失败，外部目标无命中，系统解析未代发。 |
| 有活动流时停听、拒转或无响应 | 持续发送可编号的标记，记下故障注入、检测、最后送达和断开时间。已接通的隧道也要被关闭。故障后发出的新标记不能到达目标。无响应场景在测试前约定超时，报告实际耗时。 |
| 容器内代理、宿主转发或启动器退出 | 分别中止本轮拥有的组件，检查旧通道和已有流关闭，子进程无残留外联能力，新请求失败。用错误进程占用旧测试端口，验证身份不符时保持离线。 |
| 上游恢复，或从 P 切到 Q | 先暂停新转发、关闭旧流，再校验新上游身份并完成一次到目标的往返。保留 P 监听以观察误用。恢复后新标记只经授权的上游出现，旧端口零新增业务流量。 |

关闭监听端口后，已建立的隧道仍可能收发。宿主转发进程要用穿过上游到达受控目标的健康检查检测这种情况。检测到故障后，关闭相关隧道及待转发的数据，不在恢复后重放旧请求。静默超时要分别报告检测窗口内的在途数据和超时后的零送达。

每种故障均同时测宿主的默认 DNS、已有 TCP 流上的新数据及一条新建 TCP 连接。出现直连、代发或宿主异常时立即回滚。即使界面尚未报告“离线”，网络隔离也应始终生效。

### S5 · 两空间共用上游，分别启停

用另一个标准用户为 B 创建独立容器、代理进程和 IPC 通道。两个窗口及各自的原生子进程在同一交互桌面使用不同标记，并发经过同一测试上游。按操作系统身份归属请求，用请求中自报的 A、B 字段关联日志。

验收顺序为同时成功、互访对方入口被拒、只停 A 而 B 的旧流和新请求正常、重开 A、只停 B 而 A 继续正常、两边在线时停共同上游、恢复。共同故障时分别检查 A、B 的旧流、新请求、直连诱饵和系统 DNS，宿主同期对照必须成功。出现串户时停两边，保留首次错配的通道和进程记录。

### S6 · 在新容器下恢复日常工作流

| 用户操作 | 验收 |
| --- | --- |
| 打开、再次点击、独立停止、重开启动器 | 记录前台窗口句柄及所属进程。相同空间回到原窗口，另一空间继续工作，重开后每个空间只恢复自己的合成资料。 |
| A、B 同时登录，先确认 B 再确认 A | 分别使用模拟邮箱。回调绑定空间、发起请求和单次状态，重复、过期、串户和重开前的旧回调均被拒绝。 |
| 在原目录编辑合成项目 | A、B 各有私有资料。授权写者能在原路径产生 Git 差异，只读者不能写或删，未获授权者不能读。目录别名也只能有一个写者。交接须先释放旧句柄，回滚保留宿主的原项目与改动。涉及新增 ACL 时先确认具体对象。 |
| A 用上海、B 用洛杉矶，只改 A 并重开 | 核对默认界面语言、`Intl`、请求的 `Accept-Language`、子进程读数及冬夏两次 UTC 偏移，B 与宿主作为对照。Windows 原生时区另列。若必需界面依赖宿主时区，记录该功能受限，重新评审需求。[原生时区 API](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-getdynamictimezoneinformation) |

### S7 · 给每一类出口和系统代发路径定结论

建立一张覆盖表。每行记录“发起进程与身份、目标、健康时路径、故障结果、观察点、未测原因”。覆盖已用的 HTTP/HTTPS、长连接、原生 TCP、UDP/QUIC、应用自带加密 DNS、系统 DNS，及应用实际触发的外部浏览器、更新和后台服务。既要测同容器子进程，也要核对由系统另行启动的进程归属。对必需功能，未知身份或未知出口会阻断交付。

原生 IPv6 单列。按现有决定暂缓，待用户确认且能取得同协议、同目标的可达基线后，再测容器阻断。对局域网或外网作保证前，宿主和容器外探针也须在对应网络的受控目标完成正对照。需要调整网卡、TUN 或系统 DNS 才能取证时停在方案评审。缺少基线的协议在发布说明中保留为未验证。

### S8 · 经单独授权验证官方程序并交付

先用空白资料和获准的启动方式验证签名 MSIX 激活、两窗归属和进程树，任一辅助进程被宿主接管即暂停对应流程。经用户同意后，再由账户持有人在官方界面完成交错认证和日常操作。需要用户操作浏览器、接入实际指定代理或重启 Windows 时，按对应授权范围执行。代理故障演练始终使用可停的测试代理。

最终验收逐项对应 A1 双开与聚焦、A2 邮箱与回调、A3 应用及系统正常重启后的资料与会话、A4 项目原路径与权限、A5 正常出口、A6 故障与恢复、A7 语言与时区。每项记录适用的系统、SDK、程序版本和证据。交付启动、聚焦、停止、离线状态、代理恢复和卸载入口，并验证撤回后宿主仍能工作。没有官方授权时，阶段成果停在已验证的模拟器版本。

## 统一的取证与回滚

- **DNS**。每个身份、API 和阶段分配全新完整域名，同时记录调用 PID、DNS Client 服务 PID 以及 ETW 3010（发送）和 3011（回复）。容器外同账户作正对照，宿主在测试期间用另一随机名验证跟踪仍有效。服务归属不明、采集缺段或丢失事件时，结果记为证据不足。调用报错、缓存命中和仅看到零回复均不足以判定无代发。
- **数据路径**。代理、目标与直连诱饵分别计数，用运行号和标记关联。先证明协议和目标在对照条件下可达，再解释容器内的零命中。健康阶段需有上游与目标两端证据。故障阶段的宿主旧连接要实际收发新数据，新连接要得到独立响应。
- **回滚**。开始前登记本轮容器、进程、管道、端口、跟踪和临时目录。有获准的 ACL 或 WFP 变更时，保存原所有者与 DACL、规则 GUID 和独立的回滚入口。结束时先停本轮工作负载，再关通道和监听，撤销本轮规则并恢复原权限。读回过滤器、端口、跟踪、文件权限及宿主对照。出现残留则保持测试空间停止，记录具体对象供续做。
- **交接**。每完成一步，在本页更新日期、阶段、适用版本、报告名、通过或失败的判据、回滚结果和下一步。本机保留详细证据，仓库只收录脱敏摘要。代理地址、机器标识、账户凭据、会话资料和原始跟踪保留在本机。长期范围见[项目记忆](AGENTS.md)。
