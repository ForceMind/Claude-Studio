# 交接用合成夹具源码

两个目录保存最近实机验证所用的构建输入。请以 Windows x64 和现有的 .NET Framework C# 编译器检查。源文件里的同名部分类型属于各自的单独构建。

| 夹具 | 构建输入 | 已记录结果 |
| --- | --- | --- |
| startup-permissions | 目录内两个 C# 源文件和 windows-lab-n4-preflight.cs。目标为 x64 EXE，定义 N4_HOST_CREATE，引用 System.Web.Extensions.dll。 | 使用标准挂起参数后，CreateProcessWithTokenW 成功。原默认 DACL 仍允许普通 A 获取可恢复主线程的权限。 |
| mxc-bind 的探针 | 仅用 Probe.cs。目标为 x64 EXE，引用 System.Web.Extensions.dll。 | 同一 A 的 PSEC 内，规则生效时四项 IPv4 绑定与隐式绑定操作仍成功。 |
| mxc-bind 的 WFP 与令牌读取 | Guard.cs、Inspect.cs、windows-lab-wfp.cs、windows-lab-wfp-container.cs、windows-lab-wfp-bind.cs 和 windows-lab-n4-account-guard.cs。目标为 x64 DLL。 | 独立读回过滤器、确认容器身份并验证回滚。 |

实机控制脚本、逐轮清单及原始报告仍由原机器保存。下一步优先审阅[启动权限预检](../../ROADMAP.md#启动权限预检结果)。
