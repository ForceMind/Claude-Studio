# Claude Browser Android 合成原型

本目录是独立 Kotlin / 系统 WebView 合成原型，版本 `0.5.0-prototype.2`（`versionCode=50002`）。移植以 Windows 0.5.0 源码快照的账号和标签边界为基线。GitHub Actions 已完成官网和 Play 两个 Debug 包的构建、lint 和签名校验，10 项静态检查和每渠道各 15 项 JVM 测试通过。两个测试 APK 和 SHA-256 见 [Actions 产物](https://github.com/ForceMind/Claude-Studio/actions/runs/45220367140/artifacts/14840242885)。设备 WebView 和真实站点仍待验收。

## 已实现的入口

- 原生界面管理 A/B，各自使用固定、持久的 AndroidX `ProfileStore`，标签布局保存到应用私有 `SharedPreferences`。Cookie、WebStorage 由各自 WebView Profile 保存；退出到后台时调用对应 CookieManager 的 `flush()`。不调用默认的全局 CookieManager。不支持 `MULTI_PROFILE` 时拒绝开启多账号。
- 所有 WebView，包括 `onCreateWindow` 创建的子页面，构造后第一项操作都是 `WebViewCompat.setProfile`。弹窗使用原生 `WebViewTransport` 接管 Chromium 首次导航；不通过第二次 `loadUrl` 重放认证导航。UI 明确标出账户、合成弹窗与资源 URL。
- 页面实例按账号与标签共同索引。只有当前账号选中页的用户手势能创建合成弹窗。关闭弹窗仅移除同账号匹配的页面实例，保留同账号未被关闭的选中页以及其他账号的标签状态。
- 「账号设置」可交换 A/B 顺序。顺序随布局保存，旧布局默认 A 后 B，资料标识和已保存标签保持原样。
- 窄屏保留活动标签，其余从「更多」切换。「撤销关闭」按账号恢复普通合成页，最多保留 5 个原 WebView，时限为 10 分钟。容量淘汰后，该时限内仍可重新加载安全合成页。过期、异常导航及弹窗退出会丢弃对应恢复记录。
- 清除某账号的本机登录需要确认。具备 `DELETE_BROWSING_DATA` 时，关闭该账号的全部活动和缓存页面，清除其 Profile 中的 Cookie、网站存储和缓存。清理意图在重启后可继续，回调确认完成后才能再打开目标账号的页面，其他账号仍可用。已保存标签地址保留。此流程的设备效果待验证。[WebStorageCompat](https://developer.android.com/reference/androidx/webkit/WebStorageCompat.html)
- 每账户最多 12 个标签；应用重开保留 A/B 布局、所选标签与资料 Profile。已关闭的弹窗标签移除。进程重建后的弹窗按普通标签恢复 URL，不能恢复旧的 `window.opener` 或进行中的认证事务。损坏或不认识的布局版本保留原始值并关闭入口。
- 共同 HTTP 上游仅接受明确的数字 IPv4 与端口，本次运行锁定。`PROXY_OVERRIDE` 不可用、输入无效、调用失败或应用回调尚未到达时，不创建和导航页面。不添加 DIRECT 或绕过列表；通过 `removeImplicitRules()` 去掉默认 localhost/link-local 绕过。不改 Android 系统代理。
- 合成页是 `assets/demo.html` 与 `assets/popup.html`，使用 `WebViewAssetLoader`。代理应用成功后，点击 A/B 或新标签才加载。所有 WebView 仍设置 `blockNetworkLoads=true`，资源拦截器仅放行这两个完整 URL。可分别写入随机合成 Cookie/localStorage，并从同账户合成弹窗读回；不自动打开任何网页。

以上是代码行为设计，尚无设备上的多资料、Cookie 落盘或弹窗实测证据。共同代理设置成功也不证明上游健康，更不证明 DNS、QUIC、WebRTC、Service Worker、原生请求、Android 系统服务或其他应用没有直连。系统 WebView 不能当作 Windows 进程隔离或 VPN；本原型不提供每账户独立代理、语言或时区伪装。

## 更新行为

`UpdatePolicy.kt` 移植桌面检查合约，使用 UTC 04:00 对应北京时间 12:00，不随手机时区变化。

| 场景 | 行为 |
| --- | --- |
| 冷启动、再次收到启动器打开 Intent | 每次发起检查；在途检查合并。冷启动不补历史日期。 |
| 普通恢复前台 | 对照时钟和未完成触发，不因单纯恢复重复检查。 |
| 前台持续打开 | 每分钟及下一北京时间中午对照；午前已完成检查不能抵销午间检查。 |
| 睡眠或后台跨过中午 | 再次可运行时补最近一个已到期中午，可能是昨天；跳过更早日期，不批量补查。 |
| 断网、超时 | 失败后 30 秒、2 分钟、10 分钟封顶重试；网络恢复可提前重试；每次检查 15 秒超时，迟到结果丢弃。 |
| 不合法清单或配置缺失 | 当前触发停止自动重试；新的打开或下一中午再核对。 |
| 被系统挂起或强行停止 | 不承诺准点；没有 exact alarm、前台服务或后台周期任务。强停后必须由用户重新打开。 |

当前自动检查只会报告渠道配置未就绪，不发网络请求。定时检查不下载、不安装；UI 的“确认安装更新”是独立操作。Play 路径准备为用户点击后才请求 Play 自己的更新确认/下载/安装流程。

## 渠道与发布闸门

`website`（官网 APK）与 `play`（Play AAB）使用不同的原型 applicationId 后缀，避免相互覆盖；生产包名尚未批准。debug 另有 `.debug` 后缀。不请求 `REQUEST_INSTALL_PACKAGES`，不包含官网 APK 下载或系统安装器调用，也没有生产证书、公钥和更新 URL。

- 官网渠道：`ChannelUpdateClient` 关闭真实检查、下载和安装。启用前必须批准 HTTPS 更新源、签名清单与公钥、最低支持版本、防降级状态、清单大小/过期/重放规则；下载 APK 后核对哈希、包名、签名证书或已批准证书轮换链及严格更高 `versionCode`，随后用户确认系统安装。仅哈希或 HTTPS 不足以作为发布信任。官网安装还受系统“安装未知应用”授权限制。
- Play 渠道：只通过 Play In-App Update API，绝不转到官网 APK。`PLAY_UPDATE_ENABLED=false` 时不创建 Play manager 或请求检查。生产前需要获批包名、Play App Signing 与上传密钥、真实测试轨道和安装来源验证。Play App Signing 与上传密钥职责不同，不能假设官网证书能覆盖 Play 安装。
- 正式 APK/AAB 构建和发布待签名、包名、渠道测试及独立授权。未来同渠道升级须保持包名、被系统接受的签名谱系和严格递增 `versionCode`。不同 Actions 运行可以使用不同的 Debug 签名，保留资料的升级仍需同签名设备验收。

## GitHub Actions 非浏览器构建

固定构建组合为 JDK 17、Gradle 8.11.1、Android SDK 35、AGP 8.9.2、Kotlin 2.1.20、AndroidX WebKit 1.13.0。[平台工作流](../.github/workflows/platform-builds.yml)在 GitHub 托管的 Ubuntu runner 核对 Gradle 分发包的 SHA-256，再在本模块执行以下任务：

```text
gradle --no-daemon :app:testWebsiteDebugUnitTest :app:testPlayDebugUnitTest
gradle --no-daemon :app:assembleWebsiteDebug :app:assemblePlayDebug
gradle --no-daemon :app:lintWebsiteDebug :app:lintPlayDebug
```

`UpdatePolicyTest.kt` 覆盖启动、普通恢复、午前检查、在途中跨午、睡眠跨日、冷启动不补历史、退避/恢复、无效配置、在途去重与 UTC 映射。工作流要求两个渠道各有非空 JVM 测试结果，校验 Debug APK 的包标识和签名，再把两份 APK 及 SHA-256 上传为短期 Actions 产物。设备 WebView 使用单独验收。

实机授权后还需：记录 Android/WebView 版本和能力位，交错写入 A/B Cookie 与 localStorage、重开和升级后读回，检查弹窗首请求/opener、独立标签，注入共同代理失败和恢复并观察代理/目标/DNS/宿主对照，检查各更新触发与用户拒绝安装，最后分别使用官网及 Play 测试升级。当前这些项目均未验证。

官方 API 依据：[ProfileStore](https://developer.android.com/reference/androidx/webkit/ProfileStore)、[setProfile](https://developer.android.com/reference/androidx/webkit/WebViewCompat#setProfile(android.webkit.WebView,java.lang.String))、[ProxyController](https://developer.android.com/reference/androidx/webkit/ProxyController)、[ProxyConfig.Builder](https://developer.android.com/reference/androidx/webkit/ProxyConfig.Builder)、[WebViewAssetLoader](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader)、[Play In-App Updates](https://developer.android.com/guide/playcore/in-app-updates/kotlin-java)、[AGP/Gradle 兼容](https://developer.android.com/build/releases/about-agp)。
