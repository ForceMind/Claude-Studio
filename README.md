# Claude Browser · macOS 与 Android 移植

本分支基于 Windows 0.5.0 源码，维护 Claude Browser 的 macOS 和 Android 移植。两端的构建和测试由 GitHub 托管 runner 执行。

## macOS 双架构构建

推送到独立分支 `claude-browser-platform-ci` 后，Apple Silicon 和 Intel 的 GitHub 托管 runner 分别运行类型检查、非浏览器测试和 `npm run build:mac` 的对应架构目标。两个 runner 都从生成的 DMG 与 ZIP 读取包标识、版本和 Mach-O 架构，校验后按架构上载测试产物和 SHA-256。[GitHub Actions 工作流](.github/workflows/platform-builds.yml)

macOS 用户资料默认放在 `~/Library/Application Support/Claude Browser`。账号配置、持久会话和标签沿用桌面数据格式。使用 macOS 原生窗口和 `⌘` 快捷键，本地 HTTP 代理端口手动填写。升级验收在对应原生架构的 Mac 上进行，比较升级前后的账号资料、登录弹窗归属与回调、标签固定和恢复。

正式构建获准后，在 Actions 显式启用 `--mac-signed` 并配置完整的 `MAC_SIGNING_IDENTITY` 和对应签名凭据。公证使用 `--mac-notarize`，还需 Apple 官方凭据。构建会检查发布者、Team ID、Hardened Runtime、归档完整性，公证模式另检查票据和 Gatekeeper。当前两种原生架构的 DMG 和 ZIP 已通过归档核对，正式签名、公证及浏览器实测仍待验收。

## Android 系统 WebView

Android 官网和 Play 渠道各自保持包标识、签名及安装来源。现有 Android 产物为两个渠道的合成原型 Debug APK。[Android 工程与设备验收说明](android/README.md)

## Actions 测试产物

提交 `0c54434f20e7511b98c3a181b2848378b421260e` 的三个作业均通过。Apple Silicon 和 Intel 各通过 67 项非浏览器测试，各有 33 项按平台跳过。Android 两个渠道各通过 10 项 JVM 测试、lint、出包和 Debug APK 签名校验。测试产物保留 7 天。[Actions 运行 45196310481](https://github.com/ForceMind/Claude-Studio/actions/runs/45196310481)

| 构建 | 产物 |
| --- | --- |
| macOS Apple Silicon 0.5.0 | [arm64 DMG、ZIP 和 SHA-256](https://github.com/ForceMind/Claude-Studio/actions/runs/45196310481/artifacts/14828701611) |
| macOS Intel 0.5.0 | [x64 DMG、ZIP 和 SHA-256](https://github.com/ForceMind/Claude-Studio/actions/runs/45196310481/artifacts/14829236769) |
| Android 0.5.0-prototype.1 | [官网和 Play Debug APK、签名记录、测试结果和 SHA-256](https://github.com/ForceMind/Claude-Studio/actions/runs/45196310481/artifacts/14828327389) |

```text
c5264add16ebe6e9ed338f93e7e20403051e25fd7ceeb73ab418a50c0822b9e8  ClaudeBrowser-0.5.0-mac-arm64.dmg
19a26a9fd5f350c81be2d56080b89cbb4c7132b4b2e7ce7ab6c4847d2eec4b23  ClaudeBrowser-0.5.0-mac-arm64.zip
e11f3d9780990dbe6e355bcbe6984078400da76838fc9bfc94df14e7ec60e0ae  ClaudeBrowser-0.5.0-mac-x64.dmg
ddab08c0707c2d099e921884d70907f4fd8e936a8f94f919d41c525e58158517  ClaudeBrowser-0.5.0-mac-x64.zip
7712ca63b8c43446d2a8105457704289acf9c38e30a09d8c288473b6e79899a3  app-website-debug.apk
bba7ce2316d924f6adca20495513e2183f08785cd1812684a9967f382f0cac5c  app-play-debug.apk
```

## 生产更新策略

正式构建使用稳定版本号和 JSON 策略。macOS 使用 `npm run build:mac -- --mac-notarize --release-policy=<absolute-path>`，需要正式签名身份与公证凭据。Windows 主版本使用独立签名与便携换包流程。[Windows 安装交接合成测试](browser/tests/install-handoff.test.mjs)

策略使用 `schema: 1`、`product: "com.claudestudio.browser"`、`channel: "stable"`、PEM 格式的 Ed25519 `publicKey` 和 `targets`。目标键为 `win32-x64`、`darwin-arm64` 或 `darwin-x64`。每个目标指定 HTTPS 的 `feed`、一个或多个以斜杠结尾的 HTTPS 安装包路径前缀 `assets` 和发布序号下限 `minSequence`。Windows 目标还配置 `signerPins`（发行证书的 SHA-256 指纹，小写十六进制），macOS 目标配置 `teamId`。生产应用只使用构建时嵌入的策略和公钥。更新清单和包需通过配置的地址直接返回内容。返回跳转的下载链接可供网站手动下载，应用内生产连接目前拒绝跳转。

配置生产更新后，每次启动检查一次，应用持续运行时每天北京时间 12:00 再检查。睡眠或断网错过中午，恢复后只补最近一次到期检查。普通恢复前台核对到期和重试状态，同一中午和在途触发去重。退出取消当前任务，再次打开重新检查。应用保留已接受的最高发布序号和版本。下载和确认安装是独立步骤，macOS 应用内下载及确认安装等待离线公证票据验收。Android 被挂起或强停时，检查在恢复运行后遵循 [Android 渠道规则](android/README.md#更新行为)。

## 常规 Windows 版使用说明

点地址栏右侧的账户名称打开环境卡，在卡内切换账户。点「添加账号」或按 Ctrl+Shift+N，输入名称并保存，应用会切到新账号。卡片显示本地代理状态、出口 IP、网页语言和时区。网页读数可用时读取当前标签，否则显示账户设置。

点「检测出口」后，本账户会通过自己的 Chromium 会话和本地代理向 [ipify](https://www.ipify.org/) 查询其观测到的公网 IP。结果按账户保存在本次运行中，带检测时间。代理断开或重新配置后需重新检测。

- 第一次使用时，在「账户与代理设置」点「自动识别」，读取 Windows 已开启的单一本机 HTTP 代理端口，也可以手动填写。保存后端口才生效。网页语言、时区和邮箱可以下拉选择或自定义。初始配置和新建账户的网页语言默认使用英语（美国），已有账户保留原设置。时区按中文城市和地区显示，附当前 UTC 偏移与 IANA 标识，并按当地时区规则切换夏令时。中文相关的预设放在末尾。未设置邮箱时默认使用 Gmail。
- 每个账户使用独立的持久会话，登录窗口保留发起页面的账户和 opener。切换账户时会切换标签，并隐藏其他账户的弹窗。
- `Ctrl+T` 新建标签，`Ctrl+W` 关闭当前标签，`Ctrl+Shift+T` 恢复最近关闭的标签，`Ctrl+L` 聚焦地址栏。右键标签可固定，拖动同组标签可调整顺序。窗口菜单提供切换、导航和全屏操作。
- 下次启动会恢复每个账户的标签和选中页。保存的网页地址省略查询参数、片段及识别出的临时认证地址。登录是否保持取决于网站会话。

原有设置继续使用 `.browser-local/settings.json`。新引擎使用 `.browser-local/electron/`，原 Edge 资料保留在 `.browser-local/profiles/`。切换内核后需要在新会话中重新登录。便携版按 EXE 所在目录定位资料，请从平时使用的目录打开。

## 共享代码验证

Actions 执行 `npm run typecheck` 和 `npm test`，使用合成时钟、签名清单和回环服务验证更新检查，并覆盖账户、导航恢复及代理故障。真实站点、设备端登录和代理隔离仍待实测。
