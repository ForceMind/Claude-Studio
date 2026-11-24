# Claude Browser · Windows

[官网](https://claude-studio-1pm.pages.dev/) · [GitHub Pages 镜像](https://forcemind.github.io/Claude-Studio/) · [下载 Windows x64 便携版 v0.3.1](https://github.com/ForceMind/Claude-Studio/releases/download/v0.3.1/ClaudeBrowser.exe)

GitHub 当前提供 **0.3.1 便携版**。此分支的开发基线为 **0.7.0**，包含 Windows 安装版和安装版自动更新，已完成本机自签升级测试。正式签名的安装版与线上更新清单尚待发布。验收结果和接手位置见 [路线图](ROADMAP.md#windows-070-接手)。

## 选择 Windows 版本

- 便携版 ClaudeBrowser.exe 可以直接双击。它会把程序临时解包后运行，资料保存在 EXE 同级的 .browser-local。
- 安装版 ClaudeBrowser-Setup.exe 默认安装到当前 Windows 用户的程序目录，当前安装向导固定该位置，并添加桌面与开始菜单快捷方式。首次打开可使用新资料，或直接读写现有便携版的同一份资料。选择便携版所在目录或其中的 `.browser-local` 都可以。安装和卸载默认保留账号资料。两个入口共享资料时，请先退出正在运行的入口。若在共享资料中移除了初始账号，请通过 0.6.0 或更新版本打开该目录。

便携版可直接双击下载的 **ClaudeBrowser.exe**，也可按下方步骤从源码生成工作树根目录的副本。应用带有 Electron / Chromium，打开后从账户 A 开始。顶部标签栏管理当前账户的网页，地址栏右侧可以打开 Claude、邮箱，以及切换当前账户。

## 使用

点地址栏右侧的账户名称打开环境卡，在卡内切换账户。点「添加账号」或按 Ctrl+Shift+N，输入名称并保存，应用会切到新账号。卡片显示本地代理状态、出口 IP、网页语言和时区。网页读数可用时读取当前标签，否则显示账户设置。

点「检测出口」后，本账户会通过自己的 Chromium 会话和本地代理向 [ipify](https://www.ipify.org/) 查询其观测到的公网 IP。结果按账户保存在本次运行中，带检测时间。代理断开或重新配置后需重新检测。

- 第一次使用时，在「账户与代理设置」点「自动识别」，读取 Windows 已开启的单一本机 HTTP 代理端口，也可以手动填写。保存后端口才生效。网页语言、时区和邮箱可以下拉选择或自定义。初始配置和新建账户的网页语言默认使用英语（美国），已有账户保留原设置。时区按中文城市和地区显示，附当前 UTC 偏移与 IANA 标识，并按当地时区规则切换夏令时。中文相关的预设放在末尾。未设置邮箱时默认使用 Gmail。
- 每个账户使用独立的持久会话，登录窗口保留发起页面的账户和 opener。切换账户时会切换标签，并隐藏其他账户的弹窗。
- `Ctrl+T` 新建标签，`Ctrl+W` 关闭当前标签，`Ctrl+Shift+T` 恢复最近关闭的标签，`Ctrl+L` 聚焦地址栏。右键标签可固定，拖动同组标签可调整顺序。窗口菜单提供切换、导航和全屏操作。
- 下次启动会恢复每个账户的标签和选中页。保存的网页地址省略查询参数、片段及识别出的临时认证地址。登录是否保持取决于网站会话。

原有设置继续使用 `.browser-local/settings.json`。新引擎使用 `.browser-local/electron/`，原 Edge 资料保留在 `.browser-local/profiles/`。切换内核后需要在新会话中重新登录。便携版按 EXE 所在目录定位资料，请从平时使用的目录打开。

## 账号与标签

- 「账户与代理设置」支持上移、下移、清除指定账号的本机登录及移除账号。移除会删除对应空间、本机网站资料和标签记录，至少保留一个账号。清理需要确认，会关闭该账号的页面和授权窗口并清除 Cookie、网站存储及缓存。该账号的网页本地草稿可能一并清除。账号设置和安全的标签地址仍可恢复。
- 窗口变窄时，「查看全部标签」接管放不下的标签，当前标签保持可见。撤销关闭会优先接回原网页。最多暂存 5 个普通网页，最长 10 分钟。超时后按可恢复的网址重新加载。登录、验证页面和关机前关闭的页面走常规恢复规则。

## Windows 自动更新

配置了正式签名策略的应用每次打开会检查更新，保持运行时每天北京时间 12:00 再检查一次。睡眠或断网错过的检查在恢复后补查。下载和退出安装分别需要确认。更新使用单独的代理会话，验证 Ed25519 清单、发布序号、可下载范围、文件哈希和 Windows Authenticode 发布者。

普通本机构建的安装版和便携版均显示「未配置生产更新源」。正式构建需要授权的 Windows 签名身份和本机 .NET Framework 编译器。便携版运行 `npm.cmd run build -- --release-policy=<absolute-path>`，使用 `win32-x64` 目标，产物位于 `release/windows/stable`。安装版运行 `npm.cmd run build:installer -- --release-policy=<absolute-path>`，使用 `win32-x64-setup` 目标，产物位于 `release/windows/stable/installer`。两种版型分别使用自己的 HTTPS 清单地址、安装包路径范围、发布序号和防降级记录。安装版的签名清单必须包含 `"edition": "setup"`，资产文件名为 `ClaudeBrowser-Setup.exe`。

安装版更新先保存账号资料并退出程序，再调用当前用户的 NSIS 安装流程。安装完成后校验本机程序的版本及签名，通过后重新打开。从未配置更新源的旧版本过渡时，需要先手动安装首个带正式更新策略的版本。已实测签名测试版从 0.6.99 通过回环更新源升到 0.7.0，自动重启并保留合成 A、B 的配置、标签及各自的登录。真实站点会话仍待验证。

GitHub 发布时，安装包使用版本标签 `windows-setup-v<version>` 下的 `ClaudeBrowser-Setup.exe`，清单里的下载地址必须指向该版本资产。安装版的生产策略可固定 `https://raw.githubusercontent.com/ForceMind/Claude-Studio/windows-updates/win32-x64-setup.json` 为清单地址，并将 `https://github.com/ForceMind/Claude-Studio/releases/download/` 设为资产路径前缀。先上传并核对已签名的安装包，再更新 Ed25519 签名清单。应用只允许受策略认可的 GitHub Setup 资产经专用代理跳转一次到 GitHub Release CDN，下载后仍验证清单中的大小、SHA-256 和 Windows 发布者签名。

## 构建与验证

本机固定更新目录由工作树里的 .browser-local/install-directory.txt 指定。通过包检查后，构建会把更新后的 ClaudeBrowser.exe 复制到该目录。

开发环境需要 Windows x64 和 Node.js 22.18 或更新版本。在浏览器工作树运行 `npm.cmd ci`、`npm.cmd run setup` 和 `npm.cmd run build`。构建先在 `release/` 生成便携包，解包验证后更新根目录 `ClaudeBrowser.exe`。便携版可用 `npm.cmd run verify:package` 复核根目录的包。安装版用 npm.cmd run build:installer 构建到 release/windows/installer，可用 npm.cmd run verify:package -- --installer 复核。安装版构建和便携版更新策略分开。

`npm.cmd run typecheck` 检查 Electron 和 React 代码的类型。`npm.cmd test` 使用合成地址、临时设置和回环代理验证账户、导航恢复及代理故障。EXE 校验直接读取包内的 x64 内核、入口和渲染资源。公开官网本轮采用静态检查，桌面应用的自签升级另有合成会话实测。代理端口可连接仅表示 TCP 监听正常。实际站点登录、语言和时区读数、DNS 代发及宿主联网对照见[浏览器分支路线图](ROADMAP.md#浏览器原型分支)。
