using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using Forms = System.Windows.Forms;
using MediaBrushes = System.Windows.Media.Brushes;
using MediaColor = System.Windows.Media.Color;
using MediaBrush = System.Windows.Media.SolidColorBrush;

namespace ClaudeStudio.ControlPlane {
    public sealed class MainWindow : Window {
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool UnregisterHotKey(IntPtr hWnd, int id);

        const uint MOD_ALT = 0x0001;
        const uint MOD_CONTROL = 0x0002;
        const int WM_HOTKEY = 0x0312;
        const int HOTKEY_SPACE_A = 0x4101;
        const int HOTKEY_SPACE_B = 0x4202;

        readonly StudioEngine engine;
        Forms.NotifyIcon trayIcon;
        HwndSource hwndSource;
        bool hotkeysRegistered;
        bool allowExit;

        // Global bar controls
        TextBox upstreamHostBox;
        TextBox upstreamPortBox;
        TextBlock upstreamBadge;
        TextBlock hostBadge;

        // Space card controls
        sealed class SpaceCardUi {
            public TextBlock StatePill;
            public Border StatePillBorder;
            public TextBlock SidText;
            public TextBlock WfpText;
            public TextBlock PortDnsText;
            public TextBlock NoteText;
        }
        readonly Dictionary<SpaceId, SpaceCardUi> cardUi = new Dictionary<SpaceId, SpaceCardUi>();

        // Tabs controls
        TextBox projectPathBox;
        ListBox projectListBox;
        TextBlock projectStatusText;
        CheckBox templateOptInCheck;
        TextBox templateSourceBox;
        TextBlock templateStatusText;

        ComboBox handoffDirCombo;
        TextBox handoffSummaryBox;
        TextBox handoffNextBox;
        TextBox handoffPreviewBox;

        TextBox localeMatrixBox;
        TextBox auditLogBox;

        static MediaBrush HexBrush(string hex) {
            var c = (MediaColor)System.Windows.Media.ColorConverter.ConvertFromString(hex);
            var b = new MediaBrush(c);
            b.Freeze();
            return b;
        }

        public MainWindow(StudioEngine studioEngine) {
            engine = studioEngine;
            Title = "Claude Studio · 双空间沙盒控制面 (含高保真合成客户端适配器)";
            Width = 1040;
            Height = 760;
            MinWidth = 920;
            MinHeight = 660;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = HexBrush("#0F172A");
            Foreground = HexBrush("#F8FAFC");
            FontFamily = new System.Windows.Media.FontFamily("Segoe UI, Microsoft YaHei UI");

            Content = BuildLayout();
            engine.StateChanged += () => Dispatcher.BeginInvoke(new Action(RefreshAllUi));

            SourceInitialized += OnSourceInitialized;
            Closing += OnWindowClosing;
            Closed += OnWindowClosed;

            SetupTrayIcon();
            RefreshAllUi();
        }

        void OnSourceInitialized(object sender, EventArgs e) {
            var helper = new WindowInteropHelper(this);
            hwndSource = HwndSource.FromHwnd(helper.Handle);
            if (hwndSource != null) {
                hwndSource.AddHook(WndProc);
                bool a = RegisterHotKey(helper.Handle, HOTKEY_SPACE_A, MOD_CONTROL | MOD_ALT, 0x31 /* '1' */);
                bool b = RegisterHotKey(helper.Handle, HOTKEY_SPACE_B, MOD_CONTROL | MOD_ALT, 0x32 /* '2' */);
                hotkeysRegistered = a || b;
            }
        }

        IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled) {
            if (msg == WM_HOTKEY) {
                int id = wParam.ToInt32();
                if (id == HOTKEY_SPACE_A) { engine.StartSpace(SpaceId.A); ShowAndActivate(); handled = true; }
                else if (id == HOTKEY_SPACE_B) { engine.StartSpace(SpaceId.B); ShowAndActivate(); handled = true; }
            }
            return IntPtr.Zero;
        }

        void SetupTrayIcon() {
            trayIcon = new Forms.NotifyIcon {
                Icon = SystemIcons.Shield,
                Visible = true,
                Text = "Claude Studio 双空间控制面"
            };
            var menu = new Forms.ContextMenuStrip();
            menu.Items.Add("显示控制面", null, (s, e) => ShowAndActivate());
            menu.Items.Add("启动 / 聚焦 Space A (Ctrl+Alt+1)", null, (s, e) => { engine.StartSpace(SpaceId.A); ShowAndActivate(); });
            menu.Items.Add("启动 / 聚焦 Space B (Ctrl+Alt+2)", null, (s, e) => { engine.StartSpace(SpaceId.B); ShowAndActivate(); });
            menu.Items.Add(new Forms.ToolStripSeparator());
            menu.Items.Add("一键全部急停离线", null, (s, e) => engine.EmergencyKillSwitchAll());
            menu.Items.Add("退出并全量清理回滚", null, (s, e) => ExitCleanly());
            trayIcon.ContextMenuStrip = menu;
            trayIcon.DoubleClick += (s, e) => ShowAndActivate();
        }

        void ShowAndActivate() {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }

        public void ExitCleanly() {
            allowExit = true;
            engine.EmergencyKillSwitchAll();
            Close();
        }

        void OnWindowClosing(object sender, System.ComponentModel.CancelEventArgs e) {
            if (!allowExit) {
                // Clean exit by default when user clicks X (prevents hidden orphan window); tray menu also available.
                engine.EmergencyKillSwitchAll();
            }
        }

        void OnWindowClosed(object sender, EventArgs e) {
            if (hotkeysRegistered) {
                var helper = new WindowInteropHelper(this);
                UnregisterHotKey(helper.Handle, HOTKEY_SPACE_A);
                UnregisterHotKey(helper.Handle, HOTKEY_SPACE_B);
                hotkeysRegistered = false;
            }
            if (hwndSource != null) { hwndSource.RemoveHook(WndProc); hwndSource = null; }
            if (trayIcon != null) { trayIcon.Visible = false; trayIcon.Dispose(); trayIcon = null; }
        }

        UIElement BuildLayout() {
            var root = new Grid { Margin = new Thickness(16) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Global bar
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Dual cards
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Tabs

            var topBar = BuildGlobalBar();
            Grid.SetRow(topBar, 0);
            root.Children.Add(topBar);

            var cardsGrid = new Grid { Margin = new Thickness(0, 12, 0, 12) };
            cardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            cardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
            cardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var cardA = BuildSpaceCard(SpaceId.A);
            Grid.SetColumn(cardA, 0);
            cardsGrid.Children.Add(cardA);

            var cardB = BuildSpaceCard(SpaceId.B);
            Grid.SetColumn(cardB, 2);
            cardsGrid.Children.Add(cardB);

            Grid.SetRow(cardsGrid, 1);
            root.Children.Add(cardsGrid);

            var tabs = BuildTabs();
            Grid.SetRow(tabs, 2);
            root.Children.Add(tabs);
            return root;
        }

        Border BuildGlobalBar() {
            var border = new Border {
                Background = HexBrush("#1E293B"),
                BorderBrush = HexBrush("#334155"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(14, 10, 14, 10)
            };
            var dock = new DockPanel { LastChildFill = true };

            var killBtn = MakeButton("一键全部离线 (急停)", "#DC2626", "#FFFFFF");
            killBtn.FontWeight = FontWeights.Bold;
            killBtn.Click += (s, e) => engine.EmergencyKillSwitchAll();
            DockPanel.SetDock(killBtn, Dock.Right);
            dock.Children.Add(killBtn);

            var left = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
            left.Children.Add(new TextBlock {
                Text = "上游代理：", VerticalAlignment = VerticalAlignment.Center,
                Foreground = HexBrush("#CBD5E1"), FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 6, 0)
            });
            upstreamHostBox = new TextBox { Text = "127.0.0.1", Width = 92, Padding = new Thickness(6, 4, 6, 4), Background = HexBrush("#0F172A"), Foreground = MediaBrushes.White, BorderBrush = HexBrush("#475569") };
            upstreamPortBox = new TextBox { Text = "59100", Width = 62, Padding = new Thickness(6, 4, 6, 4), Margin = new Thickness(4, 0, 6, 0), Background = HexBrush("#0F172A"), Foreground = MediaBrushes.White, BorderBrush = HexBrush("#475569") };
            left.Children.Add(upstreamHostBox);
            left.Children.Add(upstreamPortBox);

            var applyBtn = MakeButton("应用并检测", "#334155", "#F8FAFC");
            applyBtn.Click += (s, e) => {
                int port;
                if (!int.TryParse(upstreamPortBox.Text.Trim(), out port)) {
                    MessageBox.Show("请输入有效端口号 (1-65535)。", "端口无效", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                string err;
                if (!engine.ConfigureUpstream(upstreamHostBox.Text, port, false, out err)) {
                    MessageBox.Show(err, "安全边界拦截", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            };
            left.Children.Add(applyBtn);

            upstreamBadge = new TextBlock { Text = "● 上游未连通", Foreground = HexBrush("#F59E0B"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 12, 0), FontWeight = FontWeights.SemiBold };
            left.Children.Add(upstreamBadge);

            hostBadge = new TextBlock { Text = "● 宿主在线", Foreground = HexBrush("#10B981"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0), FontWeight = FontWeights.SemiBold };
            left.Children.Add(hostBadge);

            var hostBtn = MakeButton("测宿主对照", "#334155", "#E2E8F0");
            hostBtn.Click += (s, e) => { string d; engine.ProbeHostContinuity(out d); };
            left.Children.Add(hostBtn);

            dock.Children.Add(left);
            border.Child = dock;
            return border;
        }

        Border BuildSpaceCard(SpaceId id) {
            var cfg = engine.GetConfig(id);
            var accent = HexBrush(cfg.AccentHex);
            var card = new Border {
                Background = HexBrush("#1E293B"),
                BorderBrush = HexBrush("#334155"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                ClipToBounds = true
            };
            var outer = new DockPanel();
            var stripe = new Border { Background = accent, Height = 5 };
            DockPanel.SetDock(stripe, Dock.Top);
            outer.Children.Add(stripe);

            var body = new StackPanel { Margin = new Thickness(14, 12, 14, 12) };
            var header = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var pillText = new TextBlock { Text = "已停止", FontSize = 12, FontWeight = FontWeights.Bold, Foreground = MediaBrushes.White };
            var pillBorder = new Border { Background = HexBrush("#475569"), CornerRadius = new CornerRadius(10), Padding = new Thickness(10, 3, 10, 3), Child = pillText };
            DockPanel.SetDock(pillBorder, Dock.Right);
            header.Children.Add(pillBorder);

            var titleStack = new StackPanel();
            titleStack.Children.Add(new TextBlock {
                Text = string.Format("{0} · {1} · {2}", cfg.DisplayName, cfg.UiLanguage, cfg.RendererTimezone),
                FontSize = 15, FontWeight = FontWeights.Bold, Foreground = HexBrush("#F8FAFC")
            });
            titleStack.Children.Add(new TextBlock {
                Text = string.Format("OS 标准账户: {0} | 快捷键: Ctrl+Alt+{1} | 资料物理隔离", cfg.LocalAccountName, id == SpaceId.A ? "1" : "2"),
                FontSize = 11.5, Foreground = HexBrush("#94A3B8"), Margin = new Thickness(0, 2, 0, 0)
            });
            header.Children.Add(titleStack);
            body.Children.Add(header);

            var sidText = new TextBlock { FontSize = 11.5, Foreground = HexBrush("#CBD5E1"), TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 2, 0, 2) };
            var wfpText = new TextBlock { FontSize = 11.5, Foreground = HexBrush("#CBD5E1"), Margin = new Thickness(0, 2, 0, 2) };
            var portDnsText = new TextBlock { FontSize = 11.5, Foreground = HexBrush("#CBD5E1"), Margin = new Thickness(0, 2, 0, 2) };
            var noteText = new TextBlock { FontSize = 11, Foreground = HexBrush("#94A3B8"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 10), MinHeight = 28 };
            body.Children.Add(sidText);
            body.Children.Add(wfpText);
            body.Children.Add(portDnsText);
            body.Children.Add(noteText);

            var actions = new WrapPanel();
            var startBtn = MakeButton("启动 / 聚焦", cfg.AccentHex, "#FFFFFF");
            startBtn.Click += (s, e) => engine.StartSpace(id);
            var cutBtn = MakeButton("临时断网", "#B45309", "#FFFFFF");
            cutBtn.Click += (s, e) => engine.DisconnectSpaceNetworkOnly(id);
            var recBtn = MakeButton("恢复代理", "#047857", "#FFFFFF");
            recBtn.Click += (s, e) => engine.ReconnectSpaceNetwork(id);
            var stopBtn = MakeButton("停止并回收", "#475569", "#FFFFFF");
            stopBtn.Click += (s, e) => engine.StopSpaceAndRollback(id);
            var twinBtn = MakeButton("打开模拟桌面窗", "#1D4ED8", "#FFFFFF");
            twinBtn.Click += (s, e) => {
                string msg;
                if (!engine.LaunchTwinPreviewForSpace(id, projectPathBox != null ? projectPathBox.Text : "", out msg)) {
                    MessageBox.Show(msg, "模拟客户端启动提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            };
            actions.Children.Add(startBtn);
            actions.Children.Add(cutBtn);
            actions.Children.Add(recBtn);
            actions.Children.Add(stopBtn);
            actions.Children.Add(twinBtn);
            body.Children.Add(actions);

            outer.Children.Add(body);
            card.Child = outer;
            cardUi[id] = new SpaceCardUi {
                StatePill = pillText, StatePillBorder = pillBorder,
                SidText = sidText, WfpText = wfpText, PortDnsText = portDnsText, NoteText = noteText
            };
            return card;
        }

        TabControl BuildTabs() {
            var tabs = new TabControl { Background = HexBrush("#1E293B"), BorderBrush = HexBrush("#334155"), Foreground = MediaBrushes.White };
            tabs.Items.Add(new TabItem { Header = "项目单写者 & 静态模板", Content = BuildProjectsTab() });
            tabs.Items.Add(new TabItem { Header = "纯文本 Handoff 抽屉", Content = BuildHandoffTab() });
            tabs.Items.Add(new TabItem { Header = "5 项语言/时区 & 脱敏诊断", Content = BuildDiagnosticsTab() });
            tabs.Items.Add(new TabItem { Header = "审计与回滚日志", Content = BuildAuditTab() });
            return tabs;
        }

        UIElement BuildProjectsTab() {
            var grid = new Grid { Margin = new Thickness(12) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var addBar = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var addBtn = MakeButton("注册并赋 Space A 写权", "#2563EB", "#FFFFFF");
            addBtn.Click += (s, e) => {
                var r = engine.Leases.RequestMount(SpaceId.A, projectPathBox.Text, ProjectAccessMode.ReadWrite);
                projectStatusText.Text = string.Format("[{0}] {1}", r.Code, r.Message);
                RefreshAllUi();
            };
            DockPanel.SetDock(addBtn, Dock.Right);
            addBar.Children.Add(addBtn);
            projectPathBox = new TextBox {
                Text = Environment.CurrentDirectory, Padding = new Thickness(6, 4, 6, 4), Margin = new Thickness(0, 0, 8, 0),
                Background = HexBrush("#0F172A"), Foreground = MediaBrushes.White, BorderBrush = HexBrush("#475569")
            };
            addBar.Children.Add(projectPathBox);
            Grid.SetRow(addBar, 0);
            grid.Children.Add(addBar);

            projectListBox = new ListBox {
                Background = HexBrush("#0F172A"), Foreground = HexBrush("#E2E8F0"),
                BorderBrush = HexBrush("#334155"), FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 12
            };
            Grid.SetRow(projectListBox, 1);
            grid.Children.Add(projectListBox);

            var opBar = new WrapPanel { Margin = new Thickness(0, 8, 0, 4) };
            var bRo = MakeButton("Space B 挂载只读", "#334155", "#FFFFFF");
            bRo.Click += (s, e) => {
                var r = engine.Leases.RequestMount(SpaceId.B, projectPathBox.Text, ProjectAccessMode.ReadOnly);
                projectStatusText.Text = string.Format("[{0}] {1}", r.Code, r.Message);
                RefreshAllUi();
            };
            var bRwConflict = MakeButton("尝试并发给 B 写权 (冲突检测)", "#991B1B", "#FFFFFF");
            bRwConflict.Click += (s, e) => {
                var r = engine.Leases.RequestMount(SpaceId.B, projectPathBox.Text, ProjectAccessMode.ReadWrite);
                projectStatusText.Text = string.Format("[{0}] {1}", r.Code, r.Message);
                RefreshAllUi();
            };
            var handoffB = MakeButton("受控交接写权 → Space B", "#D97706", "#FFFFFF");
            handoffB.Click += (s, e) => {
                var r = engine.Leases.ControlledHandoffWriter(projectPathBox.Text, SpaceId.B, engine.IsSpaceStopped);
                projectStatusText.Text = string.Format("[{0}] {1}", r.Code, r.Message);
                RefreshAllUi();
            };
            opBar.Children.Add(bRo);
            opBar.Children.Add(bRwConflict);
            opBar.Children.Add(handoffB);
            projectStatusText = new TextBlock { Foreground = HexBrush("#93C5FD"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            opBar.Children.Add(projectStatusText);
            Grid.SetRow(opBar, 2);
            grid.Children.Add(opBar);

            // Opt-in static template sync (default OFF, identity artifacts hard-blocked)
            var tplBorder = new Border { Background = HexBrush("#0F172A"), BorderBrush = HexBrush("#334155"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(10), Margin = new Thickness(0, 8, 0, 0) };
            var tplStack = new StackPanel();
            templateOptInCheck = new CheckBox { Content = "手动启用只读静态模板单向同步（默认关闭；系统硬拦截 .credentials.json / .claude.json / 会话目录）", Foreground = HexBrush("#CBD5E1"), IsChecked = false };
            tplStack.Children.Add(templateOptInCheck);
            var tplRow = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
            var syncBtn = MakeButton("测试同步校验", "#334155", "#FFFFFF");
            syncBtn.Click += (s, e) => {
                string outDir = Path.Combine(Path.GetTempPath(), "ClaudeStudioStaticTplCheck");
                var res = ProjectLeaseManager.SyncReadOnlyStaticTemplate(templateSourceBox.Text, outDir, templateOptInCheck.IsChecked == true);
                templateStatusText.Text = string.Format("[{0}] {1}", res.Code, res.Message);
            };
            DockPanel.SetDock(syncBtn, Dock.Right);
            tplRow.Children.Add(syncBtn);
            templateSourceBox = new TextBox { Text = "", Padding = new Thickness(6, 3, 6, 3), Margin = new Thickness(0, 0, 8, 0), Background = HexBrush("#1E293B"), Foreground = MediaBrushes.White, BorderBrush = HexBrush("#475569") };
            tplRow.Children.Add(templateSourceBox);
            tplStack.Children.Add(tplRow);
            templateStatusText = new TextBlock { Foreground = HexBrush("#94A3B8"), FontSize = 11.5, Margin = new Thickness(0, 4, 0, 0) };
            tplStack.Children.Add(templateStatusText);
            tplBorder.Child = tplStack;
            Grid.SetRow(tplBorder, 3);
            grid.Children.Add(tplBorder);

            return grid;
        }

        UIElement BuildHandoffTab() {
            var grid = new Grid { Margin = new Thickness(12) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var banner = new Border { Background = HexBrush("#1E3A5F"), CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 0, 8) };
            banner.Child = new TextBlock {
                Text = "安全声明：原生聊天记录、OAuth 凭据与 Account/Org UUID 按 OS 标准账户物理隔离，不跨号迁移。仅通过人工审阅的纯文本 HANDOFF.md 交接项目任务。",
                Foreground = HexBrush("#BFDBFE"), FontSize = 12, TextWrapping = TextWrapping.Wrap
            };
            Grid.SetRow(banner, 0);
            grid.Children.Add(banner);

            var form = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
            var row1 = new WrapPanel { Margin = new Thickness(0, 0, 0, 6) };
            handoffDirCombo = new ComboBox { Width = 180, Margin = new Thickness(0, 0, 8, 0) };
            handoffDirCombo.Items.Add("Space A -> Space B");
            handoffDirCombo.Items.Add("Space B -> Space A");
            handoffDirCombo.SelectedIndex = 0;
            row1.Children.Add(handoffDirCombo);

            var genBtn = MakeButton("生成脱敏 HANDOFF.md", "#2563EB", "#FFFFFF");
            genBtn.Click += (s, e) => {
                SpaceId from = handoffDirCombo.SelectedIndex == 0 ? SpaceId.A : SpaceId.B;
                SpaceId to = from == SpaceId.A ? SpaceId.B : SpaceId.A;
                handoffPreviewBox.Text = HandoffGenerator.BuildSanitizedBrief(projectPathBox.Text, from, to, handoffSummaryBox.Text, handoffNextBox.Text);
            };
            var copyBtn = MakeButton("复制到剪贴板", "#334155", "#FFFFFF");
            copyBtn.Click += (s, e) => { if (!string.IsNullOrEmpty(handoffPreviewBox.Text)) Clipboard.SetText(handoffPreviewBox.Text); };
            row1.Children.Add(genBtn);
            row1.Children.Add(copyBtn);
            form.Children.Add(row1);

            handoffSummaryBox = new TextBox { Text = "已完成本阶段功能开发与单测", Padding = new Thickness(6, 4, 6, 4), Margin = new Thickness(0, 0, 0, 4), Background = HexBrush("#0F172A"), Foreground = MediaBrushes.White, BorderBrush = HexBrush("#475569") };
            handoffNextBox = new TextBox { Text = "请在目标空间新会话中阅读 git diff 后继续审查", Padding = new Thickness(6, 4, 6, 4), Background = HexBrush("#0F172A"), Foreground = MediaBrushes.White, BorderBrush = HexBrush("#475569") };
            form.Children.Add(handoffSummaryBox);
            form.Children.Add(handoffNextBox);
            Grid.SetRow(form, 1);
            grid.Children.Add(form);

            handoffPreviewBox = new TextBox {
                IsReadOnly = true, AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                TextWrapping = TextWrapping.Wrap, Background = HexBrush("#0F172A"), Foreground = HexBrush("#E2E8F0"),
                BorderBrush = HexBrush("#334155"), FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 12, Padding = new Thickness(8)
            };
            Grid.SetRow(handoffPreviewBox, 2);
            grid.Children.Add(handoffPreviewBox);
            return grid;
        }

        UIElement BuildDiagnosticsTab() {
            var grid = new Grid { Margin = new Thickness(12) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var bar = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            var refreshBtn = MakeButton("刷新 5 项读数", "#334155", "#FFFFFF");
            refreshBtn.Click += (s, e) => RefreshAllUi();
            var exportBtn = MakeButton("导出脱敏诊断包 (JSON)", "#047857", "#FFFFFF");
            exportBtn.Click += (s, e) => {
                string json = engine.BuildSanitizedDiagnosticJson();
                string path = Path.Combine(Path.GetTempPath(), "claude-studio-sanitized-diag-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".json");
                File.WriteAllText(path, json, new UTF8Encoding(false));
                MessageBox.Show("已导出脱敏诊断包：\n" + path, "导出完成", MessageBoxButton.OK, MessageBoxImage.Information);
            };
            bar.Children.Add(refreshBtn);
            bar.Children.Add(exportBtn);
            Grid.SetRow(bar, 0);
            grid.Children.Add(bar);

            localeMatrixBox = new TextBox {
                IsReadOnly = true, AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = HexBrush("#0F172A"), Foreground = HexBrush("#E2E8F0"), BorderBrush = HexBrush("#334155"),
                FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 12, Padding = new Thickness(10)
            };
            Grid.SetRow(localeMatrixBox, 1);
            grid.Children.Add(localeMatrixBox);
            return grid;
        }

        UIElement BuildAuditTab() {
            var grid = new Grid { Margin = new Thickness(12) };
            auditLogBox = new TextBox {
                IsReadOnly = true, AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = HexBrush("#0F172A"), Foreground = HexBrush("#CBD5E1"), BorderBrush = HexBrush("#334155"),
                FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 11.5, Padding = new Thickness(8)
            };
            grid.Children.Add(auditLogBox);
            return grid;
        }

        static Button MakeButton(string text, string bgHex, string fgHex) {
            return new Button {
                Content = text,
                Background = HexBrush(bgHex),
                Foreground = HexBrush(fgHex),
                BorderThickness = new Thickness(0),
                Padding = new Thickness(10, 5, 10, 5),
                Margin = new Thickness(0, 0, 6, 4),
                Cursor = System.Windows.Input.Cursors.Hand
            };
        }

        public void RefreshAllUi() {
            upstreamBadge.Text = engine.UpstreamHealthy
                ? string.Format("● 上游在线 ({0}:{1})", engine.UpstreamHost, engine.UpstreamPort)
                : string.Format("● 上游离线 ({0}:{1})", engine.UpstreamHost, engine.UpstreamPort);
            upstreamBadge.Foreground = HexBrush(engine.UpstreamHealthy ? "#10B981" : "#F59E0B");
            hostBadge.Text = engine.HostContinuous ? "● 宿主网络在线" : "● 宿主网络异常";
            hostBadge.Foreground = HexBrush(engine.HostContinuous ? "#10B981" : "#EF4444");

            foreach (SpaceId id in new[] { SpaceId.A, SpaceId.B }) {
                var snap = engine.GetSnapshot(id);
                var ui = cardUi[id];
                string pillLabel; string pillBg;
                switch (snap.State) {
                    case SpaceNetworkState.ProxyOnline: pillLabel = "仅代理放行"; pillBg = "#059669"; break;
                    case SpaceNetworkState.ColdBlocked: pillLabel = "冷封网 (零放行)"; pillBg = "#D97706"; break;
                    case SpaceNetworkState.FaultCutoff: pillLabel = "已断流 (静态封网)"; pillBg = "#DC2626"; break;
                    case SpaceNetworkState.RollingBack: pillLabel = "回滚中"; pillBg = "#6366F1"; break;
                    default: pillLabel = "已停止"; pillBg = "#475569"; break;
                }
                ui.StatePill.Text = pillLabel;
                ui.StatePillBorder.Background = HexBrush(pillBg);
                ui.SidText.Text = "PSEC Container SID: " + snap.ContainerSid;
                ui.WfpText.Text = string.Format("WFP: StaticBlock={0} | DynamicE={1} | 权重={2} | 清单={3}",
                    snap.StaticBlockActive ? "ON(4)" : "OFF", snap.DynamicExceptionOpen ? "OPEN" : "CLOSED",
                    snap.WfpSublayerWeight, snap.WfpManifestSha256Prefix12);
                ui.PortDnsText.Text = string.Format("专用入口: {0} | 系统 DNS 代发: {1} | PID: {2}",
                    snap.ProxyPort > 0 ? ("127.0.0.1:" + snap.ProxyPort) : "(未分配)", snap.DnsSendCount, snap.Pid);
                ui.NoteText.Text = snap.LastNote;
            }

            projectListBox.Items.Clear();
            foreach (var p in engine.Leases.ListProjects()) {
                projectListBox.Items.Add(string.Format("{0,-22} | Writer={1,-4} | A_RO={2,-5} | B_RO={3,-5} | {4}",
                    p.DisplayName, p.WriterSpace, p.SpaceAReadOnly, p.SpaceBReadOnly, p.CanonicalPath));
            }

            var aLoc = engine.GetSnapshot(SpaceId.A).LocaleReadings;
            var bLoc = engine.GetSnapshot(SpaceId.B).LocaleReadings;
            var sb = new StringBuilder();
            sb.AppendLine("=== 5 类语言与时区透明读数（严格分项，不掩盖原生边界） ===");
            sb.AppendLine();
            sb.AppendLine(string.Format("1. 窗口语言       | A: {0,-26} | B: {1}", aLoc.WindowLanguage, bLoc.WindowLanguage));
            sb.AppendLine(string.Format("2. 渲染器时区     | A: {0,-26} | B: {1}", aLoc.RendererTimezone + " (" + aLoc.RendererRefUtcFormatted + ")", bLoc.RendererTimezone + " (" + bLoc.RendererRefUtcFormatted + ")"));
            sb.AppendLine(string.Format("3. 请求语言       | A: {0,-26} | B: {1}", aLoc.RequestAcceptLanguage, bLoc.RequestAcceptLanguage));
            sb.AppendLine(string.Format("4. 子进程偏好     | A: LANG={0}, TZ={1}", aLoc.ChildLangEnv, aLoc.ChildTzEnv));
            sb.AppendLine(string.Format("                  | B: LANG={0}, TZ={1}", bLoc.ChildLangEnv, bLoc.ChildTzEnv));
            sb.AppendLine(string.Format("5. Win32 原生时区 | Bias={0}min | Standard={1} | Daylight={2}",
                aLoc.WindowsNativeTimezone.BiasMinutes, aLoc.WindowsNativeTimezone.StandardName, aLoc.WindowsNativeTimezone.DaylightName));
            sb.AppendLine("   边界说明       | " + aLoc.NativeTimezoneBoundaryNote);
            localeMatrixBox.Text = sb.ToString();

            var logSb = new StringBuilder();
            var entries = engine.GetAuditLog();
            for (int i = entries.Count - 1; i >= 0; i--) {
                var e = entries[i];
                logSb.AppendLine(string.Format("[{0}] [{1,-15}] [{2,-6}] {3}", e.Utc, e.Category, e.Space, e.Message));
            }
            auditLogBox.Text = logSb.ToString();
        }
    }
}
