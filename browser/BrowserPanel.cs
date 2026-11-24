using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("Claude 浏览器")]
[assembly: AssemblyProduct("Claude Studio Browser")]
[assembly: AssemblyVersion("0.1.1.0")]

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        string name;
        using (var hash = SHA256.Create())
            name = @"Local\ClaudeBrowser-" + BitConverter.ToString(hash.ComputeHash(
                Encoding.UTF8.GetBytes(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\').ToLowerInvariant())), 0, 12);
        using (var mutex = new Mutex(false, name))
        {
            bool owns;
            try { owns = mutex.WaitOne(0); } catch (AbandonedMutexException) { owns = true; }
            if (!owns) { MessageBox.Show("此目录的管理窗口已打开。", "Claude 浏览器"); return; }
            try { Application.Run(new BrowserPanel()); }
            finally { mutex.ReleaseMutex(); }
        }
    }

    internal static string PrepareRuntime()
    {
        var assembly = Assembly.GetExecutingAssembly();
        string cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Claude-Studio-Browser", "runtime");
        string destination = Path.Combine(cache, assembly.ManifestModule.ModuleVersionId.ToString("N"));
        if (Directory.Exists(destination)) return destination;
        Directory.CreateDirectory(cache);
        string staging = Path.Combine(cache, Guid.NewGuid().ToString("N") + ".tmp");
        Directory.CreateDirectory(staging);
        try
        {
            using (var resource = assembly.GetManifestResourceStream("browser.zip"))
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read))
                archive.ExtractToDirectory(staging);
            try { Directory.Move(staging, destination); }
            catch (IOException) { if (!Directory.Exists(destination)) throw; }
        }
        finally { if (Directory.Exists(staging)) Directory.Delete(staging, true); }
        return destination;
    }
}

internal class Profile { public string language { get; set; } public string zone { get; set; } public string mail { get; set; } }
internal class Settings { public int? port { get; set; } public Dictionary<string, Profile> profiles { get; set; } }
internal class Reply
{
    public string @event { get; set; }
    public string message { get; set; }
    public Settings settings { get; set; }
    public Dictionary<string, string> states { get; set; }
}

internal sealed class BrowserPanel : Form
{
    private readonly ComboBox account = new ComboBox(), language = new ComboBox(), zone = new ComboBox();
    private readonly TextBox port = new TextBox(), mail = new TextBox();
    private readonly Label status = new Label();
    private readonly Panel controls = new Panel();
    private readonly JavaScriptSerializer json = new JavaScriptSerializer();
    private Settings settings;
    private Process worker;
    private StreamWriter input;
    private bool closing, finished;

    internal BrowserPanel()
    {
        Text = "Claude 浏览器";
        Font = new Font("Microsoft YaHei UI", 10);
        ClientSize = new Size(580, 370);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        controls.SetBounds(0, 0, 580, 295);
        Controls.Add(controls);
        account.DropDownStyle = ComboBoxStyle.DropDownList;
        account.Items.AddRange(new object[] { "A", "B" });
        account.SelectedIndex = 0;
        account.SelectedIndexChanged += delegate { ShowProfile(); };
        language.Items.AddRange(new object[] { "system", "zh-CN", "zh-TW", "en-US", "ja-JP" });
        zone.Items.AddRange(new object[] { "system", "Asia/Shanghai", "Asia/Tokyo", "America/Los_Angeles", "UTC" });
        Field("账户空间", account, 18);
        Field("本地代理端口", port, 58);
        Field("网页语言", language, 98);
        Field("网页时区", zone, 138);
        Field("邮箱主页", mail, 178);
        port.MaxLength = 5;
        var hint = new Label { Text = "本机 HTTP / mixed 端口 · system 表示跟随系统", AutoSize = true, ForeColor = Color.DimGray };
        hint.Location = new Point(165, 213);
        controls.Controls.Add(hint);
        Button("打开 Claude", "claude", 22, 145);
        Button("打开邮箱", "mail", 177, 117);
        Button("保存设置", "save", 304, 117);
        Button("停止空间", "stop", 431, 112);
        status.SetBounds(22, 304, 535, 62);
        status.Text = "正在准备管理窗口…";
        Controls.Add(status);
        controls.Enabled = false;
        Shown += async delegate { await RunController(); };
        FormClosing += ClosingPanel;
    }

    private void Field(string caption, Control field, int y)
    {
        var label = new Label { Text = caption };
        label.SetBounds(22, y + 4, 139, 26);
        field.SetBounds(165, y, 378, 30);
        field.AccessibleName = caption;
        controls.Controls.Add(label);
        controls.Controls.Add(field);
    }

    private void Button(string caption, string action, int x, int width)
    {
        var button = new Button { Text = caption };
        button.SetBounds(x, 250, width, 38);
        button.Click += delegate { Send(action); };
        controls.Controls.Add(button);
    }

    private void ShowProfile()
    {
        if (settings == null) return;
        Profile profile = settings.profiles[account.Text];
        language.Text = profile.language;
        zone.Text = profile.zone;
        mail.Text = profile.mail;
        port.Text = settings.port.HasValue ? settings.port.Value.ToString() : "";
    }

    private async Task RunController()
    {
        try
        {
            string runtime = await Task.Run((Func<string>)Program.PrepareRuntime);
            if (closing) { finished = true; Close(); return; }
            var start = new ProcessStartInfo(Path.Combine(runtime, "node.exe"), "browser/controller.mjs");
            start.WorkingDirectory = runtime;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.StandardOutputEncoding = new UTF8Encoding(false);
            start.EnvironmentVariables["CLAUDE_BROWSER_DATA_DIR"] = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".browser-local");
            worker = Process.Start(start);
            input = new StreamWriter(worker.StandardInput.BaseStream, new UTF8Encoding(false), 1024, true);
            input.AutoFlush = true;
            string line;
            while ((line = await worker.StandardOutput.ReadLineAsync()) != null)
            {
                if (closing) continue;
                var reply = json.Deserialize<Reply>(line);
                if (reply.@event == "fatal") throw new InvalidOperationException(reply.message);
                if (reply.settings != null) settings = reply.settings;
                if (reply.@event == "ready") ShowProfile();
                if (reply.@event != "status") controls.Enabled = true;
                status.Text = reply.@event == "failure" ? reply.message :
                    "A · " + reply.states["A"] + "      B · " + reply.states["B"];
            }
            if (!closing) status.Text = "管理进程已退出，请重新打开窗口。";
        }
        catch (Exception error) { if (!closing) status.Text = "启动或通信失败：" + error.Message; }
        {
            controls.Enabled = false;
            if (worker != null)
            {
                try { worker.StandardInput.Close(); } catch (IOException) { }
                await Task.Run((Action)worker.WaitForExit);
                worker.Dispose();
            }
            finished = true;
            if (closing) Close();
        }
    }

    private void Send(string action)
    {
        int number;
        if (!Int32.TryParse(port.Text, out number) || number < 1 || number > 65535)
        {
            if (action != "stop") { status.Text = "请输入 1–65535 的本地代理端口。"; return; }
        }
        controls.Enabled = false;
        try
        {
            input.WriteLine(json.Serialize(new { action = action, id = account.Text, port = number,
                profile = new Profile { language = language.Text.Trim(), zone = zone.Text.Trim(), mail = mail.Text.Trim() } }));
            status.Text = "正在处理账户 " + account.Text + "…";
        }
        catch (IOException error) { status.Text = error.Message; }
    }

    private void ClosingPanel(object sender, FormClosingEventArgs args)
    {
        if (finished) return;
        args.Cancel = true;
        if (closing) return;
        closing = true;
        controls.Enabled = false;
        status.Text = "正在关闭账户窗口…";
        if (input != null)
        {
            try { input.WriteLine("{\"action\":\"quit\"}"); } catch (IOException) { }
        }
    }
}
