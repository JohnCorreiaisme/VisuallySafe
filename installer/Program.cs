using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace VisuallySafeSetup
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            // the two hidden jobs that run with permission (started by the window below, after the person clicked Install)
            if (args.Length >= 3 && args[0] == "--install-files") return Installer.InstallFiles(args[1], args[2], args.Length > 3 ? args[3] : "");
            if (args.Length >= 3 && args[0] == "--uninstall-files") return Installer.UninstallFiles(args[1], args[2]);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length >= 1 && args[0] == "--update") return Installer.UpdateRun();
            // quiet install and removal for package managers (winget): no windows, an exit code instead
            bool silent = Array.Exists(args, a => a == "--silent" || a == "/S" || a == "/s");
            if (silent && Array.IndexOf(args, "--uninstall") >= 0) return Installer.SilentUninstall();
            if (silent) return Installer.SilentInstall();
            if (args.Length >= 1 && args[0] == "--uninstall") { Application.Run(new UninstallForm()); return 0; }
            if (args.Length >= 2 && args[0] == "--shots") { var f = new SetupForm(); f.Snap(args[1]); return 0; }
            Application.Run(new SetupForm());
            return 0;
        }
    }

    static class Installer
    {
        public static string Dest { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VisuallySafe"); } }
        public static string StartMenuLink { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Visually Safe.lnk"); } }
        const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\VisuallySafe";
        static readonly string[] ShellRoots = { "*", "Directory", "AllFilesystemObjects", "Drive", "lnkfile", "InternetShortcut" };

        public static bool IsAdmin { get { using (var id = WindowsIdentity.GetCurrent()) return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator); } }

        public static string PayloadVersion()
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
                using (var z = new ZipArchive(s, ZipArchiveMode.Read))
                {
                    var e = z.GetEntry("version.txt");
                    if (e != null) using (var r = new StreamReader(e.Open())) return r.ReadToEnd().Trim();
                }
            }
            catch { }
            return "";
        }

        public static bool DotNet48()
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"))
                    return k != null && Convert.ToInt32(k.GetValue("Release") ?? 0) >= 528040;
            }
            catch { return false; }
        }

        public static bool WindowsOk { get { return Environment.OSVersion.Version.Major >= 10; } }

        public static bool DefenderFound()
        {
            string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender");
            return Directory.Exists(p);
        }

        // ---- the program used to be called TinyGuard: its old folder, tasks and entries are removed when the new one is installed
        public static string LegacyDest { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TinyGuard"); } }

        public static void RemoveLegacy(string keepDest)
        {
            try { Run("schtasks.exe", "/delete /tn \"TinyGuard\" /f"); Run("schtasks.exe", "/delete /tn \"TinyGuard Watchdog\" /f"); } catch { }
            try { Registry.LocalMachine.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\TinyGuard", false); } catch { }
            try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "TinyGuard.lnk")); } catch { }
            string old = LegacyDest;
            if (Directory.Exists(old) && !string.Equals(old.TrimEnd((char)92), (keepDest ?? "").TrimEnd((char)92), StringComparison.OrdinalIgnoreCase))
                for (int i = 0; i < 6; i++)
                {
                    try { Directory.Delete(old, true); break; }
                    catch { CloseRunning(keepDest ?? old); System.Threading.Thread.Sleep(500); }
                }
        }

        /// <summary>Carries settings and history over from the old TinyGuard data folder (only when the new one doesn't exist yet).</summary>
        public static void MigrateData()
        {
            try
            {
                string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string oldD = Path.Combine(root, "TinyGuard"), newD = Path.Combine(root, "VisuallySafe");
                if (Directory.Exists(oldD) && !Directory.Exists(newD)) Directory.Move(oldD, newD);
            }
            catch { }
        }

        public static void CloseRunning(string dest)
        {
            foreach (string name in new[] { "VisuallySafe", "TinyGuard", "yara64", "yarac64" })       // the program and the scanner tools it starts
                foreach (var p in Process.GetProcessesByName(name))
                    try
                    {
                        string f = p.MainModule.FileName;
                        if (!f.StartsWith(dest, StringComparison.OrdinalIgnoreCase) && !f.StartsWith(LegacyDest, StringComparison.OrdinalIgnoreCase)) continue;      // only the copies in the install folders
                        p.CloseMainWindow();
                        if (!p.WaitForExit(3000)) { p.Kill(); p.WaitForExit(3000); }
                    }
                    catch { }
        }

        static int Run(string exe, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args) { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden };
                using (var p = Process.Start(psi)) { p.WaitForExit(30000); return p.ExitCode; }
            }
            catch { return -1; }
        }

        public static void MakeShortcut(string path, string target, string workDir, string description)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            dynamic l = sh.CreateShortcut(path);
            l.TargetPath = target; l.WorkingDirectory = workDir; l.Description = description; l.IconLocation = target + ",0";
            l.Save();
        }

        /// <summary>Runs with permission. Puts the program in Program Files, adds the Start menu entry, and registers it so Windows can uninstall it.</summary>
        public static int InstallFiles(string dest, string resultFile, string user)
        {
            try
            {
                if (!IsAdmin) throw new Exception("this step needs permission");
                CloseRunning(dest);
                Directory.CreateDirectory(dest);
                string root = Path.GetFullPath(dest).TrimEnd('\\') + "\\";
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
                using (var z = new ZipArchive(s, ZipArchiveMode.Read))
                    foreach (var e in z.Entries)
                    {
                        if (e.FullName.EndsWith("/") || e.FullName == "version.txt") continue;
                        string target = Path.GetFullPath(Path.Combine(dest, e.FullName.Replace('/', '\\')));
                        if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase)) continue;       // never write outside the install folder
                        Directory.CreateDirectory(Path.GetDirectoryName(target));
                        for (int attempt = 0; ; attempt++)
                        {
                            try { e.ExtractToFile(target, true); break; }
                            catch (IOException) when (attempt < 8) { CloseRunning(dest); System.Threading.Thread.Sleep(700); }      // a file still in use: stop what holds it and try again
                        }
                    }
                string exe = Path.Combine(dest, "VisuallySafe.exe");
            MigrateData();
            try { using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true)) if (k != null) k.DeleteValue("TinyGuard", false); } catch { }
            foreach (string r in ShellRoots) try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\" + r + @"\shell\TinyGuardScan", false); } catch { }
                if (!File.Exists(exe)) throw new Exception("the program file was not unpacked");
                File.Copy(exe, Path.Combine(dest, "VisuallySafe.scr"), true);                  // the screen saver copies
                File.Copy(exe, Path.Combine(dest, "VisuallySafeDefrag.scr"), true);
                File.Copy(Assembly.GetExecutingAssembly().Location, Path.Combine(dest, "VisuallySafeSetup.exe"), true);     // kept so Windows can uninstall it later
                MakeShortcut(StartMenuLink, exe, dest, "Visually Safe: a helpful antivirus companion");
                try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "TinyGuard.lnk")); } catch { }      // the old name

                string ver = PayloadVersion();
                using (var k = Registry.LocalMachine.CreateSubKey(UninstallKey))
                {
                    k.SetValue("DisplayName", "Visually Safe");
                    k.SetValue("DisplayVersion", ver);
                    k.SetValue("Publisher", "Visually Safe");
                    k.SetValue("InstallLocation", dest);
                    k.SetValue("DisplayIcon", exe);
                    k.SetValue("UninstallString", "\"" + Path.Combine(dest, "VisuallySafeSetup.exe") + "\" --uninstall");
                    k.SetValue("QuietUninstallString", "\"" + Path.Combine(dest, "VisuallySafeSetup.exe") + "\" --uninstall --silent");
                    k.SetValue("URLInfoAbout", "https://github.com/JohnCorreiaisme/VisuallySafe");
                    k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                }
                // start it when the person logs in, with full rights, without a permission box each time (only when it is the same person who is installing)
                string me = WindowsIdentity.GetCurrent().Name;
                if (string.IsNullOrEmpty(user) || string.Equals(user, me, StringComparison.OrdinalIgnoreCase))
                    Run("schtasks.exe", "/create /tn \"VisuallySafe\" /tr \"\\\"" + exe + "\\\"\" /sc onlogon /rl highest /f");
                RemoveLegacy(dest);
                File.WriteAllText(resultFile, "OK");
                return 0;
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(resultFile, ex.Message); } catch { }
                return 1;
            }
        }

        public static int UninstallFiles(string dest, string resultFile)
        {
            try
            {
                if (!IsAdmin) throw new Exception("this step needs permission");
                CloseRunning(dest);
                Run("schtasks.exe", "/delete /tn \"VisuallySafe\" /f");
                Run("schtasks.exe", "/delete /tn \"VisuallySafe Watchdog\" /f");
                RemoveLegacy(null);
                try { File.Delete(StartMenuLink); } catch { }
                try { Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, false); } catch { }
                // this very program lives in the folder, so the folder is removed a moment after it closes
                var psi = new ProcessStartInfo("cmd.exe", "/c ping 127.0.0.1 -n 4 >nul & rmdir /s /q \"" + dest + "\"") { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden };
                Process.Start(psi);
                File.WriteAllText(resultFile, "OK");
                return 0;
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(resultFile, ex.Message); } catch { }
                return 1;
            }
        }

        /// <summary>The parts that belong to the person's own account (they must be done without the extra permission).</summary>
        public static void PersonalSetup(string dest, bool desktopIcon, bool startWithWindows, bool wizard, string name, string email)
        {
            string exe = Path.Combine(dest, "VisuallySafe.exe");
            try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "TinyGuard.lnk")); } catch { }      // the old name
            if (desktopIcon)
                try { MakeShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Visually Safe.lnk"), exe, dest, "Visually Safe"); } catch { }
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                    if (startWithWindows) k.SetValue("VisuallySafe", "\"" + exe + "\""); else k.DeleteValue("VisuallySafe", false);
            }
            catch { }
            try
            {
                string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VisuallySafe");
                Directory.CreateDirectory(data);
                // keep anything already set up (mail server and so on); only change what this page asked for
                string ini = Path.Combine(data, "helper.ini");
                var kv = new System.Collections.Generic.Dictionary<string, string> { { "on", "0" }, { "wizard", "1" }, { "autoCheck", "1" }, { "intro", "0" }, { "name", "your family" }, { "email", "" }, { "smtp", "" }, { "port", "587" }, { "user", "" }, { "pass", "" }, { "server", "" } };
                if (File.Exists(ini))
                    foreach (string l in File.ReadAllLines(ini)) { int i = l.IndexOf('='); if (i > 0) kv[l.Substring(0, i)] = l.Substring(i + 1); }
                kv["on"] = wizard ? "1" : kv["on"]; kv["wizard"] = wizard ? "1" : "0";
                if (name.Length > 0) kv["name"] = name;
                if (email.Length > 0) kv["email"] = email;
                File.WriteAllLines(ini, kv.Select(p => p.Key + "=" + p.Value));
            }
            catch { }
        }

        public static void RemovePersonal()
        {
            try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Visually Safe.lnk")); } catch { }
            try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "TinyGuard.lnk")); } catch { }
            try { using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true)) if (k != null) k.DeleteValue("VisuallySafe", false); } catch { }
            foreach (string r in ShellRoots) try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\" + r + @"\shell\VisuallySafeScan", false); } catch { }
        }

        /// <summary>Starts the hidden permission job. Returns null on success, or a short text: "cancelled" or the problem.</summary>
        /// <summary>The automatic update: no pages, just the Windows permission box, then the new version starts.</summary>
        public static int UpdateRun()
        {
            string resultFile = Path.Combine(Path.GetTempPath(), "visuallysafe-update-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".txt");
            string me = WindowsIdentity.GetCurrent().Name;
            string err = RunWithPermission("--install-files " + (char)34 + Dest + (char)34 + " " + (char)34 + resultFile + (char)34 + " " + (char)34 + me + (char)34, resultFile);
            if (err == null)
            {
                try { Process.Start(new ProcessStartInfo(Path.Combine(Dest, "VisuallySafe.exe")) { UseShellExecute = true, WorkingDirectory = Dest }); } catch { }
                return 0;
            }
            if (err != "cancelled") MessageBox.Show("The update could not finish (" + err + "). Nothing was changed, and your current version still works.", "Visually Safe update");
            return 1;
        }

        /// <summary>Quiet install (--silent): the same files, shortcuts and start-up entry as the normal installer's defaults, no pages. 0 = installed.</summary>
        public static int SilentInstall()
        {
            string resultFile = Path.Combine(Path.GetTempPath(), "visuallysafe-setup-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".txt");
            string me = WindowsIdentity.GetCurrent().Name;
            string err;
            if (IsAdmin) { InstallFiles(Dest, resultFile, me); string r = File.Exists(resultFile) ? File.ReadAllText(resultFile).Trim() : ""; err = r == "OK" ? null : (r.Length == 0 ? "it did not finish" : r); }
            else err = RunWithPermission("--install-files " + (char)34 + Dest + (char)34 + " " + (char)34 + resultFile + (char)34 + " " + (char)34 + me + (char)34, resultFile);
            try { File.Delete(resultFile); } catch { }
            if (err != null) return 1;
            try { PersonalSetup(Dest, true, true, true, "", ""); } catch { }
            return 0;
        }

        /// <summary>Quiet removal (--uninstall --silent). Settings are kept, as with the normal uninstaller. 0 = removed.</summary>
        public static int SilentUninstall()
        {
            string resultFile = Path.Combine(Path.GetTempPath(), "visuallysafe-remove-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".txt");
            string err;
            if (IsAdmin) { UninstallFiles(Dest, resultFile); string r = File.Exists(resultFile) ? File.ReadAllText(resultFile).Trim() : ""; err = r == "OK" ? null : (r.Length == 0 ? "it did not finish" : r); }
            else err = RunWithPermission("--uninstall-files " + (char)34 + Dest + (char)34 + " " + (char)34 + resultFile + (char)34, resultFile);
            try { File.Delete(resultFile); } catch { }
            if (err != null) return 1;
            try { RemovePersonal(); } catch { }
            return 0;
        }

        public static string RunWithPermission(string verbArgs, string resultFile)
        {
            try
            {
                try { File.Delete(resultFile); } catch { }
                var psi = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, verbArgs) { Verb = "runas", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden };
                using (var p = Process.Start(psi)) p.WaitForExit();
                string r = File.Exists(resultFile) ? File.ReadAllText(resultFile).Trim() : "";
                return r == "OK" ? null : (r.Length == 0 ? "it did not finish" : r);
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { return "cancelled"; }
            catch (Exception ex) { return ex.Message; }
        }
    }

    /// <summary>The friendly installer window: big text, one thing at a time, and it explains the Windows permission box before it appears.</summary>
    class SetupForm : Form
    {
        static readonly Color Ink = Color.FromArgb(30, 34, 48), Soft = Color.FromArgb(90, 98, 118), Blue = Color.FromArgb(30, 90, 190), Green = Color.FromArgb(34, 139, 70), Cream = Color.FromArgb(255, 247, 214);
        readonly List<Panel> pages = new List<Panel>();
        int page;
        readonly Button bBack, bNext;
        RadioButton rOther, rMe; TextBox tName, tEmail; CheckBox cDesktop, cStart, cWizard;
        Label lStatus, lDoneTitle, lDoneBody; CheckBox cLaunch; Button bAgain;
        string resultTitle = "", resultBody = "";

        static Font F(float px, bool bold = false) { return new Font("Segoe UI", px, bold ? FontStyle.Bold : FontStyle.Regular, GraphicsUnit.Pixel); }

        public SetupForm()
        {
            Text = "Visually Safe Setup"; StartPosition = FormStartPosition.CenterScreen; FormBorderStyle = FormBorderStyle.FixedSingle; MaximizeBox = false;
            ClientSize = new Size(860, 600); BackColor = Color.White; ForeColor = Ink;
            try { Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location); } catch { }
            bBack = Btn("Back", 30, 520, 150, Color.FromArgb(120, 126, 142));
            bNext = Btn("Next", 640, 520, 190, Blue);
            bBack.Click += (s, e) => { if (page > 0 && page <= 2) Show(page - 1); };
            bNext.Click += (s, e) => Next();
            Controls.AddRange(new Control[] { bBack, bNext });
            BuildWelcome(); BuildWho(); BuildPermission(); BuildWorking(); BuildDone();
            Show(0);
        }

        Button Btn(string text, int x, int y, int w, Color c)
        {
            var b = new Button { Text = text, Left = x, Top = y, Width = w, Height = 56, FlatStyle = FlatStyle.Flat, BackColor = c, ForeColor = Color.White, Font = F(22, true), Cursor = Cursors.Hand };
            b.FlatAppearance.BorderSize = 0; return b;
        }

        Panel NewPage()
        {
            var p = new Panel { Left = 0, Top = 0, Width = 860, Height = 510, BackColor = Color.White, Visible = false };
            Controls.Add(p); pages.Add(p); return p;
        }

        Label L(Panel p, string text, int x, int y, int w, int h, float px, bool bold = false, Color? c = null)
        {
            var l = new Label { Text = text, Left = x, Top = y, Width = w, Height = h, Font = F(px, bold), ForeColor = c ?? Ink, AutoSize = false };
            p.Controls.Add(l); return l;
        }

        void BuildWelcome()
        {
            var p = NewPage();
            L(p, "Welcome to Visually Safe", 40, 24, 780, 56, 38, true);
            L(p, "A helpful antivirus companion. Clear green, yellow and red badges show what has been checked and what is safe, using Windows' built-in protection. An optional wizard can explain things aloud.", 44, 92, 770, 100, 21, false, Soft);
            L(p, "It works alongside Microsoft Defender. It does not replace it, and it is not made by or connected to Microsoft.", 44, 190, 770, 60, 18, false, Soft);
            bool win = Installer.WindowsOk, net = Installer.DotNet48(), def = Installer.DefenderFound();
            L(p, (win ? "✓  " : "✗  ") + "Windows 10 or 11" + (win ? "" : "  (this needs Windows 10 or newer)"), 44, 262, 770, 32, 21, true, win ? Green : Color.Firebrick);
            L(p, (net ? "✓  " : "✗  ") + ".NET Framework 4.8" + (net ? "" : "  (a free Windows add-on is missing: search the web for  Microsoft .NET Framework 4.8 download)"), 44, 298, 770, 32, 21, true, net ? Green : Color.Firebrick);
            L(p, (def ? "✓  " : "–  ") + "Microsoft Defender found" + (def ? "" : "  (Visually Safe still works, but it can't use Windows' own scanner)"), 44, 334, 770, 32, 21, true, def ? Green : Soft);
            var tip = new Panel { Left = 40, Top = 388, Width = 780, Height = 100, BackColor = Cream };
            tip.Controls.Add(new Label { Text = "If Windows shows a blue box saying “Windows protected your PC”, that is normal for a new program. Click “More info”, then “Run anyway”.", Left = 16, Top = 12, Width = 750, Height = 78, Font = F(19), ForeColor = Ink });
            p.Controls.Add(tip);
            if (!win) bNextBlocked = true;
        }
        bool bNextBlocked;

        void BuildWho()
        {
            var p = NewPage();
            L(p, "Who is this for?", 40, 24, 780, 50, 34, true);
            rOther = new RadioButton { Text = "I am setting it up for someone else (a parent, grandparent, friend)", Left = 44, Top = 90, Width = 770, Height = 36, Font = F(21), Checked = true };
            rMe = new RadioButton { Text = "I am setting it up for myself", Left = 44, Top = 130, Width = 770, Height = 36, Font = F(21) };
            p.Controls.AddRange(new Control[] { rOther, rMe });
            var lName = L(p, "What should the wizard call you, when he says “please ask …”?", 44, 188, 770, 30, 19, false, Soft);
            tName = new TextBox { Left = 44, Top = 220, Width = 500, Font = F(22), Text = "" };
            var lMail = L(p, "Your email address, so you get an alert if he finds a problem (optional):", 44, 276, 770, 30, 19, false, Soft);
            tEmail = new TextBox { Left = 44, Top = 308, Width = 600, Font = F(22) };
            p.Controls.AddRange(new Control[] { tName, tEmail });
            cWizard = new CheckBox { Text = "Also show the helper wizard on the screen", Left = 44, Top = 372, Width = 770, Height = 32, Font = F(20), Checked = true };
            cDesktop = new CheckBox { Text = "Put a Visually Safe icon on the Desktop", Left = 44, Top = 410, Width = 770, Height = 32, Font = F(20), Checked = true };
            cStart = new CheckBox { Text = "Start Visually Safe when Windows starts", Left = 44, Top = 448, Width = 770, Height = 32, Font = F(20), Checked = true };
            p.Controls.AddRange(new Control[] { cWizard, cDesktop, cStart });
            rMe.CheckedChanged += (s, e) =>
            {
                lName.Text = rMe.Checked ? "Who should the wizard say to ask for help? (optional)" : "What should the wizard call you, when he says “please ask …”?";
                lMail.Text = rMe.Checked ? "An email address for alerts (optional):" : "Your email address, so you get an alert if he finds a problem (optional):";
            };
        }

        void BuildPermission()
        {
            var p = NewPage();
            L(p, "Windows will ask for permission", 40, 24, 780, 50, 34, true);
            L(p, "When you click Install, Windows shows a box like the one below. Please click Yes.", 44, 84, 770, 64, 22, false, Soft);
            // a picture of the Windows permission box, so nobody is surprised
            var box = new Panel { Left = 44, Top = 160, Width = 470, Height = 210, BackColor = Color.FromArgb(240, 243, 249), BorderStyle = BorderStyle.FixedSingle };
            box.Controls.Add(new Label { Text = "User Account Control", Left = 14, Top = 10, Width = 440, Height = 26, Font = F(17, true), ForeColor = Color.FromArgb(40, 60, 120) });
            box.Controls.Add(new Label { Text = "Do you want to allow this app to make changes to your device?", Left = 14, Top = 46, Width = 440, Height = 60, Font = F(20), ForeColor = Ink });
            box.Controls.Add(new Label { Text = "Visually Safe Setup", Left = 14, Top = 112, Width = 300, Height = 26, Font = F(17), ForeColor = Soft });
            var yes = new Label { Text = "Yes", Left = 90, Top = 150, Width = 120, Height = 44, Font = F(22, true), ForeColor = Color.White, BackColor = Blue, TextAlign = ContentAlignment.MiddleCenter };
            var no = new Label { Text = "No", Left = 250, Top = 150, Width = 120, Height = 44, Font = F(22), ForeColor = Ink, BackColor = Color.FromArgb(205, 208, 216), TextAlign = ContentAlignment.MiddleCenter };
            box.Controls.AddRange(new Control[] { yes, no });
            p.Controls.Add(box);
            L(p, "<  Click Yes", 530, 196, 290, 44, 28, true, Blue);
            L(p, "Why it asks: Visually Safe goes into the protected Program Files folder, and it needs permission to check files anywhere on the computer and to start when Windows starts. It changes no security settings.", 44, 384, 770, 100, 19, false, Soft);
        }

        void BuildWorking()
        {
            var p = NewPage();
            L(p, "Installing…", 40, 24, 780, 50, 34, true);
            lStatus = L(p, "Waiting for you to click Yes on the Windows box…", 44, 110, 770, 120, 24, false, Soft);
        }

        void BuildDone()
        {
            var p = NewPage();
            lDoneTitle = L(p, "", 40, 24, 780, 56, 38, true);
            lDoneBody = L(p, "", 44, 100, 770, 220, 22, false, Soft);
            cLaunch = new CheckBox { Text = "Start Visually Safe now (the wizard will say hello)", Left = 44, Top = 360, Width = 770, Height = 36, Font = F(21), Checked = true };
            p.Controls.Add(cLaunch);
            var support = new LinkLabel { Text = "Free and open source. Say thanks on Ko-fi (optional)", Left = 44, Top = 420, Width = 770, Height = 30, Font = F(19), LinkColor = Blue };
            support.LinkClicked += (s, e) => { try { Process.Start(new ProcessStartInfo("https://ko-fi.com/johncorreia9791") { UseShellExecute = true }); } catch { } };
            p.Controls.Add(support);
            bAgain = Btn("Try again", 400, 520, 220, Blue); bAgain.Visible = false; bAgain.Click += (s, e) => Show(2);
            Controls.Add(bAgain);
        }

        /// <summary>Developer aid: draws every page to a picture without showing a window.</summary>
        public void Snap(string dir)
        {
            Directory.CreateDirectory(dir);
            StartPosition = FormStartPosition.Manual; Location = new Point(-4000, -4000); ShowInTaskbar = false; base.Show(); Application.DoEvents();
            Action<string> save = n => { using (var bmp = new Bitmap(Width, Height)) { DrawToBitmap(bmp, new Rectangle(0, 0, Width, Height)); bmp.Save(Path.Combine(dir, n + ".png")); } };
            for (int i = 0; i < 4; i++) { Show(i); Application.DoEvents(); save("page" + i); }
            Finish(null); Application.DoEvents(); save("done-ok"); Finish("cancelled"); Application.DoEvents(); save("done-cancelled"); Close();
        }

        void Show(int i)
        {
            page = i;
            for (int k = 0; k < pages.Count; k++) pages[k].Visible = k == i;
            bBack.Visible = i >= 1 && i <= 2;
            bNext.Visible = i != 3;
            bNext.Enabled = true; bAgain.Visible = false;
            bNext.Text = i == 2 ? "Install" : i == 4 ? "Finish" : "Next";
            bNext.BackColor = i == 2 ? Green : Blue;
            if (i == 0 && bNextBlocked) bNext.Enabled = false;
            if (i == 4) { bAgain.Visible = !resultOk; cLaunch.Visible = resultOk; bNext.Text = resultOk ? "Finish" : "Close"; }
        }

        bool resultOk;

        void Next()
        {
            if (page == 0 || page == 1) Show(page + 1);
            else if (page == 2) Install();
            else if (page == 4) { if (resultOk && cLaunch.Checked) Launch(); Close(); }
        }

        void Launch()
        {
            // "the wizard will say hello": the program is told this is the first start, so he introduces himself (only when he is switched on)
            try { Process.Start(new ProcessStartInfo(Path.Combine(Installer.Dest, "VisuallySafe.exe"), cWizard.Checked ? "--hello" : "") { UseShellExecute = true, WorkingDirectory = Installer.Dest }); } catch { }
        }

        void Install()
        {
            Show(3);
            lStatus.Text = "Waiting for you to click Yes on the Windows box…";
            string name = tName.Text.Trim(), email = tEmail.Text.Trim();
            bool desk = cDesktop.Checked, start = cStart.Checked, wiz = cWizard.Checked;
            string resultFile = Path.Combine(Path.GetTempPath(), "tinyguard-setup-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".txt");
            string me = WindowsIdentity.GetCurrent().Name;
            Task.Run(() =>
            {
                string err = Installer.RunWithPermission("--install-files \"" + Installer.Dest + "\" \"" + resultFile + "\" \"" + me + "\"", resultFile);
                if (err == null)
                {
                    try { BeginInvoke(new Action(() => lStatus.Text = "Setting things up for you…")); } catch { }
                    Installer.PersonalSetup(Installer.Dest, desk, start, wiz, name, email);
                }
                try { File.Delete(resultFile); } catch { }
                try { BeginInvoke(new Action(() => Finish(err))); } catch { }
            });
        }

        void Finish(string err)
        {
            resultOk = err == null;
            if (err == null)
            {
                lDoneTitle.Text = "All set!";
                lDoneBody.Text = "Visually Safe is installed." + (cWizard.Checked ? " The wizard will appear on the screen and say hello." : "") + "\r\n\r\nYou can open it from the Start menu" + (cDesktop.Checked ? " or the Desktop icon" : "") + ". To remove it later, use Windows Settings, then Apps.";
            }
            else if (err == "cancelled")
            {
                lDoneTitle.Text = "No problem. Nothing was installed.";
                lDoneBody.Text = "The Windows permission box was closed, or No was clicked, so Windows did not allow the install.\r\n\r\nPress Try again and click Yes when the box appears. If it asks for a password, it needs the password of the person who owns this computer.";
            }
            else
            {
                lDoneTitle.Text = "Something went wrong.";
                lDoneBody.Text = "Visually Safe could not finish installing (" + err + ").\r\n\r\nPlease close any other Visually Safe windows and try again. If it keeps happening, ask the person who owns this computer.";
            }
            Show(4);
        }
    }

    /// <summary>Removing it: explains the permission box first, then removes the program (the person's data stays).</summary>
    class UninstallForm : Form
    {
        static Font F(float px, bool bold = false) { return new Font("Segoe UI", px, bold ? FontStyle.Bold : FontStyle.Regular, GraphicsUnit.Pixel); }
        readonly Label lTitle, lBody; readonly Button bGo, bClose;

        public UninstallForm()
        {
            Text = "Remove Visually Safe"; StartPosition = FormStartPosition.CenterScreen; FormBorderStyle = FormBorderStyle.FixedSingle; MaximizeBox = false;
            ClientSize = new Size(760, 420); BackColor = Color.White;
            lTitle = new Label { Text = "Remove Visually Safe?", Left = 36, Top = 24, Width = 690, Height = 56, Font = F(34, true) };
            lBody = new Label { Text = "Windows will ask for permission. Click Yes.\r\n\r\nYour settings and scan history are kept, in case you install it again.", Left = 40, Top = 100, Width = 680, Height = 200, Font = F(22), ForeColor = Color.FromArgb(90, 98, 118) };
            bGo = new Button { Text = "Remove", Left = 340, Top = 330, Width = 190, Height = 56, FlatStyle = FlatStyle.Flat, BackColor = Color.Firebrick, ForeColor = Color.White, Font = F(22, true) };
            bClose = new Button { Text = "Cancel", Left = 550, Top = 330, Width = 170, Height = 56, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(120, 126, 142), ForeColor = Color.White, Font = F(22, true) };
            bGo.FlatAppearance.BorderSize = 0; bClose.FlatAppearance.BorderSize = 0;
            Controls.AddRange(new Control[] { lTitle, lBody, bGo, bClose });
            bClose.Click += (s, e) => Close();
            bGo.Click += (s, e) =>
            {
                bGo.Enabled = false; lBody.Text = "Waiting for you to click Yes on the Windows box…";
                string resultFile = Path.Combine(Path.GetTempPath(), "tinyguard-remove-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".txt");
                string dest = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                Task.Run(() =>
                {
                    string err = Installer.RunWithPermission("--uninstall-files \"" + dest + "\" \"" + resultFile + "\"", resultFile);
                    if (err == null) Installer.RemovePersonal();
                    try { File.Delete(resultFile); } catch { }
                    try
                    {
                        BeginInvoke(new Action(() =>
                        {
                            lTitle.Text = err == null ? "Visually Safe was removed." : err == "cancelled" ? "Nothing was removed." : "Something went wrong.";
                            lBody.Text = err == null ? "Thank you for trying it." : err == "cancelled" ? "The permission box was closed, so Windows did not allow it." : "Could not remove it (" + err + ").";
                            bGo.Visible = false; bClose.Text = "Close";
                        }));
                    }
                    catch { }
                });
            };
        }
    }
}
