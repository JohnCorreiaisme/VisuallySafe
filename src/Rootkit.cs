using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace TinyGuard
{
    enum Sev { Note = 0, Warn = 1, Bad = 2 }

    class Finding
    {
        public Sev Sev;
        public string Title = "", Detail = "", Path = "", Advice = "";
        public int RegRoot;               // 1 = your startup list (HKCU), 2 = all-users (HKLM); 0 = not a removable startup entry
        public string RegSub = "", RegValue = "", Link = "";
    }

    /// <summary>
    /// Looks for the user-mode signs of a rootkit: bad drivers, processes hidden from the process list,
    /// tampered startup entries and hosts file. A rootkit deep in the kernel can fool all of this, which is why the
    /// page also offers Microsoft Defender Offline (a scan from outside Windows).
    /// </summary>
    class RootkitCheck
    {
        [DllImport("psapi.dll", SetLastError = true)] static extern bool EnumDeviceDrivers([Out] IntPtr[] bases, int cb, out int needed);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode)] static extern int GetDeviceDriverFileName(IntPtr b, StringBuilder name, int size);
        [DllImport("psapi.dll", SetLastError = true)] static extern bool EnumProcesses([Out] int[] ids, int size, out int needed);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", CharSet = CharSet.Unicode)] static extern bool Process32First(IntPtr snap, ref PROCESSENTRY32 e);
        [DllImport("kernel32.dll", EntryPoint = "Process32NextW", CharSet = CharSet.Unicode)] static extern bool Process32Next(IntPtr snap, ref PROCESSENTRY32 e);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32
        {
            public uint dwSize, cntUsage, th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID, cntThreads, th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }

        public const int Steps = 4;
        public volatile bool Running;
        public string Step = "";
        public int StepNo;
        public List<Finding> Findings = new List<Finding>();
        public DateTime Finished = DateTime.MinValue;
        public int Drivers, Processes, Entries;
        public string ListStatus = "", Coverage = "", Notes = "";

        readonly string dataDir;
        readonly Dictionary<string, string> lol = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, string> signers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static readonly string Win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        static readonly HttpClient http = MakeHttp();

        static HttpClient MakeHttp()
        {
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("TinyGuard/" + Engine.Version);
            return h;
        }

        readonly HashSet<string> ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string IgnoreFile { get { return Path.Combine(dataDir, "ignored-findings.txt"); } }
        static string Key(Finding f) { return f.Title + "|" + f.Path; }
        public int IgnoredCount { get { lock (ignored) return ignored.Count; } }

        public RootkitCheck(string dataDir)
        {
            this.dataDir = dataDir;
            try { if (File.Exists(IgnoreFile)) foreach (string l in File.ReadAllLines(IgnoreFile)) if (l.Length > 0) ignored.Add(l); } catch { }
        }

        /// <summary>Stop reporting this finding in future checks.</summary>
        public void Ignore(Finding f)
        {
            lock (ignored) { if (ignored.Add(Key(f))) { try { File.AppendAllText(IgnoreFile, Key(f) + Environment.NewLine); } catch { } } }
            Findings = Findings.Where(x => !ReferenceEquals(x, f) && Key(x) != Key(f)).ToList();
        }

        string LolFile { get { return Path.Combine(dataDir, "loldrivers.tsv"); } }

        // ------------------------------------------------------------------ run

        public void Run(bool allowNetwork)
        {
            if (Running) return;
            Running = true;
            var found = new List<Finding>();
            Drivers = Processes = Entries = 0;
            try
            {
                Begin(0, "Loading the known-bad driver list…");
                LoadLol(allowNetwork);
                Begin(1, "Checking loaded drivers…");
                CheckDrivers(found);
                Begin(2, "Looking for hidden programs…");
                CheckHiddenProcesses(found);
                Begin(3, "Checking startup entries and the hosts file…");
                CheckStartup(found);
                CheckHosts(found);
            }
            catch (Exception ex)
            {
                found.Add(new Finding { Sev = Sev.Note, Title = "The check stopped early", Detail = ex.GetBaseException().Message });
            }
            lock (ignored) found = found.Where(f => !ignored.Contains(Key(f))).ToList();
            Findings = found.OrderByDescending(f => f.Sev).ThenBy(f => f.Title).ToList();
            Coverage = "Checked " + Drivers + " drivers, " + Processes + " running programs, " + Entries + " startup entries and the hosts file." + (IgnoredCount > 0 ? " " + IgnoredCount + " ignored finding" + (IgnoredCount == 1 ? "" : "s") + " hidden." : "");
            Notes = (Admin.IsAdmin ? "Ran as administrator." : "Ran without administrator rights, so protected programs couldn't be inspected.") + " " + ListStatus + ".";
            Finished = DateTime.Now;
            Step = "";
            Running = false;
        }

        void Begin(int n, string text) { StepNo = Math.Max(n, 1); Step = text; }

        // ------------------------------------------------------------------ LOLDrivers

        void LoadLol(bool allowNetwork)
        {
            bool stale = !File.Exists(LolFile) || (DateTime.Now - File.GetLastWriteTime(LolFile)).TotalDays > 7;
            try { if (!stale && File.ReadLines(LolFile).First().Split('\t').Length < 4) stale = true; } catch { stale = true; }   // older file without entry ids
            if (stale && allowNetwork)
            {
                try
                {
                    string csv = http.GetStringAsync("https://www.loldrivers.io/api/drivers.csv").GetAwaiter().GetResult();
                    if (csv.Length > 100000 && csv.Length < 30000000)
                    {
                        var lines = new List<string>();
                        foreach (var row in ParseCsv(csv).Skip(1))
                        {
                            if (row.Count < 27) continue;
                            string cat = row[6].Trim(), tags = row[26].Split(',')[0].Trim(), desc = row[11].Trim();
                            string name = tags.Length > 0 ? tags : desc.Length > 0 ? desc : "unnamed driver";
                            foreach (Match m in Regex.Matches(row[17], "[0-9a-fA-F]{64}"))
                                lines.Add(m.Value.ToLowerInvariant() + "\t" + cat + "\t" + name.Replace('\t', ' ') + "\t" + row[0].Trim());
                        }
                        if (lines.Count > 500)
                        {
                            string tmp = LolFile + ".tmp";
                            File.WriteAllLines(tmp, lines);
                            if (File.Exists(LolFile)) File.Delete(LolFile);
                            File.Move(tmp, LolFile);
                        }
                    }
                }
                catch { }
            }
            lol.Clear();
            try
            {
                if (File.Exists(LolFile))
                    foreach (string l in File.ReadAllLines(LolFile))
                    {
                        string[] p = l.Split('\t');
                        if (p.Length >= 3) lol[p[0]] = p[1] + "\t" + p[2] + "\t" + (p.Length > 3 ? p[3] : "");
                    }
            }
            catch { }
            ListStatus = lol.Count > 0
                ? "Known-bad driver list: " + lol.Count + " fingerprints (updated " + File.GetLastWriteTime(LolFile).ToString("MMM d") + ")"
                : "Known-bad driver list not available" + (allowNetwork ? " (couldn't download it)" : " (online checks are off)");
        }

        /// <summary>Minimal CSV reader: quoted fields, doubled quotes, line breaks inside quotes.</summary>
        static IEnumerable<List<string>> ParseCsv(string text)
        {
            var row = new List<string>(); var sb = new StringBuilder(); bool q = false;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (q)
                {
                    if (c == '"') { if (i + 1 < text.Length && text[i + 1] == '"') { sb.Append('"'); i++; } else q = false; }
                    else sb.Append(c);
                }
                else if (c == '"') q = true;
                else if (c == ',') { row.Add(sb.ToString()); sb.Clear(); }
                else if (c == '\n' || c == '\r')
                {
                    if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                    row.Add(sb.ToString()); sb.Clear();
                    yield return row; row = new List<string>();
                }
                else sb.Append(c);
            }
            if (sb.Length > 0 || row.Count > 0) { row.Add(sb.ToString()); yield return row; }
        }

        // ------------------------------------------------------------------ helpers

        string Signer(string path)
        {
            string s;
            if (signers.TryGetValue(path, out s)) return s;
            try { s = Trust.TrustedSigner(path); } catch { s = null; }
            signers[path] = s;
            return s;
        }

        static string Sha256(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var h = SHA256.Create())
            {
                var sb = new StringBuilder();
                foreach (byte b in h.ComputeHash(fs)) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        static bool Risky(string path)
        {
            string p = path.ToLowerInvariant();
            return p.Contains("\\appdata\\") || p.Contains("\\temp\\") || p.Contains("\\users\\public\\") || p.Contains("\\programdata\\")
                || p.Contains("\\downloads\\") || p.Contains("\\$recycle.bin\\") || p.Contains("\\desktop\\");
        }

        // ------------------------------------------------------------------ 1. drivers

        const string DriverAdvice = "If you don't recognise this driver, search its name online before doing anything. Unsigned or vulnerable drivers are a favourite way for malware to get deep into Windows. Remove the program it belongs to, then restart; if you can't tell what it is, run the Defender Offline scan below.";

        static string DriverPath(string raw)
        {
            string p = raw;
            if (p.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) p = Win + p.Substring(11);
            else if (p.StartsWith("\\??\\")) p = p.Substring(4);
            else if (p.StartsWith("\\")) p = Path.GetPathRoot(Win).TrimEnd('\\') + p;
            else if (!Path.IsPathRooted(p)) p = Path.Combine(Win, p);
            return p;
        }

        void CheckDrivers(List<Finding> found)
        {
            var raws = new List<string>();
            int needed;
            EnumDeviceDrivers(null, 0, out needed);
            var bases = new IntPtr[Math.Max(needed / IntPtr.Size, 1) + 16];
            if (EnumDeviceDrivers(bases, bases.Length * IntPtr.Size, out needed))
                for (int i = 0; i < needed / IntPtr.Size; i++)
                {
                    var sb = new StringBuilder(1024);
                    if (bases[i] != IntPtr.Zero && GetDeviceDriverFileName(bases[i], sb, sb.Capacity) != 0) raws.Add(sb.ToString());
                }
            if (raws.Count < 5)
            {
                // Windows hides driver addresses from programs without administrator rights; ask WMI instead.
                try
                {
                    using (var q = new System.Management.ManagementObjectSearcher("SELECT PathName FROM Win32_SystemDriver WHERE State = 'Running'"))
                        foreach (System.Management.ManagementObject o in q.Get())
                        {
                            string pn = o["PathName"] as string;
                            if (!string.IsNullOrEmpty(pn)) raws.Add(pn);
                        }
                }
                catch { }
            }
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in raws)
            {
                string path = DriverPath(raw);
                if (!seen.Add(path)) continue;
                Drivers++;
                string name = Path.GetFileName(path);
                if (!File.Exists(path))
                {
                    found.Add(new Finding { Sev = Sev.Warn, Title = "Driver with no file on disk: " + name, Path = path,
                        Detail = "This driver is running in Windows but its file can't be found. Hidden driver files are a rootkit sign (though a few legitimate drivers load from memory).",
                        Advice = DriverAdvice });
                    continue;
                }
                string sha = null;
                try { sha = Sha256(path); } catch { }
                string hit;
                if (sha != null && lol.TryGetValue(sha, out hit))
                {
                    string[] h = hit.Split('\t');
                    bool mal = h[0].IndexOf("malicious", StringComparison.OrdinalIgnoreCase) >= 0;
                    found.Add(new Finding { Sev = mal ? Sev.Bad : Sev.Warn, Path = path, Link = h.Length > 2 && h[2].Length > 0 ? "https://www.loldrivers.io/drivers/" + h[2] + "/" : "",
                        Title = (mal ? "Known malicious driver: " : "Known vulnerable driver: ") + name,
                        Detail = mal ? "This driver's fingerprint is on the LOLDrivers list of drivers used by malware (listed as " + h[1] + ")."
                                     : "This driver is on the LOLDrivers list: it has a flaw attackers abuse to take over Windows (listed as " + h[1] + "). It may be part of software you use; old versions are the problem.",
                        Advice = mal ? "Treat this as an infection: run the Defender Offline scan below, and change your passwords from a different, clean device."
                                     : "If it belongs to a program you use, update that program to its newest version. If you don't use it, uninstall the program." });
                    continue;
                }
                if (Signer(path) == null)
                    found.Add(new Finding { Sev = Sev.Warn, Title = "Unsigned driver: " + name, Path = path,
                        Detail = "Windows loaded this driver but it has no valid digital signature, which Windows normally requires for kernel drivers.",
                        Advice = DriverAdvice });
            }
        }

        // ------------------------------------------------------------------ 2. hidden processes

        static HashSet<int> ListPids()
        {
            var r = new HashSet<int>();
            var ids = new int[8192]; int needed;
            if (EnumProcesses(ids, ids.Length * 4, out needed)) for (int i = 0; i < needed / 4; i++) r.Add(ids[i]);
            return r;
        }

        static HashSet<int> ToolhelpPids()
        {
            var r = new HashSet<int>();
            IntPtr snap = CreateToolhelp32Snapshot(0x2, 0);
            if (snap == new IntPtr(-1) || snap == IntPtr.Zero) return r;
            try
            {
                var e = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32)) };
                for (bool ok = Process32First(snap, ref e); ok; ok = Process32Next(snap, ref e)) r.Add((int)e.th32ProcessID);
            }
            finally { CloseHandle(snap); }
            return r;
        }

        static bool Alive(int pid, out string path)
        {
            path = null;
            IntPtr h = OpenProcess(0x1000, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                uint code;
                if (!GetExitCodeProcess(h, out code) || code != 259) return false;
                var sb = new StringBuilder(1024); int size = sb.Capacity;
                if (QueryFullProcessImageName(h, 0, sb, ref size)) path = sb.ToString();
                return true;
            }
            finally { CloseHandle(h); }
        }

        void CheckHiddenProcesses(List<Finding> found)
        {
            var a = ListPids(); var b = ToolhelpPids();
            Processes = a.Count;
            // Ask Windows directly about every possible process number: a program unlinked from the lists still answers.
            var suspects = new List<int>();
            string p;
            for (int pid = 8; pid < 262144; pid += 4)
                if (!a.Contains(pid) && !b.Contains(pid) && Alive(pid, out p)) suspects.Add(pid);
            foreach (int pid in a.Where(x => x > 4 && !b.Contains(x)).Concat(b.Where(x => x > 4 && !a.Contains(x)))) suspects.Add(pid);
            if (suspects.Count == 0) return;

            Thread.Sleep(700); // a program that merely started a moment ago will now be in both lists
            var a2 = ListPids(); var b2 = ToolhelpPids();
            foreach (int pid in suspects.Distinct())
            {
                if (!Alive(pid, out p)) continue;
                bool inA = a2.Contains(pid), inB = b2.Contains(pid);
                if (inA && inB) continue;
                found.Add(new Finding
                {
                    Sev = inA || inB ? Sev.Warn : Sev.Bad,
                    Title = (inA || inB ? "Program shown by only one process list: " : "Hidden program: ") + (p != null ? Path.GetFileName(p) : "process " + pid),
                    Path = p ?? "",
                    Detail = "Process number " + pid + " is running but " + (inA || inB ? "one of Windows' two process lists leaves it out." : "is missing from both of Windows' process lists, which is what a rootkit does to hide a program."),
                    Advice = "This can occasionally be a false alarm for security software. If you don't recognise the name, run the Defender Offline scan below."
                });
            }
        }

        // ------------------------------------------------------------------ 3. startup entries

        const string StartAdvice = "If you don't recognise this, search the file name online. If it's something you don't want, delete the entry (Task Manager's Startup tab, or Autoruns from Microsoft) and quarantine the file.";

        static string ExtractExe(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) return null;
            string c = Environment.ExpandEnvironmentVariables(command.Trim());
            string p;
            if (c.StartsWith("\"")) { int e = c.IndexOf('"', 1); p = e > 0 ? c.Substring(1, e - 1) : c.Substring(1); }
            else
            {
                var m = Regex.Match(c, @"^(.*?\.(exe|com|bat|cmd|scr|vbs|js|ps1|dll|sys))(\s|,|$)", RegexOptions.IgnoreCase);
                p = m.Success ? m.Groups[1].Value : c.Split(' ')[0];
            }
            if (p.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) p = Win + p.Substring(11);
            else if (p.StartsWith("\\??\\")) p = p.Substring(4);
            if (!Path.IsPathRooted(p))
            {
                string sys = Path.Combine(Win, "System32", p);
                p = File.Exists(sys) ? sys : Path.Combine(Win, p);
            }
            return p;
        }

        void CheckEntry(List<Finding> found, string source, string name, string command, int regRoot = 0, string regSub = "", string regValue = "")
        {
            string path;
            try { path = ExtractExe(command); } catch { return; }
            if (path == null) return;
            Entries++;
            if (!File.Exists(path))
            {
                found.Add(new Finding { Sev = Sev.Note, Title = "Startup entry points to a missing file: " + name, Path = path, RegRoot = regRoot, RegSub = regSub, RegValue = regValue,
                    Detail = source + " runs " + path + " but the file isn't there (often just leftovers from an uninstalled program).", Advice = StartAdvice });
                return;
            }
            if (Signer(path) != null) return;
            bool risky = Risky(path);
            found.Add(new Finding
            {
                Sev = risky ? Sev.Warn : Sev.Note,
                Title = "Unsigned program starts automatically: " + Path.GetFileName(path),
                Path = path, RegRoot = regRoot, RegSub = regSub, RegValue = regValue,
                Detail = source + " (" + name + ") runs it" + (risky ? " from a folder that malware often uses." : ". It has no digital signature, which is common for small or home-made tools."),
                Advice = StartAdvice
            });
        }

        void CheckStartup(List<Finding> found)
        {
            // Run keys
            foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
                foreach (string sub in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                                               @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" })
                    try
                    {
                        using (var k = root.OpenSubKey(sub))
                            if (k != null)
                                foreach (string v in k.GetValueNames())
                                    CheckEntry(found, (root == Registry.CurrentUser ? "Your" : "All-users") + " startup list", v, k.GetValue(v) as string, root == Registry.CurrentUser ? 1 : 2, sub, v);
                    }
                    catch { }

            // Startup folders
            foreach (var dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
                try
                {
                    if (!Directory.Exists(dir)) continue;
                    foreach (string f in Directory.GetFiles(dir))
                    {
                        if (Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                        string target = f;
                        if (f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                            try
                            {
                                dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
                                string t = sh.CreateShortcut(f).TargetPath;
                                if (!string.IsNullOrEmpty(t)) target = t;
                            }
                            catch { }
                        CheckEntry(found, "Startup folder", Path.GetFileName(f), "\"" + target + "\"");
                    }
                }
                catch { }

            // Windows' own login settings, which have fixed expected values
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                    if (k != null)
                    {
                        string shell = ((k.GetValue("Shell") as string) ?? "explorer.exe").Trim();
                        string ui = ((k.GetValue("Userinit") as string) ?? "").Trim().TrimEnd(',').Trim();
                        Entries += 2;
                        if (!shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                            found.Add(new Finding { Sev = Sev.Bad, Title = "Windows login shell was changed", Detail = "The program Windows starts as your desktop is \"" + shell + "\" instead of explorer.exe. Malware uses this to run at every login.",
                                Advice = "Run the Defender Offline scan below. Don't change the setting by hand unless you know what it should be." });
                        if (ui.Length > 0 && !ui.Equals(Path.Combine(Win, "system32", "userinit.exe"), StringComparison.OrdinalIgnoreCase))
                            found.Add(new Finding { Sev = Sev.Bad, Title = "Windows login program was changed", Detail = "Userinit is \"" + ui + "\" instead of the normal userinit.exe, so something else runs when you sign in.",
                                Advice = "Run the Defender Offline scan below." });
                    }
            }
            catch { }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"))
                {
                    string ai = (k == null ? null : k.GetValue("AppInit_DLLs") as string) ?? "";
                    Entries++;
                    if (ai.Trim().Length > 0)
                        found.Add(new Finding { Sev = Sev.Warn, Title = "AppInit_DLLs is set", Detail = "These DLLs are loaded into almost every program: " + ai.Trim() + ". Old software used this; so does malware.",
                            Advice = "If you don't recognise the DLL names, run the Defender Offline scan below." });
                }
            }
            catch { }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"))
                    if (k != null)
                        foreach (string app in k.GetSubKeyNames())
                            using (var s = k.OpenSubKey(app))
                            {
                                string dbg = s == null ? null : s.GetValue("Debugger") as string;
                                if (string.IsNullOrWhiteSpace(dbg)) continue;
                                Entries++;
                                found.Add(new Finding { Sev = Sev.Warn, Title = "Program launch is redirected: " + app,
                                    Detail = "Windows starts \"" + dbg + "\" whenever " + app + " is launched. Developers use this, but malware uses it to hijack or block security tools.",
                                    Advice = "If you didn't set this up yourself or with a developer tool, run the Defender Offline scan below." });
                            }
            }
            catch { }

            // Services that start with Windows
            try
            {
                using (var svcs = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                    if (svcs != null)
                        foreach (string name in svcs.GetSubKeyNames())
                            using (var s = svcs.OpenSubKey(name))
                            {
                                if (s == null) continue;
                                int type = Convert.ToInt32(s.GetValue("Type", 0)), start = Convert.ToInt32(s.GetValue("Start", 4));
                                if ((type & 0x30) == 0 || start > 2) continue;
                                string image = s.GetValue("ImagePath") as string;
                                using (var par = s.OpenSubKey("Parameters"))
                                {
                                    string dll = par == null ? null : par.GetValue("ServiceDll") as string; // svchost services: the real code is here
                                    if (!string.IsNullOrEmpty(dll)) image = dll;
                                }
                                CheckEntry(found, "Windows service", name, image);
                            }
            }
            catch { }
        }

        // ------------------------------------------------------------------ 4. hosts file

        static readonly string[] SecurityWords = { "microsoft", "windows", "defender", "avast", "avg.", "kaspersky", "eset", "norton", "symantec", "mcafee",
            "malwarebytes", "bitdefender", "sophos", "virustotal", "trendmicro", "comodo", "avira", "windowsupdate" };

        void CheckHosts(List<Finding> found)
        {
            string file = Path.Combine(Win, "System32", "drivers", "etc", "hosts");
            if (!File.Exists(file)) return;
            int blocks = 0;
            foreach (string raw in File.ReadAllLines(file))
            {
                string line = raw.Split('#')[0].Trim();
                if (line.Length == 0) continue;
                string[] p = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (p.Length < 2) continue;
                string ip = p[0];
                bool loop = ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0";
                foreach (string host in p.Skip(1))
                {
                    string h = host.ToLowerInvariant();
                    if (h == "localhost" || h == "broadcasthost" || h.StartsWith("ip6-")) continue;
                    bool security = SecurityWords.Any(h.Contains);
                    if (security)
                        found.Add(new Finding { Sev = Sev.Warn, Title = "Hosts file redirects " + host, Path = file,
                            Detail = "The hosts file sends " + host + " to " + ip + (loop ? ", which blocks it" : "") + ". Malware does this to stop Windows and antivirus programs updating.",
                            Advice = "If you didn't add this line yourself, open the hosts file in Notepad (as administrator) and remove it." });
                    else if (loop) blocks++;
                    else
                        found.Add(new Finding { Sev = Sev.Note, Title = "Hosts file sends " + host + " elsewhere", Path = file,
                            Detail = "The hosts file points " + host + " to " + ip + ". Fine if you or a program you use added it.", Advice = "If you don't remember adding this, remove the line from the hosts file." });
                }
            }
            if (blocks > 0)
                found.Add(new Finding { Sev = Sev.Note, Title = "Hosts file blocks " + blocks + " website name" + (blocks == 1 ? "" : "s"), Path = file,
                    Detail = "Lines pointing sites to 0.0.0.0 or 127.0.0.1 block them. Ad blockers and some tools do this on purpose.", Advice = "Nothing to do unless you didn't expect it." });
            Entries++;
        }

        // ------------------------------------------------------------------ Defender Offline

        /// <summary>Starts Microsoft Defender Offline. The PC RESTARTS IMMEDIATELY. Returns an error message or null.</summary>
        public static string StartDefenderOffline()
        {
            try
            {
                var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -WindowStyle Hidden -Command \"Start-MpWDOScan\"")
                { UseShellExecute = true, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
                if (!Admin.IsAdmin) psi.Verb = "runas";
                Process.Start(psi);
                return null;
            }
            catch (Exception ex) { return ex.GetBaseException().Message; }
        }
    }
}
