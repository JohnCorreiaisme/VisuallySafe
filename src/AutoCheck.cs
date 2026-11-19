using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TinyGuard
{
    /// <summary>
    /// The twice-a-week check for family helper mode: Monday and Thursday around noon, or about three minutes after start-up if a week has gone by
    /// (the PC was off). It updates the protection, looks at the Desktop and Downloads, and tells the person (and the family by email) how it went.
    /// </summary>
    static class AutoCheck
    {
        static Engine eng; static volatile bool running, cancel;
        static readonly DateTime started = DateTime.Now;

        public static bool Running { get { return running; } }
        public static void Cancel() { if (running) cancel = true; }

        public static void Start(Engine e) { eng = e; }

        /// <summary>Called every 30 seconds by the helper.</summary>
        public static void Tick()
        {
            if (eng == null || running || eng.ScanActive || Helper.Cfg == null || !Helper.Cfg.On || !Helper.Cfg.AutoCheck || ScreenSaver.Active) return;
            if ((DateTime.Now - started).TotalMinutes < 3) return;                   // a delayed start: let Windows finish starting up first
            try { if (IdleInfo.FullscreenAppActive()) return; } catch { }
            DateTime last = eng.S.LastAutoCheck > 0 ? new DateTime(eng.S.LastAutoCheck) : DateTime.MinValue;
            bool overdue = (DateTime.Now - last).TotalDays >= 7;
            var now = DateTime.Now;
            bool slotDay = now.DayOfWeek == DayOfWeek.Monday || now.DayOfWeek == DayOfWeek.Thursday;
            bool slotDue = slotDay && now.Hour >= 12 && last < now.Date.AddHours(12);
            if (overdue || slotDue) RunNow(false);
        }

        public static void RunNow(bool manual)
        {
            if (running || eng == null) return;
            if (eng.ScanActive) { if (manual) Wizard.Say("A scan is already running, so I will wait until it has finished.", false, null); return; }
            running = true; cancel = false;
            Task.Run(() =>
            {
                string summary;
                try { summary = Run(manual); }
                catch (Exception ex) { summary = "I tried to check your computer but something went wrong (" + ex.Message + ")."; }
                finally { running = false; }
                if (cancel) { cancel = false; Wizard.Say("Okay, I stopped the check.", false, null); return; }
                eng.S.LastAutoCheck = DateTime.Now.Ticks; eng.S.Save();
                Wizard.Say(summary, summary.Contains("attention"), null);
            });
        }

        static string Run(bool manual)
        {
            Wizard.Cast(3.2);
            if (manual) Wizard.Say("Okay, I am checking your computer now. It may take a few minutes.", false, null);
            int before = eng.NeedAttention();
            // 1. keep the protection up to date
            string upd = "";
            try { eng.Yara.Update(); } catch { }
            string def = DefenderLink.UpdateSignatures();
            if (def != null) upd = " I updated my protection" + (def.Length > 0 ? " and Microsoft Defender's" : "") + ".";
            // 2. look at the places people actually use
            var places = new List<string>
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup)
            }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            places.AddRange(Wizard.DesktopItems());      // each Desktop icon on its own, so each one gets its ring
            foreach (string p in places) eng.ScanNow(p);
            var sw = Stopwatch.StartNew();
            Thread.Sleep(3000);
            while (!cancel && sw.Elapsed.TotalMinutes < 25 && places.Any(p => eng.ProgressOf(p) >= 0)) Thread.Sleep(1500);
            if (cancel) return "";
            // 3. what starts with Windows
            var fresh = Persistence.Check(eng, false);
            int after = eng.NeedAttention();
            int found = Math.Max(0, after - before);
            string who = Wizard.Who;
            string body = "I finished my check.";
            if (found > 0 || fresh.Count > 0)
            {
                body += found > 0 ? " I found " + found + (found == 1 ? " thing" : " things") + " that need your attention." : "";
                if (fresh.Count > 0) body += " A new program was set to start with Windows. If you did not install something, please ask " + who + ".";
                body += " Please ask " + who + " to take a look.";
                Helper.Notify("TinyGuard check on " + Environment.MachineName, "The scheduled check found " + found + " item(s) needing attention" + (fresh.Count > 0 ? " and new start-up entries:\r\n" + string.Join("\r\n", fresh) : "") + ".");
            }
            else body += " Everything looks fine." + upd + " I looked at your Desktop and Downloads.";
            return body;
        }
    }

    /// <summary>Notices new things set to start with Windows (the way most malware survives a restart): Run keys, Startup folders, auto-start services and scheduled tasks.</summary>
    static class Persistence
    {
        static readonly object gate = new object();

        static List<string> Snapshot()
        {
            var l = new List<string>();
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                foreach (string sub in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" })
                    try
                    {
                        using (var k = hive.OpenSubKey(sub))
                            if (k != null) foreach (string n in k.GetValueNames()) l.Add("Run|" + (hive == Registry.CurrentUser ? "user" : "pc") + "|" + n + "|" + Convert.ToString(k.GetValue(n)));
                    }
                    catch { }
            foreach (var d in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
                try { foreach (string f in Directory.GetFiles(d)) if (!f.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) l.Add("Startup|" + Path.GetFileName(f) + "|" + f); } catch { }
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                    if (k != null)
                        foreach (string n in k.GetSubKeyNames())
                            try
                            {
                                using (var s = k.OpenSubKey(n))
                                {
                                    object start = s.GetValue("Start"), img = s.GetValue("ImagePath");
                                    if (start == null || Convert.ToInt32(start) != 2 || img == null) continue;
                                    string path = Convert.ToString(img);
                                    if (path.IndexOf(@"\windows\", StringComparison.OrdinalIgnoreCase) >= 0 || path.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase)) continue;
                                    l.Add("Service|" + n + "|" + path);
                                }
                            }
                            catch { }
            }
            catch { }
            try
            {
                string tasks = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
                foreach (string f in Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories).Take(4000))
                {
                    string rel = f.Substring(tasks.Length).TrimStart('\\');
                    if (rel.StartsWith("Microsoft\\", StringComparison.OrdinalIgnoreCase)) continue;
                    l.Add("Task|" + rel + "|");
                }
            }
            catch { }
            return l;
        }

        /// <summary>Compare with what was there last time. The very first run only records what is there.</summary>
        public static List<string> Check(Engine eng, bool alert)
        {
            var fresh = new List<string>();
            lock (gate)
            {
                try
                {
                    string file = Path.Combine(eng.DataDir, "startup-items.txt");
                    var now = Snapshot();
                    if (File.Exists(file))
                    {
                        var old = new HashSet<string>(File.ReadAllLines(file), StringComparer.OrdinalIgnoreCase);
                        foreach (string s in now)
                            if (!old.Contains(s))
                            {
                                var p = s.Split('|');
                                fresh.Add(p[0] + ": " + p[1] + (p.Length > 2 && p[2].Length > 0 ? " (" + p[p.Length - 1] + ")" : ""));
                                string exe = ExeOf(p[p.Length - 1]);
                                if (exe != null) try { eng.ScanNow(exe); } catch { }
                            }
                    }
                    File.WriteAllLines(file, now);
                }
                catch { }
            }
            if (alert && fresh.Count > 0 && Found != null) Found("New program set to start with Windows", string.Join("\n", fresh.Take(3)));
            return fresh;
        }

        public static event Action<string, string> Found;

        static string ExeOf(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return null;
            cmd = Environment.ExpandEnvironmentVariables(cmd.Trim());
            try
            {
                if (cmd.StartsWith("\"")) { int e = cmd.IndexOf('"', 1); if (e > 1) cmd = cmd.Substring(1, e - 1); }
                else { int i = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase); if (i > 0) cmd = cmd.Substring(0, i + 4); }
                return File.Exists(cmd) ? cmd : null;
            }
            catch { return null; }
        }
    }
}
