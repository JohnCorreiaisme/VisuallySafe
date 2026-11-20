using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;

namespace TinyGuard
{
    /// <summary>Microsoft Defender's own verdict on a file, asked through its command-line scanner (MpCmdRun.exe).
    /// Report only: -DisableRemediation means Defender never removes anything on Visually Safe's behalf.</summary>
    static class DefenderLink
    {
        public class Answer { public bool Threat; public string Name = ""; public bool Ml; }

        static string exe; static bool looked;
        static readonly SemaphoreSlim gate = new SemaphoreSlim(2);     // a folder scan must not start dozens of Defender scans at once

        public static string Exe
        {
            get
            {
                if (looked) return exe;
                looked = true;
                try
                {
                    string plat = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
                    string best = null;
                    if (Directory.Exists(plat))
                        foreach (string d in Directory.GetDirectories(plat))
                        {
                            string c = Path.Combine(d, "MpCmdRun.exe");
                            if (File.Exists(c) && (best == null || string.Compare(Path.GetFileName(d), Path.GetFileName(Path.GetDirectoryName(best)), StringComparison.OrdinalIgnoreCase) > 0)) best = c;
                        }
                    if (best == null)
                    {
                        string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
                        if (File.Exists(pf)) best = pf;
                    }
                    exe = best;
                }
                catch { }
                return exe;
            }
        }

        public static bool Available { get { return Exe != null; } }

        /// <summary>Ask Defender to fetch its newest definitions. "ok" when it worked, null when it could not.</summary>
        public static string UpdateSignatures()
        {
            string mp = Exe; if (mp == null) return null;
            try
            {
                var psi = new ProcessStartInfo(mp, "-SignatureUpdate") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var p = Process.Start(psi))
                {
                    p.StandardOutput.ReadToEndAsync(); p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(180000)) { try { p.Kill(); } catch { } return null; }
                    return p.ExitCode == 0 ? "ok" : null;
                }
            }
            catch { return null; }
        }

        /// <summary>A plain-words line about Defender: on or off, and how fresh its definitions are.</summary>
        public static string StatusText()
        {
            try
            {
                using (var s = new System.Management.ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus"))
                    foreach (System.Management.ManagementObject o in s.Get())
                    {
                        bool av = Convert.ToBoolean(o["AntivirusEnabled"]), rt = Convert.ToBoolean(o["RealTimeProtectionEnabled"]);
                        DateTime upd = System.Management.ManagementDateTimeConverter.ToDateTime(Convert.ToString(o["AntivirusSignatureLastUpdated"]));
                        return "Microsoft Defender is " + (av ? "on" : "OFF") + ", real-time protection is " + (rt ? "on" : "OFF") + ". Its definitions were updated " + upd.ToString("g") + " (version " + o["AntivirusSignatureVersion"] + ").";
                    }
            }
            catch { }
            return Available ? "Microsoft Defender is installed, but I could not read its status." : "Microsoft Defender was not found on this PC.";
        }

        const string Ns = @"root\Microsoft\Windows\Defender";

        public class Health
        {
            public bool Installed, Enabled, RealTime;
            public int SigAgeDays = -1, QuickAgeDays = -1;      // -1: unknown, or never
            public List<string> Active = new List<string>();    // threats Windows says are still active
        }

        static string Str(System.Management.ManagementBaseObject o, string prop) { try { return Convert.ToString(o[prop]); } catch { return ""; } }
        static int Days(System.Management.ManagementBaseObject o, string prop)
        {
            try { object v = o[prop]; if (v == null) return -1; long n = Convert.ToInt64(v); return n < 0 || n > 100000 ? -1 : (int)n; } catch { return -1; }
        }

        /// <summary>What Windows' own protection says about itself: is it on, how fresh is it, when did it last scan, is anything still active.</summary>
        public static Health GetHealth()
        {
            var h = new Health { Installed = Available };
            try
            {
                using (var s = new System.Management.ManagementObjectSearcher(Ns, "SELECT * FROM MSFT_MpComputerStatus"))
                    foreach (System.Management.ManagementObject o in s.Get())
                    {
                        h.Enabled = Str(o, "AntivirusEnabled") == "True"; h.RealTime = Str(o, "RealTimeProtectionEnabled") == "True";
                        h.SigAgeDays = Days(o, "AntivirusSignatureAge"); h.QuickAgeDays = Days(o, "QuickScanAge");
                    }
            }
            catch { }
            try
            {
                using (var s = new System.Management.ManagementObjectSearcher(Ns, "SELECT * FROM MSFT_MpThreat"))
                    foreach (System.Management.ManagementObject o in s.Get())
                        if (Str(o, "IsActive") == "True") h.Active.Add(Str(o, "ThreatName"));
            }
            catch { }
            return h;
        }

        public class Det { public string Name = "", Where = ""; public DateTime When; }

        /// <summary>Everything Windows' protection has found since the given moment.</summary>
        public static List<Det> Detections(DateTime since)
        {
            var l = new List<Det>(); var names = new Dictionary<string, string>();
            try
            {
                using (var s = new System.Management.ManagementObjectSearcher(Ns, "SELECT * FROM MSFT_MpThreat"))
                    foreach (System.Management.ManagementObject o in s.Get()) names[Str(o, "ThreatID")] = Str(o, "ThreatName");
            }
            catch { }
            try
            {
                using (var s = new System.Management.ManagementObjectSearcher(Ns, "SELECT * FROM MSFT_MpThreatDetection"))
                    foreach (System.Management.ManagementObject o in s.Get())
                    {
                        DateTime t; try { t = System.Management.ManagementDateTimeConverter.ToDateTime(Str(o, "InitialDetectionTime")); } catch { continue; }
                        if (t <= since) continue;
                        string name; names.TryGetValue(Str(o, "ThreatID"), out name);
                        string where = ""; try { var r = o["Resources"] as string[]; if (r != null && r.Length > 0) where = r[0]; } catch { }
                        l.Add(new Det { Name = name ?? "", Where = where, When = t });
                    }
            }
            catch { }
            return l;
        }

        /// <summary>Run Windows' own scan (quick or full) and wait for it. Returns "clean", "threats", "failed" or null if Windows protection is not there.</summary>
        public static volatile bool Running;
        static Process scanProc; static volatile bool cancelled;

        /// <summary>Ask Windows to stop the scan Visually Safe started (only that one: it is stopped by its own process, never by name).</summary>
        public static void CancelScan()
        {
            var p = scanProc; string mp = Exe;
            if (!Running || p == null) return;
            cancelled = true;
            try { if (mp != null) Process.Start(new ProcessStartInfo(mp, "-Cancel") { UseShellExecute = false, CreateNoWindow = true }); } catch { }
            try { p.Kill(); } catch { }
        }

        public static string Scan(bool quick, Action<int> everyMinuteOrSo)
        {
            string mp = Exe; if (mp == null) return null;
            Running = true; cancelled = false;
            try
            {
                var psi = new ProcessStartInfo(mp, "-Scan -ScanType " + (quick ? "1" : "2")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var p = Process.Start(psi))
                {
                    scanProc = p;
                    p.StandardOutput.ReadToEndAsync(); p.StandardError.ReadToEndAsync();
                    var sw = Stopwatch.StartNew();
                    while (!p.WaitForExit(cancelled ? 1000 : 90000))
                    {
                        if (everyMinuteOrSo != null) everyMinuteOrSo((int)sw.Elapsed.TotalMinutes);
                        if (sw.Elapsed.TotalMinutes > 180) { try { p.Kill(); } catch { } return "failed"; }
                    }
                    if (cancelled) return "stopped";
                    return p.ExitCode == 0 ? "clean" : p.ExitCode == 2 ? "threats" : "failed";
                }
            }
            catch { return cancelled ? "stopped" : "failed"; }
            finally { scanProc = null; Running = false; }
        }

        /// <summary>A threat name from Windows ("Trojan:Win32/Something.A") in plain words.</summary>
        public static string Plain(string name)
        {
            string n = name ?? "", kind = n.Contains(":") ? n.Substring(0, n.IndexOf(':')) : n, what;
            switch (kind.ToLowerInvariant())
            {
                case "trojan": what = "a harmful program pretending to be something useful"; break;
                case "ransom": what = "a program that locks your files and asks for money"; break;
                case "pua": case "pup": what = "an unwanted program that may show ads or slow the computer"; break;
                case "backdoor": what = "a program that lets criminals into your computer"; break;
                case "worm": what = "a harmful program that spreads by itself"; break;
                case "virus": what = "a harmful program that infects other files"; break;
                case "exploit": what = "a trick that attacks a weakness in a program"; break;
                case "hacktool": what = "a hacking tool"; break;
                case "adware": what = "a program that fills the screen with adverts"; break;
                case "trojanspy": case "spyware": case "infostealer": what = "a program that spies on you"; break;
                case "behavior": what = "a program that acted in a dangerous way"; break;
                case "browsermodifier": what = "something that changes your web browser settings"; break;
                default: what = "a harmful or unwanted program"; break;
            }
            if (n.EndsWith("!ml", StringComparison.OrdinalIgnoreCase) || n.IndexOf("!MTB", StringComparison.OrdinalIgnoreCase) >= 0) what += " (Windows is only guessing, so it may be a false alarm)";
            return what;
        }

        /// <summary>Null when Defender couldn't answer (not installed, turned off, timed out).</summary>
        public static Answer Check(string path)
        {
            string mp = Exe;
            if (mp == null) return null;
            if (!gate.Wait(30000)) return null;
            try
            {
                var psi = new ProcessStartInfo(mp, "-Scan -ScanType 3 -DisableRemediation -File \"" + path + "\"")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var p = Process.Start(psi))
                {
                    var outTask = p.StandardOutput.ReadToEndAsync();
                    p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(25000)) { try { p.Kill(); } catch { } return null; }
                    string text = outTask.Result ?? "";
                    var a = new Answer();
                    if (p.ExitCode == 0) return a;                                      // scanned, nothing found
                    if (p.ExitCode != 2) return null;                                   // couldn't scan (service off, file gone, access denied)
                    a.Threat = true;
                    var m = Regex.Match(text, @"Threat\s*:\s*(.+)");
                    if (m.Success) a.Name = m.Groups[1].Value.Trim();
                    else { m = Regex.Match(text, @"found\s+(\S+)"); if (m.Success) a.Name = m.Groups[1].Value.Trim(); }
                    a.Ml = a.Name.IndexOf("!ml", StringComparison.OrdinalIgnoreCase) >= 0 || a.Name.IndexOf("Heur", StringComparison.OrdinalIgnoreCase) >= 0;
                    return a;
                }
            }
            catch { return null; }
            finally { gate.Release(); }
        }
    }
}
