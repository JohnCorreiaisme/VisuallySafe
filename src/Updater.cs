using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace VisuallySafe
{
    class Pkg { public string Name = "", Id = "", Version = "", Available = "", Source = ""; }

    /// <summary>Finds and installs newer versions of programs through winget (built into Windows 10/11).</summary>
    static class Updater
    {
        static List<Pkg> cache;
        static DateTime cacheAt = DateTime.MinValue;
        static readonly object gate = new object();
        static readonly Regex IdRx = new Regex(@"^[A-Za-z0-9][A-Za-z0-9._+\-]{1,120}$");

        static int Run(string args, int timeoutSec, CancellationToken ct, out string output)
        {
            var psi = new ProcessStartInfo("winget.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
            using (var p = Process.Start(psi))
            {
                var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                DateTime end = DateTime.Now.AddSeconds(timeoutSec);
                while (!p.WaitForExit(300))
                    if (ct.IsCancellationRequested || DateTime.Now > end) { try { p.Kill(); } catch { } output = ""; return -1; }
                output = o.Result + e.Result;
                return p.ExitCode;
            }
        }

        /// <summary>Programs that have a newer version available. Null (with an error message) if winget can't be used.</summary>
        public static List<Pkg> Upgrades(CancellationToken ct, out string error)
        {
            error = null;
            lock (gate) if (cache != null && (DateTime.Now - cacheAt).TotalMinutes < 10) return cache;
            string output; int code;
            try { code = Run("upgrade --accept-source-agreements --disable-interactivity", 120, ct, out output); }
            catch (Exception ex) { error = "winget isn't available on this PC (" + ex.Message + ")"; return null; }
            if (ct.IsCancellationRequested) { error = "stopped."; return null; }
            var list = Parse(output);
            if (list == null) { error = code == 0 || output.Contains("No installed package") ? null : "winget couldn't list updates"; list = new List<Pkg>(); }
            lock (gate) { cache = list; cacheAt = DateTime.Now; }
            return list;
        }

        public static List<Pkg> Parse(string output)
        {
            var lines = (output ?? "").Replace("\r", "\n").Split('\n');
            int h = Array.FindIndex(lines, l => l.TrimStart().StartsWith("Name") && l.Contains("Id") && l.Contains("Version") && l.Contains("Available"));
            if (h < 0) return null;
            string head = lines[h];
            int iId = head.IndexOf("Id"), iVer = head.IndexOf("Version"), iAv = head.IndexOf("Available"), iSrc = head.IndexOf("Source");
            if (iId < 1 || iVer <= iId || iAv <= iVer) return null;
            var list = new List<Pkg>();
            for (int i = h + 1; i < lines.Length; i++)
            {
                string l = lines[i];
                if (l.Length == 0 || l.StartsWith("---")) continue;
                if (l.Length <= iAv || Regex.IsMatch(l, @"^\d+ upgrades? available")) break;
                Func<int, int, string> cut = (a, b) => (b <= a || a >= l.Length) ? "" : l.Substring(a, Math.Min(b, l.Length) - a).Trim();
                var p = new Pkg { Name = cut(0, iId), Id = cut(iId, iVer), Version = cut(iVer, iAv), Available = cut(iAv, iSrc > iAv ? iSrc : l.Length), Source = iSrc > iAv ? cut(iSrc, l.Length) : "" };
                if (IdRx.IsMatch(p.Id)) list.Add(p);
            }
            return list;
        }

        static string Norm(string s) { return Regex.Replace((s ?? "").ToLowerInvariant(), "[^a-z0-9]", ""); }

        static string Clean(string name)
        {
            // "7-Zip 22.01 (x64)" -> "7-Zip": drop brackets and the version tail
            string n = Regex.Replace(name ?? "", @"\s*\(.*?\)", "");
            return Regex.Replace(n, @"\s+v?\d[\d.\-+]*\b.*$", "").Trim();
        }

        static readonly string[] Generic = { "microsoft", "windows", "microsoftwindows", "microsoftcorporation", "operatingsystem" };

        /// <summary>The installed program an exe/driver belongs to, if winget knows a newer version of it.</summary>
        public static Pkg Find(string path, List<Pkg> pkgs)
        {
            if (pkgs == null || pkgs.Count == 0 || string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            var names = new List<string>();
            try { var vi = FileVersionInfo.GetVersionInfo(path); names.Add(vi.ProductName); }
            catch { }
            // the program's own folder under Program Files / AppData\Local\Programs, e.g. "Armoury Crate"
            try
            {
                string d = Path.GetDirectoryName(path);
                while (!string.IsNullOrEmpty(d))
                {
                    string parent = Path.GetDirectoryName(d) ?? "";
                    string pn = Path.GetFileName(parent) ?? "";
                    if (pn.StartsWith("Program Files", StringComparison.OrdinalIgnoreCase) || pn.Equals("Programs", StringComparison.OrdinalIgnoreCase)) { names.Add(Path.GetFileName(d)); break; }
                    d = parent;
                }
            }
            catch { }

            Pkg best = null; int bestLen = 0;
            foreach (string raw in names)
            {
                string c = Norm(raw);
                if (c.Length < 3 || Generic.Contains(c) || c.Contains("operatingsystem")) continue;
                foreach (var p in pkgs)
                {
                    string pn = Norm(Clean(p.Name));
                    if (pn.Length < 3) continue;
                    bool match = pn == c || (c.Length >= 5 && pn.Length >= 5 && (pn.Contains(c) || c.Contains(pn)));
                    if (match && pn.Length > bestLen) { best = p; bestLen = pn.Length; }
                }
            }
            return best;
        }

        /// <summary>Installs the newer version. Returns an error message, or null on success.</summary>
        public static string Upgrade(Pkg p, CancellationToken ct)
        {
            if (p == null || !IdRx.IsMatch(p.Id)) return "no valid package to update";
            string output; int code;
            try { code = Run("upgrade --id " + p.Id + " --exact --silent --accept-source-agreements --accept-package-agreements --disable-interactivity", 900, ct, out output); }
            catch (Exception ex) { return "winget isn't available (" + ex.Message + ")"; }
            if (ct.IsCancellationRequested) return "stopped";
            if (code == 0) { lock (gate) cache = null; return null; }
            string last = (output ?? "").Replace("\r", "\n").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 3 && !x.StartsWith("-") && !x.StartsWith("\\") && !x.StartsWith("/") && !x.StartsWith("|")).LastOrDefault() ?? "";
            return "winget stopped with code " + code + (last.Length > 0 ? ": " + (last.Length > 160 ? last.Substring(0, 160) : last) : "");
        }
    }
}
