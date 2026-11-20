using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Web.Script.Serialization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace VisuallySafe
{
    class YaraHit { public string Rule = "", Description = ""; public int Score; }

    /// <summary>
    /// Runs the official YARA engine (bin\yara\yara64.exe) with the YARA-Forge core rules
    /// (bin\yara\core.yar) plus any of the user's own rules in &lt;data&gt;\rules\*.yar.
    /// Rules are compiled once into &lt;data&gt;\rules.yarc and recompiled when a source changes.
    /// </summary>
    class Yara
    {
        readonly string yara, yarac, bundledCore, dataCore, userDir, compiled, dataDir;
        // Updated rules live in the data folder and win over the copy that shipped with Visually Safe.
        string core { get { return File.Exists(dataCore) ? dataCore : bundledCore; } }
        public string RulesVersion { get { return ReadVersion(core); } }
        public DateTime LastCheck = DateTime.MinValue;
        public string UpdateStatus = "";
        volatile bool updating;
        public bool Updating { get { return updating; } }
        public bool Ready { get; private set; }
        public string Status { get; private set; }

        public Yara(string binDir, string dataDir)
        {
            string d = Path.Combine(binDir, "yara");
            yara = Path.Combine(d, "yara64.exe");
            yarac = Path.Combine(d, "yarac64.exe");
            bundledCore = Path.Combine(d, "core.yar");
            dataCore = Path.Combine(dataDir, "core.yar");
            this.dataDir = dataDir;
            userDir = Path.Combine(dataDir, "rules");
            compiled = Path.Combine(dataDir, "rules.yarc");
            Directory.CreateDirectory(userDir);
            Status = "YARA not installed";
        }

        /// <summary>Compile rules if needed. Safe to call from a background thread.</summary>
        public void Prepare()
        {
            if (!File.Exists(yara) || !File.Exists(yarac) || !File.Exists(core)) { Ready = false; Status = "YARA not installed"; return; }
            var user = Directory.GetFiles(userDir, "*.yar").Concat(Directory.GetFiles(userDir, "*.yara")).OrderBy(f => f).ToArray();
            DateTime newest = user.Select(File.GetLastWriteTimeUtc).Concat(new[] { File.GetLastWriteTimeUtc(core) }).Max();
            string stamp = compiled + ".list";
            string list = core + "|" + string.Join("|", user);
            bool fresh = File.Exists(compiled) && File.GetLastWriteTimeUtc(compiled) >= newest
                         && File.Exists(stamp) && File.ReadAllText(stamp) == list;
            string note = "";
            if (!fresh)
            {
                var args = new StringBuilder("-w \"core:" + core + "\"");
                foreach (string u in user) args.Append(" \"user:" + u + "\"");
                string err;
                if (Run(yarac, args + " \"" + compiled + "\"", 120, out err) != 0)
                {
                    // A broken rule of the user's must not switch YARA off: fall back to the core rules.
                    note = " (your rules have an error and were skipped)";
                    if (Run(yarac, "-w \"core:" + core + "\" \"" + compiled + "\"", 120, out err) != 0)
                    { Ready = false; Status = "YARA rules failed to compile"; return; }
                }
                File.WriteAllText(stamp, note.Length == 0 ? list : "");
            }
            Ready = true;
            Status = "YARA ready" + note;
        }

        /// <summary>The strongest matching rule, or null if nothing matches.</summary>
        public YaraHit Scan(string path)
        {
            if (!Ready) return null;
            string output;
            if (Run(yara, "-w -m -N -a 20 -C \"" + compiled + "\" \"" + path + "\"", 30, out output) != 0) return null;
            YaraHit best = null;
            foreach (string line in output.Split('\n'))
            {
                var m = Regex.Match(line, @"^(\S+)\s+\[(.*)\]\s+");
                if (!m.Success) continue;
                var h = new YaraHit { Rule = m.Groups[1].Value };
                var sc = Regex.Match(m.Groups[2].Value, @"\bscore\s*=\s*""?(\d+)");
                h.Score = sc.Success ? int.Parse(sc.Groups[1].Value) : 70;
                var ds = Regex.Match(m.Groups[2].Value, "\\bdescription\\s*=\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                h.Description = ds.Success ? ds.Groups[1].Value.Replace("\\\"", "\"") : "";
                if (best == null || h.Score > best.Score) best = h;
            }
            return best;
        }

        static string ReadVersion(string corePath)
        {
            try { return File.ReadAllText(Path.ChangeExtension(corePath, ".version")).Trim(); } catch { return "unknown"; }
        }

        static readonly HttpClient http = MakeHttp();
        static HttpClient MakeHttp()
        {
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("VisuallySafe/" + Engine.Version);
            return h;
        }

        /// <summary>
        /// Fetch the newest YARA-Forge core rules if there is one. New rules are only used after they
        /// compile cleanly, so a bad download can never switch YARA off. Returns true if rules changed.
        /// Runs on a background thread; the scanner thread picks the new rules up on its next Prepare().
        /// </summary>
        public bool Update()
        {
            if (updating || !File.Exists(yarac)) return false;
            updating = true;
            string tmpDir = Path.Combine(dataDir, "update-tmp");
            try
            {
                UpdateStatus = "Checking for new rules…";
                var rel = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(
                    http.GetStringAsync("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest").GetAwaiter().GetResult());
                string tag = rel["tag_name"] as string ?? "";
                string url = null; long size = 0;
                foreach (Dictionary<string, object> a in (System.Collections.ArrayList)rel["assets"])
                    if ((a["name"] as string) == "yara-forge-rules-core.zip")
                    { url = a["browser_download_url"] as string; size = Convert.ToInt64(a["size"]); }
                LastCheck = DateTime.Now;
                string have = RulesVersion;
                // Tags are dates (yyyyMMdd), so a plain comparison tells newer from older.
                if (url == null || !Regex.IsMatch(tag, @"^\d{8}$") || string.CompareOrdinal(tag, have) <= 0)
                { UpdateStatus = "Rules are up to date"; return false; }
                if (!url.StartsWith("https://github.com/YARAHQ/yara-forge/releases/download/") || size <= 0 || size > 50L * 1024 * 1024)
                { UpdateStatus = "Update skipped: unexpected download"; return false; }

                UpdateStatus = "Downloading rules " + tag + "…";
                if (Directory.Exists(tmpDir)) Directory.Delete(tmpDir, true);
                Directory.CreateDirectory(tmpDir);
                string zip = Path.Combine(tmpDir, "core.zip");
                File.WriteAllBytes(zip, http.GetByteArrayAsync(url).GetAwaiter().GetResult());
                if (new FileInfo(zip).Length != size) { UpdateStatus = "Update failed: download incomplete"; return false; }

                string newRules = Path.Combine(tmpDir, "core.yar");
                using (var z = ZipFile.OpenRead(zip))
                {
                    var e = z.Entries.FirstOrDefault(x => x.FullName.EndsWith("yara-rules-core.yar", StringComparison.OrdinalIgnoreCase));
                    if (e == null || e.Length > 200L * 1024 * 1024) { UpdateStatus = "Update failed: rules missing from download"; return false; }
                    e.ExtractToFile(newRules);
                }
                string err;
                if (Run(yarac, "-w \"core:" + newRules + "\" \"" + Path.Combine(tmpDir, "test.yarc") + "\"", 180, out err) != 0)
                { UpdateStatus = "Update skipped: new rules didn't compile"; return false; }

                File.WriteAllText(Path.Combine(tmpDir, "core.version"), tag);
                if (File.Exists(dataCore)) File.Delete(dataCore);
                File.Move(newRules, dataCore);
                File.SetLastWriteTimeUtc(dataCore, DateTime.UtcNow); // zip dates can be older than the compiled rules
                File.Copy(Path.Combine(tmpDir, "core.version"), Path.ChangeExtension(dataCore, ".version"), true);
                UpdateStatus = "Updated to rules " + tag;
                return true;
            }
            catch (Exception ex)
            {
                LastCheck = DateTime.Now;
                UpdateStatus = "Couldn't check for rules (" + ex.GetBaseException().Message.TrimEnd('.') + ")";
                return false;
            }
            finally
            {
                try { if (Directory.Exists(tmpDir)) Directory.Delete(tmpDir, true); } catch { }
                updating = false;
            }
        }

        static int Run(string exe, string args, int timeoutSec, out string stdout)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (var p = Process.Start(psi))
            {
                p.PriorityClass = ProcessPriorityClass.BelowNormal;
                var err = p.StandardError.ReadToEndAsync();
                var outp = p.StandardOutput.ReadToEndAsync();
                if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(); } catch { } stdout = ""; return -1; }
                stdout = outp.Result + err.Result;
                return p.ExitCode;
            }
        }
    }
}
