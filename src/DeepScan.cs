using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace TinyGuard
{
    /// <summary>The extra, slower checks a deep scan adds on top of the normal ones.</summary>
    static class DeepChecks
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_STREAM_DATA { public long StreamSize; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstStreamW(string file, int level, out WIN32_FIND_STREAM_DATA data, int flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool FindNextStreamW(IntPtr h, out WIN32_FIND_STREAM_DATA data);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);

        /// <summary>NTFS "alternate data streams" other than the harmless download marker; malware can hide a program in one.</summary>
        public static string HiddenStreams(string path, out bool program)
        {
            program = false;
            var found = new List<string>();
            WIN32_FIND_STREAM_DATA d;
            IntPtr h = FindFirstStreamW(path, 0, out d, 0);
            if (h == new IntPtr(-1)) return null;
            try
            {
                do
                {
                    string n = d.cStreamName ?? "";
                    if (n == "::$DATA" || n.StartsWith(":Zone.Identifier", StringComparison.OrdinalIgnoreCase) || d.StreamSize <= 0) continue;
                    found.Add(n.Replace(":$DATA", "") + " (" + d.StreamSize + " bytes)");
                    try
                    {
                        using (var fs = new FileStream(path + n.Replace(":$DATA", ""), FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            if (fs.ReadByte() == 'M' && fs.ReadByte() == 'Z') program = true;
                    }
                    catch { }
                } while (FindNextStreamW(h, out d));
            }
            finally { FindClose(h); }
            return found.Count == 0 ? null : string.Join(", ", found.Take(3));
        }

        static readonly string[] Packers = { "upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".petite", "mpress1", "mpress2", ".nsp0", ".enigma1", ".boom" };

        /// <summary>Reads a program's header and sections and reports things packers and malware leave behind.</summary>
        public static string PeCheck(string path, out int points)
        {
            points = 0;
            int soft = 0; bool upx = false;   // soft clues (entropy, big installer data) only count when something firmer backs them up
            var why = new List<string>();
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var br = new BinaryReader(fs))
                {
                    if (fs.Length < 1024) return null;
                    fs.Position = 0x3C; int pe = br.ReadInt32();
                    if (pe < 0 || pe > fs.Length - 256) return null;
                    fs.Position = pe;
                    if (br.ReadUInt32() != 0x00004550) return null;
                    fs.Position = pe + 6; int nsec = br.ReadUInt16();
                    fs.Position = pe + 20; int optSize = br.ReadUInt16();
                    long opt = pe + 24;
                    fs.Position = opt; int magic = br.ReadUInt16();
                    fs.Position = opt + 16; uint entry = br.ReadUInt32();
                    long ddir = opt + (magic == 0x20B ? 112 : 96);
                    fs.Position = ddir + 8; uint importSize = 0; br.ReadUInt32(); importSize = br.ReadUInt32();
                    if (nsec <= 0 || nsec > 96) return null;
                    long table = opt + optSize; long maxRaw = 0; int writableExec = 0; bool epOk = false; int epIndex = -1;
                    for (int i = 0; i < nsec; i++)
                    {
                        fs.Position = table + i * 40;
                        string name = Encoding.ASCII.GetString(br.ReadBytes(8)).TrimEnd('\0').ToLowerInvariant();
                        uint vsize = br.ReadUInt32(), va = br.ReadUInt32(), rsize = br.ReadUInt32(), rptr = br.ReadUInt32();
                        fs.Position = table + i * 40 + 36; uint ch = br.ReadUInt32();
                        maxRaw = Math.Max(maxRaw, (long)rptr + rsize);
                        if (name.StartsWith("upx")) upx = true;   // UPX is a common, honest compressor: not suspicious by itself
                        else if (Packers.Contains(name)) { points += 3; why.Add("packer section " + name); }
                        if ((ch & 0x20000000) != 0 && (ch & 0x80000000) != 0) writableExec++;
                        if (rsize == 0 && vsize > 1048576 && !upx) { soft++; why.Add("empty section that unpacks to " + vsize / 1048576 + " MB"); }
                        if (entry >= va && entry < va + Math.Max(vsize, rsize)) { epIndex = i; epOk = true; if ((ch & 0x80000000) != 0 && (ch & 0x20000000) != 0 && !upx) { points += 2; why.Add("entry point in a writable+executable section"); } }
                        if (rsize >= 4096 && rsize <= 8 * 1024 * 1024 && rptr > 0 && rptr + rsize <= fs.Length)
                        {
                            long keep = fs.Position; fs.Position = rptr; var data = br.ReadBytes((int)rsize); fs.Position = keep;
                            var hist = new int[256]; foreach (byte b in data) hist[b]++;
                            double ent = 0; foreach (int c in hist) if (c > 0) { double p = (double)c / data.Length; ent -= p * Math.Log(p, 2); }
                            if (ent > 7.4 && !upx) { soft++; why.Add("section " + name + " looks scrambled (entropy " + ent.ToString("0.0") + ")"); }
                        }
                    }
                    if (epOk && epIndex == nsec - 1 && nsec > 1 && !upx) { soft++; why.Add("entry point is in the last section"); }
                    if (!epOk && entry != 0) { points++; why.Add("entry point is outside every section"); }
                    if (writableExec > 0 && !upx) { soft++; why.Add(writableExec + " writable+executable section" + (writableExec == 1 ? "" : "s")); }
                    if (importSize == 0 && fs.Length > 20000) { points += 2; why.Add("imports nothing"); }
                    long overlay = fs.Length - maxRaw;
                    if (overlay > 1048576 && overlay > fs.Length / 2) { soft++; why.Add("large hidden payload appended after the program (" + overlay / 1048576 + " MB)"); }
                }
            }
            catch { return null; }
            if (points > 0) points += soft;       // firm evidence present: the soft clues now add up
            else points = 0;
            return points == 0 || why.Count == 0 ? null : string.Join("; ", why.Take(4));
        }

        static readonly Regex[] ScriptPatterns =
        {
            new Regex(@"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", RegexOptions.IgnoreCase),
            new Regex(@"FromBase64String", RegexOptions.IgnoreCase),
            new Regex(@"\b(IEX|Invoke-Expression)\b", RegexOptions.IgnoreCase),
            new Regex(@"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|Start-BitsTransfer", RegexOptions.IgnoreCase),
            new Regex(@"certutil[^\r\n]*(-urlcache|-decode)", RegexOptions.IgnoreCase),
            new Regex(@"bitsadmin[^\r\n]*/transfer", RegexOptions.IgnoreCase),
            new Regex(@"regsvr32[^\r\n]*/i:\s*http", RegexOptions.IgnoreCase),
            new Regex(@"mshta\s+(http|vbscript|javascript)", RegexOptions.IgnoreCase),
            new Regex(@"-w(indowstyle)?\s+hidden", RegexOptions.IgnoreCase),
            new Regex(@"rundll32[^\r\n]*javascript:", RegexOptions.IgnoreCase),
            new Regex(@"vssadmin[^\r\n]*delete\s+shadows", RegexOptions.IgnoreCase),
            new Regex(@"Set-MpPreference[^\r\n]*Disable", RegexOptions.IgnoreCase)
        };
        static readonly string[] ScriptNames = { "encoded PowerShell command", "decodes hidden data", "runs text as code", "downloads files", "certutil download/decode", "bitsadmin download", "regsvr32 remote script", "mshta remote script", "hidden window", "rundll32 script", "deletes backups (shadow copies)", "turns off Defender" };
        static readonly HashSet<string> ScriptExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".psm1" };

        public static string ScriptCheck(string path, out int hits)
        {
            hits = 0;
            if (!ScriptExts.Contains(Path.GetExtension(path))) return null;
            try
            {
                string text;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var buf = new byte[(int)Math.Min(fs.Length, 300 * 1024)];
                    int n = fs.Read(buf, 0, buf.Length);
                    text = Encoding.UTF8.GetString(buf, 0, n);
                }
                var names = new List<string>();
                for (int i = 0; i < ScriptPatterns.Length; i++) if (ScriptPatterns[i].IsMatch(text)) names.Add(ScriptNames[i]);
                hits = names.Count;
                return names.Count == 0 ? null : string.Join(", ", names.Take(4));
            }
            catch { return null; }
        }

        static readonly HashSet<string> Runnable = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".lnk", ".msi", ".dll" };

        /// <summary>Looks inside a zip (or an Office file): suspicious names, compression bombs, programs hidden inside. Returns a reason and a severity (1 suspicious, 2 malware).</summary>
        public static string ArchiveCheck(Engine eng, string path, out int severity)
        {
            severity = 0;
            string ext = Path.GetExtension(path).ToLowerInvariant();
            bool zip = ext == ".zip", office = ext == ".docx" || ext == ".xlsx" || ext == ".pptx";
            if (!zip && !office) return null;
            string temp = null;
            try
            {
                using (var za = ZipFile.OpenRead(path))
                {
                    long total = 0; int count = 0, extracted = 0; var why = new List<string>(); int encrypted = 0;
                    foreach (var e in za.Entries)
                    {
                        if (++count > 500) break;
                        total += e.Length;
                        string name = e.FullName;
                        if (office) { if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) { severity = Math.Max(severity, 1); why.Add("an Office file with a hidden macro but a macro-free extension"); } continue; }
                        if (name.IndexOf((char)0x202E) >= 0) { severity = Math.Max(severity, 1); why.Add("a file name that hides its real type"); }
                        if (Regex.IsMatch(name, @"\.(pdf|docx?|xlsx?|jpe?g|png|txt|mp3|mp4)\s*\.(exe|scr|js|vbs|bat|cmd|hta|lnk)$", RegexOptions.IgnoreCase)) { severity = Math.Max(severity, 1); why.Add("\"" + Path.GetFileName(name) + "\" pretends to be a document"); }
                        string ee = Path.GetExtension(name);
                        if (Runnable.Contains(ee) && e.Length > 0 && e.Length <= 20L * 1024 * 1024 && extracted < 20)
                        {
                            extracted++;
                            if (temp == null) { temp = Path.Combine(Path.GetTempPath(), "tg-deep-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp); }
                            string tf = Path.Combine(temp, extracted + ee);
                            try
                            {
                                e.ExtractToFile(tf, true);
                                string sha;
                                using (var fs = File.OpenRead(tf)) using (var h = SHA256.Create()) sha = BitConverter.ToString(h.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
                                if (eng.IsBlockedHash(sha)) { severity = 2; why.Add("\"" + Path.GetFileName(name) + "\" inside it is on your block list"); }
                                else if (eng.Yara.Ready)
                                {
                                    var y = eng.Yara.Scan(tf);
                                    if (y != null) { severity = Math.Max(severity, y.Score >= 80 ? 2 : 1); why.Add("\"" + Path.GetFileName(name) + "\" inside it matches YARA rule " + y.Rule); }
                                }
                            }
                            catch (InvalidDataException) { encrypted++; }
                            catch { }
                        }
                    }
                    if (total > 2L * 1024 * 1024 * 1024 || (new FileInfo(path).Length > 0 && total / Math.Max(1, new FileInfo(path).Length) > 1000 && total > 500L * 1024 * 1024)) { severity = Math.Max(severity, 1); why.Add("expands to " + total / 1048576 + " MB (a compression bomb?)"); }
                    if (encrypted > 0) why.Add(encrypted + " protected file(s) inside couldn't be opened");
                    return why.Count == 0 ? null : string.Join("; ", why.Take(3));
                }
            }
            catch { return null; }
            finally { if (temp != null) try { Directory.Delete(temp, true); } catch { } }
        }
    }

    /// <summary>
    /// Slowly examines every file with extra checks while the PC is idle. It runs at background priority (low CPU and disk),
    /// pauses the moment the user is back, and rests between files so the processor never races.
    /// </summary>
    class DeepScanner
    {
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll")] static extern bool SetThreadPriority(IntPtr h, int p);
        [DllImport("kernel32.dll")] static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

        readonly Engine eng;
        Thread worker;
        volatile bool active, stop;
        readonly Queue<string> queue = new Queue<string>();
        long lastIdle, lastKernel, lastUser;
        public int Total, Done, Flagged, CpuLimit = 40;
        public string Current = "", Phase = "Waiting";
        public DateTime Started = DateTime.MinValue, Finished = DateTime.MinValue;
        public bool Active { get { return active; } }

        public DeepScanner(Engine e) { eng = e; }

        public void SetActive(bool on)
        {
            if (on && !active) { Finished = DateTime.MinValue; if (Phase.StartsWith("Every")) Phase = "Starting"; }
            active = on;
            if (on && Started == DateTime.MinValue) Started = DateTime.Now;
            if (on) Start();
        }

        public void Start()
        {
            if (worker != null) return;
            worker = new Thread(Run) { IsBackground = true, Name = "Visually Safe deep scan", Priority = ThreadPriority.Lowest };
            worker.Start();
        }

        public void Stop() { stop = true; active = false; }

        int CpuPercent()
        {
            long i, k, u;
            if (!GetSystemTimes(out i, out k, out u)) return 0;
            long di = i - lastIdle, dk = k - lastKernel, du = u - lastUser;
            lastIdle = i; lastKernel = k; lastUser = u;
            long total = dk + du;
            return total <= 0 ? 0 : (int)(100 - di * 100 / total);
        }

        bool Rest(int ms)
        {
            // sleep in small slices so the scan stops the moment the user returns
            for (int t = 0; t < ms && active && !stop; t += 100) Thread.Sleep(100);
            return active && !stop;
        }

        void Run()
        {
            try { SetThreadPriority(GetCurrentThread(), 0x00010000); } catch { }   // THREAD_MODE_BACKGROUND_BEGIN: low CPU *and* disk priority
            CpuPercent();
            while (!stop)
            {
                if (!active) { Thread.Sleep(400); continue; }
                if (eng.ScanActive) { Thread.Sleep(1000); continue; }            // a manual scan has the machine: wait
                if (queue.Count == 0)
                {
                    Phase = "Listing files…";
                    try { BuildQueue(); } catch { }
                    if (queue.Count == 0) { Phase = "Every file has had a deep scan"; Current = ""; Finished = DateTime.Now; Thread.Sleep(3000); continue; }
                    Phase = "Deep scanning";
                }
                string path = queue.Dequeue();
                Current = path;
                var sw = Stopwatch.StartNew();
                try { DeepOne(path); } catch { }
                Done++;
                // never rush: rest three times as long as the work took, and wait out any other busy period
                if (!Rest((int)Math.Max(250, sw.ElapsedMilliseconds * 3))) continue;
                int guard = 0;
                while (active && !stop && CpuPercent() > CpuLimit && guard++ < 30) Thread.Sleep(1000);
            }
        }

        static int Priority(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (Engine.LooksScannable(path) && ext != ".zip" && ext != ".iso" && ext != ".img") return 0;
            if (ext == ".zip" || ext == ".docx" || ext == ".xlsx" || ext == ".pptx" || ext == ".pdf" || ext == ".jar" || ext == ".iso") return 1;
            return 2;
        }

        void BuildQueue()
        {
            var files = new List<string>(); int cap = 60000;
            foreach (string root in eng.S.Folders.Where(Directory.Exists))
                foreach (string f in Engine.SafeEnumerate(root))
                {
                    if (stop || !active) return;
                    if (files.Count >= cap) break;
                    var e = eng.LedgerGet(f);
                    DateTime mt = DateTime.MinValue;
                    try { mt = File.GetLastWriteTime(f); } catch { }
                    if (e != null && e.Deep && mt <= e.Time.AddSeconds(2)) continue;
                    files.Add(f);
                }
            foreach (var kv in eng.LedgerSnapshot())
                if (!kv.Value.Deep && !kv.Value.Quarantined && !kv.Value.Deleted && File.Exists(kv.Key) && !files.Contains(kv.Key, StringComparer.OrdinalIgnoreCase)) files.Add(kv.Key);
            foreach (string f in files.OrderBy(Priority).ThenBy(f => f, StringComparer.OrdinalIgnoreCase)) queue.Enqueue(f);
            Total += queue.Count;
        }

        void DeepOne(string path)
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return;
            if (eng.IsIgnored(path)) { eng.CommitDeepEntry(path, Verdict.Clean, "Ignored by you"); return; }
            if (fi.Length == 0) { eng.CommitDeepEntry(path, Verdict.Clean, "Empty file"); return; }
            if (fi.Length > 400L * 1024 * 1024) { eng.CommitDeepEntry(path, Verdict.Clean, "Too large for a deep scan, skipped"); return; }
            bool isPe; double entropy;
            var rec = eng.ExamineFile(path, out isPe, out entropy);
            if (rec == null) { eng.CommitDeepEntry(path, Verdict.Unknown, "Couldn't be read (in use?)"); return; }

            Verdict v = rec.Verdict; var notes = new List<string>();
            Action<Verdict, string> raise = (nv, why) => { if (nv > v) v = nv; notes.Add(why); };
            bool signed = rec.Detail.StartsWith("Signed by") || rec.Detail.StartsWith("Windows (catalog");

            bool prog; string streams = DeepChecks.HiddenStreams(path, out prog);
            if (streams != null) raise(prog ? Verdict.Suspicious : v, "hidden data stream " + streams + (prog ? " containing a program" : ""));

            if (eng.Yara.Ready && fi.Length <= 200L * 1024 * 1024)
            {
                var y = eng.Yara.Scan(path);
                if (y != null) raise(y.Score >= 80 ? Verdict.Malicious : Verdict.Suspicious, "YARA rule " + y.Rule + (y.Description.Length > 0 ? " (" + y.Description + ")" : ""));
            }

            if (isPe)
            {
                if (eng.Ai != null)
                {
                    double ai = eng.Ai.Score(path);
                    if (ai >= (signed ? 0.97 : 0.9)) raise(Verdict.Suspicious, "AI: " + (int)Math.Round(ai * 100) + "% malware-like");
                }
                int pts; string pe = DeepChecks.PeCheck(path, out pts);
                if (pe != null && pts >= 4 && !signed) raise(Verdict.Suspicious, "program structure: " + pe);
            }

            int hits; string sc = DeepChecks.ScriptCheck(path, out hits);
            if (sc != null && hits >= 2) raise(Verdict.Suspicious, "script does: " + sc);

            int sev; string ar = DeepChecks.ArchiveCheck(eng, path, out sev);
            if (ar != null && sev > 0) raise(sev >= 2 ? Verdict.Malicious : Verdict.Suspicious, ar);

            if (v > rec.Verdict && notes.Count > 0)
            {
                rec.Verdict = v;
                rec.Detail = "Deep scan: " + string.Join("; ", notes) + (rec.Detail.Length > 0 ? " · " + rec.Detail : "");
                Flagged++;
            }
            eng.CommitDeep(rec);
        }
    }
}
