using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace VisuallySafe
{
    class ShieldEvent { public DateTime Time; public string Text = ""; public bool Severe; public override string ToString() { return Time.ToString("MMM d  h:mm tt") + "   " + Text; } }

    /// <summary>
    /// The extra shields: ransomware watch, web blocklist, malware hash feed and self-protection.
    /// </summary>
    class Shields : IDisposable
    {
        readonly Engine eng;
        public readonly RansomShield Ransom;
        public readonly WebShield Web;
        public readonly SelfGuard Guard;
        readonly List<ShieldEvent> events = new List<ShieldEvent>();
        readonly object gate = new object();
        /// <summary>title, text, severe</summary>
        public event Action<string, string, bool> Alert;
        DateTime lastFeed = DateTime.MinValue;
        volatile bool updating;
        public string FeedStatus = "";

        public Shields(Engine e)
        {
            eng = e;
            Ransom = new RansomShield(this, e);
            Web = new WebShield(this, e);
            Guard = new SelfGuard(this, e);
        }

        public string DataDir { get { return eng.DataDir; } }

        public List<ShieldEvent> Events() { lock (gate) { var l = events.ToList(); l.Reverse(); return l; } }

        public void Log(string text, bool severe)
        {
            lock (gate) { events.Add(new ShieldEvent { Time = DateTime.Now, Text = text, Severe = severe }); if (events.Count > 200) events.RemoveAt(0); }
            try { File.AppendAllText(Path.Combine(eng.DataDir, "shield-events.log"), DateTime.Now.ToString("s") + (severe ? " [ALERT] " : " ") + text.Replace('\r', ' ').Replace('\n', ' ') + Environment.NewLine); } catch { }
        }

        public void Raise(string title, string text, bool severe)
        {
            Log(title + ": " + text, severe);
            var h = Alert; if (h != null) try { h(title, text, severe); } catch { }
        }

        public void Start()
        {
            try { Guard.Start(); } catch (Exception ex) { Log("Self-protection didn't start: " + ex.Message, false); }
            try { if (eng.S.RansomShield) Ransom.Start(null); } catch (Exception ex) { Log("Ransomware shield didn't start: " + ex.Message, false); }
        }

        /// <summary>Called every couple of seconds from the main window: starts the daily feed updates.</summary>
        public void Tick()
        {
            if (updating || !eng.S.Cloud) return;
            if ((DateTime.Now - lastFeed).TotalMinutes < 30) return;
            lastFeed = DateTime.Now;
            bool webDue = eng.S.WebShield && Admin.IsAdmin && (DateTime.Now - new DateTime(Math.Max(0, eng.S.WebChecked))).TotalHours >= 24;
            bool hashDue = eng.S.MbKey.Length > 0 && (DateTime.Now - new DateTime(Math.Max(0, eng.S.FeedChecked))).TotalHours >= 12;
            if (webDue || hashDue) UpdateFeeds(webDue, hashDue);
        }

        public void UpdateFeeds(bool web, bool hashes)
        {
            if (updating) return;
            updating = true;
            Task.Run(() =>
            {
                try
                {
                    if (web)
                    {
                        string err = Web.Update();
                        if (err == null) { eng.S.WebChecked = DateTime.Now.Ticks; eng.S.Save(); }
                    }
                    if (hashes)
                    {
                        string err = HashFeed.Update(eng, out int added);
                        FeedStatus = err ?? (added + " new malware fingerprints added " + DateTime.Now.ToString("h:mm tt"));
                        if (err == null) { eng.S.FeedChecked = DateTime.Now.Ticks; eng.S.Save(); }
                        Log("Malware list: " + FeedStatus, false);
                    }
                }
                catch (Exception ex) { Log("Feed update failed: " + ex.Message, false); }
                finally { updating = false; }
            });
        }

        public bool Updating { get { return updating; } }

        public void Dispose()
        {
            try { Ransom.Dispose(); } catch { }
            try { Guard.Dispose(); } catch { }
        }
    }

    // ================================================================================================================
    //  Ransomware shield
    // ================================================================================================================

    /// <summary>
    /// Watches your own folders (Documents, Pictures, Desktop, Videos, Music). Two things set it off: a hidden "canary" file in each folder that
    /// nothing should ever touch is changed, renamed or deleted, or many files change into something that looks encrypted within seconds.
    /// It then works out which program is writing the most data and (if you allow it) stops it, cuts its internet and quarantines it.
    /// </summary>
    class RansomShield : IDisposable
    {
        readonly Shields sh; readonly Engine eng;
        readonly List<FileSystemWatcher> ws = new List<FileSystemWatcher>();
        readonly Dictionary<string, string> canaries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // path -> expected text
        readonly List<Tuple<DateTime, string, int>> hits = new List<Tuple<DateTime, string, int>>();
        readonly BlockingCollection<string> checkQueue = new BlockingCollection<string>(new ConcurrentQueue<string>(), 3000);
        readonly Dictionary<string, DateTime> lastChecked = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        readonly object gate = new object();
        Thread worker; volatile bool stop;
        DateTime cooldown = DateTime.MinValue;
        public List<string> Folders = new List<string>();
        public int Triggers; public DateTime LastTrigger = DateTime.MinValue;
        public bool Running { get; private set; }
        public int CanaryCount { get { lock (gate) return canaries.Count; } }
        /// <summary>Overrides the automatic "stop the program" step (used by the safe test).</summary>
        public bool DryRun;

        public RansomShield(Shields s, Engine e) { sh = s; eng = e; }

        const string CanaryName = "!~visuallysafe-canary.docx";
        static readonly string[] Skip = { ".git", "node_modules", "bin", "obj", ".godot", ".import", "__pycache__", ".vs", "appdata", "library", "build", "dist", "cache", "temp", "tmp", ".gradle", "target" };
        static readonly HashSet<string> UserExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".odt", ".ods", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".zip", ".rar", ".7z", ".csv", ".sql", ".db", ".sqlite", ".psd", ".blend", ".glb", ".fbx", ".wav", ".flac", ".md", ".json", ".xml", ".html" };
        static readonly HashSet<string> BenignNew = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".tmp", ".bak", ".old", ".crdownload", ".part", ".partial", ".download", ".temp", ".backup", ".orig", ".lnk", ".blend1", ".blend2", ".new", ".swp", ".zip", ".rar", ".7z", ".txt", ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".png" };
        static readonly HashSet<string> TextExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt", ".csv", ".log", ".md", ".ini", ".json", ".xml", ".html", ".cs", ".py", ".js", ".sql", ".rtf" };
        static readonly Dictionary<string, byte[][]> Magic = new Dictionary<string, byte[][]>(StringComparer.OrdinalIgnoreCase)
        {
            { ".jpg", new[] { new byte[] { 0xFF, 0xD8, 0xFF } } }, { ".jpeg", new[] { new byte[] { 0xFF, 0xD8, 0xFF } } },
            { ".png", new[] { new byte[] { 0x89, 0x50, 0x4E, 0x47 } } }, { ".gif", new[] { Encoding.ASCII.GetBytes("GIF8") } },
            { ".pdf", new[] { Encoding.ASCII.GetBytes("%PDF") } }, { ".bmp", new[] { Encoding.ASCII.GetBytes("BM") } },
            { ".zip", new[] { Encoding.ASCII.GetBytes("PK") } }, { ".docx", new[] { Encoding.ASCII.GetBytes("PK") } }, { ".xlsx", new[] { Encoding.ASCII.GetBytes("PK") } },
            { ".pptx", new[] { Encoding.ASCII.GetBytes("PK") } }, { ".odt", new[] { Encoding.ASCII.GetBytes("PK") } },
            { ".rar", new[] { Encoding.ASCII.GetBytes("Rar!") } }, { ".7z", new[] { new byte[] { 0x37, 0x7A, 0xBC, 0xAF } } },
            { ".doc", new[] { new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } } }, { ".xls", new[] { new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } } }, { ".ppt", new[] { new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } } },
            { ".wav", new[] { Encoding.ASCII.GetBytes("RIFF") } }, { ".psd", new[] { Encoding.ASCII.GetBytes("8BPS") } },
            { ".sqlite", new[] { Encoding.ASCII.GetBytes("SQLite format 3") } },
            { ".blend", new[] { Encoding.ASCII.GetBytes("BLENDER"), new byte[] { 0x28, 0xB5, 0x2F, 0xFD }, new byte[] { 0x1F, 0x8B } } },
            { ".glb", new[] { Encoding.ASCII.GetBytes("glTF") } },
            { ".mp3", new[] { Encoding.ASCII.GetBytes("ID3"), new byte[] { 0xFF, 0xFB }, new byte[] { 0xFF, 0xF3 }, new byte[] { 0xFF, 0xF2 } } },
        };

        public static List<string> DefaultFolders()
        {
            var l = new List<string>();
            foreach (var f in new[] { Environment.SpecialFolder.MyDocuments, Environment.SpecialFolder.MyPictures, Environment.SpecialFolder.DesktopDirectory, Environment.SpecialFolder.MyVideos, Environment.SpecialFolder.MyMusic })
            {
                try { string p = Environment.GetFolderPath(f); if (!string.IsNullOrEmpty(p) && Directory.Exists(p) && !l.Contains(p, StringComparer.OrdinalIgnoreCase)) l.Add(p); } catch { }
            }
            return l;
        }

        public void Start(IEnumerable<string> folders)
        {
            Stop();
            Folders = (folders ?? DefaultFolders()).Where(Directory.Exists).ToList();
            stop = false;
            foreach (string dir in Folders)
            {
                MakeCanary(dir);
                try
                {
                    var w = new FileSystemWatcher(dir) { IncludeSubdirectories = true, InternalBufferSize = 64 * 1024, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size };
                    w.Created += (s, e) => OnCreatedOrChanged(e.FullPath);
                    w.Changed += (s, e) => OnCreatedOrChanged(e.FullPath);
                    w.Renamed += (s, e) => OnRenamed(e.OldFullPath, e.FullPath);
                    w.Deleted += (s, e) => OnDeleted(e.FullPath);
                    w.Error += (s, e) => { };
                    w.EnableRaisingEvents = true;
                    ws.Add(w);
                }
                catch { }
            }
            worker = new Thread(Work) { IsBackground = true, Name = "Visually Safe ransomware shield", Priority = ThreadPriority.BelowNormal };
            worker.Start();
            Running = ws.Count > 0;
            sh.Log("Ransomware shield is watching " + Folders.Count + " folder" + (Folders.Count == 1 ? "" : "s") + ".", false);
        }

        public void Stop()
        {
            Running = false; stop = true;
            foreach (var w in ws) { try { w.EnableRaisingEvents = false; w.Dispose(); } catch { } }
            ws.Clear();
            lock (gate) { canaries.Clear(); hits.Clear(); }
        }

        public void Dispose() { Stop(); }

        // ---- canary files

        static string CanaryText() { return "Visually Safe canary file. It sits here so Visually Safe can tell if ransomware starts changing your files. Please leave it alone.\r\n" + new string('x', 600); }

        void MakeCanary(string dir)
        {
            try
            {
                string old = Path.Combine(dir, "!~tinyguard-canary.docx");     // made before the rename
                if (File.Exists(old)) { File.SetAttributes(old, FileAttributes.Normal); File.Delete(old); }
                string p = Path.Combine(dir, CanaryName);
                string text = CanaryText();
                if (!File.Exists(p)) { File.WriteAllText(p, text); File.SetAttributes(p, FileAttributes.Hidden | FileAttributes.System); }
                lock (gate) canaries[p] = text;
            }
            catch { }
        }

        public void RemoveCanaries()
        {
            lock (gate) foreach (string p in canaries.Keys.ToList()) { try { File.SetAttributes(p, FileAttributes.Normal); File.Delete(p); } catch { } }
        }

        bool IsCanary(string path) { lock (gate) return canaries.ContainsKey(path); }

        // ---- events

        bool Excluded(string path)
        {
            if (path.StartsWith(eng.DataDir, StringComparison.OrdinalIgnoreCase)) return true;
            foreach (string safe in eng.S.SafeFolders) if (path.StartsWith(safe.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            string root = Folders.FirstOrDefault(f => path.StartsWith(f.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
            string rel = root == null ? path : path.Substring(root.TrimEnd('\\').Length);
            foreach (string seg in rel.Split('\\')) if (Array.IndexOf(Skip, seg.ToLowerInvariant()) >= 0) return true;
            return false;
        }

        void OnDeleted(string path) { if (IsCanary(path)) CanaryTouched(path, "deleted"); }

        void OnCreatedOrChanged(string path)
        {
            if (stop) return;
            if (IsCanary(path))
            {
                string expect; lock (gate) canaries.TryGetValue(path, out expect);
                try { if (File.ReadAllText(path) != expect) CanaryTouched(path, "changed"); } catch (FileNotFoundException) { } catch { }
                return;
            }
            if (Excluded(path)) return;
            string name = Path.GetFileName(path);
            if (LooksLikeNote(name)) { AddHit(path, 4); return; }
            if (!checkQueue.TryAdd(path)) { }
        }

        void OnRenamed(string oldPath, string newPath)
        {
            if (stop) return;
            if (IsCanary(oldPath)) { CanaryTouched(oldPath, "renamed"); return; }
            if (Excluded(newPath)) return;
            string oe = Path.GetExtension(oldPath), ne = Path.GetExtension(newPath);
            if (!UserExt.Contains(oe)) { OnCreatedOrChanged(newPath); return; }
            bool changed = !string.Equals(oe, ne, StringComparison.OrdinalIgnoreCase) && ne.Length > 0 && !BenignNew.Contains(ne) && !UserExt.Contains(ne);
            bool appended = Path.GetFileName(newPath).StartsWith(Path.GetFileName(oldPath) + ".", StringComparison.OrdinalIgnoreCase) && !BenignNew.Contains(ne);
            if (changed || appended) AddHit(newPath, 1);
            else OnCreatedOrChanged(newPath);
        }

        static bool LooksLikeNote(string name)
        {
            string n = name.ToLowerInvariant();
            if (!(n.EndsWith(".txt") || n.EndsWith(".html") || n.EndsWith(".hta") || n.EndsWith(".url") || n.EndsWith(".png"))) return false;
            return n.Contains("decrypt") || n.Contains("ransom") || n.Contains("restore_files") || n.Contains("restore-files") || n.Contains("recover_files") || n.Contains("recover-files") || n.Contains("how_to_recover") || n.Contains("your_files") || n.Contains("files_encrypted");
        }

        // ---- checking changed files for "looks encrypted"

        void Work()
        {
            foreach (string path in checkQueue.GetConsumingEnumerable())
            {
                if (stop) break;
                try
                {
                    DateTime t;
                    lock (lastChecked) { if (lastChecked.TryGetValue(path, out t) && (DateTime.Now - t).TotalSeconds < 4) continue; lastChecked[path] = DateTime.Now; if (lastChecked.Count > 4000) lastChecked.Clear(); }
                    Thread.Sleep(150);
                    if (LooksEncrypted(path)) AddHit(path, 1);
                }
                catch { }
            }
        }

        /// <summary>True if the file's name says it should be a document, picture, etc. but its contents are random-looking noise.</summary>
        public static bool LooksEncrypted(string path)
        {
            string ext = Path.GetExtension(path);
            byte[][] heads; bool isText = TextExt.Contains(ext);
            bool known = Magic.TryGetValue(ext, out heads);
            if (!known && !isText) return false;
            byte[] buf;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length < 512) return false;
                    buf = new byte[(int)Math.Min(fs.Length, 65536)];
                    int n = 0, r; while (n < buf.Length && (r = fs.Read(buf, n, buf.Length - n)) > 0) n += r;
                    if (n < 512) return false;
                    if (n < buf.Length) Array.Resize(ref buf, n);
                }
            }
            catch { return false; }
            if (known && heads.Any(h => buf.Length >= h.Length && h.Select((b, i) => buf[i] == b).All(x => x))) return false;   // still starts like the real thing
            double ent = Entropy(buf);
            return ent > (isText && !known ? 7.2 : 7.4);
        }

        public static double Entropy(byte[] b)
        {
            var c = new int[256]; foreach (byte x in b) c[x]++;
            double e = 0; foreach (int k in c) if (k > 0) { double p = (double)k / b.Length; e -= p * Math.Log(p, 2); }
            return e;
        }

        // ---- deciding

        void CanaryTouched(string path, string what)
        {
            sh.Log("The ransomware canary file " + path + " was " + what + ".", true);
            AddHit(path, 8);
        }

        void AddHit(string path, int weight)
        {
            bool fire = false; int total = 0;
            lock (gate)
            {
                var now = DateTime.Now;
                hits.RemoveAll(h => (now - h.Item1).TotalSeconds > 20);
                if (!hits.Any(h => h.Item2.Equals(path, StringComparison.OrdinalIgnoreCase) && h.Item3 >= weight)) hits.Add(Tuple.Create(now, path, weight));
                total = hits.GroupBy(h => h.Item2, StringComparer.OrdinalIgnoreCase).Sum(g => g.Max(h => h.Item3));
                if (total >= 8 && now >= cooldown) { cooldown = now.AddMinutes(3); fire = true; hits.Clear(); }
            }
            if (fire) Task.Run(() => Respond(total));
        }

        // ---- reacting

        [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern bool GetProcessIoCounters(IntPtr h, out IoCounters c);
        [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }

        static Dictionary<int, ulong> WriteSample()
        {
            var d = new Dictionary<int, ulong>();
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    IntPtr h = OpenProcess(0x1000, false, p.Id);
                    if (h == IntPtr.Zero) continue;
                    try { IoCounters c; if (GetProcessIoCounters(h, out c)) d[p.Id] = c.WriteBytes; } finally { CloseHandle(h); }
                }
                catch { }
                finally { p.Dispose(); }
            }
            return d;
        }

        /// <summary>The programs writing the most data right now that aren't Windows or a trusted publisher.</summary>
        List<KeyValuePair<int, string>> Suspects()
        {
            var a = WriteSample(); Thread.Sleep(1500); var b = WriteSample();
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            int me = Process.GetCurrentProcess().Id;
            var res = new List<KeyValuePair<int, string>>();
            foreach (var kv in b.OrderByDescending(x => { ulong o; return a.TryGetValue(x.Key, out o) && x.Value >= o ? x.Value - o : 0; }).Take(8))
            {
                ulong o; if (!a.TryGetValue(kv.Key, out o) || kv.Value < o + 512 * 1024) continue;   // under half a megabyte in 1.5 s: not busy enough
                if (kv.Key <= 4 || kv.Key == me) continue;
                string path = ProcWatch.PathOf(kv.Key);
                if (string.IsNullOrEmpty(path) || path.StartsWith(win, StringComparison.OrdinalIgnoreCase)) continue;
                try { if (Trust.TrustedSigner(path) != null) continue; } catch { }
                res.Add(new KeyValuePair<int, string>(kv.Key, path));
                if (res.Count >= 3) break;
            }
            return res;
        }

        void Respond(int score)
        {
            Triggers++; LastTrigger = DateTime.Now;
            List<KeyValuePair<int, string>> suspects;
            try { suspects = Suspects(); } catch { suspects = new List<KeyValuePair<int, string>>(); }
            var done = new List<string>();
            if (suspects.Count > 0 && eng.S.RansomAutoStop && !DryRun)
            {
                foreach (var s in suspects)
                {
                    string line = Path.GetFileName(s.Value);
                    if (ProcWatch.Kill(s.Key, s.Value)) line += " stopped"; else line += " could not be stopped";
                    try { if (Admin.IsAdmin && Firewall.Block(s.Value) == null) line += ", internet cut"; } catch { }
                    string err; try { if (eng.QuarantinePath(s.Value, "Looked like ransomware (it was changing many of your files into scrambled data)", out err)) line += ", quarantined"; } catch { }
                    done.Add(line);
                }
                sh.Raise("Ransomware stopped", "Many of your files started turning into scrambled data. Visually Safe did this: " + string.Join("; ", done) + ". Check your Documents folder and restore anything damaged from a backup.", true);
            }
            else if (suspects.Count > 0)
                sh.Raise("Ransomware warning", "Many of your files are being scrambled" + (DryRun ? " (this is only the test)" : "") + ". Busiest programs: " + string.Join(", ", suspects.Select(x => Path.GetFileName(x.Value))) + ".", true);
            else
                sh.Raise("Ransomware warning", "Many of your files are being scrambled" + (DryRun ? " (this is only the test)" : "") + ", but Visually Safe couldn't tell which program is doing it. If you didn't start this, disconnect the network and shut the PC down.", true);
        }

        /// <summary>A safe test: makes a throw-away folder, scrambles a few dozen made-up files in it the way ransomware would, and reports what the shield did.</summary>
        public static string SelfTest(Shields sh, Engine eng)
        {
            string tmp = Path.Combine(Path.GetTempPath(), "tg-ransom-" + Guid.NewGuid().ToString("N").Substring(0, 6));
            Directory.CreateDirectory(tmp);
            var shield = new RansomShield(sh, eng) { DryRun = true };
            int before = shield.Triggers;
            try
            {
                shield.Start(new[] { tmp });
                var rnd = new Random();
                var files = new List<string>();
                for (int i = 0; i < 24; i++)
                {
                    string f = Path.Combine(tmp, "report" + i + ".txt");
                    File.WriteAllText(f, string.Join(" ", Enumerable.Range(0, 400).Select(x => "word" + x)));
                    files.Add(f);
                }
                Thread.Sleep(600);
                foreach (string f in files)
                {
                    var junk = new byte[4096]; rnd.NextBytes(junk);
                    File.WriteAllBytes(f, junk);
                    Thread.Sleep(30);
                }
                for (int i = 0; i < 40 && shield.Triggers == before; i++) Thread.Sleep(250);
                return shield.Triggers > before ? "PASS: the shield noticed the made-up ransomware" : "FAIL: nothing was noticed";
            }
            finally { shield.Stop(); shield.RemoveCanaries(); try { Directory.Delete(tmp, true); } catch { } }
        }
    }

    // ================================================================================================================
    //  Web blocklist
    // ================================================================================================================

    /// <summary>
    /// Blocks known malware and phishing websites for every program on the PC by pointing their names at 0.0.0.0 in the Windows hosts file.
    /// The lists come from free public feeds. Visually Safe only touches the part of the hosts file between its own two marker lines, and keeps a backup.
    /// </summary>
    class WebShield
    {
        readonly Shields sh; readonly Engine eng;
        public const string Begin = "# BEGIN Visually Safe web shield (do not edit between these lines)", End = "# END Visually Safe web shield";
        public static string HostsPath { get { return Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts"); } }
        public string Status = "";
        const int MaxDomains = 40000;
        static readonly string[][] Sources =
        {
            new[] { "URLhaus malware sites", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt" },
            new[] { "Phishing Army phishing sites", "https://phishing.army/download/phishing_army_blocklist.txt" },
        };
        // never block these, whatever a list says
        static readonly string[] Never = { "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "google.com", "googleapis.com", "gstatic.com", "github.com", "githubusercontent.com", "anthropic.com", "claude.ai", "openai.com", "cloudflare.com", "apple.com", "mozilla.org", "localhost" };
        static readonly Regex DomainRx = new Regex(@"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$", RegexOptions.Compiled);

        public WebShield(Shields s, Engine e) { sh = s; eng = e; }

        string CacheFile { get { return Path.Combine(eng.DataDir, "web-blocklist.txt"); } }
        string CustomFile { get { return Path.Combine(eng.DataDir, "web-custom.txt"); } }
        string AllowFile { get { return Path.Combine(eng.DataDir, "web-allow.txt"); } }
        HashSet<string> cache;

        public static bool IsNever(string d) { return Never.Any(n => d == n || d.EndsWith("." + n)); }

        public static bool ValidDomain(string d)
        {
            if (d == null || d.Length > 253 || !DomainRx.IsMatch(d)) return false;
            string last = d.Substring(d.LastIndexOf('.') + 1);
            return last.Any(char.IsLetter);   // not an IP address
        }

        /// <summary>Pulls the domain names out of a hosts-style or plain list.</summary>
        public static List<string> ParseList(string text)
        {
            var res = new List<string>();
            foreach (string raw in text.Split('\n'))
            {
                string l = raw.Trim(); int c = l.IndexOf('#'); if (c >= 0) l = l.Substring(0, c).Trim();
                if (l.Length == 0) continue;
                var parts = l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                string d = (parts.Length >= 2 ? parts[1] : parts[0]).ToLowerInvariant().TrimEnd('.');
                if (ValidDomain(d) && !IsNever(d)) res.Add(d);
            }
            return res;
        }

        List<string> ReadLines(string file) { try { return File.ReadAllLines(file).Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0 && !x.StartsWith("#")).ToList(); } catch { return new List<string>(); } }
        public List<string> Custom() { return ReadLines(CustomFile); }
        public List<string> Allowed() { return ReadLines(AllowFile); }
        public void AddCustom(string d) { Append(CustomFile, d); }
        public void AddAllow(string d) { Append(AllowFile, d); }
        void Append(string file, string d) { d = (d ?? "").Trim().ToLowerInvariant(); if (!ValidDomain(d)) return; var l = ReadLines(file); if (!l.Contains(d)) { l.Add(d); try { File.WriteAllLines(file, l); } catch { } } }

        static string Download(string url)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = 30000; req.ReadWriteTimeout = 30000; req.UserAgent = "Visually Safe";
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var st = resp.GetResponseStream())
            using (var ms = new MemoryStream())
            {
                var buf = new byte[1 << 16]; int n;
                while ((n = st.Read(buf, 0, buf.Length)) > 0) { ms.Write(buf, 0, n); if (ms.Length > 20 * 1024 * 1024) throw new IOException("list too big"); }
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        /// <summary>Downloads the lists and writes the block into the hosts file. Returns an error message, or null.</summary>
        public string Update()
        {
            if (!Admin.IsAdmin) { Status = "Needs administrator rights"; return Status; }
            var all = new List<string>();
            int ok = 0; string lastErr = null;
            foreach (var src in Sources)
            {
                try { var l = ParseList(Download(src[1])); all.AddRange(l); ok++; sh.Log(src[0] + ": " + l.Count + " sites", false); }
                catch (Exception ex) { lastErr = src[0] + ": " + ex.Message; sh.Log("Couldn't get " + lastErr, false); }
            }
            if (ok == 0) { Status = "Couldn't download the lists (" + lastErr + ")"; return Status; }
            return Apply(all);
        }

        /// <summary>Writes the given domains (plus your custom ones, minus your allowed ones) into the hosts file.</summary>
        public string Apply(IEnumerable<string> fromLists)
        {
            // your own list first, then the lists in the order they were downloaded (malware sites before phishing sites), up to the cap
            var seen = new HashSet<string>(); var list = new List<string>();
            var allow = new HashSet<string>(Allowed());
            foreach (string d in Custom().Concat(fromLists))
                if (ValidDomain(d) && !allow.Contains(d) && seen.Add(d)) { list.Add(d); if (list.Count >= MaxDomains) break; }
            try { File.WriteAllLines(CacheFile, list); } catch { }
            cache = null;
            string err = WriteHosts(list);
            if (err != null) { Status = err; return err; }
            Status = list.Count.ToString("N0") + " sites blocked · updated " + DateTime.Now.ToString("MMM d h:mm tt");
            sh.Log("Web blocklist: " + Status, false);
            return null;
        }

        static string StripBlock(string text)
        {
            int a = text.IndexOf(Begin, StringComparison.Ordinal);
            if (a < 0) return text;
            int b = text.IndexOf(End, a, StringComparison.Ordinal);
            if (b < 0) return text.Substring(0, a).TrimEnd() + Environment.NewLine;   // damaged block: drop the rest of what we wrote
            return (text.Substring(0, a).TrimEnd() + Environment.NewLine + text.Substring(b + End.Length).TrimStart('\r', '\n')).TrimEnd() + Environment.NewLine;
        }

        string WriteHosts(List<string> domains)
        {
            try
            {
                string path = HostsPath, text = File.Exists(path) ? File.ReadAllText(path) : "";
                string bak = Path.Combine(eng.DataDir, "hosts.original.bak");
                if (!File.Exists(bak) && text.Length > 0) File.WriteAllText(bak, StripBlock(text));
                string clean = StripBlock(text);
                var sb = new StringBuilder(clean.TrimEnd() + Environment.NewLine + Environment.NewLine);
                if (domains != null && domains.Count > 0)
                {
                    sb.AppendLine(Begin);
                    foreach (string d in domains) sb.Append("0.0.0.0 ").AppendLine(d);
                    sb.AppendLine(End);
                }
                if (File.Exists(path)) { var at = File.GetAttributes(path); if ((at & FileAttributes.ReadOnly) != 0) File.SetAttributes(path, at & ~FileAttributes.ReadOnly); }
                File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
                Flush();
                return null;
            }
            catch (Exception ex) { return "Couldn't write the hosts file: " + ex.Message; }
        }

        static void Flush()
        {
            try { using (var p = Process.Start(new ProcessStartInfo("ipconfig.exe", "/flushdns") { CreateNoWindow = true, UseShellExecute = false })) p.WaitForExit(8000); } catch { }
        }

        public string Remove()
        {
            string err = WriteHosts(null);
            if (err == null) Status = "Off";
            return err;
        }

        /// <summary>How many sites are in the hosts file right now (0 if the block isn't there).</summary>
        public int Installed()
        {
            try
            {
                string text = File.ReadAllText(HostsPath);
                int a = text.IndexOf(Begin, StringComparison.Ordinal); if (a < 0) return 0;
                int b = text.IndexOf(End, a, StringComparison.Ordinal); if (b < 0) return 0;
                return text.Substring(a, b - a).Split('\n').Count(l => l.StartsWith("0.0.0.0 "));
            }
            catch { return 0; }
        }

        public string Reapply() { return Apply(ReadLines(CacheFile)); }

        public bool IsBlocked(string domain)
        {
            domain = (domain ?? "").Trim().ToLowerInvariant();
            if (cache == null) cache = new HashSet<string>(ReadLines(CacheFile));
            return cache.Contains(domain) || Custom().Contains(domain);
        }
    }

    // ================================================================================================================
    //  Malware fingerprint feed
    // ================================================================================================================

    static class HashFeed
    {
        /// <summary>Pulls the newest malware fingerprints from abuse.ch MalwareBazaar (needs the user's free key) into the block list.</summary>
        public static string Update(Engine eng, out int added)
        {
            added = 0;
            if (eng.S.MbKey.Length == 0) return "Add your free abuse.ch key in Settings to switch this on";
            try
            {
                var req = (HttpWebRequest)WebRequest.Create("https://mb-api.abuse.ch/api/v1/");
                req.Method = "POST"; req.ContentType = "application/x-www-form-urlencoded"; req.Timeout = 30000; req.UserAgent = "Visually Safe";
                req.Headers.Add("Auth-Key", eng.S.MbKey);
                byte[] body = Encoding.ASCII.GetBytes("query=get_recent&selector=time");
                using (var st = req.GetRequestStream()) st.Write(body, 0, body.Length);
                string json;
                using (var resp = (HttpWebResponse)req.GetResponse()) using (var rd = new StreamReader(resp.GetResponseStream())) json = rd.ReadToEnd();
                return Apply(eng, json, out added);
            }
            catch (Exception ex) { return "Couldn't reach MalwareBazaar: " + ex.Message; }
        }

        public static string Apply(Engine eng, string json, out int added)
        {
            added = 0;
            var js = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };
            var root = js.DeserializeObject(json) as Dictionary<string, object>;
            if (root == null) return "Unexpected answer from MalwareBazaar";
            object status; if (root.TryGetValue("query_status", out status) && !"ok".Equals(status as string)) return "MalwareBazaar said: " + status;
            var hashes = new List<string>();
            var data = root.ContainsKey("data") ? root["data"] as System.Collections.IEnumerable : null;
            if (data != null)
                foreach (var item in data)
                {
                    var d = item as Dictionary<string, object>; object h;
                    if (d != null && d.TryGetValue("sha256_hash", out h) && h is string && ((string)h).Length == 64) hashes.Add(((string)h).ToLowerInvariant());
                }
            added = eng.AddBlockedHashes(hashes);
            return null;
        }
    }

    // ================================================================================================================
    //  Self-protection
    // ================================================================================================================

    /// <summary>Notices when Visually Safe's own program or settings are changed behind its back, and brings Visually Safe back if something kills it.</summary>
    class SelfGuard : IDisposable
    {
        readonly Shields sh; readonly Engine eng;
        FileSystemWatcher settingsWatch;
        string startupHash = "";
        System.Threading.Timer timer;
        public const string WatchdogTask = "VisuallySafe Watchdog";
        public SelfGuard(Shields s, Engine e) { sh = s; eng = e; }

        static string ExitFlag(string dataDir) { return Path.Combine(dataDir, "user-exit.flag"); }
        public static void MarkUserExit(string dataDir) { try { File.WriteAllText(ExitFlag(dataDir), DateTime.Now.ToString("s")); } catch { } }
        public static bool UserExited(string dataDir) { return File.Exists(ExitFlag(dataDir)); }

        public static string HashOfSelf()
        {
            try { using (var fs = File.OpenRead(Application.ExecutablePath)) using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant(); }
            catch { return ""; }
        }

        public void Start()
        {
            try { File.Delete(ExitFlag(eng.DataDir)); } catch { }
            if (!eng.S.SelfGuard)
            {
                if (Admin.IsAdmin) System.Threading.Tasks.Task.Run(() => { try { EnsureWatchdog(false); } catch { } });     // off by default: take away a watchdog task left by an earlier version
                return;
            }
            startupHash = HashOfSelf();
            CheckRecord();
            try
            {
                settingsWatch = new FileSystemWatcher(eng.DataDir, "settings.ini") { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size };
                settingsWatch.Changed += (s, e) => OnSettingsChanged();
                settingsWatch.EnableRaisingEvents = true;
            }
            catch { }
            timer = new System.Threading.Timer(_ => Periodic(), null, 10 * 60 * 1000, 10 * 60 * 1000);
            if (Admin.IsAdmin) EnsureWatchdog(true);
            ApplyProcessProtection(eng.S.ProtectProcess);
        }

        /// <summary>Remembers the program's fingerprint per version; the same version with a different fingerprint means the file was changed.</summary>
        void CheckRecord()
        {
            try
            {
                string f = Path.Combine(eng.DataDir, "self-check.txt");
                string rec = Engine.Version + "|" + startupHash;
                if (File.Exists(f))
                {
                    string[] old = File.ReadAllText(f).Trim().Split('|');
                    if (old.Length == 2 && old[0] == Engine.Version && old[1] != startupHash)
                        sh.Raise("Visually Safe's program changed", "Visually Safe's own program file is different from the one it started as last time, with the same version number. If you didn't update it yourself, something may have tampered with it.", true);
                }
                File.WriteAllText(f, rec);
            }
            catch { }
        }

        void Periodic()
        {
            try
            {
                string now = HashOfSelf();
                if (startupHash.Length > 0 && now.Length > 0 && now != startupHash)
                {
                    startupHash = now;
                    sh.Raise("Visually Safe's program changed", "The Visually Safe program file on disk was replaced while it was running. If you didn't just install an update, treat this as suspicious.", true);
                }
            }
            catch { }
        }

        void OnSettingsChanged()
        {
            try
            {
                if ((DateTime.UtcNow - Settings.LastSaved).TotalSeconds < 3) return;   // our own save
                Thread.Sleep(300);
                string line = File.ReadAllLines(Path.Combine(eng.DataDir, "settings.ini")).FirstOrDefault(l => l.StartsWith("enabled="));
                if (line != null && line != "enabled=" + (eng.S.Enabled ? "1" : "0"))
                {
                    eng.S.Save();
                    sh.Raise("Visually Safe's settings were changed", "Something edited Visually Safe's settings file to switch protection " + (line == "enabled=0" ? "off" : "on") + ". Visually Safe put its own setting back.", true);
                }
            }
            catch { }
        }

        // ---- come back if killed

        static int Schtasks(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("schtasks.exe", args) { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden };
                using (var p = Process.Start(psi)) { p.WaitForExit(15000); return p.ExitCode; }
            }
            catch { return -1; }
        }

        public static bool WatchdogExists() { return Schtasks("/query /tn \"" + WatchdogTask + "\"") == 0; }

        public void EnsureWatchdog(bool on)
        {
            if (!Admin.IsAdmin) return;
            if (on && !WatchdogExists())
                Schtasks("/create /tn \"" + WatchdogTask + "\" /tr \"\\\"" + Application.ExecutablePath + "\\\" --watchdog\" /sc minute /mo 2 /rl highest /f");
            else if (!on && WatchdogExists()) Schtasks("/delete /tn \"" + WatchdogTask + "\" /f");
        }

        /// <summary>What the scheduled task runs: start Visually Safe again if it isn't running and you didn't close it yourself.</summary>
        public static int WatchdogRun(string dataDir)
        {
            try
            {
                if (UserExited(dataDir)) return 0;
                if (!Settings.Load(dataDir).SelfGuard) return 0;
                int me = Process.GetCurrentProcess().Id;
                string name = Path.GetFileNameWithoutExtension(Application.ExecutablePath);
                if (Process.GetProcessesByName(name).Any(p => p.Id != me)) return 0;
                Process.Start(new ProcessStartInfo(Application.ExecutablePath) { UseShellExecute = true });
            }
            catch { }
            return 0;
        }

        // ---- optional: other programs can't end Visually Safe

        [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetKernelObjectSecurity(IntPtr handle, int info, byte[] sd);

        /// <summary>Stops ordinary programs from ending or injecting into Visually Safe. An administrator can still end it from Task Manager; "Exit" in the tray menu always works.</summary>
        public void ApplyProcessProtection(bool on)
        {
            try
            {
                var sd = new RawSecurityDescriptor("D:");
                var dacl = new RawAcl(2, 3);
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                const int All = 0x1FFFFF, Dangerous = 0x0001 | 0x0002 | 0x0008 | 0x0020 | 0x0200 | 0x0800;   // terminate, create thread, vm operation, vm write, set information, suspend/resume
                int idx = 0;
                if (on) dacl.InsertAce(idx++, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, Dangerous, everyone, false, null));
                dacl.InsertAce(idx++, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, All, system, false, null));
                dacl.InsertAce(idx++, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, All, everyone, false, null));
                sd.DiscretionaryAcl = dacl;
                var bytes = new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes, 0);
                SetKernelObjectSecurity(Process.GetCurrentProcess().Handle, 4, bytes);
            }
            catch { }
        }

        public void Dispose()
        {
            try { if (timer != null) timer.Dispose(); } catch { }
            try { if (settingsWatch != null) settingsWatch.Dispose(); } catch { }
        }
    }
}
