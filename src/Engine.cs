using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TinyGuard
{
    enum Verdict { Clean, KnownGood, Unknown, Suspicious, Malicious }

    class ScanRecord
    {
        public DateTime Time;
        public string FilePath = "";
        public string Sha256 = "";
        public Verdict Verdict;
        public string Detail = "";
        public bool Quarantined;
        public string Name { get { return Path.GetFileName(FilePath); } }
        public bool IsThreat { get { return Verdict >= Verdict.Suspicious; } }
    }

    class Job { public string Path = ""; public bool Manual, Scan, FolderDone; public int Pid; }

    /// <summary>What TinyGuard last concluded about one file (every file it has examined, not just the flagged ones).</summary>
    class LedgerEntry { public Verdict Verdict; public DateTime Time; public bool Quarantined, Deleted, Deep; public string Detail = ""; }

    class QuarantineItem
    {
        public string Id = "";
        public string OriginalPath = "";
        public string Sha256 = "";
        public DateTime Time;
        public string Reason = "";
        public string Name { get { return Path.GetFileName(OriginalPath); } }
    }

    class Settings
    {
        public bool Enabled = true, Cloud = true, AutoQuarantine = true;
        public string MbKey = "";
        public long RulesChecked;
        public bool ScreensaverIdle, SystemSaver, SaverDefrag = true, ScanGlow = true;
        public int ScreensaverMinutes = 5;
        public string PrevScr = "", PrevActive = "", PrevTimeout = "", SaverMode = "scan";
        public List<string> Folders = new List<string>();
        public List<string> SafeFolders = new List<string>();
        public bool FirstRun;
        public bool RansomShield = true, RansomAutoStop = true, WebShield, SelfGuard, ProtectProcess;
        public long WebChecked, FeedChecked;
        public long DefenderSeen;        // Windows' protection reports before this moment have already been told to the person
        public long LastAutoCheck;       // when the twice-a-week family-helper check last finished
        public long BadgeResetAt;        // scans from before this moment no longer show a badge (the reset scanned icons button)
        public bool UseDefender = true;   // ask Microsoft Defender for its verdict on files you scan that nobody else vouches for
        public int BadgeHours = 48;      // how long a "scanned" badge shows when the mouse is over an icon (0 = off, 100000 = never expires)
        public static DateTime LastSaved = DateTime.MinValue;
        string file;

        [DllImport("shell32.dll")]
        static extern int SHGetKnownFolderPath(ref Guid id, uint flags, IntPtr token, out IntPtr path);

        public static string Downloads()
        {
            try
            {
                Guid id = new Guid("374DE290-123F-4565-9164-39C4925E467B");
                if (SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out IntPtr p) == 0)
                {
                    string s = Marshal.PtrToStringUni(p);
                    Marshal.FreeCoTaskMem(p);
                    if (!string.IsNullOrEmpty(s)) return s;
                }
            }
            catch { }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }

        public static Settings Load(string dataDir)
        {
            var s = new Settings { file = Path.Combine(dataDir, "settings.ini") };
            if (!File.Exists(s.file))
            {
                s.FirstRun = true;
                s.Folders = new List<string>
                {
                    Downloads(),
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup)
                }.Where(Directory.Exists).ToList();
                return s;
            }
            foreach (string line in File.ReadAllLines(s.file))
            {
                int i = line.IndexOf('=');
                if (i < 1) continue;
                string k = line.Substring(0, i), v = line.Substring(i + 1);
                switch (k)
                {
                    case "enabled": s.Enabled = v == "1"; break;
                    case "cloud": s.Cloud = v == "1"; break;
                    case "autoQuarantine": s.AutoQuarantine = v == "1"; break;
                    case "mbKey": s.MbKey = Unprotect(v); break;
                    case "folders": s.Folders = Split(v); break;
                    case "safe": s.SafeFolders = Split(v); break;
                    case "rulesChecked": long.TryParse(v, out s.RulesChecked); break;
                    case "saverIdle": s.ScreensaverIdle = v == "1"; break;
                    case "saverMinutes": int.TryParse(v, out s.ScreensaverMinutes); if (s.ScreensaverMinutes < 1) s.ScreensaverMinutes = 5; break;
                    case "systemSaver": s.SystemSaver = v == "1"; break;
                    case "saverDefrag": s.SaverDefrag = v == "1"; break;
                    case "scanGlow": s.ScanGlow = v != "0"; break;
                    case "badgeReset": long.TryParse(v, out s.BadgeResetAt); break;
                    case "badgeHours": int.TryParse(v, out s.BadgeHours); if (s.BadgeHours < 0) s.BadgeHours = 48; break;
                    case "ransom": s.RansomShield = v != "0"; break;
                    case "ransomStop": s.RansomAutoStop = v != "0"; break;
                    case "webShield": s.WebShield = v == "1"; break;
                    case "selfGuard": s.SelfGuard = v == "1"; break;
                    case "defSeen": long.TryParse(v, out s.DefenderSeen); break;
                    case "lastAutoCheck": long.TryParse(v, out s.LastAutoCheck); break;
                    case "useDefender": s.UseDefender = v != "0"; break;
                    case "protectProc": s.ProtectProcess = v == "1"; break;
                    case "webChecked": long.TryParse(v, out s.WebChecked); break;
                    case "feedChecked": long.TryParse(v, out s.FeedChecked); break;
                    case "saverMode": s.SaverMode = v == "defrag" ? "defrag" : "scan"; break;
                    case "prevScr": s.PrevScr = v; break;
                    case "prevActive": s.PrevActive = v; break;
                    case "prevTimeout": s.PrevTimeout = v; break;
                }
            }
            return s;
        }

        public void Save()
        {
            LastSaved = DateTime.UtcNow;
            File.WriteAllLines(file, new[]
            {
                "enabled=" + (Enabled ? "1" : "0"),
                "cloud=" + (Cloud ? "1" : "0"),
                "autoQuarantine=" + (AutoQuarantine ? "1" : "0"),
                "mbKey=" + Protect(MbKey),
                "folders=" + string.Join("|", Folders),
                "safe=" + string.Join("|", SafeFolders),
                "rulesChecked=" + RulesChecked,
                "saverIdle=" + (ScreensaverIdle ? "1" : "0"),
                "saverMinutes=" + ScreensaverMinutes,
                "systemSaver=" + (SystemSaver ? "1" : "0"),
                "saverDefrag=" + (SaverDefrag ? "1" : "0"),
                "scanGlow=" + (ScanGlow ? "1" : "0"),
                "badgeHours=" + BadgeHours, "badgeReset=" + BadgeResetAt, "ransom=" + (RansomShield ? "1" : "0"), "ransomStop=" + (RansomAutoStop ? "1" : "0"), "webShield=" + (WebShield ? "1" : "0"),
                "selfGuard=" + (SelfGuard ? "1" : "0"), "useDefender=" + (UseDefender ? "1" : "0"), "lastAutoCheck=" + LastAutoCheck, "defSeen=" + DefenderSeen, "protectProc=" + (ProtectProcess ? "1" : "0"), "webChecked=" + WebChecked, "feedChecked=" + FeedChecked,
                "saverMode=" + SaverMode,
                "prevScr=" + PrevScr, "prevActive=" + PrevActive, "prevTimeout=" + PrevTimeout
            });
        }

        static List<string> Split(string v)
        {
            return v.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        }

        // The optional API key is encrypted for this Windows user (DPAPI), not stored as plain text.
        static string Protect(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(s), null, DataProtectionScope.CurrentUser));
        }

        static string Unprotect(string s)
        {
            try
            {
                return string.IsNullOrEmpty(s) ? "" :
                    Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(s), null, DataProtectionScope.CurrentUser));
            }
            catch { return ""; }
        }
    }

    class Engine : IDisposable
    {
        public const string Version = "1.0.81";
        const string EicarSha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        const int MaxHistory = 500;

        static readonly HashSet<string> RiskyExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".cpl", ".sys", ".bat", ".cmd", ".ps1",
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk",
            ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img"
        };
        // Checked, but only shown in Activity when something is wrong with them.
        static readonly HashSet<string> QuietExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".zip", ".rar", ".7z", ".iso", ".img", ".dll" };
        static readonly HashSet<string> PartialExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".crdownload", ".part", ".partial", ".tmp", ".download", ".quar" };
        static readonly HashSet<string> ScriptExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".bat", ".cmd" };
        static readonly HashSet<string> RareExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".scr", ".pif", ".hta", ".com" };
        static readonly HashSet<string> DocExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".mp3", ".mp4", ".zip" };
        static readonly HashSet<string> RunnableExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk", ".msi", ".ps1" };

        public readonly string DataDir, QuarDir;
        public readonly Settings S;
        public readonly AiModel Ai;
        public readonly Yara Yara;
        public readonly RootkitCheck Rootkit;
        public readonly NetTools Tools;
        public readonly DeepScanner Deep;
        public readonly Shields Shield;
        static readonly string StoreApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps") + "\\";
        readonly ConcurrentQueue<Job> urgent = new ConcurrentQueue<Job>(); // programs starting right now jump the queue
        public readonly NetMonitor Net;   // null unless running as administrator
        readonly ProcWatch procs;
        DateTime yaraChecked = DateTime.MinValue;
        DateTime nextRulesCheck = DateTime.Now.AddMinutes(2); // never hit the network right at startup
        public const double AiThreshold = 0.9;
        public event Action<ScanRecord> Threat;
        public DateTime PausedUntil = DateTime.MinValue;
        public int Revision;

        class CacheEntry { public Verdict V; public string Detail; public DateTime At; }

        readonly object gate = new object();
        readonly List<ScanRecord> history = new List<ScanRecord>();
        readonly List<QuarantineItem> quarantine = new List<QuarantineItem>();
        readonly Dictionary<string, CacheEntry> cache = new Dictionary<string, CacheEntry>();
        readonly HashSet<string> blocked = new HashSet<string>();
        readonly HashSet<string> allowed = new HashSet<string>();
        readonly Dictionary<string, DateTime> pending = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        readonly BlockingCollection<Job> queue = new BlockingCollection<Job>();
        readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        readonly Timer timer;
        readonly Thread worker;
        volatile bool busy, cacheDirty, disposed;
        DateTime lastCacheSave = DateTime.Now;

        string HistoryFile { get { return Path.Combine(DataDir, "history.tsv"); } }
        string CacheFile { get { return Path.Combine(DataDir, "cache.tsv"); } }
        string QuarFile { get { return Path.Combine(DataDir, "quarantine.tsv"); } }
        string BlockFile { get { return Path.Combine(DataDir, "blocklist.txt"); } }
        string AllowFile { get { return Path.Combine(DataDir, "allowlist.txt"); } }

        public Engine(string dataDir)
        {
            DataDir = dataDir;
            QuarDir = Path.Combine(dataDir, "Quarantine");
            Directory.CreateDirectory(QuarDir);
            S = Settings.Load(dataDir);
            Ai = AiModel.TryLoad(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tinyguard.model"));
            Yara = new Yara(AppDomain.CurrentDomain.BaseDirectory, dataDir);
            Rootkit = new RootkitCheck(dataDir);
            Tools = new NetTools(dataDir);
            Deep = new DeepScanner(this);
            Shield = new Shields(this);
            if (S.FirstRun) S.Save();
            LoadState();
            RebuildWatchers();
            worker = new Thread(Work) { IsBackground = true, Name = "TinyGuard scanner", Priority = ThreadPriority.BelowNormal };
            worker.Start();
            procs = new ProcWatch(ProcessStarted);
            if (Environment.GetEnvironmentVariable("TINYGUARD_NOSHIELDS") != "1") Shield.Start();
            if (Admin.IsAdmin) { Net = new NetMonitor(); Net.Start(); }
            else if (Environment.GetEnvironmentVariable("TINYGUARD_NETDEMO") == "1") { Net = new NetMonitor(); Net.Demo(); } // developer aid: fake traffic for screenshots
            timer = new Timer(_ => Tick(), null, 500, 500);
        }

        public bool Active { get { return S.Enabled && DateTime.Now >= PausedUntil; } }
        public int QueueLength { get { lock (pending) return queue.Count + pending.Count + (busy ? 1 : 0); } }

        void Bump() { Interlocked.Increment(ref Revision); }

        // ---------- on / off ----------

        public void SetEnabled(bool on)
        {
            S.Enabled = on;
            PausedUntil = DateTime.MinValue;
            S.Save();
            ApplyWatchState();
        }

        public void Pause(TimeSpan t)
        {
            PausedUntil = DateTime.Now + t;
            ApplyWatchState();
        }

        void ApplyWatchState()
        {
            bool on = Active;
            lock (watchers)
                foreach (var w in watchers) { try { w.EnableRaisingEvents = on; } catch { } }
            if (!on) lock (pending) pending.Clear();
            Bump();
        }

        public void RebuildWatchers()
        {
            lock (watchers)
            {
                foreach (var w in watchers) w.Dispose();
                watchers.Clear();
                foreach (string dir in S.Folders.Where(Directory.Exists))
                {
                    try
                    {
                        var w = new FileSystemWatcher(dir)
                        {
                            IncludeSubdirectories = true,
                            InternalBufferSize = 64 * 1024,
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                        };
                        w.Created += (s, e) => OnFsEvent(e.FullPath);
                        w.Changed += (s, e) => OnFsEvent(e.FullPath);
                        w.Renamed += (s, e) => OnFsEvent(e.FullPath);
                        w.EnableRaisingEvents = Active;
                        watchers.Add(w);
                    }
                    catch { }
                }
            }
            Bump();
        }

        void OnFsEvent(string path)
        {
            if (!Active || path.StartsWith(DataDir, StringComparison.OrdinalIgnoreCase)) return;
            // Wait until the file has been quiet for a moment, so we hash it once when the copy/download ends.
            lock (pending) pending[path] = DateTime.Now.AddSeconds(1.5);
        }

        void Tick()
        {
            if (disposed) return;
            try
            {
                if (PausedUntil != DateTime.MinValue && DateTime.Now >= PausedUntil)
                {
                    PausedUntil = DateTime.MinValue;
                    ApplyWatchState();
                }
                List<string> due = null;
                lock (pending)
                {
                    DateTime now = DateTime.Now;
                    foreach (var kv in pending)
                        if (kv.Value <= now) (due ?? (due = new List<string>())).Add(kv.Key);
                    if (due != null) foreach (string p in due) pending.Remove(p);
                }
                if (due != null)
                {
                    foreach (string p in due) queue.Add(new Job { Path = p });
                    Bump();
                }
                if (cacheDirty && (DateTime.Now - lastCacheSave).TotalSeconds > 30) SaveCache();
                if (ledgerDirty && (DateTime.Now - ledgerSaved).TotalSeconds > 30) SaveLedger();
                // Look for new YARA rules once a day, only while online checks are allowed.
                if (S.Cloud && DateTime.Now >= nextRulesCheck && !Yara.Updating
                    && (DateTime.Now - new DateTime(S.RulesChecked)).TotalHours >= 24)
                {
                    nextRulesCheck = DateTime.Now.AddHours(1); // if this attempt fails, retry in an hour
                    CheckRulesNow();
                }
            }
            catch { }
        }

        // ---------- scanning ----------

        // Manual scans (a selection of icons, "Scan with TinyGuard") run several at a time, and every item lights up at once while it waits.

        public void ScanNow(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            ManualTask(path);
            Bump();
        }

        /// <summary>Files inside a folder (up to max), skipping folders that can't be read and not following links, so one locked subfolder doesn't end the list early.</summary>
        static List<string> FilesUnder(string root, int max)
        {
            var res = new List<string>(); var stack = new Stack<string>(); stack.Push(root);
            while (stack.Count > 0 && res.Count < max)
            {
                string d = stack.Pop();
                try { foreach (string f in Directory.GetFiles(d)) { if (res.Count >= max) break; res.Add(f); } } catch { }
                try
                {
                    foreach (string sub in Directory.GetDirectories(d))
                    {
                        try { if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                        stack.Push(sub);
                    }
                }
                catch { }
            }
            return res;
        }

        Task ManualTask(string path)
        {
            ProgTrack(path);
            if (S.ScanGlow) { var h = GlowBegin; if (h != null) try { h(path); } catch { } }
            return Task.Run(() =>
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        var kids = new List<Task>(); var kidPaths = new List<string>(); folderKids[path] = kidPaths;
                        try { foreach (string f in FilesUnder(path, 2000)) { ProgTrack(f); kidPaths.Add(f); kids.Add(ManualFile(f, false, path)); } } catch { }
                        try { Task.WaitAll(kids.ToArray()); } catch { }
                        Verdict worst = Verdict.Clean; string root = path.TrimEnd((char)92) + (char)92;
                        foreach (var kv in LedgerSnapshot())
                            if (kv.Key.StartsWith(root, StringComparison.OrdinalIgnoreCase)) { var v = kv.Value.Quarantined || kv.Value.Deleted ? Verdict.Malicious : kv.Value.Verdict; if (v > worst && v >= Verdict.Suspicious) worst = v; }
                        RaiseGlowEnd(path, worst);
                    }
                    else ManualFile(path, true).Wait();
                }
                catch { }
            });
        }

        // A fixed set of worker threads does the manual checks (a plain Task per file starved the thread pool when a big folder was queued, and the online lookups inside each check need pool threads too).
        // two lines: single items you picked go first; the files inside a folder you scanned wait in the second line, so a huge folder can't hold up the next things you pick
        readonly ConcurrentQueue<Tuple<string, bool, TaskCompletionSource<bool>>> manualFirst = new ConcurrentQueue<Tuple<string, bool, TaskCompletionSource<bool>>>();
        // the files inside scanned folders: one line per folder, served in turn, so a new folder starts at once instead of waiting behind a huge one
        readonly object secondLock = new object();
        readonly List<string> secondGroups = new List<string>();
        readonly Dictionary<string, Queue<Tuple<string, bool, TaskCompletionSource<bool>>>> secondByGroup = new Dictionary<string, Queue<Tuple<string, bool, TaskCompletionSource<bool>>>>(StringComparer.OrdinalIgnoreCase);
        int secondNext;

        void EnqueueSecond(string group, Tuple<string, bool, TaskCompletionSource<bool>> job)
        {
            lock (secondLock)
            {
                Queue<Tuple<string, bool, TaskCompletionSource<bool>>> q;
                if (!secondByGroup.TryGetValue(group, out q)) { q = new Queue<Tuple<string, bool, TaskCompletionSource<bool>>>(); secondByGroup[group] = q; secondGroups.Add(group); }
                q.Enqueue(job);
            }
        }

        bool TryDequeueSecond(out Tuple<string, bool, TaskCompletionSource<bool>> job)
        {
            lock (secondLock)
            {
                for (int i = 0; i < secondGroups.Count; i++)
                {
                    int idx = (secondNext + i) % secondGroups.Count; string g = secondGroups[idx]; var q = secondByGroup[g];
                    if (q.Count == 0) continue;
                    job = q.Dequeue();
                    if (q.Count == 0) { secondByGroup.Remove(g); secondGroups.RemoveAt(idx); secondNext = idx; } else secondNext = idx + 1;
                    return true;
                }
            }
            job = null; return false;
        }
        readonly SemaphoreSlim manualCount = new SemaphoreSlim(0);
        public int ManualPending { get { return Volatile.Read(ref manualPending); } }
        int manualWorkers, manualRunning, manualPending;     // pending = queued + being checked: the background scanner waits while this is above zero

        void StartManualWorkers()
        {
            if (Interlocked.CompareExchange(ref manualWorkers, 12, 0) != 0) return;
            for (int i = 0; i < 12; i++)
            {
                var t = new Thread(() =>
                {
                    while (true)
                    {
                        manualCount.Wait();
                        Tuple<string, bool, TaskCompletionSource<bool>> job;
                        if (!manualFirst.TryDequeue(out job) && !TryDequeueSecond(out job)) continue;
                        string path = job.Item1;
                        try
                        {
                            Interlocked.Increment(ref manualRunning); busy = true; ActiveFile = path;
                            try { ScanFile(path, true); } catch { }
                            ActiveEnded = DateTime.Now;
                        }
                        finally { busy = Interlocked.Decrement(ref manualRunning) > 0; Bump(); }
                        if (job.Item2)
                        {
                            Verdict v = Verdict.Unknown;
                            var le = LedgerGet(path);
                            if (le != null) v = le.Quarantined || le.Deleted ? Verdict.Malicious : le.Verdict;
                            RaiseGlowEnd(path, v);
                        }
                        Interlocked.Decrement(ref manualPending);
                        job.Item3.TrySetResult(true);
                    }
                }) { IsBackground = true, Name = "TinyGuard manual scan" };
                t.Start();
            }
        }

        Task ManualFile(string path, bool lit = false, string group = null)
        {
            StartManualWorkers();
            var tcs = new TaskCompletionSource<bool>();
            Interlocked.Increment(ref manualPending);
            if (lit) manualFirst.Enqueue(Tuple.Create(path, lit, tcs)); else EnqueueSecond(group ?? "", Tuple.Create(path, lit, tcs));
            manualCount.Release();
            return tcs.Task;
        }

        /// <summary>Called by the process watcher when a program starts.</summary>
        public void ProcessStarted(int pid, string path, bool alreadyRunning)
        {
            if (!Active) return;
            var j = new Job { Path = path, Pid = pid };
            if (alreadyRunning) queue.Add(j);
            else { urgent.Enqueue(j); queue.Add(new Job { Path = "" }); } // the empty job just wakes the scanner
        }

        // ----- quick scan state (lives here so it survives switching pages in the window) -----
        public volatile bool ScanActive, ScanStopped;
        public int ScanTotal, ScanDone, ScanFound;
        public string ScanCurrent = "";
        public DateTime ScanEnded = DateTime.MinValue;
        volatile bool scanCancel, scanEnumerating;
        readonly object scanLock = new object();
        bool lastRecordWasThreat;

        // ----- ledger: every file examined, for the Scan map -----
        readonly Dictionary<string, LedgerEntry> ledger = new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);
        readonly ConcurrentQueue<KeyValuePair<string, LedgerEntry>> ledgerChanges = new ConcurrentQueue<KeyValuePair<string, LedgerEntry>>();
        volatile bool ledgerDirty;
        DateTime ledgerSaved = DateTime.Now;
        public volatile string ActiveFile = "";
        public DateTime ActiveEnded = DateTime.MinValue;
        string LedgerFile { get { return Path.Combine(DataDir, "ledger.tsv"); } }

        /// <summary>The file being examined right now (or one finished a moment ago), for the map's animation.</summary>
        public string ActiveFileNow
        {
            get
            {
                string a = ActiveFile;
                return a.Length > 0 && (busy || (DateTime.Now - ActiveEnded).TotalMilliseconds < 1200) ? a : "";
            }
        }

        public static bool LooksScannable(string path)
        {
            string ext = Path.GetExtension(path);
            return RiskyExts.Contains(ext) && !PartialExts.Contains(ext);
        }

        void Ledger(string path, Verdict v, bool quarantined, bool deleted, string detail, bool deep = false)
        {
            if (string.IsNullOrEmpty(path)) return;
            var e = new LedgerEntry { Verdict = v, Time = DateTime.Now, Quarantined = quarantined, Deleted = deleted, Deep = deep, Detail = (detail ?? "").Length > 120 ? detail.Substring(0, 120) : (detail ?? "") };
            lock (ledger)
            {
                LedgerEntry old;
                if (!deep && ledger.TryGetValue(path, out old) && old.Deep && old.Verdict == v && old.Quarantined == quarantined && old.Deleted == deleted) e.Deep = true;   // a quick re-check doesn't undo a deep scan
                ledger[path] = e;
                if (ledger.Count > 45000)
                    foreach (var k in ledger.OrderBy(x => x.Value.Time).Take(5000).Select(x => x.Key).ToList()) ledger.Remove(k);
            }
            ledgerChanges.Enqueue(new KeyValuePair<string, LedgerEntry>(path, e));
            KeyValuePair<string, LedgerEntry> drop;
            while (ledgerChanges.Count > 5000) ledgerChanges.TryDequeue(out drop);   // nobody is watching the map: don't let it grow
            ledgerDirty = true;
        }

        void Ledger(ScanRecord r) { Ledger(r.FilePath, r.Verdict, r.Quarantined, false, r.Detail); }

        public LedgerEntry LedgerGet(string path) { lock (ledger) { LedgerEntry e; return ledger.TryGetValue(path, out e) ? e : null; } }

        /// <summary>Adds fingerprints from a malware feed to the block list. Returns how many were new.</summary>
        public int AddBlockedHashes(IEnumerable<string> hashes)
        {
            int n = 0; var fresh = new List<string>();
            lock (gate)
                foreach (string h in hashes)
                    if (h != null && h.Length == 64 && !allowed.Contains(h) && blocked.Add(h)) { n++; fresh.Add(h); }
            if (n > 0) { try { File.AppendAllLines(BlockFile, fresh); } catch { } Bump(); }
            return n;
        }

        public bool IsBlockedHash(string sha) { lock (gate) return blocked.Contains(sha); }

        /// <summary>Hash and normally classify one file, for the deep scanner. Null if it can't be read.</summary>
        public ScanRecord ExamineFile(string path, out bool isPe, out double entropy)
        {
            isPe = false; entropy = 0;
            string sha, md5;
            if (!Hash(path, out sha, out md5, out isPe, out entropy)) return null;
            var rec = new ScanRecord { Time = DateTime.Now, FilePath = path, Sha256 = sha };
            Classify(rec, md5, isPe, entropy);
            return rec;
        }

        public void CommitDeepEntry(string path, Verdict v, string detail) { Ledger(path, v, false, false, detail, true); Bump(); }

        /// <summary>Record the result of a deep scan: update the ledger, quarantine real malware, and list anything flagged.</summary>
        public void CommitDeep(ScanRecord rec)
        {
            if (rec.Verdict == Verdict.Malicious && S.AutoQuarantine) DoQuarantine(rec);
            Ledger(rec.FilePath, rec.Verdict, rec.Quarantined, false, rec.Detail, true);
            if (rec.IsThreat)
            {
                bool known;
                lock (gate) known = history.Any(h => h.IsThreat && h.Sha256 == rec.Sha256 && string.Equals(h.FilePath, rec.FilePath, StringComparison.OrdinalIgnoreCase));
                if (!known) Record(rec);
            }
            Bump();
        }

        public List<KeyValuePair<string, LedgerEntry>> LedgerSnapshot() { lock (ledger) return ledger.ToList(); }

        public List<KeyValuePair<string, LedgerEntry>> DrainLedgerChanges()
        {
            var l = new List<KeyValuePair<string, LedgerEntry>>();
            KeyValuePair<string, LedgerEntry> kv;
            while (l.Count < 2000 && ledgerChanges.TryDequeue(out kv)) l.Add(kv);
            return l;
        }

        void SaveLedger()
        {
            try
            {
                string[] lines;
                lock (ledger)
                    lines = ledger.Select(kv => string.Join("\t", kv.Key.Replace('\t', ' '), ((int)kv.Value.Verdict).ToString(), kv.Value.Time.Ticks.ToString(),
                        (kv.Value.Quarantined ? "q" : "") + (kv.Value.Deleted ? "d" : "") + (kv.Value.Deep ? "x" : "") + "-", (kv.Value.Detail ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' '))).ToArray();
                ledgerDirty = false;
                File.WriteAllLines(LedgerFile, lines);
                ledgerSaved = DateTime.Now;
            }
            catch { }
        }

        public void QuickScan(IEnumerable<string> only = null)
        {
            lock (scanLock)
            {
                if (ScanActive) return;
                ScanActive = true; ScanStopped = false; scanCancel = false; scanEnumerating = true;
                ScanTotal = ScanDone = ScanFound = 0; ScanCurrent = "";
            }
            var folders = (only ?? S.Folders).ToList();
            Bump();
            Task.Run(() =>
            {
                foreach (string root in folders)
                    foreach (string f in SafeEnumerate(root))
                    {
                        if (disposed || scanCancel) break;
                        if (!IsCandidate(f)) continue;
                        Interlocked.Increment(ref ScanTotal);
                        queue.Add(new Job { Path = f, Scan = true });
                    }
                scanEnumerating = false;
                FinishScanIfDone();
                Bump();
            });
        }

        public void StopScan() { if (ScanActive) { scanCancel = true; ScanStopped = true; Bump(); } }

        void FinishScanIfDone()
        {
            lock (scanLock)
            {
                if (!ScanActive || scanEnumerating || ScanDone < ScanTotal) return;
                ScanActive = false; ScanCurrent = ""; ScanEnded = DateTime.Now;
            }
        }

        /// <summary>Threats and suspicious files the user hasn't dealt with yet.</summary>
        public int NeedAttention() { lock (gate) return history.Count(h => h.IsThreat && !h.Quarantined && File.Exists(h.FilePath)); }

        /// <summary>Quarantine everything that needs action. Returns how many couldn't be moved.</summary>
        public int QuarantineAllThreats()
        {
            List<ScanRecord> todo;
            lock (gate) todo = history.Where(h => h.IsThreat && !h.Quarantined && File.Exists(h.FilePath)).ToList();
            int failed = 0;
            foreach (var r in todo) if (!Quarantine(r)) failed++;
            return failed;
        }

        /// <summary>Quarantine a file that isn't in the log yet (for example one found by the rootkit check).</summary>
        public bool QuarantinePath(string path, string reason, out string error)
        {
            error = null;
            if (!File.Exists(path)) { error = "the file isn't there any more"; return false; }
            string sha, md5; bool isPe; double entropy;
            if (!Hash(path, out sha, out md5, out isPe, out entropy)) { error = "couldn't read the file"; return false; }
            var rec = new ScanRecord { Time = DateTime.Now, FilePath = path, Sha256 = sha, Verdict = Verdict.Suspicious, Detail = reason };
            if (!DoQuarantine(rec)) { error = rec.Detail.Contains("—") ? rec.Detail.Substring(rec.Detail.IndexOf('—') + 1).Trim() : "couldn't move it (in use?)"; return false; }
            Ledger(rec);
            Record(rec, false);
            return true;
        }

        /// <summary>Delete a flagged file permanently (no Recycle Bin). Returns an error message or null.</summary>
        public string DeleteFile(ScanRecord r)
        {
            try
            {
                if (File.Exists(r.FilePath)) { File.SetAttributes(r.FilePath, FileAttributes.Normal); File.Delete(r.FilePath); }
            }
            catch (Exception ex) { return ex.Message; }
            Ledger(r.FilePath, r.Verdict, r.Quarantined, true, r.Detail);
            lock (gate) { r.Detail += " · deleted by you"; SaveHistory(); }
            Bump();
            return null;
        }

        internal static IEnumerable<string> SafeEnumerate(string root)
        {
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                string dir = stack.Pop();
                string[] files = null, dirs = null;
                try { files = Directory.GetFiles(dir); dirs = Directory.GetDirectories(dir); } catch { }
                if (files != null) foreach (string f in files) yield return f;
                if (dirs != null)
                    foreach (string d in dirs)
                    {
                        bool link = false;
                        try { link = (File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0; } catch { link = true; }
                        if (!link) stack.Push(d);
                    }
            }
        }

        // ---- "Ignore": things you told TinyGuard to leave alone (a file, a whole folder, or a file type)
        string IgnoreFile { get { return Path.Combine(DataDir, "ignore.txt"); } }
        List<string[]> ignores;
        List<string[]> Ignores()
        {
            lock (gate)
            {
                if (ignores == null)
                {
                    ignores = new List<string[]>();
                    try { foreach (string l in File.ReadAllLines(IgnoreFile)) { int i = l.IndexOf('|'); if (i > 0) ignores.Add(new[] { l.Substring(0, i), l.Substring(i + 1) }); } } catch { }
                }
                return ignores;
            }
        }

        public bool IsIgnored(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (var r in Ignores().ToArray())
            {
                if (r[0] == "file" && string.Equals(path, r[1], StringComparison.OrdinalIgnoreCase)) return true;
                if (r[0] == "folder" && path.StartsWith(r[1].TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
                if (r[0] == "ext" && string.Equals(Path.GetExtension(path), r[1], StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>kind: "file", "folder" or "ext". Hides every matching finding and stops scanning those files.</summary>
        public void AddIgnore(string kind, string value)
        {
            lock (gate)
            {
                Ignores().Add(new[] { kind, value });
                try { File.WriteAllLines(IgnoreFile, Ignores().Select(r => r[0] + "|" + r[1])); } catch { }
                foreach (var h in history.Where(h => !h.Quarantined && IsIgnored(h.FilePath))) { h.Verdict = Verdict.Clean; h.Detail = "Ignored by you"; }
                SaveHistory();
            }
            Bump();
        }

        public int IgnoreCount { get { return Ignores().Count; } }

        public void ClearIgnores()
        {
            lock (gate) { Ignores().Clear(); try { File.Delete(IgnoreFile); } catch { } }
            Bump();
        }

        bool IsSafeFolder(string path)
        {
            if (IsIgnored(path)) return true;
            if (path.StartsWith(DataDir, StringComparison.OrdinalIgnoreCase)) return true;
            // TinyGuard's own folder: itself and the YARA engine it starts for every scan.
            if (path.StartsWith(AppDomain.CurrentDomain.BaseDirectory, StringComparison.OrdinalIgnoreCase)) return true;
            // while developing: TinyGuard's own build folders next to the project file (bin, bin_new)
            try
            {
                string parent = Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory.TrimEnd((char)92));
                if (parent != null && File.Exists(Path.Combine(parent, "TinyGuard.csproj")) && (path.StartsWith(Path.Combine(parent, "bin") + (char)92, StringComparison.OrdinalIgnoreCase) || path.StartsWith(Path.Combine(parent, "bin_new") + (char)92, StringComparison.OrdinalIgnoreCase))) return true;
            }
            catch { }
            foreach (string s in S.SafeFolders)
                if (path.StartsWith(s.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        static bool IsCandidate(string path)
        {
            string ext = Path.GetExtension(path);
            if (PartialExts.Contains(ext)) return false;
            if (RiskyExts.Contains(ext)) return true;
            try
            {
                // Programs hiding behind another extension still start with "MZ".
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    return fs.ReadByte() == 'M' && fs.ReadByte() == 'Z';
            }
            catch { return false; }
        }

        public void CheckRulesNow()
        {
            if (Yara.Updating) return;
            Task.Run(() =>
            {
                Bump();
                bool changed = Yara.Update();
                if (!Yara.UpdateStatus.StartsWith("Couldn't"))
                {
                    S.RulesChecked = DateTime.Now.Ticks;
                    S.Save();
                }
                if (changed)
                {
                    yaraChecked = DateTime.MinValue;               // scanner recompiles before its next file
                    queue.Add(new Job { Path = "" }); // ...and wakes up now to do it
                }
                Bump();
            });
        }

        void PrepareYara()
        {
            // Picks up new or edited rules in the data folder's "rules" subfolder within a minute.
            try { Yara.Prepare(); } catch { }
            yaraChecked = DateTime.Now;
            Bump();
        }

        // ---- the light that runs around a file's icon while it is checked (see ScanGlow)
        public event Action<string> GlowBegin;
        public event Action<string, Verdict> GlowEnd;
        string glowOpen;

        // how far along the check of an item is (0..1), for the ring that fills around its icon; -1 = not known
        readonly ConcurrentDictionary<string, double> prog = new ConcurrentDictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        readonly ConcurrentDictionary<string, List<string>> folderKids = new ConcurrentDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void ProgTrack(string path) { if (!string.IsNullOrEmpty(path)) prog.TryAdd(path, 0); }
        void SetProg(string path, double v) { double old; if (path != null && prog.TryGetValue(path, out old) && v > old) prog[path] = Math.Min(1, v); }
        public double ProgressOf(string path)
        {
            List<string> kids;
            if (folderKids.TryGetValue(path, out kids))
            {
                if (kids.Count == 0) return -1;
                double sum = 0; foreach (string k in kids.ToArray()) { double d; if (prog.TryGetValue(k, out d)) sum += d; }
                return sum / kids.Count;
            }
            double p; return prog.TryGetValue(path, out p) ? p : -1;
        }
        // folders that were scanned as a whole: remembered so the hover badge can show on them too (files are remembered in the ledger)
        readonly object folderLock = new object();
        Dictionary<string, Tuple<DateTime, Verdict>> folderScans;
        string FolderScanFile { get { return Path.Combine(DataDir, "folder-scans.tsv"); } }

        void LoadFolderScans()
        {
            if (folderScans != null) return;
            folderScans = new Dictionary<string, Tuple<DateTime, Verdict>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (string line in File.ReadAllLines(FolderScanFile))
                {
                    var p = line.Split((char)9); long t; int vv;
                    if (p.Length == 3 && long.TryParse(p[1], out t) && int.TryParse(p[2], out vv)) folderScans[p[0]] = Tuple.Create(new DateTime(t), (Verdict)vv);
                }
            }
            catch { }
            // a folder flagged in the past is re-judged from what its files say now
            try
            {
                var snap = LedgerSnapshot();
                foreach (string k in folderScans.Keys.ToList())
                {
                    if (folderScans[k].Item2 < Verdict.Suspicious) continue;
                    string root = k.TrimEnd((char)92) + (char)92; Verdict worst = Verdict.Clean;
                    foreach (var kv in snap)
                        if (kv.Key.StartsWith(root, StringComparison.OrdinalIgnoreCase)) { var v = kv.Value.Quarantined || kv.Value.Deleted ? Verdict.Malicious : kv.Value.Verdict; if (v > worst && v >= Verdict.Suspicious) worst = v; }
                    if (worst < folderScans[k].Item2) folderScans[k] = Tuple.Create(folderScans[k].Item1, worst);
                }
            }
            catch { }
        }

        void RememberFolderScan(string path, Verdict v)
        {
            lock (folderLock)
            {
                LoadFolderScans();
                folderScans[path] = Tuple.Create(DateTime.Now, v);
                try { File.WriteAllLines(FolderScanFile, folderScans.Select(kv => kv.Key + (char)9 + kv.Value.Item1.Ticks + (char)9 + (int)kv.Value.Item2).ToArray()); } catch { }
            }
        }

        /// <summary>When an item (file or whole folder) was last scanned and what the result was, for the hover badge.</summary>
        public bool BadgeFor(string path, out DateTime when, out Verdict v)
        {
            when = DateTime.MinValue; v = Verdict.Unknown;
            var le = LedgerGet(path);
            if (le != null) { when = le.Time; v = le.Quarantined || le.Deleted ? Verdict.Malicious : le.Verdict; return when.Ticks >= S.BadgeResetAt; }
            lock (folderLock)
            {
                LoadFolderScans();
                Tuple<DateTime, Verdict> f;
                if (folderScans.TryGetValue(path.TrimEnd((char)92), out f)) { when = f.Item1; v = f.Item2; return when.Ticks >= S.BadgeResetAt; }
            }
            return false;
        }

        void RaiseGlowEnd(string path, Verdict v)
        {
            try { if (Directory.Exists(path)) RememberFolderScan(path.TrimEnd((char)92), v); } catch { }
            List<string> kids;
            if (folderKids.TryRemove(path, out kids)) foreach (string k in kids) { double d; prog.TryRemove(k, out d); }
            double x; prog.TryRemove(path, out x);
            var he = GlowEnd; if (he != null) try { he(path, v); } catch { }
        }

        static bool TopLevelOfWatched(string path)
        {
            try
            {
                string dir = Path.GetDirectoryName(path).TrimEnd('\\');
                foreach (string w in new[] { Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), Settings.Downloads() })
                    if (string.Equals(dir, w.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch { }
            return false;
        }

        void GlowStart(string path)
        {
            if (glowOpen != null || string.IsNullOrEmpty(path) || !S.ScanGlow) return;
            glowOpen = path; ProgTrack(path);
            var h = GlowBegin; if (h != null) try { h(path); } catch { }
        }

        void GlowStop()
        {
            if (glowOpen == null) return;
            string p = glowOpen; glowOpen = null;
            Verdict v = Verdict.Unknown;
            if (!Directory.Exists(p))
            {
                var le = LedgerGet(p);
                if (le != null) v = le.Quarantined || le.Deleted ? Verdict.Malicious : le.Verdict;
                if (!File.Exists(p) && le == null) v = Verdict.Unknown;
            }
            RaiseGlowEnd(p, v);
        }

        void Work()
        {
            PrepareYara();
            foreach (var next in queue.GetConsumingEnumerable())
            {
                Job item;
                if (urgent.TryDequeue(out item)) queue.Add(next); // do the new program first, keep the other job
                else item = next;
                if ((DateTime.Now - yaraChecked).TotalSeconds > 60) PrepareYara();
                // a scan the user asked for comes first: the background scanner waits until those are done (program-start checks still go through)
                while (Volatile.Read(ref manualPending) > 0 && item.Pid == 0 && !scanCancel) Thread.Sleep(150);
                busy = true;
                if (item.Scan && scanCancel) { Interlocked.Increment(ref ScanDone); FinishScanIfDone(); busy = false; Bump(); continue; }
                if (item.Scan) ScanCurrent = item.Path;
                if (!string.IsNullOrEmpty(item.Path)) ActiveFile = item.Path;
                lastRecordWasThreat = false;
                glowOpen = null;
                try
                {
                    if (item.FolderDone)
                    {
                        Verdict worst = Verdict.Clean; string root = item.Path.TrimEnd((char)92) + (char)92;
                        foreach (var kv in LedgerSnapshot())
                            if (kv.Key.StartsWith(root, StringComparison.OrdinalIgnoreCase)) { var v = kv.Value.Quarantined || kv.Value.Deleted ? Verdict.Malicious : kv.Value.Verdict; if (v > worst && v >= Verdict.Suspicious) worst = v; }
                        RaiseGlowEnd(item.Path, worst);
                        busy = false; continue;
                    }
                    bool glowIt = !item.Scan && item.Pid == 0 && !string.IsNullOrEmpty(item.Path) && (item.Manual || TopLevelOfWatched(item.Path));
                    if (glowIt && Directory.Exists(item.Path))
                    {
                        // a new or chosen folder: light it up and check what is inside it
                        GlowStart(item.Path); glowOpen = null;     // the light keeps running until the last file inside is checked
                        var kidList = new List<string>(); folderKids[item.Path] = kidList;
                        try { foreach (string f in FilesUnder(item.Path, 2000)) { ProgTrack(f); kidList.Add(f); queue.Add(new Job { Path = f, Manual = true }); } } catch { }
                        queue.Add(new Job { Path = item.Path, FolderDone = true });
                    }
                    else
                    {
                        if (glowIt && File.Exists(item.Path) && (item.Manual || (!IsSafeFolder(item.Path) && IsCandidate(item.Path)))) GlowStart(item.Path);
                        if (item.Pid != 0) ScanProcess(item.Pid, item.Path); else ScanFile(item.Path, item.Manual);
                    }
                }
                catch { }
                GlowStop();
                if (item.Scan)
                {
                    if (lastRecordWasThreat) Interlocked.Increment(ref ScanFound);
                    Interlocked.Increment(ref ScanDone);
                    FinishScanIfDone();
                }
                ActiveEnded = DateTime.Now;
                busy = false;
                Bump();
            }
        }

        static FileStream OpenWhenReady(string path)
        {
            // Prefer to wait until whoever is writing the file lets go of it.
            for (int i = 0; i < 30; i++)
            {
                try { return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1 << 16, FileOptions.SequentialScan); }
                catch (FileNotFoundException) { return null; }
                catch (DirectoryNotFoundException) { return null; }
                catch (UnauthorizedAccessException) { return null; }
                catch (IOException) { Thread.Sleep(500); }
            }
            try { return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan); }
            catch { return null; }
        }

        bool Hash(string path, out string sha, out string md5, out bool isPe, out double entropy)
        {
            sha = md5 = null; isPe = false; entropy = 0;
            using (FileStream fs = OpenWhenReady(path))
            {
                if (fs == null || fs.Length == 0) return false;
                using (var s256 = SHA256.Create())
                using (var m5 = MD5.Create())
                {
                    var buf = new byte[1 << 16];
                    var hist = new long[256];
                    long total = 0; int n; bool first = true; int rounds = 0; long len = Math.Min(fs.Length, 2L * 1024 * 1024 * 1024);     // a file over 2 GB is fingerprinted by its first 2 GB
                    while (total < len && (n = fs.Read(buf, 0, (int)Math.Min(buf.Length, len - total))) > 0)
                    {
                        if ((++rounds & 7) == 0 && len > 0) SetProg(path, 0.8 * total / len);
                        if (first) { isPe = n >= 2 && buf[0] == 'M' && buf[1] == 'Z'; first = false; }
                        s256.TransformBlock(buf, 0, n, null, 0);
                        m5.TransformBlock(buf, 0, n, null, 0);
                        for (int i = 0; i < n; i++) hist[buf[i]]++;
                        total += n;
                    }
                    s256.TransformFinalBlock(buf, 0, 0);
                    m5.TransformFinalBlock(buf, 0, 0);
                    sha = Hex(s256.Hash); md5 = Hex(m5.Hash);
                    foreach (long c in hist)
                        if (c > 0) { double p = (double)c / total; entropy -= p * Math.Log(p, 2); }
                }
            }
            return true;
        }

        void ScanFile(string path, bool manual)
        {
            try { ScanFileCore(path, manual); }
            finally { SetProg(path, 1); }
        }

        void ScanFileCore(string path, bool manual)
        {
            if (!File.Exists(path)) return;
            string qid = PlaceholderId(path);
            if (qid != null) { if (manual) RecheckQuarantined(path, qid); return; }     // a stand-in for a quarantined file: only a manual scan re-checks it
            if (!manual && (IsSafeFolder(path) || !IsCandidate(path))) return;

            string sha, md5; bool isPe; double entropy;
            if (!Hash(path, out sha, out md5, out isPe, out entropy))
            {
                if (manual)
                {
                    // a file you picked always gets an answer, even an empty one or one that can't be opened
                    long flen = -1; try { flen = new FileInfo(path).Length; } catch { }
                    var none = new ScanRecord { Time = DateTime.Now, FilePath = path, Sha256 = "", Verdict = flen == 0 ? Verdict.Clean : Verdict.Unknown, Detail = flen == 0 ? "Empty file" : "Couldn't open it to check (in use, or no permission)" };
                    Ledger(none);
                }
                return;
            }
            SetProg(path, 0.8);

            var rec = new ScanRecord { Time = DateTime.Now, FilePath = path, Sha256 = sha };
            Classify(rec, md5, isPe, entropy);
            if (manual) AskDefender(rec);
            SetProg(path, 0.97);
            Ledger(rec);

            string ext = Path.GetExtension(path);
            if (!manual && !rec.IsThreat && QuietExts.Contains(ext)) return;

            lock (gate)
            {
                // The same file often raises several change events; don't list it twice.
                if (!manual && history.Any(h => h.Sha256 == sha && (rec.Time - h.Time).TotalSeconds < 60
                        && string.Equals(h.FilePath, path, StringComparison.OrdinalIgnoreCase))) return;
            }

            if (rec.Verdict == Verdict.Malicious && S.AutoQuarantine) { DoQuarantine(rec); Ledger(rec); }
            Record(rec);
        }

        // Microsoft Defender gets a say on files you scan that nothing else has vouched for. Report only: Defender removes nothing for us.
        void AskDefender(ScanRecord rec)
        {
            if (!S.UseDefender || !S.Cloud || rec.Verdict >= Verdict.Malicious) return;
            if (rec.Verdict != Verdict.Unknown && rec.Verdict != Verdict.Suspicious) return;     // signed or already-known-good files need no second opinion
            try { if (rec.FilePath.StartsWith(AppDomain.CurrentDomain.BaseDirectory, StringComparison.OrdinalIgnoreCase)) return; } catch { }     // never judge ourselves: Defender has mislabelled TinyGuard before
            var a = DefenderLink.Check(rec.FilePath);
            if (a == null) return;
            if (!a.Threat) { rec.Detail += " · Microsoft Defender: no threat found"; return; }
            string name = a.Name.Length > 0 ? a.Name : "a threat";
            if (a.Ml) { rec.Verdict = Verdict.Suspicious; rec.Detail = "Microsoft Defender suspects " + name + " (a machine-guess, so unconfirmed)"; }
            else { rec.Verdict = Verdict.Malicious; rec.Detail = "Microsoft Defender: " + name; }
        }

        void Record(ScanRecord rec, bool notify = true)
        {
            lock (gate)
            {
                history.Add(rec);
                if (history.Count > MaxHistory) history.RemoveRange(0, history.Count - MaxHistory);
                try { File.AppendAllText(HistoryFile, Line(rec) + "\r\n"); } catch { }
            }
            lastRecordWasThreat = rec.IsThreat;
            Bump();
            if (notify && rec.IsThreat) { var t = Threat; if (t != null) t(rec); }
        }

        // Programs already judged, by path + size + date, so a program that starts often is hashed once.
        readonly Dictionary<string, Verdict> seenPrograms = new Dictionary<string, Verdict>(StringComparer.OrdinalIgnoreCase);
        string SeenFile { get { return Path.Combine(DataDir, "programs.tsv"); } }

        void ScanProcess(int pid, string path)
        {
            if (!Active || string.IsNullOrEmpty(path) || !File.Exists(path) || IsSafeFolder(path)) return;
            string key;
            try { var fi = new FileInfo(path); key = path + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks; }
            catch { return; }
            bool known; Verdict before;
            lock (gate) known = seenPrograms.TryGetValue(key, out before);
            if (known && before < Verdict.Suspicious) return;
            if (TopLevelOfWatched(path)) GlowStart(path);

            string sha, md5; bool isPe; double entropy;
            if (!Hash(path, out sha, out md5, out isPe, out entropy)) return;
            var rec = new ScanRecord { Time = DateTime.Now, FilePath = path, Sha256 = sha };
            Classify(rec, md5, isPe, entropy);
            Ledger(rec);
            lock (gate)
            {
                seenPrograms[key] = rec.Verdict;
                try { File.AppendAllText(SeenFile, key.Replace('\t', ' ') + "\t" + (int)rec.Verdict + "\r\n"); } catch { }
            }

            // Safe programs stay out of Activity (it would fill up with every app you open);
            // first sightings of unknown programs and anything worse are listed.
            if (!rec.IsThreat && (known || rec.Verdict != Verdict.Unknown)) return;
            rec.Detail = "Running program · " + rec.Detail;

            if (rec.Verdict == Verdict.Malicious && S.AutoQuarantine)
            {
                if (ProcWatch.Kill(pid, path)) rec.Detail += " · stopped it";
                string keep = rec.Detail;
                for (int i = 0; i < 20; i++)
                {
                    if (DoQuarantine(rec)) break;
                    rec.Detail = keep;
                    Thread.Sleep(250); // the file stays locked for a moment after the program ends
                }
                if (!rec.Quarantined) rec.Detail += " — could not quarantine (file in use)";
            }
            Ledger(rec);
            Record(rec);
        }

        void Classify(ScanRecord rec, string md5, bool isPe, double entropy)
        {
            string sha = rec.Sha256, path = rec.FilePath;
            bool blockedHash, allowedHash; CacheEntry hit;
            lock (gate)
            {
                blockedHash = blocked.Contains(sha);
                allowedHash = allowed.Contains(sha);
                cache.TryGetValue(sha, out hit);
                if (hit != null && (DateTime.Now - hit.At).TotalHours > (hit.V == Verdict.Unknown ? 24 : 24 * 30)) hit = null;
                if (hit != null && hit.V == Verdict.Suspicious && hit.Detail != null && hit.Detail.Contains("not a program, so unconfirmed")) hit = null;     // an old false alarm saved by an earlier version: judge it again
            }

            if (allowedHash) { rec.Verdict = Verdict.Clean; rec.Detail = "Marked safe by you"; return; }
            if (sha == EicarSha) { rec.Verdict = Verdict.Malicious; rec.Detail = "EICAR test file (a harmless file made for testing antivirus)"; return; }
            if (blockedHash) { rec.Verdict = Verdict.Malicious; rec.Detail = "On your own block list"; return; }

            if (hit != null) { rec.Verdict = hit.V; rec.Detail = hit.Detail; }
            else
            {
                bool cacheable = true;
                string signer = Trust.TrustedSigner(path);
                if (signer != null) { rec.Verdict = Verdict.Clean; rec.Detail = "Signed by " + signer; }
                else if (path.StartsWith(StoreApps, StringComparison.OrdinalIgnoreCase))
                {
                    // Only Windows can write here, and Store packages are signature-checked when installed.
                    rec.Verdict = Verdict.Clean; rec.Detail = "Microsoft Store app";
                }
                else if (path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) { rec.Verdict = Verdict.Unknown; rec.Detail = "Shortcut: checked on this PC (a shortcut has nothing to look up online)"; cacheable = false; }     // quick: no online look-up, so a bunch of shortcuts scans at once and a broken one can't hold it up
                else if (!S.Cloud) { rec.Verdict = Verdict.Unknown; rec.Detail = "Not signed; online check is turned off"; cacheable = false; }
                else
                {
                    try
                    {
                        string fam;
                        var cymru = Task.Run(() => Cloud.CymruListed(md5));
                        string circlDetail = null;
                        var circl = Task.Run(() => { string dd; var r = Cloud.Circl(sha, out dd); circlDetail = dd; return r; });
                        if (cymru.Wait(1500) && cymru.Result) { rec.Verdict = Verdict.Malicious; rec.Detail = "Listed as malware by Team Cymru"; }
                        else if (S.MbKey.Length > 0 && (fam = Cloud.MalwareBazaar(sha, S.MbKey)) != null)
                        {
                            rec.Verdict = Verdict.Malicious;
                            rec.Detail = "Listed as malware by MalwareBazaar" + (fam.Length > 0 ? " (" + fam + ")" : "");
                        }
                        else
                        {
                            CloudAnswer a = circl.Result; // rethrows if CIRCL couldn't be reached
                            string detail = circlDetail;
                            if (a == CloudAnswer.Bad)
                            {
                                // One list alone, on a file that isn't a program (e.g. a popular .js library), is often a
                                // false alarm: flag it for review but don't auto-quarantine.
                                if (isPe) { rec.Verdict = Verdict.Malicious; rec.Detail = detail; }
                                else { rec.Verdict = Verdict.Unknown; rec.Detail = detail + " · not a program, so not flagged"; }     // one list alone on a text/image/data file is nearly always a false alarm (licences, readmes, icons)
                            }
                            else if (a == CloudAnswer.Good) { rec.Verdict = Verdict.KnownGood; rec.Detail = detail; }
                            else { rec.Verdict = Verdict.Unknown; rec.Detail = "Not signed, and no online record of it yet"; }
                        }
                    }
                    catch
                    {
                        rec.Verdict = Verdict.Unknown; rec.Detail = "Not signed; couldn't reach the online check"; cacheable = false;
                    }
                }
                if (cacheable)
                    lock (gate)
                    {
                        cache[sha] = new CacheEntry { V = rec.Verdict, Detail = rec.Detail, At = DateTime.Now };
                        cacheDirty = true;
                    }
            }

            // Nobody vouches for it: check it against the YARA rules (programs and scripts alike).
            if (rec.Verdict == Verdict.Unknown && Yara.Ready)
            {
                YaraHit y = Yara.Scan(path);
                if (y != null)
                {
                    rec.Verdict = y.Score >= 80 ? Verdict.Malicious : Verdict.Suspicious;
                    rec.Detail = "YARA rule " + y.Rule + (y.Description.Length > 0 ? ": " + y.Description : "");
                    return;
                }
            }

            // Still nothing: look at how the file presents itself.
            if (rec.Verdict == Verdict.Unknown)
            {
                var why = new List<string>();
                // Language (.mui) and metadata (.winmd) files are built like programs but hold no code.
                if (isPe && IsResourceOnlyPe(path)) isPe = false;
                int score = Heuristics(path, isPe, entropy, why);
                // The AI model only looks at programs (it was trained on Windows programs).
                double ai = isPe && Ai != null ? Ai.Score(path) : -1;
                if (ai >= 0)
                {
                    int pct = (int)Math.Round(ai * 100);
                    if (ai >= AiThreshold) { score += ai >= 0.9 ? 3 : 1; why.Insert(0, "AI: " + pct + "% malware-like"); }
                    else rec.Detail += " · AI: " + pct + "% malware-like";
                }
                if (score >= 3) { rec.Verdict = Verdict.Suspicious; rec.Detail = Capital(string.Join("; ", why)); }
            }
        }

        /// <summary>
        /// True for .mui/.mun language files and .winmd metadata files that really are code-free:
        /// .mui/.mun need no entry point and no exports; .winmd needs a .NET metadata header and no native entry point.
        /// A real program renamed to one of these extensions fails the checks and is still flagged.
        /// </summary>
        static bool IsResourceOnlyPe(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext != ".mui" && ext != ".mun" && ext != ".winmd") return false;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var br = new BinaryReader(fs))
                {
                    if (fs.Length < 0x40 || br.ReadUInt16() != 0x5A4D) return false;
                    fs.Position = 0x3C;
                    uint pe = br.ReadUInt32();
                    if (pe < 0x40 || pe + 0x18 + 0x70 > fs.Length) return false;
                    fs.Position = pe;
                    if (br.ReadUInt32() != 0x00004550) return false;            // "PE\0\0"
                    fs.Position = pe + 4 + 16;
                    ushort optSize = br.ReadUInt16();
                    long opt = pe + 4 + 20;
                    fs.Position = opt;
                    ushort magic = br.ReadUInt16();
                    bool pe32 = magic == 0x10B;
                    if (!pe32 && magic != 0x20B) return false;
                    fs.Position = opt + 16;
                    uint entry = br.ReadUInt32();                                // AddressOfEntryPoint
                    long dirs = opt + (pe32 ? 96 : 112);
                    if (dirs + 15 * 8 > opt + optSize || dirs + 15 * 8 > fs.Length) return false;
                    fs.Position = dirs;
                    uint exportRva = br.ReadUInt32(); uint exportSize = br.ReadUInt32();
                    fs.Position = dirs + 14 * 8;
                    uint clrRva = br.ReadUInt32();
                    if (entry != 0) return false;
                    if (ext == ".winmd") return clrRva != 0;
                    return exportRva == 0 && exportSize == 0;
                }
            }
            catch { return false; }
        }

        // file types that are legitimately built like programs (plug-ins, language files, metadata, Python/Node modules)
        static readonly HashSet<string> CodeLikeExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".winmd", ".mui", ".mun", ".pyd", ".node", ".ax", ".ocx", ".bpl", ".rll", ".tlb", ".vst3", ".dle", ".xll" };

        static int Heuristics(string path, bool isPe, double entropy, List<string> why)
        {
            int score = 0;
            string name = Path.GetFileName(path), ext = Path.GetExtension(path);
            string inner = Path.GetExtension(Path.GetFileNameWithoutExtension(path));
            if (RunnableExts.Contains(ext) && DocExts.Contains(inner)) { score += 3; why.Add("pretends to be a " + inner.TrimStart('.') + " file but is really a program"); }
            if (name.IndexOf((char)0x202E) >= 0) { score += 4; why.Add("name uses a trick character to hide its real type"); }
            if (name.Contains("     ")) { score += 3; why.Add("name is padded with spaces to hide its real type"); }
            if (isPe && !RiskyExts.Contains(ext) && !CodeLikeExts.Contains(ext)) { score += 3; why.Add("a program hiding behind a " + (ext.Length > 0 ? ext : "missing") + " extension"); }
            if (RareExts.Contains(ext)) { score += 2; why.Add("rarely-legitimate file type (" + ext + ")"); }
            else if (ScriptExts.Contains(ext)) { score += 1; why.Add("script file"); }
            if (isPe) { score += 1; why.Add("unsigned program"); }
            if (isPe && entropy > 7.3) { score += 1; why.Add("contents look packed or scrambled"); }
            string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (startup.Length > 0 && path.StartsWith(startup, StringComparison.OrdinalIgnoreCase)) { score += 2; why.Add("set to run every time Windows starts"); }
            if (ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)) { string lnk = ShortcutAbuse(path); if (lnk != null) { score += 3; why.Add(lnk); } }
            return score;
        }

        // Shortcut (.lnk) droppers: a shortcut that starts a Windows scripting tool AND carries a strong clue
        // (hidden window, encoded or download-and-run command, web address). Either alone is normal.
        static readonly string[] LnkTools = { "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin", "cmd.exe" };
        static readonly string[] LnkClues = { "-enc", "-windowstyle hidden", "-w hidden", "-nop", "downloadstring", "downloadfile", "invoke-expression", "iex(", "iex ", "http://", "https://", "frombase64string", "-urlcache", "scrobj.dll" };

        static string ShortcutAbuse(string path)
        {
            try
            {
                byte[] b;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length < 76 || fs.Length > (1 << 20)) return null;
                    b = new byte[fs.Length];
                    int got = 0, n;
                    while (got < b.Length && (n = fs.Read(b, got, b.Length - got)) > 0) got += n;
                    if (got < 76) return null;
                }
                if (b[0] != 0x4C || b[1] != 0 || b[2] != 0 || b[3] != 0) return null; // not a shortcut header
                // text inside a shortcut is stored as UTF-16 or ANSI; look at both
                string text = (Encoding.Unicode.GetString(b) + "\n" + Encoding.ASCII.GetString(b)).Replace("\0", "").ToLowerInvariant();
                string tool = null, clue = null;
                foreach (string t in LnkTools) if (text.Contains(t)) { tool = t; break; }
                if (tool == null) return null;
                foreach (string c in LnkClues) if (text.Contains(c)) { clue = c; break; }
                if (clue == null) return null;
                return "shortcut that runs " + tool.Replace(".exe", "") + " with a suspicious command (" + clue.Trim() + ")";
            }
            catch { return null; }
        }

        static string Capital(string s) { return s.Length == 0 ? s : char.ToUpper(s[0]) + s.Substring(1); }
        static string Hex(byte[] b) { var sb = new StringBuilder(b.Length * 2); foreach (byte x in b) sb.Append(x.ToString("x2")); return sb.ToString(); }

        // ---------- quarantine ----------

        static void XorCopy(string from, string to)
        {
            // Stored scrambled so a quarantined file can't be run by accident.
            using (var a = new FileStream(from, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            using (var b = new FileStream(to, FileMode.CreateNew, FileAccess.Write))
            {
                var buf = new byte[1 << 16]; int n;
                while ((n = a.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++) buf[i] ^= 0x5A;
                    b.Write(buf, 0, n);
                }
            }
        }

        bool DoQuarantine(ScanRecord r)
        {
            string id = Guid.NewGuid().ToString("N");
            string dest = Path.Combine(QuarDir, id + ".quar");
            try
            {
                XorCopy(r.FilePath, dest);
                File.SetAttributes(r.FilePath, FileAttributes.Normal);
                File.Delete(r.FilePath);
            }
            catch (Exception ex)
            {
                try { File.Delete(dest); } catch { }
                r.Detail += " — could not quarantine (" + ex.Message.TrimEnd('.') + ")";
                return false;
            }
            lock (gate)
            {
                quarantine.Add(new QuarantineItem { Id = id, OriginalPath = r.FilePath, Sha256 = r.Sha256, Time = DateTime.Now, Reason = r.Detail });
                SaveQuarantine();
            }
            r.Quarantined = true;
            WritePlaceholder(r.FilePath, id);
            return true;
        }

        // ---- a quarantined file leaves a small stand-in under its old name, so its icon stays (red) and double-clicking it
        //      can't run anything. Scanning the stand-in with TinyGuard re-checks the real file and gives it back only if it is clean now.
        const string PlaceholderMark = "TINYGUARD-QUARANTINED:";

        static void WritePlaceholder(string path, string id)
        {
            try
            {
                string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd((char)92) + (char)92;
                if (!path.StartsWith(home, StringComparison.OrdinalIgnoreCase) || File.Exists(path) || Directory.Exists(path)) return;
                File.WriteAllText(path, PlaceholderMark + id + "\r\nTinyGuard removed this file because it looked dangerous, and keeps the real file locked away.\r\nTo look at it again: right-click this icon and choose \"Scan with TinyGuard\" (or open TinyGuard > Quarantine).\r\n");
            }
            catch { }
        }

        /// <summary>The quarantine id if the file is one of our stand-ins, else null.</summary>
        static string PlaceholderId(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length < 30 || fi.Length > 600) return null;
                string t = File.ReadAllText(path);
                if (!t.StartsWith(PlaceholderMark, StringComparison.Ordinal)) return null;
                int e = t.IndexOfAny(new[] { (char)13, (char)10 });
                return e > PlaceholderMark.Length ? t.Substring(PlaceholderMark.Length, e - PlaceholderMark.Length) : null;
            }
            catch { return null; }
        }

        void RecheckQuarantined(string path, string id)
        {
            QuarantineItem q;
            lock (gate) q = quarantine.FirstOrDefault(x => x.Id == id);
            string src = Path.Combine(QuarDir, id + ".quar");
            if (q == null || !File.Exists(src)) { try { File.Delete(path); } catch { } Ledger(path, Verdict.Clean, false, false, "Quarantined copy is gone"); return; }
            string tmpDir = Path.Combine(QuarDir, "check-" + id), tmp = Path.Combine(tmpDir, Path.GetFileName(q.OriginalPath));
            try
            {
                try { Directory.Delete(tmpDir, true); } catch { }
                Directory.CreateDirectory(tmpDir);
                XorCopy(src, tmp);
                string sha, md5; bool isPe; double entropy;
                if (!Hash(tmp, out sha, out md5, out isPe, out entropy)) return;
                SetProg(path, 0.8);
                var rec = new ScanRecord { Time = DateTime.Now, FilePath = tmp, Sha256 = sha };
                Classify(rec, md5, isPe, entropy);
                rec.FilePath = path;
                if (!rec.IsThreat)
                {
                    File.Delete(path);
                    XorCopy(src, path);
                    File.Delete(src);
                    lock (gate) { quarantine.Remove(q); SaveQuarantine(); }
                    Ledger(path, Verdict.Clean, false, false, "Re-checked: clean, given back");
                }
                else
                {
                    rec.Detail = "Re-checked: " + rec.Detail; rec.Quarantined = true;
                    Ledger(path, rec.Verdict, true, false, rec.Detail);
                }
            }
            catch { }
            finally { try { Directory.Delete(tmpDir, true); } catch { } }
        }

        public bool Quarantine(ScanRecord r)
        {
            if (r.Quarantined || !File.Exists(r.FilePath)) return false;
            bool ok = DoQuarantine(r);
            if (ok) Ledger(r);
            lock (gate) SaveHistory();
            Bump();
            return ok;
        }

        public void MarkSafe(ScanRecord r)
        {
            lock (gate)
            {
                allowed.Add(r.Sha256);
                blocked.Remove(r.Sha256);
                File.WriteAllLines(AllowFile, allowed);
                File.WriteAllLines(BlockFile, blocked);
                foreach (var h in history.Where(h => h.Sha256 == r.Sha256 && !h.Quarantined))
                { h.Verdict = Verdict.Clean; h.Detail = "Marked safe by you"; }
                SaveHistory();
            }
            Ledger(r.FilePath, Verdict.Clean, false, false, "Marked safe by you");
            Bump();
        }

        /// <summary>Flag a file as suspicious by hand (the opposite of Mark as safe).</summary>
        public void Flag(ScanRecord r)
        {
            lock (gate)
            {
                allowed.Remove(r.Sha256);
                File.WriteAllLines(AllowFile, allowed);
                foreach (var h in history.Where(h => h.Sha256 == r.Sha256 && !h.Quarantined))
                { h.Verdict = Verdict.Suspicious; h.Detail = "Flagged by you"; }
                SaveHistory();
            }
            Ledger(r.FilePath, Verdict.Suspicious, false, false, "Flagged by you");
            Bump();
        }

        public string Restore(QuarantineItem q)
        {
            string src = Path.Combine(QuarDir, q.Id + ".quar");
            string target = q.OriginalPath;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                if (File.Exists(target) && PlaceholderId(target) == q.Id) File.Delete(target);
                if (File.Exists(target))
                    target =Path.Combine(Path.GetDirectoryName(target),
                        Path.GetFileNameWithoutExtension(target) + " (restored)" + Path.GetExtension(target));
                lock (gate) { allowed.Add(q.Sha256); File.WriteAllLines(AllowFile, allowed); }
                XorCopy(src, target);
                File.Delete(src);
            }
            catch (Exception ex) { return ex.Message; }
            lock (gate) { quarantine.Remove(q); SaveQuarantine(); }
            Ledger(q.OriginalPath, Verdict.Clean, false, false, "Restored by you");
            Bump();
            return null;
        }

        /// <summary>Overwrites the file with zeros, then deletes it, retrying if something has it open. Returns an error message or null.</summary>
        static string WipeAndDelete(string file)
        {
            string last = null;
            for (int i = 0; i < 6; i++)
            {
                try
                {
                    if (!File.Exists(file)) return null;
                    File.SetAttributes(file, FileAttributes.Normal);
                    try
                    {
                        using (var fs = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None))
                        {
                            long left = fs.Length; var zeros = new byte[1 << 16];
                            while (left > 0) { int n = (int)Math.Min(left, zeros.Length); fs.Write(zeros, 0, n); left -= n; }
                            fs.Flush(true);
                        }
                    }
                    catch { } // wiping is best effort; deleting is what matters
                    File.Delete(file);
                    if (!File.Exists(file)) return null;
                }
                catch (Exception ex) { last = ex.Message; }
                Thread.Sleep(300);
            }
            return last ?? "the file is still on the disk after trying to delete it";
        }

        /// <summary>Removes a quarantined file from the disk for good. The list entry only goes once the file is really gone.</summary>
        public string DeleteQuarantined(QuarantineItem q)
        {
            string err = WipeAndDelete(Path.Combine(QuarDir, q.Id + ".quar"));
            if (err != null) return err;
            try { if (File.Exists(q.OriginalPath) && PlaceholderId(q.OriginalPath) == q.Id) File.Delete(q.OriginalPath); } catch { }
            lock (gate) { quarantine.Remove(q); SaveQuarantine(); }
            Bump();
            return null;
        }

        /// <summary>Deletes everything in quarantine, including leftover files that have no list entry. Returns how many couldn't be deleted.</summary>
        public int DeleteAllQuarantined()
        {
            int failed = 0;
            foreach (var q in QuarantineSnapshot()) if (DeleteQuarantined(q) != null) failed++;
            try
            {
                foreach (string f in Directory.GetFiles(QuarDir, "*.quar"))
                {
                    string id = Path.GetFileNameWithoutExtension(f);
                    bool tracked; lock (gate) tracked = quarantine.Any(x => x.Id == id);
                    if (!tracked && WipeAndDelete(f) != null) failed++;
                }
            }
            catch { }
            Bump();
            return failed;
        }

        /// <summary>Quarantined files on disk that TinyGuard has lost track of (from older versions that hid delete failures).</summary>
        public int LeftoverCount()
        {
            try
            {
                lock (gate) return Directory.GetFiles(QuarDir, "*.quar").Count(f => !quarantine.Any(x => x.Id == Path.GetFileNameWithoutExtension(f)));
            }
            catch { return 0; }
        }

        // ---------- views for the UI ----------

        public List<ScanRecord> Snapshot() { lock (gate) { var l = history.ToList(); l.Reverse(); return l.OrderByDescending(r => r.Verdict >= Verdict.Suspicious ? (int)r.Verdict : 0).ToList(); } }     // red first, then yellow, then the rest newest first (the sort is stable)
        public List<QuarantineItem> QuarantineSnapshot() { lock (gate) { var l = quarantine.ToList(); l.Reverse(); return l; } }

        public void Stats(out int checkedToday, out int threats, out int unknownToday, out int inQuarantine)
        {
            lock (gate)
            {
                DateTime today = DateTime.Today;
                checkedToday = history.Count(h => h.Time >= today);
                threats = history.Count(h => h.IsThreat);
                unknownToday = history.Count(h => h.Time >= today && h.Verdict == Verdict.Unknown);
                inQuarantine = quarantine.Count;
            }
        }

        public void SettingsChanged() { S.Save(); RebuildWatchers(); }

        // ---------- persistence ----------

        static string Clean(string s) { return (s ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' '); }

        static string Line(ScanRecord r)
        {
            return string.Join("\t", r.Time.Ticks.ToString(), Clean(r.FilePath), r.Sha256, ((int)r.Verdict).ToString(), Clean(r.Detail), r.Quarantined ? "1" : "0");
        }

        void SaveHistory() { try { File.WriteAllLines(HistoryFile, history.Select(Line)); } catch { } }

        void SaveQuarantine()
        {
            try
            {
                File.WriteAllLines(QuarFile, quarantine.Select(q =>
                    string.Join("\t", q.Id, Clean(q.OriginalPath), q.Sha256, q.Time.Ticks.ToString(), Clean(q.Reason))));
            }
            catch { }
        }

        void SaveCache()
        {
            try
            {
                string[] lines;
                lock (gate)
                {
                    lines = cache.Select(kv => string.Join("\t", kv.Key, ((int)kv.Value.V).ToString(), Clean(kv.Value.Detail), kv.Value.At.Ticks.ToString())).ToArray();
                    cacheDirty = false;
                }
                File.WriteAllLines(CacheFile, lines);
                lastCacheSave = DateTime.Now;
            }
            catch { }
        }

        void LoadState()
        {
            try
            {
                if (File.Exists(HistoryFile))
                {
                    string[] lines = File.ReadAllLines(HistoryFile);
                    foreach (string l in lines.Skip(Math.Max(0, lines.Length - MaxHistory)))
                    {
                        string[] p = l.Split('\t');
                        if (p.Length < 6) continue;
                        history.Add(new ScanRecord
                        {
                            Time = new DateTime(long.Parse(p[0])), FilePath = p[1], Sha256 = p[2],
                            Verdict = (Verdict)int.Parse(p[3]), Detail = p[4], Quarantined = p[5] == "1"
                        });
                    }
                    if (lines.Length > MaxHistory * 2) SaveHistory();
                }
            }
            catch { }
            try
            {
                if (File.Exists(QuarFile))
                    foreach (string l in File.ReadAllLines(QuarFile))
                    {
                        string[] p = l.Split('\t');
                        if (p.Length < 5 || !File.Exists(Path.Combine(QuarDir, p[0] + ".quar"))) continue;
                        quarantine.Add(new QuarantineItem { Id = p[0], OriginalPath = p[1], Sha256 = p[2], Time = new DateTime(long.Parse(p[3])), Reason = p[4] });
                    }
            }
            catch { }
            try
            {
                if (File.Exists(CacheFile))
                    foreach (string l in File.ReadAllLines(CacheFile))
                    {
                        string[] p = l.Split('\t');
                        if (p.Length < 4) continue;
                        cache[p[0]] = new CacheEntry { V = (Verdict)int.Parse(p[1]), Detail = p[2], At = new DateTime(long.Parse(p[3])) };
                    }
            }
            catch { }
            try
            {
                if (File.Exists(SeenFile))
                    foreach (string l in File.ReadAllLines(SeenFile))
                    {
                        int t = l.LastIndexOf('\t');
                        if (t > 0) seenPrograms[l.Substring(0, t)] = (Verdict)int.Parse(l.Substring(t + 1));
                    }
            }
            catch { }
            try
            {
                if (File.Exists(LedgerFile))
                    foreach (string l in File.ReadAllLines(LedgerFile))
                    {
                        string[] p = l.Split('\t');
                        if (p.Length < 5) continue;
                        ledger[p[0]] = new LedgerEntry { Verdict = (Verdict)int.Parse(p[1]), Time = new DateTime(long.Parse(p[2])), Quarantined = p[3].Contains("q"), Deleted = p[3].Contains("d"), Deep = p[3].Contains("x"), Detail = p[4] };
                    }
            }
            catch { }
            // earlier versions flagged ordinary files (licences, readmes, images) that one list called malware: take those flags back
            Func<string, bool> oldFalseAlarm = d => d != null && d.Contains("not a program, so unconfirmed");
            history.RemoveAll(h => h.Verdict == Verdict.Suspicious && oldFalseAlarm(h.Detail));
            foreach (var k in ledger.Where(x => x.Value.Verdict == Verdict.Suspicious && oldFalseAlarm(x.Value.Detail)).Select(x => x.Key).ToList()) ledger[k].Verdict = Verdict.Unknown;
            SaveHistory(); ledgerDirty = true;
            LoadHashes(BlockFile, blocked);
            LoadHashes(AllowFile, allowed);
        }

        static void LoadHashes(string file, HashSet<string> into)
        {
            try
            {
                if (!File.Exists(file)) return;
                foreach (string l in File.ReadAllLines(file))
                {
                    string h = l.Trim().ToLowerInvariant();
                    if (h.Length == 64) into.Add(h);
                }
            }
            catch { }
        }

        public void Dispose()
        {
            disposed = true;
            try { Shield.Dispose(); } catch { }
            timer.Dispose();
            procs.Dispose();
            if (Net != null) Net.Dispose();
            lock (watchers) { foreach (var w in watchers) w.Dispose(); watchers.Clear(); }
            if (cacheDirty) SaveCache();
            Deep.Stop();
            if (ledgerDirty) SaveLedger();
        }
    }
}
