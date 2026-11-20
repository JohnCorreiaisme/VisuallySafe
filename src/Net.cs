using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace VisuallySafe
{
    static class Admin
    {
        public static bool IsAdmin
        {
            get
            {
                try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
                catch { return false; }
            }
        }
    }

    /// <summary>One program's network traffic: totals plus one-second buckets for the last minute.</summary>
    class AppTraffic
    {
        public const int Seconds = 60;
        public string Path = "", Name = "";
        public readonly long[] InHist = new long[Seconds], OutHist = new long[Seconds]; // oldest .. newest
        public long CurIn, CurOut, TotalIn, TotalOut;
        public DateTime LastActive = DateTime.MinValue;
        public bool Blocked;
        public bool CanBlock { get { return Path.Length > 2 && Path[1] == ':'; } }
        public long RateIn { get { return InHist[Seconds - 1]; } }
        public long RateOut { get { return OutHist[Seconds - 1]; } }
        public long Recent { get { long s = 0; for (int i = Seconds - 5; i < Seconds; i++) s += InHist[i] + OutHist[i]; return s; } }
    }

    /// <summary>
    /// Live per-program upload/download using Windows' own kernel network events (ETW).
    /// Needs administrator rights. Counts TCP and UDP (so QUIC/HTTP3 browser traffic too).
    /// </summary>
    class NetMonitor : IDisposable
    {
        const string SessionName = "VisuallySafe Network";
        static readonly Guid SessionGuid = new Guid("6d3f1a4e-2b7c-4f1e-9a51-3c0b8e7d2f10");
        static readonly Guid TcpIpGuid = new Guid("9a280ac0-c8e0-11d1-84e2-00c04fb998a2");
        static readonly Guid UdpIpGuid = new Guid("bf3a50c5-a9c9-4988-a005-2df0b7c80f80");
        static readonly Guid ProcessGuid = new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c");
        readonly Dictionary<int, string> startedPaths = new Dictionary<int, string>();

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int StartTrace(out ulong handle, string name, IntPtr props);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int ControlTrace(ulong handle, string name, IntPtr props, uint code);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern ulong OpenTrace(IntPtr logfile);
        [DllImport("advapi32.dll")] static extern int ProcessTrace(ulong[] handles, int count, IntPtr start, IntPtr end);
        [DllImport("advapi32.dll")] static extern int CloseTrace(ulong handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate void EventCallback(IntPtr record);

        readonly Dictionary<string, AppTraffic> apps = new Dictionary<string, AppTraffic>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<int, AppTraffic> byPid = new Dictionary<int, AppTraffic>();
        readonly EventCallback callback; // kept alive for as long as Windows may call it
        readonly Timer roll;
        IntPtr logfile = IntPtr.Zero, nameBuf = IntPtr.Zero;
        ulong traceHandle;
        Thread pump;
        public string Error { get; private set; }
        public bool Running { get; private set; }
        public long EventsSeen;

        public NetMonitor()
        {
            callback = OnEvent;
            roll = new Timer(_ => Roll(), null, 1000, 1000);
        }

        static IntPtr MakeProps()
        {
            const int size = 120 + 1024 * 2;
            IntPtr p = Marshal.AllocHGlobal(size);
            for (int i = 0; i < size; i++) Marshal.WriteByte(p, i, 0);
            Marshal.WriteInt32(p, 0, size);                          // Wnode.BufferSize
            Marshal.Copy(SessionGuid.ToByteArray(), 0, p + 24, 16);  // Wnode.Guid
            Marshal.WriteInt32(p, 40, 1);                            // Wnode.ClientContext = QPC clock
            Marshal.WriteInt32(p, 44, 0x20000);                      // WNODE_FLAG_TRACED_GUID
            Marshal.WriteInt32(p, 48, 64);                           // BufferSize (KB)
            Marshal.WriteInt32(p, 64, 0x100 | 0x2000000);            // real time + system logger mode
            Marshal.WriteInt32(p, 68, 1);                            // FlushTimer: deliver every second
            Marshal.WriteInt32(p, 72, 0x10000 | 0x1);                // EnableFlags: NETWORK_TCPIP + PROCESS
            Marshal.WriteInt32(p, 116, 120);                         // LoggerNameOffset
            return p;
        }

        public bool Start()
        {
            if (Running) return true;
            if (!Admin.IsAdmin) { Error = "needs administrator rights"; return false; }
            IntPtr props = MakeProps();
            try
            {
                int rc = StartTrace(out traceHandle, SessionName, props);
                if (rc == 183) // left over from a crash: stop it and start fresh
                {
                    IntPtr stop = MakeProps();
                    ControlTrace(0, SessionName, stop, 1);
                    Marshal.FreeHGlobal(stop);
                    for (int i = 0; i < 120 + 2048; i++) Marshal.WriteByte(props, i, 0);
                    Marshal.FreeHGlobal(props);
                    props = MakeProps();
                    rc = StartTrace(out traceHandle, SessionName, props);
                }
                if (rc != 0) { Error = "couldn't start network events (code " + rc + ")"; return false; }
            }
            finally { Marshal.FreeHGlobal(props); }

            // EVENT_TRACE_LOGFILEW (448 bytes on 64-bit): LoggerName @8, ProcessTraceMode @28, EventRecordCallback @424.
            logfile = Marshal.AllocHGlobal(448);
            for (int i = 0; i < 448; i++) Marshal.WriteByte(logfile, i, 0);
            nameBuf = Marshal.StringToHGlobalUni(SessionName);
            Marshal.WriteIntPtr(logfile, 8, nameBuf);
            Marshal.WriteInt32(logfile, 28, 0x100 | 0x10000000); // real time + EVENT_RECORD callbacks
            Marshal.WriteIntPtr(logfile, 424, Marshal.GetFunctionPointerForDelegate(callback));
            ulong h = OpenTrace(logfile);
            if (h == ulong.MaxValue) { Error = "couldn't open network events"; StopSession(); return false; }

            pump = new Thread(() =>
            {
                try { ProcessTrace(new[] { h }, 1, IntPtr.Zero, IntPtr.Zero); } catch { }
                CloseTrace(h);
            }) { IsBackground = true, Name = "Visually Safe network events" };
            pump.Start();
            Running = true;
            Error = null;
            return true;
        }

        void OnEvent(IntPtr rec)
        {
            try
            {
                // EVENT_RECORD: ProviderId @24, Opcode @45, UserDataLength @86, UserData @96.
                byte op = Marshal.ReadByte(rec, 45);
                if (op == 1 || op == 3) { ProcessStart(rec); return; }
                bool send = op == 10 || op == 26, recv = op == 11 || op == 27;
                if (!send && !recv) return;
                var g = new byte[16];
                Marshal.Copy(rec + 24, g, 0, 16);
                var provider = new Guid(g);
                if (provider != TcpIpGuid && provider != UdpIpGuid) return;
                if (Marshal.ReadInt16(rec, 86) < 8) return;
                IntPtr data = Marshal.ReadIntPtr(rec, 96);
                int pid = Marshal.ReadInt32(data, 0);
                int size = Marshal.ReadInt32(data, 4);
                if (size <= 0) return;
                Interlocked.Increment(ref EventsSeen);
                lock (apps)
                {
                    AppTraffic a = For(pid);
                    if (send) { a.CurOut += size; a.TotalOut += size; }
                    else { a.CurIn += size; a.TotalIn += size; }
                    a.LastActive = DateTime.Now;
                }
            }
            catch { }
        }

        /// <summary>Kernel process start (1) / already-running (3) event: remember PID -> program path.</summary>
        void ProcessStart(IntPtr rec)
        {
            var g = new byte[16];
            Marshal.Copy(rec + 24, g, 0, 16);
            if (new Guid(g) != ProcessGuid) return;
            int len = (ushort)Marshal.ReadInt16(rec, 86);
            IntPtr d = Marshal.ReadIntPtr(rec, 96);
            if (len < 48) return;
            // Process_V4_TypeGroup1 on 64-bit: UniqueProcessKey(8) ProcessId(4) ParentId(4) SessionId(4)
            // ExitStatus(4) DirectoryTableBase(8) Flags(4) UserSID(variable) ImageFileName(ANSI) CommandLine(UTF-16)
            int pid = Marshal.ReadInt32(d, 8);
            int o = 36;
            if (Marshal.ReadInt32(d, o) == 0) o += 4;                      // no SID
            else { o += 16; o += 8 + 4 * Marshal.ReadByte(d, o + 1); }     // TOKEN_USER header, then the SID
            if (o >= len) return;
            string image = Marshal.PtrToStringAnsi(d + o) ?? "";
            o += image.Length + 1;
            string cmd = o < len ? Marshal.PtrToStringUni(d + o) ?? "" : "";
            string path = image;
            string first = cmd.StartsWith("\"") ? cmd.Substring(1).Split('"')[0] : cmd.Split(' ')[0];
            if (first.Length > 3 && first[1] == ':' && first.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) path = first;
            if (path.Length == 0) return;
            lock (apps) { startedPaths[pid] = path; byPid.Remove(pid); }
        }

        AppTraffic For(int pid)
        {
            AppTraffic a;
            if (byPid.TryGetValue(pid, out a)) return a;
            string started;
            startedPaths.TryGetValue(pid, out started);
            string live = pid == 0 || pid == 4 ? "System" : ProcWatch.PathOf(pid);
            string path = live ?? started ?? ("Process " + pid);
            if (!apps.TryGetValue(path, out a))
            {
                a = new AppTraffic { Path = path, Name = path.Contains("\\") ? System.IO.Path.GetFileName(path) : path };
                apps[path] = a;
            }
            byPid[pid] = a;
            return a;
        }

        void Roll()
        {
            if (demo) return;
            lock (apps)
            {
                foreach (var a in apps.Values)
                {
                    Array.Copy(a.InHist, 1, a.InHist, 0, AppTraffic.Seconds - 1);
                    Array.Copy(a.OutHist, 1, a.OutHist, 0, AppTraffic.Seconds - 1);
                    a.InHist[AppTraffic.Seconds - 1] = a.CurIn;
                    a.OutHist[AppTraffic.Seconds - 1] = a.CurOut;
                    a.CurIn = a.CurOut = 0;
                }
                // PIDs get reused; forget the mapping now and then so a new program isn't credited to an old one.
                if (DateTime.Now.Second % 20 == 0) byPid.Clear();
            }
        }

        /// <summary>Programs seen in the last 15 minutes, busiest first, plus everything blocked.</summary>
        public List<AppTraffic> Snapshot(HashSet<string> blocked)
        {
            lock (apps)
            {
                foreach (string b in blocked)
                    if (!apps.ContainsKey(b)) apps[b] = new AppTraffic { Path = b, Name = System.IO.Path.GetFileName(b) };
                DateTime cutoff = DateTime.Now.AddMinutes(-15);
                foreach (var a in apps.Values) a.Blocked = blocked.Contains(a.Path);
                return apps.Values.Where(a => a.Blocked || a.LastActive >= cutoff)
                           .OrderByDescending(a => a.Recent).ThenByDescending(a => a.LastActive).ToList();
            }
        }

        public void Totals(out long down, out long up)
        {
            down = up = 0;
            lock (apps) foreach (var a in apps.Values) { down += a.RateIn; up += a.RateOut; }
        }

        /// <summary>Developer aid: fill in made-up traffic so the Network page can be looked at without admin rights.</summary>
        public void Demo()
        {
            var rnd = new Random(7);
            string[][] progs = {
                new[] { @"C:\Program Files\Google\Chrome\Application\chrome.exe", "900000", "60000" },
                new[] { @"C:\Program Files (x86)\Steam\steam.exe", "2400000", "20000" },
                new[] { @"C:\Users\Example\AppData\Local\Discord\app-1.0\Discord.exe", "40000", "35000" },
                new[] { @"C:\Windows\System32\svchost.exe", "8000", "3000" },
                new[] { @"C:\Users\Example\Downloads\mystery-tool.exe", "0", "0" } };
            lock (apps)
                for (int k = 0; k < progs.Length; k++)
                {
                    var a = new AppTraffic { Path = progs[k][0], Name = System.IO.Path.GetFileName(progs[k][0]), LastActive = DateTime.Now };
                    long dn = long.Parse(progs[k][1]), up = long.Parse(progs[k][2]);
                    for (int i = 0; i < AppTraffic.Seconds; i++)
                    {
                        double wave = 0.55 + 0.45 * Math.Sin(i / (4.0 + k) + k);
                        a.InHist[i] = (long)(dn * wave * (0.7 + 0.6 * rnd.NextDouble()));
                        a.OutHist[i] = (long)(up * (1 - wave * 0.5) * (0.6 + 0.8 * rnd.NextDouble()));
                        a.TotalIn += a.InHist[i]; a.TotalOut += a.OutHist[i];
                    }
                    apps[a.Path] = a;
                }
            demo = true;
            Running = true;
        }
        bool demo;

        void StopSession()
        {
            IntPtr p = MakeProps();
            ControlTrace(0, SessionName, p, 1); // EVENT_TRACE_CONTROL_STOP; ends ProcessTrace too
            Marshal.FreeHGlobal(p);
        }

        public void Dispose()
        {
            roll.Dispose();
            if (Running) { Running = false; StopSession(); }
            if (pump != null) pump.Join(800);
        }
    }

    /// <summary>Blocks a program's internet access with Windows Firewall rules (needs administrator rights).</summary>
    static class Firewall
    {
        const string Group = "VisuallySafe";
        static bool Ours(string g) { return g == Group || g == "TinyGuard"; }       // rules made before the rename

        static dynamic Policy() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); }

        public static HashSet<string> Blocked()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (dynamic r in Policy().Rules)
                {
                    string g = r.Grouping, app = r.ApplicationName;
                    if (Ours(g) && !string.IsNullOrEmpty(app) && r.Enabled) set.Add(app);
                }
            }
            catch { }
            return set;
        }

        public static string Block(string path)
        {
            try
            {
                path = Path.GetFullPath(path); // Windows Firewall silently ignores relative program paths
                dynamic policy = Policy();
                foreach (int dir in new[] { 2, 1 }) // outbound, inbound
                {
                    dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                    rule.Name = "VisuallySafe block " + (dir == 2 ? "out" : "in") + ": " + path;
                    rule.Description = "Added by Visually Safe. Unblock it from Visually Safe's Network page.";
                    rule.ApplicationName = path;
                    rule.Action = 0;           // block
                    rule.Direction = dir;
                    rule.Enabled = true;
                    rule.Profiles = 0x7FFFFFFF; // all network types
                    rule.Grouping = Group;
                    policy.Rules.Add(rule);
                }
                return null;
            }
            catch (Exception ex) { return ex.GetBaseException().Message; }
        }

        public static string Unblock(string path)
        {
            try
            {
                path = Path.GetFullPath(path);
                dynamic policy = Policy();
                var names = new List<string>();
                foreach (dynamic r in policy.Rules)
                {
                    string g = r.Grouping, app = r.ApplicationName;
                    if (Ours(g) && string.Equals(app, path, StringComparison.OrdinalIgnoreCase)) names.Add((string)r.Name);
                }
                foreach (string n in names) policy.Rules.Remove(n);
                return null;
            }
            catch (Exception ex) { return ex.GetBaseException().Message; }
        }
    }
}
