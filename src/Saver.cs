using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace TinyGuard
{
    static class IdleInfo
    {
        [StructLayout(LayoutKind.Sequential)] struct LASTINPUTINFO { public uint cbSize, dwTime; }
        [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO p);
        [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport("user32.dll")] static extern IntPtr GetDesktopWindow();
        [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
        [StructLayout(LayoutKind.Sequential)] struct RECT { public int L, T, R, B; }

        public static uint LastInputTick()
        {
            var i = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO)) };
            return GetLastInputInfo(ref i) ? i.dwTime : 0;
        }

        public static int IdleMs() { return (int)((uint)Environment.TickCount - LastInputTick()); }

        /// <summary>True when the front window covers a whole screen (a game or a video), when a screen saver shouldn't start.</summary>
        public static bool FullscreenAppActive()
        {
            try
            {
                IntPtr h = GetForegroundWindow();
                if (h == IntPtr.Zero || h == GetDesktopWindow() || h == GetShellWindow()) return false;
                RECT r; if (!GetWindowRect(h, out r)) return false;
                var sc = Screen.FromRectangle(new Rectangle(r.L, r.T, r.R - r.L, r.B - r.T)).Bounds;
                return r.L <= sc.Left && r.T <= sc.Top && r.R >= sc.Right && r.B >= sc.Bottom;
            }
            catch { return false; }
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Network picture: live connections as glowing endpoints around the screen, with particles flowing to and from the centre

    class NetConn
    {
        public string Key = "", Name = "", Host = "";
        public IPAddress Addr; public int Port, Pid;
        public double Down, Up;
        public DateTime Born = DateTime.Now, Seen = DateTime.Now;
        public bool Lan;
        public double Angle;
    }

    class NetSampler
    {
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern int GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int cls, int reserved);

        readonly Engine eng;
        Thread th; volatile bool stop;
        public volatile NetConn[] Conns = new NetConn[0];
        public double GlobalDown, GlobalUp;
        readonly Dictionary<string, NetConn> live = new Dictionary<string, NetConn>();
        readonly Dictionary<string, string> hosts = new Dictionary<string, string>();
        readonly Dictionary<int, string> names = new Dictionary<int, string>();
        long lastRx, lastTx; DateTime lastAt = DateTime.MinValue;

        public NetSampler(Engine e) { eng = e; }
        public void Start() { th = new Thread(Loop) { IsBackground = true, Priority = ThreadPriority.BelowNormal, Name = "Visually Safe network picture" }; th.Start(); }
        public void Stop() { stop = true; }

        void Loop() { while (!stop) { try { Sample(); } catch { } for (int i = 0; i < 10 && !stop; i++) Thread.Sleep(100); } }

        static int NetPort(int raw) { return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF); }

        class Row { public IPAddress Remote; public int Port, Pid; }

        static List<Row> ReadTcp(bool v6)
        {
            var list = new List<Row>();
            int size = 0, af = v6 ? 23 : 2;
            GetExtendedTcpTable(IntPtr.Zero, ref size, true, af, 5, 0);
            IntPtr buf = Marshal.AllocHGlobal(size + 64);
            try
            {
                if (GetExtendedTcpTable(buf, ref size, true, af, 5, 0) != 0) return list;
                int n = Marshal.ReadInt32(buf), row = v6 ? 56 : 24;
                for (int i = 0; i < n; i++)
                {
                    IntPtr r = buf + 4 + i * row;
                    int state = Marshal.ReadInt32(r, v6 ? 48 : 0);
                    if (state != 5) continue;   // established
                    IPAddress ra; int rport, pid;
                    if (!v6) { ra = new IPAddress((uint)Marshal.ReadInt32(r, 12) & 0xFFFFFFFFu); rport = NetPort(Marshal.ReadInt32(r, 16)); pid = Marshal.ReadInt32(r, 20); }
                    else { var a = new byte[16]; Marshal.Copy(r + 24, a, 0, 16); ra = new IPAddress(a); rport = NetPort(Marshal.ReadInt32(r, 44)); pid = Marshal.ReadInt32(r, 52); }
                    if (IPAddress.IsLoopback(ra) || ra.Equals(IPAddress.Any) || ra.Equals(IPAddress.IPv6Any)) continue;
                    list.Add(new Row { Remote = ra, Port = rport, Pid = pid });
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return list;
        }

        string NameOf(int pid)
        {
            string n;
            if (names.TryGetValue(pid, out n)) return n;
            string p = pid == 4 ? "System" : ProcWatch.PathOf(pid);
            n = p == null ? "process " + pid : p.Contains("\\") ? Path.GetFileName(p) : p;
            if (names.Count > 2000) names.Clear();
            names[pid] = n; return n;
        }

        void Sample()
        {
            // overall speed from the network cards
            long rx = 0, tx = 0;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                if (nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback && nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    try { var st = nic.GetIPv4Statistics(); rx += st.BytesReceived; tx += st.BytesSent; } catch { }
            var now = DateTime.Now;
            if (lastAt != DateTime.MinValue) { double dt = Math.Max(0.2, (now - lastAt).TotalSeconds); GlobalDown = Math.Max(0, (rx - lastRx) / dt); GlobalUp = Math.Max(0, (tx - lastTx) / dt); }
            lastRx = rx; lastTx = tx; lastAt = now;

            var rows = ReadTcp(false).Concat(ReadTcp(true)).ToList();
            var seenKeys = new HashSet<string>();
            foreach (var r in rows)
            {
                string key = r.Pid + "|" + r.Remote + "|" + r.Port;
                seenKeys.Add(key);
                NetConn c;
                if (!live.TryGetValue(key, out c))
                {
                    c = new NetConn { Key = key, Addr = r.Remote, Port = r.Port, Pid = r.Pid, Name = NameOf(r.Pid), Lan = NetTools.IsPrivate(r.Remote) };
                    uint h = 2166136261; foreach (char ch in r.Remote.ToString()) { h ^= ch; h *= 16777619; }
                    c.Angle = (h % 6283) / 1000.0;
                    live[key] = c;
                }
                c.Seen = now;
            }
            foreach (var k in live.Where(kv => (now - kv.Value.Seen).TotalSeconds > 2.5).Select(kv => kv.Key).ToList()) live.Remove(k);

            // how fast each one is going: exact per-program speeds if the network monitor runs, otherwise the overall speed shared out
            var list = live.Values.ToList();
            Dictionary<string, double[]> app = null;
            if (eng.Net != null && eng.Net.Running)
            {
                app = new Dictionary<string, double[]>(StringComparer.OrdinalIgnoreCase);
                try { foreach (var a in eng.Net.Snapshot(new HashSet<string>())) app[a.Name] = new double[] { a.RateIn, a.RateOut }; } catch { }
            }
            var inet = list.Where(c => !c.Lan).ToList();
            var share = inet.Count > 0 ? inet : list;
            foreach (var c in list)
            {
                double[] rate;
                if (app != null && app.TryGetValue(c.Name, out rate)) { int same = list.Count(x => x.Name == c.Name); c.Down = rate[0] / same; c.Up = rate[1] / same; }
                else if (share.Contains(c)) { c.Down = GlobalDown / share.Count; c.Up = GlobalUp / share.Count; }
                else { c.Down = c.Up = 0; }
                string key = c.Addr.ToString(); string host;
                lock (hosts)
                {
                    if (!hosts.TryGetValue(key, out host))
                    {
                        hosts[key] = ""; var addr = c.Addr;
                        Task.Run(() => { try { var t = Task.Run(() => Dns.GetHostEntry(addr).HostName); if (t.Wait(2000)) lock (hosts) hosts[addr.ToString()] = t.Result; } catch { } });
                    }
                }
                c.Host = host ?? "";
            }
            Conns = list.OrderByDescending(c => c.Down + c.Up).Take(40).ToArray();
        }
    }

    class NetArt
    {
        class P { public NetConn C; public bool Down; public double Age, Life; public float Off; }
        readonly List<P> ps = new List<P>();
        readonly Random rnd = new Random();
        readonly Dictionary<NetConn, double> acc = new Dictionary<NetConn, double>();
        double last = -1;

        static PointF Bez(PointF a, PointF c, PointF b, double u)
        {
            double v = 1 - u;
            return new PointF((float)(v * v * a.X + 2 * v * u * c.X + u * u * b.X), (float)(v * v * a.Y + 2 * v * u * c.Y + u * u * b.Y));
        }

        static double Pps(double rate) { return rate < 200 ? 0.4 : Math.Min(26, 1.5 + 5.5 * Math.Log10(rate / 200.0)); }

        public static string Rate(double b) { return b < 1024 ? (int)b + " B/s" : b < 1048576 ? (b / 1024).ToString("0.#") + " KB/s" : (b / 1048576).ToString("0.0") + " MB/s"; }

        public void Draw(Graphics g, float W, float H, double t, NetConn[] conns, double down, double up)
        {
            double dt = last < 0 ? 0.03 : Math.Min(0.2, t - last); last = t;
            float cx = W / 2, cy = H / 2, rx = W * 0.44f, ry = H * 0.42f;
            var hub = new PointF(cx, cy);
            Color blue = Color.FromArgb(110, 180, 255), amber = Color.FromArgb(255, 190, 90);

            // soft glow in the middle, so the node network sits on top of a "this PC" hub
            using (var path = new GraphicsPath())
            {
                path.AddEllipse(cx - H * 0.45f, cy - H * 0.45f, H * 0.9f, H * 0.9f);
                using (var pg = new PathGradientBrush(path) { CenterColor = Color.FromArgb(46, 60, 110, 200), SurroundColors = new[] { Color.FromArgb(0, 10, 20, 50) } }) g.FillPath(pg, path);
            }

            // spread the endpoints out so they don't sit on top of each other
            var cs = conns.OrderBy(c => c.Angle).ToList();
            var ang = cs.Select(c => c.Angle).ToArray();
            double sep = cs.Count == 0 ? 0 : Math.Min(0.16, 6.2 / cs.Count * 0.9);
            for (int i = 1; i < ang.Length; i++) if (ang[i] < ang[i - 1] + sep) ang[i] = ang[i - 1] + sep;
            var pos = new Dictionary<NetConn, PointF>();
            for (int i = 0; i < cs.Count; i++) pos[cs[i]] = new PointF(cx + rx * (float)Math.Cos(ang[i]), cy + ry * (float)Math.Sin(ang[i]));

            if (cs.Count == 0)
            {
                for (int k = 0; k < 3; k++)
                {
                    double ph = (t * 0.12 + k / 3.0) % 1.0; float rr = (float)(ph * H * 0.5);
                    using (var p = new Pen(Color.FromArgb((int)(40 * (1 - ph)), blue), 1.5f)) g.DrawEllipse(p, cx - rr, cy - rr, rr * 2, rr * 2);
                }
                Theme.Str(g, "No network activity right now", Theme.F(14), Color.FromArgb(120, 150, 180), new RectangleF(0, H * 0.92f, W, 22), StringAlignment.Center);
            }

            // links, new-connection pulses and orbs
            int idx = 0;
            foreach (var c in cs)
            {
                var p = pos[c];
                float dx = p.X - cx, dy = p.Y - cy, len = (float)Math.Sqrt(dx * dx + dy * dy);
                float side = (idx++ % 2 == 0 ? 1 : -1) * 0.16f * len;
                var ctrl = new PointF((cx + p.X) / 2 - dy / len * side, (cy + p.Y) / 2 + dx / len * side);
                using (var pen = new Pen(Color.FromArgb(c.Lan ? 36 : 48, c.Lan ? Color.FromArgb(120, 220, 150) : blue), 1.2f))
                    g.DrawBezier(pen, hub, ctrl, ctrl, p);
                double born = (DateTime.Now - c.Born).TotalSeconds;
                if (born < 2.5) using (var pen = new Pen(Color.FromArgb((int)(200 * (1 - born / 2.5)), Color.White), 1.6f)) { float rr = (float)(8 + born * 26); g.DrawEllipse(pen, p.X - rr, p.Y - rr, rr * 2, rr * 2); }

                double act = c.Down + c.Up;
                float orb = (float)(5 + Math.Min(8, Math.Log10(1 + act / 512.0) * 2.6));
                Color oc = c.Lan ? Color.FromArgb(120, 220, 150) : c.Up > c.Down ? amber : blue;
                using (var br = new SolidBrush(Color.FromArgb(46, oc))) g.FillEllipse(br, p.X - orb * 2.4f, p.Y - orb * 2.4f, orb * 4.8f, orb * 4.8f);
                using (var br = new SolidBrush(oc)) g.FillEllipse(br, p.X - orb, p.Y - orb, orb * 2, orb * 2);
                if (idx <= 12)
                {
                    string host = c.Host.Length > 0 ? c.Host : c.Addr.ToString();
                    if (host.Length > 34) host = host.Substring(0, 33) + "…";
                    bool right = p.X > cx;
                    float lx = right ? p.X + orb + 8 : p.X - orb - 8, ly = p.Y - 14;
                    var al = right ? StringAlignment.Near : StringAlignment.Far;
                    float bx = right ? lx : lx - 230;
                    Theme.Str(g, c.Name, Theme.F(12, true), Color.FromArgb(215, 235, 255), new RectangleF(bx, ly, 230, 16), al);
                    Theme.Str(g, host + (act > 0 ? "  ·  ↓" + Rate(c.Down) + " ↑" + Rate(c.Up) : ""), Theme.F(10), Color.FromArgb(150, 170, 195), new RectangleF(bx, ly + 15, 230, 14), al);
                }

                // spawn particles in proportion to how much is flowing
                double a;
                acc.TryGetValue(c, out a);
                a += (Pps(c.Down) + Pps(c.Up)) * dt;
                acc[c] = a;
                while (acc[c] >= 1 && ps.Count < 600)
                {
                    acc[c] -= 1;
                    bool isDown = rnd.NextDouble() < (c.Down + 1) / (c.Down + c.Up + 2);
                    ps.Add(new P { C = c, Down = isDown, Life = 1.9 + rnd.NextDouble() * 1.2, Off = (float)(rnd.NextDouble() - 0.5) * 6 });
                }
            }
            foreach (var dead in acc.Keys.Where(k => !cs.Contains(k)).ToList()) acc.Remove(dead);

            // particles: download flows in to the middle (blue), upload flows out (amber)
            for (int i = ps.Count - 1; i >= 0; i--)
            {
                var pt = ps[i]; pt.Age += dt;
                PointF e;
                if (pt.Age > pt.Life || !pos.TryGetValue(pt.C, out e)) { ps.RemoveAt(i); continue; }
                float dx = e.X - cx, dy = e.Y - cy, len = Math.Max(1, (float)Math.Sqrt(dx * dx + dy * dy));
                int ix = cs.IndexOf(pt.C);
                float side = (ix % 2 == 0 ? 1 : -1) * 0.16f * len;
                var ctrl = new PointF((cx + e.X) / 2 - dy / len * side, (cy + e.Y) / 2 + dx / len * side);
                double u = pt.Age / pt.Life; u = u * u * (3 - 2 * u);
                Color col = pt.Down ? blue : amber;
                for (int k = 0; k < 4; k++)
                {
                    double uu = Math.Max(0, u - k * 0.022);
                    var q = pt.Down ? Bez(e, ctrl, hub, uu) : Bez(hub, ctrl, e, uu);
                    float rr = 3.2f - k * 0.6f;
                    int al = (int)(230 * (1 - k * 0.24) * Math.Sin(Math.PI * Math.Min(1, pt.Age / pt.Life)));
                    using (var br = new SolidBrush(Color.FromArgb(Math.Max(0, al), col))) g.FillEllipse(br, q.X + pt.Off * 0.2f - rr, q.Y - rr, rr * 2, rr * 2);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------

    /// <summary>Registers Visually Safe as the Windows screen saver (a .scr copy of itself) and restores whatever was set before.</summary>
    static class SystemSaver
    {
        [DllImport("user32.dll", SetLastError = true)] static extern bool SystemParametersInfo(uint action, uint param, IntPtr v, uint flags);
        const string DesktopKey = @"Control Panel\Desktop";

        public static string ScrPathFor(string mode) { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, mode == "defrag" ? "TinyGuardDefrag.scr" : "TinyGuard.scr"); }
        public static string ScrPath { get { return ScrPathFor("scan"); } }

        /// <summary>Keeps TinyGuard.scr the same as TinyGuard.exe (after an update).</summary>
        public static void SyncCopy()
        {
            foreach (string mode in new[] { "scan", "defrag" })
                try
                {
                    string exe = Application.ExecutablePath, scr = ScrPathFor(mode);
                    if (string.Equals(exe, scr, StringComparison.OrdinalIgnoreCase)) continue;
                    if (!File.Exists(scr) || new FileInfo(scr).Length != new FileInfo(exe).Length || File.GetLastWriteTimeUtc(scr) < File.GetLastWriteTimeUtc(exe)) File.Copy(exe, scr, true);
                }
                catch { }
        }

        public static void Enable(Settings s, int minutes, string subkey = DesktopKey, bool notify = true)
        {
            SyncCopy();
            using (var k = Registry.CurrentUser.CreateSubKey(subkey))
            {
                if (!s.SystemSaver)
                {
                    s.PrevScr = k.GetValue("SCRNSAVE.EXE") as string ?? "";
                    s.PrevActive = k.GetValue("ScreenSaveActive") as string ?? "";
                    s.PrevTimeout = k.GetValue("ScreenSaveTimeOut") as string ?? "";
                }
                k.SetValue("SCRNSAVE.EXE", ScrPathFor(s.SaverMode));
                k.SetValue("ScreenSaveActive", "1");
                k.SetValue("ScreenSaveTimeOut", (minutes * 60).ToString());
            }
            s.SystemSaver = true; s.Save();
            if (notify) { SystemParametersInfo(0x000F, (uint)(minutes * 60), IntPtr.Zero, 3); SystemParametersInfo(0x0011, 1, IntPtr.Zero, 3); }
        }

        public static void Disable(Settings s, string subkey = DesktopKey, bool notify = true)
        {
            using (var k = Registry.CurrentUser.CreateSubKey(subkey))
            {
                if (string.IsNullOrEmpty(s.PrevScr)) k.DeleteValue("SCRNSAVE.EXE", false); else k.SetValue("SCRNSAVE.EXE", s.PrevScr);
                k.SetValue("ScreenSaveActive", string.IsNullOrEmpty(s.PrevScr) ? "0" : (string.IsNullOrEmpty(s.PrevActive) ? "1" : s.PrevActive));
                if (!string.IsNullOrEmpty(s.PrevTimeout)) k.SetValue("ScreenSaveTimeOut", s.PrevTimeout);
            }
            s.SystemSaver = false; s.Save();
            if (notify) SystemParametersInfo(0x0011, string.IsNullOrEmpty(s.PrevScr) ? 0u : 1u, IntPtr.Zero, 3);
        }

        public static bool IsRegistered(string subkey = DesktopKey)
        {
            try { using (var k = Registry.CurrentUser.OpenSubKey(subkey)) { string v = k == null ? null : k.GetValue("SCRNSAVE.EXE") as string; return string.Equals(v, ScrPathFor("scan"), StringComparison.OrdinalIgnoreCase) || string.Equals(v, ScrPathFor("defrag"), StringComparison.OrdinalIgnoreCase); } }
            catch { return false; }
        }
    }

    // ---------------------------------------------------------------------------------------------------------

    /// <summary>The full-screen block map shown after the deep scan: one colour per file, a moving read/write head, spotlighting a scattered file.</summary>
    class SaverDefragView : Control
    {
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 40 };
        readonly Random rnd = new Random();
        int spot = -1; DateTime spotAt = DateTime.MinValue;

        public SaverDefragView()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            BackColor = Color.Black;
            timer.Tick += (s, e) => { if (Visible) Invalidate(); };
            timer.Start();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            try { Paint2(e); }
            catch (Exception ex) { try { var sn = DefragService.Snapshot; File.AppendAllText(Path.Combine(Path.GetTempPath(), "tinyguard-paint.log"), DateTime.Now + " spot=" + spot + " file=[" + (sn != null && spot >= 0 && spot < sn.Files.Count ? sn.Files[spot] : "?") + "] " + ex + Environment.NewLine); } catch { } }
        }

        void Paint2(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Color.Black);
            Theme.Prep(g);
            g.SmoothingMode = SmoothingMode.HighSpeed;
            float W = Width / Theme.K, H = Height / Theme.K;
            var s = DefragService.Snapshot; var r = DefragService.Runner;
            double t = clock.Elapsed.TotalSeconds;

            string title = DefragService.Preview && !r.Running ? "Defrag " + DefragService.Drive : r.Running ? "Defragmenting " + DefragService.Drive : r.Finished != DateTime.MinValue && r.ExitCode == 0 ? DefragService.Drive + " is tidy" : "Drive " + DefragService.Drive;
            Theme.Str(g, title, Theme.F(Math.Max(22, H * 0.04f), true), Color.FromArgb(235, 240, 250), new RectangleF(W * 0.05f, H * 0.03f, W * 0.6f, H * 0.07f));
            float bx = W * 0.05f, by = H * 0.095f, bw = W * 0.9f;
            Theme.FillRound(g, Color.FromArgb(40, 46, 62), new RectangleF(bx, by, bw, 8), 4);
            int pct = r.Running || r.Finished != DateTime.MinValue ? r.Percent : 0;
            if (pct > 0) Theme.FillRound(g, Color.FromArgb(255, 110, 190, 255), new RectangleF(bx, by, Math.Max(8, bw * pct / 100f), 8), 4);
            Theme.Str(g, pct > 0 ? pct + "%" : "", Theme.F(Math.Max(16, H * 0.028f), true), Color.FromArgb(150, 200, 255), new RectangleF(W * 0.65f, H * 0.03f, W * 0.3f, H * 0.07f), StringAlignment.Far);

            if (DefragService.Notice.Length > 0)
                Theme.Str(g, DefragService.Notice, Theme.F(Math.Max(13, H * 0.022f)), Color.FromArgb(255, 190, 90), new RectangleF(W * 0.05f, H * 0.105f, W * 0.9f, Math.Max(13, H * 0.022f) + 8));
            if (s == null)
            {
                string msg = DefragService.Building ? DefragService.BuildStatus : DefragService.Error.Length > 0 ? DefragService.Error : "Mapping the drive…";
                Theme.Str(g, msg, Theme.F(Math.Max(16, H * 0.03f)), Color.FromArgb(150, 170, 195), new RectangleF(0, 0, W, H), StringAlignment.Center);
                return;
            }
            var area = new RectangleF(W * 0.04f, H * 0.14f, W * 0.92f, H * 0.68f);
            if (spot < 0 || (DateTime.Now - spotAt).TotalSeconds > 6)
            {
                var frag = Enumerable.Range(0, s.Files.Count).Where(i => s.Frags[i] > 1 && s.Frags[i] < 60).ToList();
                spot = frag.Count > 0 ? frag[rnd.Next(frag.Count)] : -1; spotAt = DateTime.Now;
            }
            bool illustrate = DefragService.Preview || (r.Running && DefragService.Ssd);
            if (illustrate) { var sim = DefragService.Sim(); if (sim != null) sim.Draw(g, area, t, BlockSim.Progress(t)); }
            else BlockPainter.Draw(g, area, s, DefragService.Prev, t, spot, r.Running);

            float fs = Math.Max(12, H * 0.02f);
            string spotText = spot >= 0 && spot < s.Files.Count ? "Spotlight: " + Path.GetFileName(s.Files[spot]) + " is in " + s.Frags[spot] + " pieces" : "";
            Theme.Str(g, spotText, Theme.F(fs), Color.FromArgb(200, 215, 235), new RectangleF(W * 0.05f, H * 0.822f, W * 0.6f, fs + 8));
            string stats = s.FileCount + " files mapped · " + s.Fragmented + " in more than one piece (" + s.FragPercent.ToString("0.0") + "%)";
            Theme.Str(g, stats, Theme.F(fs), Color.FromArgb(150, 170, 195), new RectangleF(W * 0.05f, H * 0.856f, W * 0.7f, fs + 8));
            string line = illustrate ? "Illustration: Windows only trims a solid-state drive, so this shows what a defrag does." : r.Running ? (r.Last.Length > 0 ? r.Last : "Working…") : DefragService.Ssd ? "Solid-state drive: Windows only trims it" : r.Finished != DateTime.MinValue ? (r.ExitCode == 0 ? "Finished." : r.Last) : "";
            Theme.Str(g, line, Theme.F(fs), Color.FromArgb(150, 170, 195), new RectangleF(W * 0.05f, H * 0.89f, W * 0.9f, fs + 8));
            Theme.Str(g, "Move the mouse or press a key to leave", Theme.F(fs), Color.FromArgb(90, 105, 130), new RectangleF(W * 0.5f, H * 0.925f, W * 0.45f, fs + 8), StringAlignment.Far);
            // legend
            float lx = W * 0.05f, ly = H * 0.925f;
            Theme.Str(g, "Each colour is one file. Dark = free space.", Theme.F(fs), Color.FromArgb(120, 135, 160), new RectangleF(lx, ly, W * 0.4f, fs + 8));
        }

        public void SetRate(int ms) { if (timer.Interval != ms) timer.Interval = ms; }
        protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }
    }

    class SaverForm : Form
    {
        public readonly MapView Map;
        public readonly SaverDefragView Defrag;

        public SaverForm(Engine eng, Rectangle bounds, bool primary)
        {
            FormBorderStyle = FormBorderStyle.None; StartPosition = FormStartPosition.Manual; Bounds = bounds;
            TopMost = true; ShowInTaskbar = false; BackColor = Color.Black; KeyPreview = false;
            SetStyle(ControlStyles.OptimizedDoubleBuffer, true);
            if (!primary) return;
            Map = new MapView(eng) { Dock = DockStyle.Fill, Saver = true, Enabled = false };
            Defrag = new SaverDefragView { Dock = DockStyle.Fill, Visible = false, Enabled = false };
            Controls.Add(Map); Controls.Add(Defrag);
        }

        protected override CreateParams CreateParams { get { var cp = base.CreateParams; cp.ExStyle |= 0x80; return cp; } }   // WS_EX_TOOLWINDOW: no taskbar button
    }

    /// <summary>Starts and ends the screen saver.</summary>
    static class ScreenSaver
    {
        public static bool Active { get; private set; }
        static readonly List<SaverForm> forms = new List<SaverForm>();
        static System.Windows.Forms.Timer timer;
        static Engine eng; static Action ended;
        static NetSampler sampler; static NetArt art;
        static uint baseline; static DateTime started; static int phase;   // 0 scanning, 1 defragmenting, 2 finished
        static DateTime lastDefragDone = DateTime.MinValue;
        static bool defragOnly;
        static readonly Stopwatch clock = Stopwatch.StartNew();

        /// <param name="mode">"scan" (deep scan, then defrag), "defrag" (just the defrag display) or null for the one chosen in Settings</param>
        public static void Start(Engine e, Action onEnded, string mode = null)
        {
            if (Active) return;
            eng = e; ended = onEnded; Active = true; phase = 0; started = DateTime.Now; baseline = IdleInfo.LastInputTick();
            defragOnly = (mode ?? eng.S.SaverMode) == "defrag";
            sampler = new NetSampler(eng); art = new NetArt(); rateLevel = -1; LowPriority(true);
            if (!defragOnly) { sampler.Start(); eng.Deep.SetActive(true); }
            var screens = Screen.AllScreens;
            foreach (var sc in screens)
            {
                bool primary = sc.Primary;
                var f = new SaverForm(eng, sc.Bounds, primary);
                if (primary)
                {
                    f.Map.BackPainter = (g, W, H, t) => art.Draw(g, W, H, t, sampler.Conns, sampler.GlobalDown, sampler.GlobalUp);
                    f.Map.FrontPainter = Hud;
                }
                forms.Add(f);
                f.Show();
            }
            Cursor.Hide();
            if (defragOnly) { var pf = forms.FirstOrDefault(f => f.Map != null); if (pf != null) BeginDefrag(pf); }
            timer = new System.Windows.Forms.Timer { Interval = 250 };
            timer.Tick += (s, ev) => Tick();
            timer.Start();
        }

        static void Hud(Graphics g, float W, float H, double t)
        {
            var d = eng.Deep;
            float fs = Math.Max(12, H * 0.019f);
            string head = "Visually Safe · " + (d.Phase.StartsWith("Every") ? "Deep scan complete" : "Deep scan");
            Theme.Str(g, head, Theme.F(fs * 1.5f, true), Color.FromArgb(220, 235, 255), new RectangleF(W * 0.03f, H * 0.03f, W * 0.5f, fs * 2.4f));
            string line1 = d.Total > 0 ? d.Done.ToString("N0") + " of " + d.Total.ToString("N0") + " files examined · " + d.Flagged + " flagged" : d.Phase;
            string eta = "";
            if (d.Done > 20 && d.Total > d.Done && d.Started != DateTime.MinValue)
            {
                double per = (DateTime.Now - d.Started).TotalSeconds / d.Done; var left = TimeSpan.FromSeconds(per * (d.Total - d.Done));
                eta = left.TotalHours >= 1 ? " · about " + (int)left.TotalHours + " h " + left.Minutes + " min left" : " · about " + Math.Max(1, left.Minutes) + " min left";
            }
            Theme.Str(g, line1 + eta, Theme.F(fs), Color.FromArgb(150, 175, 205), new RectangleF(W * 0.03f, H * 0.03f + fs * 2.3f, W * 0.7f, fs + 6));
            if (!string.IsNullOrEmpty(d.Current))
                Theme.Str(g, System.IO.Path.GetFileName(d.Current), Theme.F(fs, true), Color.FromArgb(160, 215, 255), new RectangleF(W * 0.03f, H * 0.93f - fs * 1.5f, W * 0.6f, fs + 8));
            Theme.Str(g, "Taking its time: at most a small share of the processor, resting between files.", Theme.F(fs * 0.85f), Color.FromArgb(100, 118, 145), new RectangleF(W * 0.03f, H * 0.93f, W * 0.65f, fs + 8));
            Theme.Str(g, DateTime.Now.ToString("h:mm tt"), Theme.F(fs * 2.2f, true), Color.FromArgb(160, 180, 210), new RectangleF(W * 0.7f, H * 0.03f, W * 0.27f, fs * 3), StringAlignment.Far);
            Theme.Str(g, "↓ " + NetArt.Rate(sampler.GlobalDown) + "   ↑ " + NetArt.Rate(sampler.GlobalUp), Theme.F(fs), Color.FromArgb(120, 180, 255), new RectangleF(W * 0.6f, H * 0.93f, W * 0.37f, fs + 8), StringAlignment.Far);
            if (!Admin.IsAdmin && d.Phase.StartsWith("Every") && eng.S.SaverDefrag)
                Theme.Str(g, "Defragmenting needs administrator rights", Theme.F(fs * 0.9f), Color.FromArgb(255, 190, 90), new RectangleF(W * 0.35f, H * 0.03f + fs * 2.3f, W * 0.62f, fs + 6), StringAlignment.Far);
        }

        /// <summary>Switch to the block-map display and start the defrag (or, when it shouldn't really run, an illustration of one).</summary>
        static void BeginDefrag(SaverForm primary)
        {
            phase = 1;
            primary.Map.Visible = false; primary.Defrag.Visible = true;
            bool allowReal = eng.S.SaverDefrag && Admin.IsAdmin && (DateTime.Now - lastDefragDone).TotalDays > 3 && !DefragService.Runner.Running;
            DefragService.Preview = !allowReal && !DefragService.Runner.Running;
            if (!Admin.IsAdmin)
            {
                // reading the drive needs administrator rights: show a made-up drive so the display still works
                DefragService.Snapshot = DefragDemo.Make(); DefragService.Prev = null; DefragService.IsDemo = true;
                DefragService.Notice = "Demo picture: run Visually Safe as administrator to see your real drive";
                return;
            }
            DefragService.IsDemo = false; DefragService.Notice = "";
            DefragService.Rebuild(true);
            if (!allowReal) return;
            // start Windows' own defrag once the picture exists, so the first frame shows the "before"
            var go = new System.Windows.Forms.Timer { Interval = 1000 };
            go.Tick += (s, ev) =>
            {
                if (!Active) { go.Stop(); return; }
                if (DefragService.Building && DefragService.Snapshot == null) return;
                go.Stop();
                DefragService.Runner.Start(DefragService.Drive, false);
            };
            go.Start();
        }

        // Keeps the fans quiet: the longer the saver runs, the slower it redraws (full speed at first, a slow breath after the first minutes,
        // about one picture a second once it is running all night), and Visually Safe runs at low priority while it is on.
        static int rateLevel = -1;
        static System.Diagnostics.ProcessPriorityClass oldPriority = System.Diagnostics.ProcessPriorityClass.Normal; static bool priorityChanged;

        static void CalmDown(SaverForm primary)
        {
            double mins = (DateTime.Now - started).TotalMinutes;
            int level = mins < 3 ? 0 : mins < 15 ? 1 : 2;
            if (level == rateLevel) return;
            rateLevel = level;
            int map = level == 0 ? 40 : level == 1 ? 100 : 1000, defrag = level == 0 ? 50 : level == 1 ? 120 : 1000;
            if (primary.Map != null) primary.Map.SetRate(map);
            if (primary.Defrag != null) primary.Defrag.SetRate(defrag);
        }

        static void LowPriority(bool on)
        {
            try
            {
                var p = System.Diagnostics.Process.GetCurrentProcess();
                if (on && !priorityChanged) { oldPriority = p.PriorityClass; p.PriorityClass = System.Diagnostics.ProcessPriorityClass.BelowNormal; priorityChanged = true; }
                else if (!on && priorityChanged) { p.PriorityClass = oldPriority; priorityChanged = false; }
            }
            catch { }
        }

        static void Tick()
        {
            if (!Active) return;
            // leave as soon as the user touches the mouse or keyboard
            if ((DateTime.Now - started).TotalMilliseconds > 1500 && IdleInfo.LastInputTick() != baseline) { End(); return; }
            var primary = forms.FirstOrDefault(f => f.Map != null);
            if (primary == null) return;
            DefragService.KeepFresh();
            CalmDown(primary);

            if (phase == 0 && !defragOnly && eng.S.SaverDefrag && Admin.IsAdmin && eng.Deep.Phase.StartsWith("Every") && (DateTime.Now - lastDefragDone).TotalDays > 3 && !DefragService.Runner.Running)
                BeginDefrag(primary);
            else if (phase == 1 && !DefragService.Runner.Running && DefragService.Runner.Finished != DateTime.MinValue && DefragService.Runner.Finished > started)
            {
                phase = 2; lastDefragDone = DateTime.Now;
                DefragService.Rebuild(false);
            }
        }

        /// <summary>Developer aid: draws the saver off-screen and saves pictures of the scan phase and the defrag phase.</summary>
        public static void Demo(Engine e, string outDir, int scanSeconds)
        {
            eng = e; Active = true; sampler = new NetSampler(eng); art = new NetArt(); sampler.Start();
            eng.Deep.SetActive(true);
            var f = new SaverForm(eng, new Rectangle(-4000, -4000, 1280, 720), true);
            f.Map.BackPainter = (g, W, H, t) => art.Draw(g, W, H, t, sampler.Conns, sampler.GlobalDown, sampler.GlobalUp);
            f.Map.FrontPainter = Hud;
            f.Show();
            Action<int> pump = ms => { var sw = Stopwatch.StartNew(); while (sw.ElapsedMilliseconds < ms) { System.Threading.Thread.Sleep(30); Application.DoEvents(); } };
            Action<string> shot = name => { using (var bmp = new Bitmap(f.Width, f.Height)) { f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height)); bmp.Save(Path.Combine(outDir, name), System.Drawing.Imaging.ImageFormat.Png); } };
            pump(scanSeconds * 1000 / 2); shot("saver-scan1.png");
            pump(scanSeconds * 1000 / 2); shot("saver-scan2.png");
            DefragService.Snapshot = DefragDemo.Make(); DefragService.Runner.Percent = 37; DefragService.Runner.Last = "Defragmenting C: (37% complete)";
            f.Map.Visible = false; f.Defrag.Visible = true; DefragService.Preview = true;
            pump(9000); shot("saver-defrag1.png"); pump(14000); shot("saver-defrag2.png"); DefragService.Preview = false;
            Active = false; sampler.Stop(); eng.Deep.SetActive(false); f.Close();
        }

        public static void End()
        {
            if (!Active) return;
            Active = false; LowPriority(false);
            if (timer != null) { timer.Stop(); timer.Dispose(); timer = null; }
            Cursor.Show();
            try { sampler.Stop(); } catch { }
            if (!defragOnly) eng.Deep.SetActive(false);
            DefragService.Preview = false; DefragService.Notice = "";
            if (DefragService.IsDemo) { DefragService.Snapshot = DefragService.Prev = null; DefragService.IsDemo = false; }
            if (DefragService.Runner.Running) DefragService.Runner.Stop();
            foreach (var f in forms) { try { f.Close(); f.Dispose(); } catch { } }
            forms.Clear();
            var cb = ended; ended = null;
            if (cb != null) cb();
        }
    }

    /// <summary>Lets TinyGuard.scr (started by Windows) ask the running Visually Safe to show the screen saver.</summary>
    static class SaverPipe
    {
        static string NameFor(string dataDir) { return "TinyGuardPipe-" + (Environment.UserName + "|" + dataDir.ToLowerInvariant()).GetHashCode().ToString("x"); }

        public static string ModeOf(string cmd) { return cmd == "SAVER-DEFRAG" ? "defrag" : cmd == "SAVER-SCAN" ? "scan" : null; }

        public static void StartServer(string dataDir, Action<string, Action> onCommand)
        {
            var th = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        var ps = new PipeSecurity();
                        ps.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
                        var srv = new NamedPipeServerStream(NameFor(dataDir), PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096, ps);
                        srv.WaitForConnection();
                        // each command runs on its own thread: a long one (the screen saver runs until it ends) must not make later requests, like scanning icons, wait behind it
                        var conn = srv;
                        new Thread(() =>
                        {
                            try
                            {
                                using (conn)
                                {
                                    var rd = new StreamReader(conn, Encoding.UTF8); var wr = new StreamWriter(conn, Encoding.UTF8) { AutoFlush = true };
                                    string cmd = rd.ReadLine() ?? "";
                                    var done = new ManualResetEventSlim(false);
                                    onCommand(cmd, () => done.Set());
                                    done.Wait(TimeSpan.FromHours(12));
                                    try { wr.WriteLine("DONE"); } catch { }
                                }
                            }
                            catch { }
                        }) { IsBackground = true, Name = "Visually Safe pipe command" }.Start();
                    }
                    catch { Thread.Sleep(1000); }
                }
            }) { IsBackground = true, Name = "Visually Safe pipe" };
            th.Start();
        }

        /// <summary>Sends a command to a running TinyGuard. Returns false if none is running. With wait, blocks until it reports done.</summary>
        public static bool TryClient(string dataDir, string cmd, bool wait)
        {
            // Many launches can arrive at once (a whole selection of icons), and the pipe serves one at a time: wait our turn.
            int tries = cmd.StartsWith("SCAN|") ? 12 : 1;
            for (int i = 0; i < tries; i++)
            {
                try
                {
                    using (var c = new NamedPipeClientStream(".", NameFor(dataDir), PipeDirection.InOut))
                    {
                        c.Connect(1500);
                        var wr = new StreamWriter(c, Encoding.UTF8) { AutoFlush = true }; var rd = new StreamReader(c, Encoding.UTF8);
                        wr.WriteLine(cmd);
                        if (wait) rd.ReadLine();
                        return true;
                    }
                }
                catch { if (i + 1 < tries) Thread.Sleep(250); }
            }
            return false;
        }
    }
}
