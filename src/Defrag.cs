using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TinyGuard
{
    /// <summary>One picture of how a drive is laid out: blocks of clusters, who owns each, and how many pieces each file is in.</summary>
    class DiskSnapshot
    {
        public int Cols, Rows;
        public byte[] Used;                   // 0..255: how full each block is
        public int[] Owner;                   // index into Files of the file that owns most of the block, or -1
        public List<string> Files = new List<string>();
        public List<int> Frags = new List<int>();
        public long TotalClusters, ClusterBytes, ClustersPerBlock;
        public int FileCount, Fragmented;
        public DateTime At = DateTime.Now;
        public string Drive = "C:";
        public List<int[]> Flights;           // {from block, to block, file} pairs: blocks that moved since the previous snapshot
        public double FragPercent { get { return FileCount == 0 ? 0 : 100.0 * Fragmented / FileCount; } }
    }

    /// <summary>Reads a volume's cluster bitmap and each file's extents straight from NTFS (needs administrator rights).</summary>
    static class DiskMap
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inb, int insz, IntPtr outb, int outsz, out int ret, IntPtr ov);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

        static readonly IntPtr Bad = new IntPtr(-1);

        public static bool IsSsd(string drive)
        {
            IntPtr h = CreateFileW(@"\\.\" + drive.Substring(0, 1) + ":", 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h == Bad) return false;
            IntPtr inb = Marshal.AllocHGlobal(16), outb = Marshal.AllocHGlobal(16);
            try
            {
                for (int i = 0; i < 16; i++) { Marshal.WriteByte(inb, i, 0); Marshal.WriteByte(outb, i, 0); }
                Marshal.WriteInt32(inb, 0, 7);   // StorageDeviceSeekPenaltyProperty
                int ret;
                if (!DeviceIoControl(h, 0x2D1400, inb, 12, outb, 16, out ret, IntPtr.Zero)) return false;
                return Marshal.ReadByte(outb, 8) == 0;   // no seek penalty = solid state
            }
            finally { Marshal.FreeHGlobal(inb); Marshal.FreeHGlobal(outb); CloseHandle(h); }
        }

        static List<long[]> Extents(string path)
        {
            var list = new List<long[]>();
            IntPtr h = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
            if (h == Bad) return null;
            IntPtr inb = Marshal.AllocHGlobal(8), outb = Marshal.AllocHGlobal(8192);
            try
            {
                long start = 0;
                for (int guard = 0; guard < 400; guard++)
                {
                    Marshal.WriteInt64(inb, 0, start);
                    int ret;
                    bool ok = DeviceIoControl(h, 0x00090073, inb, 8, outb, 8192, out ret, IntPtr.Zero);
                    int err = ok ? 0 : Marshal.GetLastWin32Error();
                    if (!ok && err != 234) return list.Count > 0 ? list : null;
                    int count = Marshal.ReadInt32(outb, 0);
                    long vcn = Marshal.ReadInt64(outb, 8);
                    for (int i = 0; i < count; i++)
                    {
                        long next = Marshal.ReadInt64(outb, 16 + i * 16), lcn = Marshal.ReadInt64(outb, 24 + i * 16);
                        if (lcn >= 0) list.Add(new[] { lcn, next - vcn });
                        vcn = next; start = next;
                    }
                    if (ok) break;
                }
                return list;
            }
            finally { Marshal.FreeHGlobal(inb); Marshal.FreeHGlobal(outb); CloseHandle(h); }
        }

        static readonly byte[] Pop = Enumerable.Range(0, 256).Select(i => (byte)Convert.ToString(i, 2).Count(c => c == '1')).ToArray();

        /// <summary>Builds a snapshot. Pass the previous one to reuse its file list (much faster).</summary>
        public static DiskSnapshot Build(string drive, int cols, int rows, CancellationToken ct, DiskSnapshot reuse, Action<string> status)
        {
            string letter = drive.Substring(0, 1);
            IntPtr vol = CreateFileW(@"\\.\" + letter + ":", 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (vol == Bad) throw new UnauthorizedAccessException("Reading the drive's layout needs administrator rights.");
            var s = new DiskSnapshot { Cols = cols, Rows = rows, Drive = letter + ":" };
            try
            {
                IntPtr vd = Marshal.AllocHGlobal(256);
                int ret;
                if (!DeviceIoControl(vol, 0x00090064, IntPtr.Zero, 0, vd, 256, out ret, IntPtr.Zero)) throw new InvalidOperationException("This drive isn't NTFS, so its layout can't be read.");
                s.TotalClusters = Marshal.ReadInt64(vd, 16); s.ClusterBytes = Marshal.ReadInt32(vd, 40);
                Marshal.FreeHGlobal(vd);

                long bytes = s.TotalClusters / 8 + 64;
                if (bytes > 192L * 1024 * 1024) throw new InvalidOperationException("This drive is too large to draw.");
                status("Reading which parts of the drive are in use…");
                IntPtr inb = Marshal.AllocHGlobal(8), bm = Marshal.AllocHGlobal((int)bytes + 16);
                try
                {
                    Marshal.WriteInt64(inb, 0, 0);
                    if (!DeviceIoControl(vol, 0x0009006F, inb, 8, bm, (int)bytes + 16, out ret, IntPtr.Zero) && Marshal.GetLastWin32Error() != 234) throw new InvalidOperationException("Couldn't read the drive's usage map.");
                    long bits = Marshal.ReadInt64(bm, 8);
                    s.ClustersPerBlock = Math.Max(1, (s.TotalClusters + cols * rows - 1) / (cols * rows));
                    int blocks = (int)((s.TotalClusters + s.ClustersPerBlock - 1) / s.ClustersPerBlock);
                    s.Used = new byte[cols * rows]; s.Owner = new int[cols * rows];
                    for (int i = 0; i < s.Owner.Length; i++) s.Owner[i] = -1;
                    var data = new byte[Math.Min(bytes, bits / 8 + 8)];
                    Marshal.Copy(bm + 16, data, 0, data.Length);
                    for (int b = 0; b < blocks; b++)
                    {
                        long from = b * s.ClustersPerBlock, to = Math.Min(s.TotalClusters, from + s.ClustersPerBlock);
                        long used = 0;
                        for (long c = from; c < to; )
                        {
                            long byteIdx = c >> 3;
                            if ((c & 7) == 0 && c + 8 <= to && byteIdx < data.Length) { used += Pop[data[byteIdx]]; c += 8; }
                            else { if (byteIdx < data.Length && (data[byteIdx] & (1 << (int)(c & 7))) != 0) used++; c++; }
                        }
                        s.Used[b] = (byte)Math.Min(255, used * 255 / Math.Max(1, to - from));
                    }
                }
                finally { Marshal.FreeHGlobal(inb); Marshal.FreeHGlobal(bm); }

                // who owns which blocks
                List<string> files;
                if (reuse != null) files = reuse.Files;
                else
                {
                    status("Listing files…");
                    files = new List<string>();
                    var q = new Queue<string>(); q.Enqueue(letter + @":\");
                    var clock = Stopwatch.StartNew();
                    while (q.Count > 0 && files.Count < 40000 && clock.Elapsed.TotalSeconds < 75 && !ct.IsCancellationRequested)
                    {
                        string dir = q.Dequeue();
                        DirectoryInfo di;
                        try { di = new DirectoryInfo(dir); foreach (var sub in di.GetDirectories()) if ((sub.Attributes & FileAttributes.ReparsePoint) == 0) q.Enqueue(sub.FullName); } catch { continue; }
                        try { foreach (var f in di.GetFiles()) { if (f.Length > 4096) files.Add(f.FullName); } } catch { }
                    }
                }
                var ownerClusters = new int[cols * rows];
                int idx = 0;
                foreach (string f in files)
                {
                    if (ct.IsCancellationRequested) break;
                    if (idx % 400 == 0) status("Mapping files to the drive… " + idx + " of " + files.Count);
                    var ex = Extents(f);
                    s.Files.Add(f);
                    if (ex == null || ex.Count == 0) { s.Frags.Add(0); idx++; continue; }
                    s.Frags.Add(ex.Count); s.FileCount++; if (ex.Count > 1) s.Fragmented++;
                    foreach (var e in ex)
                    {
                        long lcn = e[0], len = e[1], end = lcn + len;
                        for (long blk = lcn / s.ClustersPerBlock; blk <= (end - 1) / s.ClustersPerBlock && blk < s.Owner.Length; blk++)
                        {
                            long ov = Math.Min(end, (blk + 1) * s.ClustersPerBlock) - Math.Max(lcn, blk * s.ClustersPerBlock);
                            if (ov > ownerClusters[blk]) { s.Owner[blk] = idx; ownerClusters[blk] = (int)Math.Min(int.MaxValue, ov); }
                        }
                    }
                    idx++;
                }
                s.At = DateTime.Now;
                return s;
            }
            finally { CloseHandle(vol); }
        }
    }

    static class DefragDemo
    {
        /// <summary>A made-up drive for pictures and tests (no administrator rights needed).</summary>
        public static DiskSnapshot Make()
        {
            var rnd = new Random(11);
            var s = new DiskSnapshot { Cols = DefragService.Cols, Rows = DefragService.Rows, Drive = "C:", TotalClusters = 1000000, ClusterBytes = 4096, ClustersPerBlock = 208 };
            int n = s.Cols * s.Rows; s.Used = new byte[n]; s.Owner = new int[n];
            for (int i = 0; i < n; i++) s.Owner[i] = -1;
            int pos = 0, fi = 0;
            while (pos < n)
            {
                int len = 1 + rnd.Next(1, 40);
                bool free = rnd.NextDouble() < 0.2;
                for (int k = 0; k < len && pos < n; k++, pos++) { s.Used[pos] = free ? (byte)0 : (byte)(180 + rnd.Next(75)); if (!free) s.Owner[pos] = fi; }
                if (!free) { s.Files.Add(@"C:\Demo\file" + fi + ".dat"); s.Frags.Add(1 + (rnd.NextDouble() < 0.35 ? rnd.Next(1, 4) : 0)); fi++; }
            }
            // scatter a few files so some are visibly in pieces
            for (int k = 0; k < 220; k++) { int a = rnd.Next(n), f = rnd.Next(Math.Max(1, fi)); if (s.Used[a] > 0) s.Owner[a] = f; }
            s.FileCount = s.Files.Count; s.Fragmented = s.Frags.Count(x => x > 1);
            return s;
        }
    }

    /// <summary>Starts, watches and stops Windows' own defrag.exe (which does the real work, at low priority).</summary>
    class DefragRunner
    {
        public volatile bool Running;
        public int Percent;
        public string Phase = "", Last = "", Report = "";
        public double WindowsFragPercent = -1;
        public DateTime Finished = DateTime.MinValue;
        public int ExitCode;
        Process proc;

        public bool Start(string drive, bool analyzeOnly)
        {
            if (Running) return false;
            if (!Admin.IsAdmin) { Last = "Defragmenting needs administrator rights."; return false; }
            Running = true; Percent = 0; Report = ""; Phase = analyzeOnly ? "Analyzing" : "Starting"; Last = "";
            Task.Run(() =>
            {
                var sb = new StringBuilder();
                try
                {
                    // /O = the right optimization for the drive type (defragment a hard disk, re-trim an SSD); /U = show progress; /V = detail
                    var psi = new ProcessStartInfo("defrag.exe", drive + (analyzeOnly ? " /A /V" : " /O /U /V"))
                    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.GetEncoding(Console.OutputEncoding.CodePage) };
                    proc = Process.Start(psi);
                    try { proc.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
                    proc.OutputDataReceived += (s, e) =>
                    {
                        if (e.Data == null) return;
                        string l = e.Data.Replace("\b", "").Trim();
                        if (l.Length == 0) return;
                        sb.AppendLine(l);
                        var m = Regex.Match(l, @"(\d{1,3})\s*%");
                        if (m.Success) { int p = int.Parse(m.Groups[1].Value); if (p <= 100) Percent = p; }
                        if (!l.StartsWith("---")) { Last = l.Length > 120 ? l.Substring(0, 120) : l; if (l.IndexOf("Defragmentation", StringComparison.OrdinalIgnoreCase) >= 0 || l.IndexOf("Optimization", StringComparison.OrdinalIgnoreCase) >= 0 || l.IndexOf("Analysis", StringComparison.OrdinalIgnoreCase) >= 0 || l.IndexOf("Retrim", StringComparison.OrdinalIgnoreCase) >= 0) Phase = Last; }
                    };
                    proc.BeginOutputReadLine(); proc.ErrorDataReceived += (s, e) => { if (e.Data != null && e.Data.Trim().Length > 0) { sb.AppendLine(e.Data); Last = e.Data.Trim(); } }; proc.BeginErrorReadLine();
                    proc.WaitForExit();
                    ExitCode = proc.ExitCode;
                }
                catch (Exception ex) { Last = "Couldn't run defrag: " + ex.Message; ExitCode = -1; }
                Report = sb.ToString();
                var fm = Regex.Match(Report, @"fragmented space\s*=\s*(\d+)%", RegexOptions.IgnoreCase);
                if (fm.Success) WindowsFragPercent = double.Parse(fm.Groups[1].Value);
                Finished = DateTime.Now; Percent = ExitCode == 0 ? 100 : Percent; Running = false;
            });
            return true;
        }

        public void Stop() { try { var p = proc; if (p != null && !p.HasExited) AgentRunner.Kill(p); } catch { } }
    }

    /// <summary>Shared by the Defrag page and the screen saver so they show the same drive.</summary>
    static class DefragService
    {
        public static string Drive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).Substring(0, 2);
        public static DiskSnapshot Snapshot, Prev;
        public static volatile bool Building;
        public static string BuildStatus = "", Error = "";
        public static bool Ssd;
        public static readonly DefragRunner Runner = new DefragRunner();
        public static DateTime LastRefresh = DateTime.MinValue;
        static CancellationTokenSource cts;
        public const int Cols = 120, Rows = 40;
        public static bool Preview;                       // show the illustrated defrag even when nothing is being moved
        public static string Notice = "";                 // a line the screen saver shows under the title
        public static bool IsDemo;                        // the picture is made up (no administrator rights)

        static BlockSim sim; static DiskSnapshot simFor;
        /// <summary>The illustrated defrag for the current map (rebuilt when the map changes).</summary>
        public static BlockSim Sim()
        {
            var s = Snapshot;
            if (s == null) return null;
            if (sim == null || !ReferenceEquals(simFor, s)) { sim = new BlockSim(s); simFor = s; }
            return sim;
        }

        /// <summary>Pairs up blocks a file left with blocks it arrived in, so the move can be animated.</summary>
        static List<int[]> ComputeFlights(DiskSnapshot a, DiskSnapshot b)
        {
            var list = new List<int[]>();
            if (a == null || a.Owner.Length != b.Owner.Length) return list;
            var left = new Dictionary<int, Queue<int>>(); var arrived = new Dictionary<int, List<int>>();
            for (int i = 0; i < b.Owner.Length; i++)
            {
                int o = a.Owner[i], n = b.Owner[i];
                if (o == n) continue;
                // files are indexed per snapshot, so compare by path
                string po = o >= 0 && o < a.Files.Count ? a.Files[o] : null, pn = n >= 0 && n < b.Files.Count ? b.Files[n] : null;
                if (po == pn) continue;
                if (po != null) { int k = po.GetHashCode(); Queue<int> q; if (!left.TryGetValue(k, out q)) left[k] = q = new Queue<int>(); q.Enqueue(i); }
                if (pn != null) { int k = pn.GetHashCode(); List<int> l; if (!arrived.TryGetValue(k, out l)) arrived[k] = l = new List<int>(); l.Add(i); }
            }
            foreach (var kv in arrived)
            {
                Queue<int> q;
                if (!left.TryGetValue(kv.Key, out q)) continue;
                foreach (int to in kv.Value) { if (q.Count == 0) break; list.Add(new[] { q.Dequeue(), to, kv.Key }); if (list.Count > 1500) return list; }
            }
            return list;
        }

        public static List<string> Drives()
        {
            var l = new List<string>();
            try { foreach (var d in DriveInfo.GetDrives()) if (d.DriveType == DriveType.Fixed && d.IsReady && d.DriveFormat == "NTFS") l.Add(d.Name.Substring(0, 2)); } catch { }
            return l;
        }

        public static void Rebuild(bool full)
        {
            if (Building) return;
            Building = true; Error = "";
            cts = new CancellationTokenSource();
            var token = cts.Token; string drive = Drive; var reuse = full ? null : Snapshot;
            Task.Run(() =>
            {
                try
                {
                    Ssd = DiskMap.IsSsd(drive);
                    var snap = DiskMap.Build(drive, Cols, Rows, token, reuse, st => BuildStatus = st);
                    snap.Flights = ComputeFlights(Snapshot, snap);
                    Prev = Snapshot; Snapshot = snap; LastRefresh = DateTime.Now;
                }
                catch (Exception ex) { Error = ex.Message; }
                Building = false;
            });
        }

        /// <summary>While defragmenting, redraw from fresh data every so often so the blocks visibly move.</summary>
        public static void KeepFresh()
        {
            if (Runner.Running && !Building && Snapshot != null && (DateTime.Now - LastRefresh).TotalSeconds > 12) Rebuild(false);
        }

        public static void Cancel() { if (cts != null) cts.Cancel(); }
    }

    /// <summary>Draws the classic defrag block map, but with a colour per file, a moving read/write head and glowing changes.</summary>
    static class BlockPainter
    {
        public static Color FileColor(string path)
        {
            uint h = 2166136261;
            foreach (char c in path) { h ^= c; h *= 16777619; }
            double hue = (h % 3600) / 10.0;
            return FromHsv(hue, 0.62 + ((h >> 8) % 30) / 100.0, 0.92);
        }

        static Color FromHsv(double h, double s, double v)
        {
            double c = v * s, x = c * (1 - Math.Abs((h / 60) % 2 - 1)), m = v - c, r, g, b;
            if (h < 60) { r = c; g = x; b = 0; } else if (h < 120) { r = x; g = c; b = 0; } else if (h < 180) { r = 0; g = c; b = x; }
            else if (h < 240) { r = 0; g = x; b = c; } else if (h < 300) { r = x; g = 0; b = c; } else { r = c; g = 0; b = x; }
            return Color.FromArgb((int)((r + m) * 255), (int)((g + m) * 255), (int)((b + m) * 255));
        }

        static readonly Dictionary<int, SolidBrush> brushes = new Dictionary<int, SolidBrush>();
        static SolidBrush B(Color c) { SolidBrush b; int k = c.ToArgb(); if (!brushes.TryGetValue(k, out b)) { if (brushes.Count > 3000) brushes.Clear(); brushes[k] = b = new SolidBrush(c); } return b; }

        public static RectangleF Cell(RectangleF area, DiskSnapshot s, out float cell)
        {
            cell = Math.Min(area.Width / s.Cols, area.Height / s.Rows);
            float w = cell * s.Cols, h = cell * s.Rows;
            return new RectangleF(area.X + (area.Width - w) / 2, area.Y + (area.Height - h) / 2, w, h);
        }

        public static int BlockAt(RectangleF area, DiskSnapshot s, PointF p)
        {
            float cell; var g = Cell(area, s, out cell);
            int cx = (int)((p.X - g.X) / cell), cy = (int)((p.Y - g.Y) / cell);
            if (cx < 0 || cy < 0 || cx >= s.Cols || cy >= s.Rows) return -1;
            return cy * s.Cols + cx;
        }

        /// <param name="hover">index of a file whose blocks should light up, or -1</param>
        public static void Draw(Graphics g, RectangleF area, DiskSnapshot s, DiskSnapshot prev, double t, int hover, bool running)
        {
            if (s == null) return;
            float cell; var grid = Cell(area, s, out cell);
            float gap = Math.Max(0.8f, cell * 0.14f), size = cell - gap;
            double sinceSnap = (DateTime.Now - s.At).TotalSeconds;
            int headRow = (int)((t * 5) % s.Rows);
            int cursor = running ? (int)((t * 60) % (s.Cols * s.Rows)) : -1;
            var hoverBlocks = hover >= 0 ? new List<int>() : null;
            for (int i = 0; i < s.Cols * s.Rows; i++)
            {
                int cx = i % s.Cols, cy = i / s.Cols;
                float x = grid.X + cx * cell, y = grid.Y + cy * cell;
                if (x + cell < area.X || x > area.Right || y + cell < area.Y || y > area.Bottom) continue;
                int u = s.Used[i], owner = s.Owner[i];
                Color col;
                if (u == 0) col = Color.FromArgb(34, 40, 54);
                else if (owner >= 0)
                {
                    col = FileColor(s.Files[owner]);
                    int a = 90 + u * 165 / 255;
                    col = Color.FromArgb(Math.Min(255, a), col);
                }
                else col = Color.FromArgb(60 + u / 2, 120, 130, 160);
                bool isHover = hover >= 0 && owner == hover;
                if (isHover) { hoverBlocks.Add(i); col = Color.FromArgb(255, Math.Min(255, col.R + 60), Math.Min(255, col.G + 60), Math.Min(255, col.B + 60)); }
                if (cy == headRow && running) col = Color.FromArgb(col.A, Math.Min(255, col.R + 26), Math.Min(255, col.G + 26), Math.Min(255, col.B + 26));
                g.FillRectangle(B(col), x + gap / 2, y + gap / 2, size, size);
                // blocks that just moved glow white, then settle
                if (prev != null && sinceSnap < 2.5 && i < prev.Owner.Length && prev.Owner[i] != owner)
                    g.FillRectangle(B(Color.FromArgb((int)(220 * (1 - sinceSnap / 2.5)), 255, 255, 255)), x + gap / 2, y + gap / 2, size, size);
                if (i == cursor) g.FillRectangle(B(Color.White), x - gap, y - gap, cell + gap, cell + gap);
            }
            // blocks that really moved since the last picture glide from where they were to where they are now
            if (s.Flights != null && sinceSnap < 1.8)
            {
                double u = Math.Min(1, sinceSnap / 1.6); u = u * u * (3 - 2 * u);
                foreach (var f in s.Flights)
                {
                    float x0 = grid.X + (f[0] % s.Cols) * cell, y0 = grid.Y + (f[0] / s.Cols) * cell, x1 = grid.X + (f[1] % s.Cols) * cell, y1 = grid.Y + (f[1] / s.Cols) * cell;
                    float x = x0 + (x1 - x0) * (float)u, y = y0 + (y1 - y0) * (float)u - (float)Math.Sin(Math.PI * u) * cell * 2.5f;
                    g.FillRectangle(B(Color.FromArgb(70, 255, 255, 255)), x - cell * 0.45f, y - cell * 0.45f, cell * 1.9f, cell * 1.9f);
                    g.FillRectangle(B(Color.White), x + gap / 2, y + gap / 2, size, size);
                }
            }

            // lines linking all the pieces of the hovered file, so you can see how scattered it is
            if (hoverBlocks != null && hoverBlocks.Count > 1 && hoverBlocks.Count < 400)
                using (var p = new Pen(Color.FromArgb(180, 255, 255, 255), 1.3f) { DashStyle = DashStyle.Dot })
                {
                    PointF prevPt = PointF.Empty; bool first = true;
                    foreach (int i in hoverBlocks)
                    {
                        var pt = new PointF(grid.X + (i % s.Cols) * cell + cell / 2, grid.Y + (i / s.Cols) * cell + cell / 2);
                        if (!first) g.DrawLine(p, prevPt, pt);
                        prevPt = pt; first = false;
                    }
                }
        }
    }

    /// <summary>
    /// An illustration of what a defragmentation does: every file's blocks glide out of the mess and line up one file after another,
    /// free space collecting at the end. Used while a defrag runs on a solid-state drive (where Windows only trims, so nothing really moves),
    /// and for the "Preview defrag" button.
    /// </summary>
    class BlockSim
    {
        readonly DiskSnapshot s;
        readonly int[] src, tgt, own, used;
        readonly int m;

        public BlockSim(DiskSnapshot snap)
        {
            s = snap;
            var idx = Enumerable.Range(0, s.Used.Length).Where(i => s.Used[i] > 0).ToList();
            m = idx.Count;
            src = idx.ToArray();
            own = idx.Select(i => s.Owner[i]).ToArray(); used = idx.Select(i => (int)s.Used[i]).ToArray();
            // order on the finished drive: files one after another, unknown blocks last
            var order = Enumerable.Range(0, m).OrderBy(k => own[k] < 0 ? int.MaxValue : own[k]).ThenBy(k => src[k]).ToList();
            tgt = new int[m];
            for (int r = 0; r < m; r++) tgt[order[r]] = r;
        }

        /// <summary>0 = as it is, 1 = tidy. Loops: tidy up, rest, scatter back.</summary>
        public static double Progress(double t)
        {
            double c = t % 64;
            return c < 40 ? c / 40 : c < 52 ? 1 : 1 - (c - 52) / 12;
        }

        public void Draw(Graphics g, RectangleF area, double t, double p)
        {
            float cell; var grid = BlockPainter.Cell(area, s, out cell);
            float gap = Math.Max(0.8f, cell * 0.14f), size = cell - gap;
            using (var empty = new SolidBrush(Color.FromArgb(34, 40, 54)))
                for (int i = 0; i < s.Cols * s.Rows; i++)
                    g.FillRectangle(empty, grid.X + (i % s.Cols) * cell + gap / 2, grid.Y + (i / s.Cols) * cell + gap / 2, size, size);
            for (int k = 0; k < m; k++)
            {
                double rank = tgt[k] / (double)Math.Max(1, m);
                double local = Math.Min(1, Math.Max(0, p * 1.6 - rank * 0.6));
                double e = local * local * (3 - 2 * local);
                int a = src[k], b = tgt[k];
                float x = grid.X + ((a % s.Cols) + (float)((b % s.Cols) - (a % s.Cols)) * (float)e) * cell;
                float y = grid.Y + ((a / s.Cols) + (float)((b / s.Cols) - (a / s.Cols)) * (float)e) * cell - (float)Math.Sin(Math.PI * local) * cell * 3f;
                Color col = own[k] >= 0 ? BlockPainter.FileColor(s.Files[own[k]]) : Color.FromArgb(120, 130, 160);
                col = Color.FromArgb(Math.Min(255, 90 + used[k] * 165 / 255), col);
                bool moving = local > 0 && local < 1;
                if (moving) { using (var glow = new SolidBrush(Color.FromArgb(60, 255, 255, 255))) g.FillRectangle(glow, x - cell * 0.4f, y - cell * 0.4f, cell * 1.8f, cell * 1.8f); }
                using (var br = new SolidBrush(moving ? Color.FromArgb(255, Math.Min(255, col.R + 50), Math.Min(255, col.G + 50), Math.Min(255, col.B + 50)) : col))
                    g.FillRectangle(br, x + gap / 2, y + gap / 2, size, size);
            }
        }
    }

    /// <summary>The block map as a control.</summary>
    class BlockMapView : Painted
    {
        int hover = -1;
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 40 };
        PointF mouse;
        public BlockMapView() { BackColor = Theme.Bg; timer.Tick += (s, e) => { if (Visible) Invalidate(); }; timer.Start(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            try { Paint2(e); } catch { try { e.Graphics.Clear(Theme.Bg); } catch { } }
        }

        void Paint2(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Theme.Bg);
            Theme.Prep(g);
            g.SmoothingMode = SmoothingMode.HighSpeed;
            Theme.FillRound(g, Color.FromArgb(0x0E, 0x11, 0x17), new RectangleF(0, 0, W, H), 12);
            var s = DefragService.Snapshot;
            var area = new RectangleF(10, 10, W - 20, H - 20);
            if (s == null)
            {
                string msg = DefragService.Building ? DefragService.BuildStatus : DefragService.Error.Length > 0 ? DefragService.Error : "Click \"Map the drive\" to draw it.";
                Theme.Str(g, msg, Theme.F(13), DefragService.Error.Length > 0 ? Theme.Amber : Theme.Muted, new RectangleF(0, 0, W, H), StringAlignment.Center);
                return;
            }
            double tt = clock.Elapsed.TotalSeconds;
            if (DefragService.Preview || (DefragService.Runner.Running && DefragService.Ssd))
            {
                var sim = DefragService.Sim();
                if (sim != null) sim.Draw(g, area, tt, BlockSim.Progress(tt));
                Theme.Str(g, "Illustration of a defrag" + (DefragService.Ssd ? ": this is a solid-state drive, so Windows only trims it and nothing really moves" : ""), Theme.F(11), Color.FromArgb(255, 190, 90), new RectangleF(14, H - 26, W - 28, 18));
                return;
            }
            BlockPainter.Draw(g, area, s, DefragService.Prev, tt, hover, DefragService.Runner.Running);
            if (hover >= 0 && hover < s.Files.Count)
            {
                string tip = Path.GetFileName(s.Files[hover]) + "\n" + s.Frags[hover] + (s.Frags[hover] == 1 ? " piece" : " pieces");
                var sz = g.MeasureString(tip, Theme.F(11));
                float tx = Math.Min(W - sz.Width - 14, mouse.X + 14), ty = Math.Min(H - sz.Height - 12, mouse.Y + 14);
                Theme.FillRound(g, Color.FromArgb(240, 12, 14, 20), new RectangleF(tx - 6, ty - 3, sz.Width + 12, sz.Height + 6), 6);
                g.DrawString(tip, Theme.F(11), B2(Theme.Text), tx, ty);
            }
        }

        static SolidBrush B2(Color c) { return new SolidBrush(c); }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            mouse = new PointF(e.X / Theme.K, e.Y / Theme.K);
            var s = DefragService.Snapshot;
            if (s == null) { hover = -1; return; }
            int b = BlockAt(s);
            hover = b >= 0 && b < s.Owner.Length ? s.Owner[b] : -1;
        }

        int BlockAt(DiskSnapshot s) { return BlockPainter.BlockAt(new RectangleF(10, 10, W - 20, H - 20), s, mouse); }
        protected override void OnMouseLeave(EventArgs e) { hover = -1; base.OnMouseLeave(e); }
        protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }
    }

    /// <summary>The Defrag page.</summary>
    class DefragView : Panel
    {
        readonly Engine eng;
        readonly BlockMapView map = new BlockMapView();
        readonly Btn bDrive = new Btn("C: ▾"), bMap = new Btn("Map the drive"), bAnalyze = new Btn("Analyze"), bGo = new Btn("Defragment now", true), bPrev = new Btn("Preview");
        readonly Label info, stats, last;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 400 };

        public DefragView(Engine engine)
        {
            eng = engine;
            BackColor = Theme.Bg;
            Controls.Add(new Label { Text = "Defrag", Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            Controls.Add(new Label { Text = "Every colour is one file. Hover a block to see how scattered that file is. Windows does the real work, gently.", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });
            bDrive.Bounds = new Rectangle(28, 84, 90, 34);
            bMap.Bounds = new Rectangle(126, 84, 140, 34);
            bAnalyze.Bounds = new Rectangle(274, 84, 100, 34);
            bGo.Bounds = new Rectangle(382, 84, 160, 34);
            bPrev.Bounds = new Rectangle(550, 84, 92, 34);
            bPrev.Click += (s, e) => { DefragService.Preview = !DefragService.Preview; if (DefragService.Snapshot == null) DefragService.Rebuild(true); };
            info = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(28, 122, 614, 20), AutoEllipsis = true };
            map.Bounds = new Rectangle(28, 146, 614, 296);
            stats = new Label { ForeColor = Theme.Text, AutoSize = false, Bounds = new Rectangle(28, 448, 614, 22), AutoEllipsis = true };
            last = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(28, 472, 614, 60), AutoEllipsis = false };
            Controls.AddRange(new Control[] { bDrive, bMap, bAnalyze, bGo, bPrev, info, map, stats, last });

            bDrive.Click += (s, e) => PickDrive();
            bMap.Click += (s, e) => { DefragService.Rebuild(true); };
            bAnalyze.Click += (s, e) => DefragService.Runner.Start(DefragService.Drive, true);
            bGo.Click += (s, e) =>
            {
                if (DefragService.Runner.Running) { DefragService.Runner.Stop(); return; }
                if (!Admin.IsAdmin) { MessageBox.Show(FindForm(), "Defragmenting needs administrator rights. Use the Network page's \"Turn on network monitor\" button to restart TinyGuard as administrator.", "TinyGuard"); return; }
                if (MessageBox.Show(FindForm(), "Defragment " + DefragService.Drive + " now?\n\nWindows' own defrag tool will run at low priority and you can keep using the PC. " +
                        (DefragService.Ssd ? "This drive is a solid-state drive, so Windows will only 'trim' it (no moving of files)." : "It can take a long while on a big hard disk. You can stop it at any time.") + "\n\nProceed?",
                        "Defragment", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                if (DefragService.Snapshot == null) DefragService.Rebuild(true);
                DefragService.Runner.Start(DefragService.Drive, false);
            };
            timer.Tick += (s, e) => Tick();
            timer.Start();
        }

        void PickDrive()
        {
            var menu = Menus.Make();
            foreach (string d in DefragService.Drives())
            {
                string drive = d;
                menu.Items.Add(new ToolStripMenuItem(drive, null, (s, e) => { DefragService.Drive = drive; DefragService.Snapshot = DefragService.Prev = null; DefragService.Rebuild(true); }) { ForeColor = Theme.Text, Checked = drive == DefragService.Drive });
            }
            menu.Show(bDrive, new Point(0, bDrive.Height));
        }

        void Tick()
        {
            if (!Visible) return;
            DefragService.KeepFresh();
            var r = DefragService.Runner;
            bDrive.Text = DefragService.Drive + " ▾";
            bGo.Text = r.Running ? "Stop" : "Defragment now"; bGo.Primary = !r.Running; bGo.Danger = r.Running; bGo.Invalidate();
            bMap.Enabled = !DefragService.Building; bAnalyze.Enabled = !r.Running;
            bPrev.Text = DefragService.Preview ? "Stop preview" : "Preview"; bPrev.Invalidate();
            var s = DefragService.Snapshot;
            info.Text = DefragService.Drive + " · " + (s != null ? (s.TotalClusters * s.ClusterBytes / 1073741824) + " GB · " : "") + (s == null ? "not mapped yet" : DefragService.Ssd ? "solid-state drive: Windows trims it instead of moving files" : "hard disk")
                        + (Admin.IsAdmin ? "" : "  ·  needs administrator rights to map or defragment");
            stats.Text = s == null ? "" : s.FileCount + " files mapped · " + s.Fragmented + " in more than one piece (" + s.FragPercent.ToString("0.0") + "%)" + (r.WindowsFragPercent >= 0 ? " · Windows reports " + r.WindowsFragPercent + "% fragmented" : "");
            last.ForeColor = r.Running ? Theme.Text : Theme.Muted;
            last.Text = r.Running ? (r.Percent > 0 ? r.Percent + "%  " : "") + (r.Last.Length > 0 ? r.Last : "Working…") : r.Report.Length > 0 ? r.Report.Trim().Replace("\r", "").Split('\n').Reverse().Take(4).Reverse().Aggregate((a, b) => a + "\n" + b) : r.Last;
        }
    }
}
