using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TinyGuard
{
    /// <summary>What the map knows about one file.</summary>
    enum FState { Clean, KnownGood, Unknown, Suspicious, Malicious, Gone, NotScanned, Skipped }

    class MapNode
    {
        public string Name = "", Path = "", Label = "", Detail = "";
        public MapNode Parent, LayoutParent;
        public bool IsFile, IsWatchRoot, Expanded;
        public List<MapNode> Dirs = new List<MapNode>(), Files = new List<MapNode>();
        public Dictionary<string, MapNode> ByName = new Dictionary<string, MapNode>(StringComparer.OrdinalIgnoreCase);
        public FState State = FState.NotScanned;
        public int[] Cnt = new int[8];
        public float X, Y, R, W, Cluster;
        public DateTime Flash = DateTime.MinValue, Time = DateTime.MinValue;
        public List<MapNode> Shown;              // files drawn around an open folder
        public int ShownVersion = -1, Version;
        public bool Deep; public int DeepCnt;
        public int Total { get { int t = 0; foreach (int c in Cnt) t += c; return t; } }
        public int Scanned { get { return Cnt[0] + Cnt[1] + Cnt[2] + Cnt[3] + Cnt[4] + Cnt[5]; } }
        public int Flagged { get { return Cnt[3] + Cnt[4]; } }
    }

    /// <summary>The folder tree behind the node graph, plus the radial layout.</summary>
    class MapModel
    {
        public readonly MapNode Root = new MapNode { Name = "This PC", Expanded = true };
        readonly Dictionary<string, MapNode> files = new Dictionary<string, MapNode>(StringComparer.OrdinalIgnoreCase);
        public readonly List<MapNode> Visible = new List<MapNode>();
        public int FileCount { get { return files.Count; } }
        public const float Ring = 150f;

        static List<string> Split(string dir)
        {
            var res = new List<string>();
            string root = System.IO.Path.GetPathRoot(dir);
            if (string.IsNullOrEmpty(root)) return res;
            res.Add(root);
            foreach (string s in dir.Substring(root.Length).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries)) res.Add(s);
            return res;
        }

        public MapNode Dir(string dir)
        {
            var n = Root;
            var parts = Split(dir ?? "");
            string cur = "";
            for (int i = 0; i < parts.Count; i++)
            {
                cur = i == 0 ? parts[0] : System.IO.Path.Combine(cur, parts[i]);
                MapNode k;
                if (!n.ByName.TryGetValue(parts[i], out k))
                {
                    k = new MapNode { Name = parts[i].TrimEnd('\\'), Path = cur, Parent = n };
                    if (k.Name.Length == 0) k.Name = parts[i];
                    n.ByName[parts[i]] = k; n.Dirs.Add(k);
                }
                n = k;
            }
            return n;
        }

        static void Add(MapNode n, int slot, int delta) { for (var p = n; p != null; p = p.Parent) p.Cnt[slot] += delta; }

        static void AddDeep(MapNode n, int delta) { for (var p = n; p != null; p = p.Parent) p.DeepCnt += delta; }

        public MapNode SetFile(string path, FState st, string detail, DateTime when, bool deep = false)
        {
            MapNode n;
            if (!files.TryGetValue(path, out n))
            {
                var d = Dir(System.IO.Path.GetDirectoryName(path));
                n = new MapNode { Name = System.IO.Path.GetFileName(path), Path = path, IsFile = true, Parent = d, State = st };
                d.Files.Add(n); files[path] = n; d.Version++;
                Add(n, (int)st, 1);
                if (deep) { n.Deep = true; AddDeep(n, 1); }
            }
            else if (n.State != st)
            {
                Add(n, (int)n.State, -1); n.State = st; Add(n, (int)st, 1);
                n.Flash = DateTime.Now; n.Parent.Version++;
            }
            if (n.Deep != deep) { AddDeep(n, deep ? 1 : -1); n.Deep = deep; if (deep) n.Flash = DateTime.Now; }
            n.Detail = detail ?? ""; n.Time = when;
            return n;
        }

        public MapNode Find(string path) { MapNode n; return files.TryGetValue(path, out n) ? n : null; }

        public MapNode Touch(string path)
        {
            var n = Find(path);
            if (n != null) return n;
            if (string.IsNullOrEmpty(System.IO.Path.GetPathRoot(path ?? ""))) return null;
            return SetFile(path, FState.NotScanned, "Being checked now", DateTime.Now);
        }

        public void ExpandInteresting(IEnumerable<string> watchRoots)
        {
            foreach (var n in files.Values)
                if (n.State == FState.Suspicious || n.State == FState.Malicious || n.State == FState.Gone)
                    for (var p = n.Parent; p != null; p = p.Parent) p.Expanded = true;
            foreach (string r in watchRoots) { var d = Dir(r); d.IsWatchRoot = true; for (var p = d; p != null; p = p.Parent) if (p == d) p.Expanded = true; }
        }

        public static void ExpandTo(MapNode n, ref bool changed)
        {
            for (var p = n == null ? null : n.Parent; p != null; p = p.Parent) if (!p.Expanded) { p.Expanded = true; changed = true; }
        }

        // ---- layout: folders in rings around the centre, files as a cluster around their open folder

        public MapNode End(MapNode n)
        {
            string label = n.Name;
            while (n.Dirs.Count == 1 && n.Files.Count == 0 && !n.IsWatchRoot) { n = n.Dirs[0]; label += "\\" + n.Name; }
            n.Label = label;
            return n;
        }

        float Weigh(MapNode n)
        {
            n.R = n == Root ? 22f : Math.Min(24f, 7f + 1.5f * (float)Math.Sqrt(n.Total));
            float shown = n.Expanded ? Math.Min(n.Files.Count, 80) : 0;
            n.Cluster = shown > 0 ? 10f + 4.2f * (float)Math.Sqrt(shown) : 0;
            float own = 2f * (n.R + n.Cluster) + 18f, kids = 0;
            if (n.Expanded) foreach (var d in n.Dirs) kids += Weigh(End(d));
            n.W = Math.Max(own, kids);
            return n.W;
        }

        void Place(MapNode n, float a0, float a1, int depth)
        {
            float am = (a0 + a1) / 2f, r = depth * Ring;
            n.X = r * (float)Math.Cos(am); n.Y = r * (float)Math.Sin(am);
            Visible.Add(n);
            if (!n.Expanded) return;
            var kids = n.Dirs.Select(End).ToList();
            float sum = kids.Sum(k => k.W);
            if (sum <= 0) return;
            float a = a0;
            foreach (var k in kids) { float span = (a1 - a0) * k.W / sum; k.LayoutParent = n; Place(k, a, a + span, depth + 1); a += span; }
        }

        public void Layout()
        {
            Visible.Clear();
            Weigh(Root);
            Place(Root, 0f, (float)(2 * Math.PI), 0);
        }

        /// <summary>The files drawn around an open folder: flagged ones first, then by name, at most 80 (plus the one being scanned).</summary>
        public List<MapNode> ShownFiles(MapNode n, MapNode active)
        {
            if (n.Shown == null || n.ShownVersion != n.Version)
            {
                n.Shown = n.Files.OrderBy(f => (f.State == FState.Malicious || f.State == FState.Suspicious || f.State == FState.Gone) ? 0 : 1).ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase).Take(80).ToList();
                n.ShownVersion = n.Version;
            }
            if (active != null && active.Parent == n && !n.Shown.Contains(active) && n.Shown.Count > 0)
            {
                var l = new List<MapNode>(n.Shown); l[l.Count - 1] = active; return l;
            }
            return n.Shown;
        }
    }

    // ---------------------------------------------------------------------------------------------------------

    class MapView : Painted
    {
        struct Hit { public MapNode N; public float X, Y, R; }

        readonly Engine eng;
        MapModel model = new MapModel();
        volatile MapModel ready;
        volatile bool building;
        bool needLayout = true, needFit;
        float scale = 0.5f, ox, oy;
        public bool Follow = true;
        public bool Saver;                                           // screen-saver look: black, no buttons, scan waves
        public Action<Graphics, float, float, double> BackPainter, FrontPainter;
        class Wave { public double T0; public Dictionary<MapNode, int> Dist; public int Max; }
        readonly List<Wave> waves = new List<Wave>();
        DateTime lastWave = DateTime.MinValue, lastFit = DateTime.Now;
        public MapNode Selected;
        MapNode hover, active;
        string activePath = "";
        DateTime activeSince;
        readonly List<Hit> hits = new List<Hit>();
        Point down; bool dragging, mouseDown; float dragOx, dragOy;
        PointF mouse;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 33 };
        readonly Stopwatch clock = Stopwatch.StartNew();
        public event Action SelectionChanged;
        public event Action<MapNode> OpenRequested;
        int frame;

        static readonly Dictionary<int, SolidBrush> brushes = new Dictionary<int, SolidBrush>();
        static SolidBrush B(Color c) { int k = c.ToArgb(); SolidBrush b; if (!brushes.TryGetValue(k, out b)) brushes[k] = b = new SolidBrush(c); return b; }

        public MapView(Engine engine)
        {
            eng = engine;
            BackColor = Theme.Bg;
            Cursor = Cursors.Hand;
            if (Environment.GetEnvironmentVariable("TINYGUARD_MAPFOLLOW") == "0") Follow = false;   // developer aid
            timer.Tick += (s, e) => Tick();
            timer.Start();
        }

        public int Seen { get { return model.Root.Total; } }
        public MapModel Model { get { return model; } }

        public static Color ColorOf(FState s)
        {
            switch (s)
            {
                case FState.Clean: return Theme.Green;
                case FState.KnownGood: return Theme.Blue;
                case FState.Unknown: return Color.FromArgb(150, 158, 178);
                case FState.Suspicious: return Theme.Amber;
                case FState.Malicious: return Theme.Red;
                case FState.Gone: return Color.FromArgb(40, 120, 255);
                case FState.NotScanned: return Color.FromArgb(110, 118, 138);
                default: return Color.FromArgb(58, 64, 80);
            }
        }

        public static string NameOf(FState s)
        {
            switch (s)
            {
                case FState.Clean: return "Scanned: clean";
                case FState.KnownGood: return "Scanned: known good";
                case FState.Unknown: return "Scanned: unknown (no one recognises it)";
                case FState.Suspicious: return "Suspicious";
                case FState.Malicious: return "Malware";
                case FState.Gone: return "Found here, now quarantined or deleted";
                case FState.NotScanned: return "Not scanned yet";
                default: return "Skipped (not a program or script)";
            }
        }

        public static FState FromEntry(LedgerEntry e)
        {
            if (e.Quarantined || e.Deleted) return FState.Gone;
            switch (e.Verdict)
            {
                case Verdict.Clean: return FState.Clean;
                case Verdict.KnownGood: return FState.KnownGood;
                case Verdict.Unknown: return FState.Unknown;
                case Verdict.Suspicious: return FState.Suspicious;
                default: return FState.Malicious;
            }
        }

        // ------------------------------------------------------------------ building the map

        public void Rebuild()
        {
            if (building) return;
            building = true;
            Task.Run(() =>
            {
                try { ready = Build(); }
                catch { ready = new MapModel(); }
                building = false;
            });
        }

        public bool Building { get { return building; } }

        MapModel Build()
        {
            var m = new MapModel();
            var roots = eng.S.Folders.Where(Directory.Exists).ToList();
            var ledger = new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in eng.LedgerSnapshot()) ledger[kv.Key] = kv.Value;
            var done = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int count = 0;

            foreach (string root in roots)
            {
                var stack = new Stack<string>(); stack.Push(root);
                while (stack.Count > 0 && count < 30000)
                {
                    string dir = stack.Pop();
                    DirectoryInfo di;
                    try { di = new DirectoryInfo(dir); foreach (var sub in di.GetDirectories()) if ((sub.Attributes & FileAttributes.ReparsePoint) == 0) stack.Push(sub.FullName); }
                    catch { continue; }
                    FileInfo[] fis;
                    try { fis = di.GetFiles(); } catch { continue; }
                    foreach (var fi in fis)
                    {
                        if (count++ >= 30000) break;
                        string path = fi.FullName;
                        if (!done.Add(path)) continue;
                        LedgerEntry le; FState st; string detail = "";
                        if (ledger.TryGetValue(path, out le))
                        {
                            if (fi.LastWriteTime > le.Time.AddSeconds(2) && !le.Quarantined && !le.Deleted) { st = FState.NotScanned; detail = "Changed since it was last scanned"; }
                            else { st = FromEntry(le); detail = le.Detail; }
                        }
                        else if (Engine.LooksScannable(path)) st = FState.NotScanned;
                        else st = FState.Skipped;
                        m.SetFile(path, st, detail, le != null ? le.Time : fi.LastWriteTime, le != null && le.Deep && st != FState.NotScanned);
                    }
                }
            }

            // programs and files scanned anywhere else (running programs, old detections)
            foreach (var kv in ledger)
            {
                if (done.Contains(kv.Key)) continue;
                var le = kv.Value;
                bool there = File.Exists(kv.Key);
                if (!there && !le.Quarantined && !le.Deleted && le.Verdict < Verdict.Suspicious) continue;
                m.SetFile(kv.Key, there || le.Quarantined || le.Deleted ? FromEntry(le) : FState.Gone, le.Detail, le.Time, le.Deep);
            }
            foreach (var q in eng.QuarantineSnapshot())
                if (m.Find(q.OriginalPath) == null) m.SetFile(q.OriginalPath, FState.Gone, "Quarantined: " + q.Reason, q.Time);

            m.ExpandInteresting(roots);
            return m;
        }

        // ------------------------------------------------------------------ per-frame work

        void Tick()
        {
            if (!Visible) return;
            frame++;
            var r = ready;
            if (r != null) { ready = null; model = r; needLayout = true; needFit = true; Selected = null; hover = null; active = null; activePath = ""; if (SelectionChanged != null) SelectionChanged(); }

            if (!building)
            {
                var changes = eng.DrainLedgerChanges();
                int n = 0;
                foreach (var kv in changes)
                {
                    if (n++ > 800) break;
                    var node = model.Find(kv.Key);
                    var st = FromEntry(kv.Value);
                    bool existed = node != null;
                    node = model.SetFile(kv.Key, st, kv.Value.Detail, kv.Value.Time, kv.Value.Deep);
                    if (!existed) { node.Flash = DateTime.Now; }
                    if (st == FState.Suspicious || st == FState.Malicious || st == FState.Gone) { bool ch = false; MapModel.ExpandTo(node, ref ch); if (ch) needLayout = true; }
                }
            }

            // which file is being scanned right now
            string ap = Saver && eng.Deep.Active && !string.IsNullOrEmpty(eng.Deep.Current) ? eng.Deep.Current : eng.ActiveFileNow;
            if (!string.IsNullOrEmpty(ap))
            {
                if (!string.Equals(ap, activePath, StringComparison.OrdinalIgnoreCase))
                {
                    activePath = ap; activeSince = DateTime.Now;
                    active = building ? null : model.Touch(ap);
                    if (active != null) { bool ch = false; MapModel.ExpandTo(active, ref ch); if (ch) needLayout = true; }
                }
            }
            else { active = null; activePath = ""; }

            if (needLayout) { model.Layout(); needLayout = false; if (needFit) { FitView(); needFit = false; } }

            if (Saver)
            {
                if (active != null && active.Parent != null && !building && (DateTime.Now - lastWave).TotalMilliseconds > 900) { SpawnWave(active.Parent); lastWave = DateTime.Now; }
                if (active == null && (DateTime.Now - lastFit).TotalSeconds > 12) { FitView(); lastFit = DateTime.Now; }
            }

            // let the camera follow the scan
            if (Follow && active != null && active.Parent != null && model.Visible.Contains(active.Parent))
            {
                var p = active.Parent;
                float tx = -p.X * scale, ty = -p.Y * scale;
                ox += (tx - ox) * 0.12f; oy += (ty - oy) * 0.12f;
                if (scale < 0.5f) scale += (0.7f - scale) * 0.04f;   // zoom in a little so the scan is visible, but not so far that the map is lost
            }
            Invalidate();
        }

        public void FitView()
        {
            if (model.Visible.Count == 0) return;
            float minx = float.MaxValue, maxx = float.MinValue, miny = float.MaxValue, maxy = float.MinValue;
            foreach (var n in model.Visible)
            {
                float e = n.R + n.Cluster + 14;
                minx = Math.Min(minx, n.X - e); maxx = Math.Max(maxx, n.X + e);
                miny = Math.Min(miny, n.Y - e); maxy = Math.Max(maxy, n.Y + e);
            }
            float bw = Math.Max(maxx - minx, 60), bh = Math.Max(maxy - miny, 60);
            scale = Math.Max(0.12f, Math.Min(2.2f, Math.Min((W - 20) / bw, (H - 60) / bh)));
            ox = -((minx + maxx) / 2) * scale; oy = -((miny + maxy) / 2) * scale + 6;
        }

        public void Recentre() { needFit = true; needLayout = true; }
        public void RelayoutSoon() { needLayout = true; }

        // ------------------------------------------------------------------ drawing

        PointF Scr(float x, float y) { return new PointF(W / 2 + ox + x * scale, H / 2 + oy + y * scale); }

        static Color FolderColor(MapNode n)
        {
            if (n.Cnt[(int)FState.Malicious] > 0) return Theme.Red;
            if (n.Cnt[(int)FState.Suspicious] > 0) return Theme.Amber;
            if (n.Cnt[(int)FState.Gone] > 0) return Color.FromArgb(40, 120, 255);
            int scanned = n.Scanned, not = n.Cnt[(int)FState.NotScanned];
            if (scanned == 0 && not == 0) return Color.FromArgb(58, 64, 80);
            if (scanned == 0) return Color.FromArgb(110, 118, 138);
            if (n.Cnt[(int)FState.Unknown] > 0 && n.Cnt[(int)FState.Clean] + n.Cnt[(int)FState.KnownGood] == 0) return Color.FromArgb(150, 158, 178);
            return Theme.Green;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            // One bad drawing call must never turn the whole view into a white box with a red X.
            try { Paint2(e); }
            catch (Exception ex)
            {
                try { File.AppendAllText(Path.Combine(eng.DataDir, "crash.log"), DateTime.Now.ToString("s") + " [map paint] " + ex.Message + Environment.NewLine + ex.StackTrace + Environment.NewLine); } catch { }
                try { e.Graphics.Clear(Saver ? Color.Black : Theme.Bg); } catch { }
            }
        }

        void Paint2(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Saver ? Color.Black : Theme.Bg);
            Theme.Prep(g);
            if (!Saver) Theme.FillRound(g, Color.FromArgb(0x10, 0x13, 0x1A), new RectangleF(0, 0, W, H), 12);
            double t = clock.Elapsed.TotalSeconds;
            DateTime now = DateTime.Now;
            hits.Clear();
            var state = g.Save();
            if (!Saver) using (var clip = Theme.Round(new RectangleF(0, 0, W, H), 12)) g.SetClip(clip);
            if (Saver && BackPainter != null) BackPainter(g, W, H, t);

            if (building && model.FileCount == 0)
            {
                Theme.Str(g, "Building the map…", Theme.F(14), Theme.Muted, new RectangleF(0, 0, W, H), StringAlignment.Center);
                g.Restore(state); return;
            }

            // edges
            using (var pen = new Pen(Theme.Line, 1.3f))
                foreach (var n in model.Visible)
                {
                    if (n.LayoutParent == null) continue;
                    var a = Scr(n.LayoutParent.X, n.LayoutParent.Y); var b = Scr(n.X, n.Y);
                    if (Math.Max(a.X, b.X) < -40 || Math.Min(a.X, b.X) > W + 40 || Math.Max(a.Y, b.Y) < -40 || Math.Min(a.Y, b.Y) > H + 40) continue;
                    pen.Color = n.Cnt[(int)FState.Malicious] > 0 ? Color.FromArgb(150, Theme.Red) : n.Cnt[(int)FState.Suspicious] > 0 ? Color.FromArgb(130, Theme.Amber) : Theme.Line;
                    g.DrawLine(pen, a, b);
                }

            // folders and their files
            foreach (var n in model.Visible)
            {
                var c = Scr(n.X, n.Y);
                float rad = n.R * scale, outer = (n.R + n.Cluster + 14) * scale;
                if (c.X + outer < 0 || c.X - outer > W || c.Y + outer < 0 || c.Y - outer > H) continue;
                hits.Add(new Hit { N = n, X = c.X, Y = c.Y, R = Math.Max(rad, 6) });

                Color col = FolderColor(n);
                if (Saver && n.Total > 0 && n.DeepCnt == 0) col = Color.FromArgb(120, col);
                var rect = new RectangleF(c.X - rad, c.Y - rad, rad * 2, rad * 2);
                if (Saver && n.DeepCnt > 0)
                {
                    float fr = n.DeepCnt / (float)Math.Max(1, n.Total);
                    g.FillEllipse(B(Color.FromArgb(14 + (int)(60 * fr), 80, 255, 170)), c.X - rad - 12, c.Y - rad - 12, rad * 2 + 24, rad * 2 + 24);
                }
                if (n.Flagged > 0 || n.Cnt[(int)FState.Gone] > 0)
                    g.FillEllipse(B(Color.FromArgb(40, col)), c.X - rad - 7, c.Y - rad - 7, rad * 2 + 14, rad * 2 + 14);
                bool hollow = n.Scanned == 0 && n.Total > 0;
                if (hollow) { using (var p = new Pen(col, 2f)) g.DrawEllipse(p, rect); g.FillEllipse(B(Color.FromArgb(30, col)), rect); }
                else g.FillEllipse(B(col), rect);
                // scanned fraction ring
                int sc = n.Scanned, ns = n.Cnt[(int)FState.NotScanned];
                if (Saver) { sc = n.DeepCnt; ns = Math.Max(0, n.Total - n.DeepCnt); }
                if (sc + ns > 0 && rad > 4)
                {
                    var rr = new RectangleF(c.X - rad - 3.5f, c.Y - rad - 3.5f, rad * 2 + 7, rad * 2 + 7);
                    using (var p = new Pen(Color.FromArgb(70, 76, 92), 2.2f)) g.DrawEllipse(p, rr);
                    if (sc > 0)
                    {
                        // GDI+ throws "out of memory" for arcs of a fraction of a degree, so keep the sweep in a safe range
                        float sweep = Math.Max(4f, Math.Min(359.5f, 360f * sc / (sc + ns)));
                        try { using (var p = new Pen(Theme.Green, 2.2f)) g.DrawArc(p, rr, -90, sweep); } catch { }
                    }
                }
                if (n == Selected) using (var p = new Pen(Theme.Text, 2f)) g.DrawEllipse(p, c.X - rad - 8, c.Y - rad - 8, rad * 2 + 16, rad * 2 + 16);
                if (!n.Expanded && n.Files.Count + n.Dirs.Count > 0 && rad > 6)
                    Theme.Str(g, "+", Theme.F(Math.Max(10, rad * 1.1f), true), Color.FromArgb(10, 14, 20), new RectangleF(c.X - rad, c.Y - rad, rad * 2, rad * 2), StringAlignment.Center);

                if (n.Expanded && n.Files.Count > 0)
                {
                    var list = model.ShownFiles(n, active);
                    for (int i = 0; i < list.Count; i++)
                    {
                        var f = list[i];
                        double ang = i * 2.39996323, dist = (n.R + 9 + 4.2 * Math.Sqrt(i)) * scale;
                        float fx = c.X + (float)(Math.Cos(ang) * dist), fy = c.Y + (float)(Math.Sin(ang) * dist);
                        f.X = (fx - W / 2 - ox) / scale; f.Y = (fy - H / 2 - oy) / scale;   // remembered for hit-testing and animation
                        float fr = Math.Max(2.2f, 3.1f * scale);
                        if (fx < -10 || fx > W + 10 || fy < -10 || fy > H + 10) continue;
                        Color fc = ColorOf(f.State);
                        if (f.State == FState.NotScanned) { using (var p = new Pen(fc, 1.3f)) g.DrawEllipse(p, fx - fr, fy - fr, fr * 2, fr * 2); }
                        else if (f.State == FState.Gone) { using (var p = new Pen(fc, 1.6f)) { g.DrawEllipse(p, fx - fr, fy - fr, fr * 2, fr * 2); g.DrawLine(p, fx - fr, fy - fr, fx + fr, fy + fr); } }
                        else g.FillEllipse(B(fc), fx - fr, fy - fr, fr * 2, fr * 2);
                        if (f.State == FState.Malicious || f.State == FState.Suspicious) g.FillEllipse(B(Color.FromArgb(50, fc)), fx - fr * 2.2f, fy - fr * 2.2f, fr * 4.4f, fr * 4.4f);
                        double age = (now - f.Flash).TotalMilliseconds;
                        if (age < 900) { float k = (float)(age / 900); using (var p = new Pen(Color.FromArgb((int)(200 * (1 - k)), fc), 1.6f)) g.DrawEllipse(p, fx - fr - 14 * k, fy - fr - 14 * k, (fr + 14 * k) * 2, (fr + 14 * k) * 2); }
                        hits.Add(new Hit { N = f, X = fx, Y = fy, R = Math.Max(fr + 2, 5) });
                    }
                    if (n.Files.Count > list.Count)
                        Theme.Str(g, "+" + (n.Files.Count - list.Count) + " more", Theme.F(10), Theme.Grey, new RectangleF(c.X - 50, c.Y + (n.R + n.Cluster + 2) * scale, 100, 14), StringAlignment.Center);
                }
            }

            if (Saver) DrawWaves(g, t);

            // the scan itself: pulse and sweep on the folder being scanned, glow and dashed beam to the active file
            if (active != null && active.Parent != null)
            {
                var fo = active.Parent;
                var c = Scr(fo.X, fo.Y);
                float rad = fo.R * scale;
                Color blue = Color.FromArgb(120, 190, 255);
                for (int k = 0; k < 2; k++)
                {
                    float ph = (float)((t * 0.9 + k * 0.5) % 1.0);
                    float rr = rad + 6 + ph * 30 * Math.Max(0.6f, scale);
                    using (var p = new Pen(Color.FromArgb((int)(170 * (1 - ph)), blue), 2f)) g.DrawEllipse(p, c.X - rr, c.Y - rr, rr * 2, rr * 2);
                }
                float sr = rad + 8;
                using (var p = new Pen(blue, 3.2f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                    g.DrawArc(p, c.X - sr, c.Y - sr, sr * 2, sr * 2, (float)((t * 240) % 360), 75f);

                float fx = c.X + 30, fy = c.Y - 30;
                if (fo.Expanded)
                {
                    var list = model.ShownFiles(fo, active);
                    int i = list.IndexOf(active);
                    if (i >= 0) { double ang = i * 2.39996323, dist = (fo.R + 9 + 4.2 * Math.Sqrt(i)) * scale; fx = c.X + (float)(Math.Cos(ang) * dist); fy = c.Y + (float)(Math.Sin(ang) * dist); }
                }
                using (var p = new Pen(Color.FromArgb(200, blue), 1.6f) { DashStyle = DashStyle.Dash, DashOffset = (float)(-t * 6) })
                    g.DrawLine(p, c.X, c.Y, fx, fy);
                float pr = 5f + 2f * (float)Math.Sin(t * 8);
                g.FillEllipse(B(Color.FromArgb(70, blue)), fx - pr * 2.6f, fy - pr * 2.6f, pr * 5.2f, pr * 5.2f);
                g.FillEllipse(B(Color.White), fx - pr * 0.8f, fy - pr * 0.8f, pr * 1.6f, pr * 1.6f);
                using (var p = new Pen(blue, 2f)) g.DrawEllipse(p, fx - pr, fy - pr, pr * 2, pr * 2);
                string nm = active.Name;
                var sz = g.MeasureString(nm, Theme.F(11, true));
                var pill = new RectangleF(fx - sz.Width / 2 - 6, fy - pr - 26, sz.Width + 12, 20);
                Theme.FillRound(g, Color.FromArgb(230, 14, 26, 44), pill, 10);
                Theme.Str(g, nm, Theme.F(11, true), Color.FromArgb(190, 225, 255), pill, StringAlignment.Center);
            }

            // folder names
            foreach (var h in hits)
            {
                var n = h.N;
                if (n.IsFile) continue;
                bool show = scale >= 0.55f || n == Selected || n == hover || n.IsWatchRoot || n.Flagged > 0 || (active != null && active.Parent == n);
                if (!show) continue;
                string label = string.IsNullOrEmpty(n.Label) ? n.Name : n.Label;
                if (label.Length > 34) label = "…" + label.Substring(label.Length - 33);
                Theme.Str(g, label, Theme.F(11, n == Selected), n == Selected ? Theme.Text : Theme.Muted, new RectangleF(h.X - 90, h.Y + h.R + 6, 180, 16), StringAlignment.Center);
            }

            g.Restore(state);
            if (Saver) { if (FrontPainter != null) FrontPainter(g, W, H, t); return; }
            DrawOverlay(g);

            if (hover != null && !dragging && hover != Selected)
            {
                string tip = hover.IsFile ? hover.Name + "\n" + NameOf(hover.State) : (hover.Label.Length > 0 ? hover.Label : hover.Name) + "\n" + hover.Total + " files, " + hover.Scanned + " scanned";
                var sz = g.MeasureString(tip, Theme.F(11));
                float tx = Math.Min(W - sz.Width - 14, mouse.X + 14), ty = Math.Min(H - sz.Height - 12, mouse.Y + 14);
                Theme.FillRound(g, Color.FromArgb(240, 12, 14, 20), new RectangleF(tx - 6, ty - 3, sz.Width + 12, sz.Height + 6), 6);
                using (var sf = new StringFormat()) g.DrawString(tip, Theme.F(11), B(Theme.Text), tx, ty, sf);
            }
        }

        // ------------------------------------------------------------------ scan waves (screen saver): the scan visibly spreading from folder to folder

        void SpawnWave(MapNode src)
        {
            if (!model.Visible.Contains(src)) return;
            var adj = new Dictionary<MapNode, List<MapNode>>();
            foreach (var n in model.Visible)
                if (n.LayoutParent != null)
                {
                    List<MapNode> a, b;
                    if (!adj.TryGetValue(n.LayoutParent, out a)) adj[n.LayoutParent] = a = new List<MapNode>();
                    if (!adj.TryGetValue(n, out b)) adj[n] = b = new List<MapNode>();
                    a.Add(n); b.Add(n.LayoutParent);
                }
            var dist = new Dictionary<MapNode, int> { { src, 0 } };
            var q = new Queue<MapNode>(); q.Enqueue(src); int max = 0;
            while (q.Count > 0)
            {
                var n = q.Dequeue(); int d = dist[n];
                if (d >= 9) continue;
                List<MapNode> nb;
                if (!adj.TryGetValue(n, out nb)) continue;
                foreach (var m in nb) if (!dist.ContainsKey(m)) { dist[m] = d + 1; max = Math.Max(max, d + 1); q.Enqueue(m); }
            }
            waves.Add(new Wave { T0 = clock.Elapsed.TotalSeconds, Dist = dist, Max = max });
            while (waves.Count > 5) waves.RemoveAt(0);
        }

        void DrawWaves(Graphics g, double t)
        {
            for (int wi = waves.Count - 1; wi >= 0; wi--)
            {
                var w = waves[wi];
                double f = (t - w.T0) * 2.3;
                if (f > w.Max + 3.5) { waves.RemoveAt(wi); continue; }
                foreach (var kv in w.Dist)
                {
                    var n = kv.Key; double k = f - kv.Value;
                    if (k < 0 || k > 3) continue;
                    var c = Scr(n.X, n.Y);
                    float rr = n.R * scale + 5 + (float)k * 10;
                    using (var p = new Pen(Color.FromArgb((int)(220 * (1 - k / 3)), 110, 255, 190), 2f)) g.DrawEllipse(p, c.X - rr, c.Y - rr, rr * 2, rr * 2);
                    if (k < 1) g.FillEllipse(B(Color.FromArgb((int)(60 * (1 - k)), 130, 255, 200)), c.X - rr, c.Y - rr, rr * 2, rr * 2);
                }
                // bright dots racing along the links as the scan spreads
                foreach (var n in model.Visible)
                {
                    var par = n.LayoutParent; int dn, dp;
                    if (par == null || !w.Dist.TryGetValue(n, out dn) || !w.Dist.TryGetValue(par, out dp)) continue;
                    MapNode near = dn < dp ? n : par, far = dn < dp ? par : n; int dnear = Math.Min(dn, dp);
                    double tt = f - dnear;
                    if (tt <= 0 || tt >= 1.6) continue;
                    var a = Scr(near.X, near.Y); var b = Scr(far.X, far.Y);
                    float u = (float)Math.Min(1, tt);
                    float x = a.X + (b.X - a.X) * u, y = a.Y + (b.Y - a.Y) * u;
                    int al = (int)(255 * (1.6 - tt) / 1.6);
                    g.FillEllipse(B(Color.FromArgb(al / 3, 130, 255, 200)), x - 9, y - 9, 18, 18);
                    g.FillEllipse(B(Color.FromArgb(al, 220, 255, 240)), x - 3.2f, y - 3.2f, 6.4f, 6.4f);
                }
            }
        }

        void DrawOverlay(Graphics g)
        {
            var root = model.Root;
            int seen = root.Total, scanned = root.Scanned, not = root.Cnt[(int)FState.NotScanned], flagged = root.Flagged, gone = root.Cnt[(int)FState.Gone], skipped = root.Cnt[(int)FState.Skipped];
            string head = seen + " files · " + scanned + " scanned · " + not + " not scanned yet" + (skipped > 0 ? " · " + skipped + " not programs" : "") + " · " + flagged + " flagged" + (gone > 0 ? " · " + gone + " removed" : "");
            Theme.FillRound(g, Color.FromArgb(200, 12, 14, 20), new RectangleF(10, 10, Math.Min(W - 20, 12 + head.Length * 6.3f), 24), 8);
            Theme.Str(g, head, Theme.F(12, true), eng.ScanActive ? Theme.Blue : Theme.Text, new RectangleF(18, 10, W - 36, 24));

            if (eng.ScanActive)
            {
                int tot = Math.Max(eng.ScanTotal, 1), dn = Math.Min(eng.ScanDone, tot); string cur = eng.ScanCurrent;
                string txt = (eng.ScanStopped ? "Stopping… " : "Manual scan: ") + dn + " of " + eng.ScanTotal + " files" + (eng.ScanFound > 0 ? " · " + eng.ScanFound + " found" : "") +
                             (string.IsNullOrEmpty(cur) ? "" : " · " + System.IO.Path.GetFileName(cur));
                float bw = Math.Min(W - 20, 12 + txt.Length * 6.3f);
                Theme.FillRound(g, Color.FromArgb(215, 12, 14, 20), new RectangleF(10, 38, bw, 30), 8);
                Theme.Str(g, txt, Theme.F(12, true), Theme.Blue, new RectangleF(18, 38, W - 36, 24));
                Theme.FillRound(g, Theme.Card2, new RectangleF(18, 61, bw - 16, 4), 2);
                Theme.FillRound(g, Theme.Green, new RectangleF(18, 61, Math.Max(4, (bw - 16) * dn / tot), 4), 2);
            }

            var items = new[] { FState.Clean, FState.Unknown, FState.Suspicious, FState.Malicious, FState.Gone, FState.NotScanned };
            string[] names = { "Clean", "Unknown", "Suspicious", "Malware", "Removed", "Not scanned" };
            float x = 14, y = H - 26;
            Theme.FillRound(g, Color.FromArgb(200, 12, 14, 20), new RectangleF(10, y - 4, 420, 24), 8);
            for (int i = 0; i < items.Length; i++)
            {
                var c = ColorOf(items[i]);
                if (items[i] == FState.NotScanned) using (var p = new Pen(c, 1.5f)) g.DrawEllipse(p, x, y + 3, 9, 9); else g.FillEllipse(B(c), x, y + 3, 9, 9);
                Theme.Str(g, names[i], Theme.F(11), Theme.Muted, new RectangleF(x + 13, y - 1, 80, 18));
                x += 14 + 13 + names[i].Length * 6.2f;
            }
            if (Selected != null)
            {
                var n = Selected;
                string line = n.IsFile ? n.Name + ": " + NameOf(n.State) + (n.Detail.Length > 0 ? " · " + n.Detail : "")
                                       : (n.Label.Length > 0 ? n.Label : n.Name) + ": " + n.Total + " files · " + n.Scanned + " scanned · " + n.Cnt[(int)FState.NotScanned] + " not scanned yet · " + n.Flagged + " flagged";
                Theme.FillRound(g, Color.FromArgb(225, 12, 14, 20), new RectangleF(10, H - 58, W - 20, 24), 8);
                Theme.Str(g, line, Theme.F(12), Theme.Text, new RectangleF(18, H - 58, W - 36, 24));
            }
        }

        // ------------------------------------------------------------------ mouse

        MapNode HitTest(PointF p)
        {
            for (int i = hits.Count - 1; i >= 0; i--)
            {
                var h = hits[i]; float dx = p.X - h.X, dy = p.Y - h.Y;
                if (dx * dx + dy * dy <= (h.R + 3) * (h.R + 3) && h.N.IsFile) return h.N;
            }
            for (int i = hits.Count - 1; i >= 0; i--)
            {
                var h = hits[i]; float dx = p.X - h.X, dy = p.Y - h.Y;
                if (!h.N.IsFile && dx * dx + dy * dy <= (h.R + 4) * (h.R + 4)) return h.N;
            }
            return null;
        }

        PointF Design(Point p) { return new PointF(p.X / Theme.K, p.Y / Theme.K); }

        protected override void OnMouseDown(MouseEventArgs e) { Focus(); if (e.Button == MouseButtons.Left) { mouseDown = true; dragging = false; down = e.Location; dragOx = ox; dragOy = oy; } }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            mouse = Design(e.Location);
            if (mouseDown)
            {
                if (!dragging && (Math.Abs(e.X - down.X) > 4 || Math.Abs(e.Y - down.Y) > 4)) { dragging = true; Follow = false; if (FollowChanged != null) FollowChanged(); }
                if (dragging) { ox = dragOx + (e.X - down.X) / Theme.K; oy = dragOy + (e.Y - down.Y) / Theme.K; }
            }
            else hover = HitTest(mouse);
        }

        public event Action FollowChanged;

        protected override void OnMouseUp(MouseEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            bool wasDrag = dragging; mouseDown = false; dragging = false;
            if (wasDrag) return;
            var n = HitTest(Design(e.Location));
            if (n == null) { Selected = null; if (SelectionChanged != null) SelectionChanged(); return; }
            Selected = n;
            if ((ModifierKeys & Keys.Alt) != 0) { if (OpenRequested != null) OpenRequested(n); }
            else if (!n.IsFile && (n.Dirs.Count + n.Files.Count) > 0) { n.Expanded = !n.Expanded; needLayout = true; }
            if (SelectionChanged != null) SelectionChanged();
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            var p = Design(e.Location);
            float old = scale;
            scale = Math.Max(0.1f, Math.Min(4f, scale * (e.Delta > 0 ? 1.18f : 1f / 1.18f)));
            float k = scale / old;
            // keep the point under the cursor fixed
            float cx = p.X - W / 2, cy = p.Y - H / 2;
            ox = cx - (cx - ox) * k; oy = cy - (cy - oy) * k;
            Follow = false; if (FollowChanged != null) FollowChanged();
        }

        protected override void OnMouseDoubleClick(MouseEventArgs e) { if (HitTest(Design(e.Location)) == null) { FitView(); } }

        protected override void OnVisibleChanged(EventArgs e) { base.OnVisibleChanged(e); if (Visible && model.FileCount == 0 && !building) Rebuild(); }

        public void SetRate(int ms) { if (timer.Interval != ms) timer.Interval = ms; }
        protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }
    }

    // ---------------------------------------------------------------------------------------------------------

    /// <summary>The Scan map page: the node graph plus its buttons.</summary>
    class MapPage : Panel
    {
        readonly Engine eng;
        readonly MapView view;
        readonly Btn bScan = new Btn("Quick scan", true), bFolder = new Btn("Scan this"), bOpen = new Btn("Properties…"), bFit = new Btn("Fit view"), bFollow = new Btn("Follow: on"), bRefresh = new Btn("Refresh");

        public MapPage(Engine engine)
        {
            eng = engine;
            BackColor = Theme.Bg;
            Controls.Add(new Label { Text = "Scan map", Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            Controls.Add(new Label { Text = "Folders as nodes: what's scanned, what isn't, and where threats were found. Click a folder to open it.", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });
            view = new MapView(eng) { Bounds = new Rectangle(28, 84, 614, 404) };
            Controls.Add(view);

            bScan.Bounds = new Rectangle(28, 498, 112, 36);
            bFolder.Bounds = new Rectangle(148, 498, 104, 36);
            bOpen.Bounds = new Rectangle(260, 498, 128, 36);
            bFit.Bounds = new Rectangle(396, 498, 84, 36);
            bFollow.Bounds = new Rectangle(488, 498, 96, 36);
            bRefresh.Bounds = new Rectangle(592, 498, 50, 36);
            bRefresh.Text = "↻";
            Controls.AddRange(new Control[] { bScan, bFolder, bOpen, bFit, bFollow, bRefresh });

            bScan.Click += (s, e) => { if (eng.ScanActive) eng.StopScan(); else eng.QuickScan(); };
            bFolder.Click += (s, e) =>
            {
                var n = view.Selected; if (n == null) return;
                if (n.IsFile) eng.ScanNow(n.Path); else eng.QuickScan(new[] { n.Path });
            };
            bOpen.Click += (s, e) => OpenNode(view.Selected);
            bFit.Click += (s, e) => { view.FitView(); };
            bFollow.Click += (s, e) => { view.Follow = !view.Follow; UpdateButtons(); };
            bRefresh.Click += (s, e) => view.Rebuild();
            view.SelectionChanged += UpdateButtons;
            view.FollowChanged += UpdateButtons;
            view.OpenRequested += OpenNode;
            var t = new System.Windows.Forms.Timer { Interval = 400 };
            t.Tick += (s, e) => { if (Visible) UpdateButtons(); };
            t.Start();
            UpdateButtons();
        }

        void UpdateButtons()
        {
            var n = view.Selected;
            bScan.Text = eng.ScanActive ? "Stop scan" : "Quick scan"; bScan.Primary = !eng.ScanActive; bScan.Danger = eng.ScanActive; bScan.Invalidate();
            bFolder.Enabled = n != null && !eng.ScanActive;
            bFolder.Text = n != null && n.IsFile ? "Scan file" : "Scan folder";
            bOpen.Enabled = n != null;
            bOpen.Text = n != null && !n.IsFile ? "Open folder" : "Properties…";
            bFollow.Text = view.Follow ? "Follow: on" : "Follow: off"; bFollow.Invalidate();
            bFolder.Invalidate(); bOpen.Invalidate();
        }

        void OpenNode(MapNode n)
        {
            if (n == null) return;
            if (!n.IsFile)
            {
                try { if (Directory.Exists(n.Path)) Process.Start("explorer.exe", "\"" + n.Path + "\""); } catch { }
                return;
            }
            var rec = eng.Snapshot().FirstOrDefault(r => string.Equals(r.FilePath, n.Path, StringComparison.OrdinalIgnoreCase));
            if (rec == null)
            {
                Verdict v = n.State == FState.Malicious ? Verdict.Malicious : n.State == FState.Suspicious ? Verdict.Suspicious : n.State == FState.Clean ? Verdict.Clean : n.State == FState.KnownGood ? Verdict.KnownGood : Verdict.Unknown;
                rec = new ScanRecord { FilePath = n.Path, Time = n.Time == DateTime.MinValue ? DateTime.Now : n.Time, Verdict = v, Detail = n.Detail.Length > 0 ? n.Detail : MapView.NameOf(n.State), Quarantined = n.State == FState.Gone };
            }
            Props.Show(FindForm(), eng, Props.ForRecord(eng, rec));
        }
    }
}
