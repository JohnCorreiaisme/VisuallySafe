using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Automation;
using System.Windows.Forms;
using Microsoft.Win32;

namespace TinyGuard
{
    /// <summary>
    /// A light that runs around the edge of a file's icon (in Explorer or on the Desktop) while Visually Safe checks it,
    /// then flashes green (clean), blue (neutral) or red (found something). It is a see-through window that mouse clicks pass through.
    /// </summary>
    class FoundItem { public Rectangle R; public IntPtr Top; }

    static class ScanGlow
    {
        static Control sync;
        static Engine eng;
        static readonly Dictionary<string, GlowForm> open = new Dictionary<string, GlowForm>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, Verdict?> early = new Dictionary<string, Verdict?>(StringComparer.OrdinalIgnoreCase);

        const int MaxGlows = 12;
        public static bool Lit(string path) { return open.ContainsKey(path); }

        public static void Init(Engine e)
        {
            eng = e; sync = new Control(); var h = sync.Handle;
            HoverBadge.Init(e, sync);
            eng.GlowBegin += p => { var s = sync; if (s != null) s.BeginInvoke(new Action(() => Begin(p))); };
            eng.GlowEnd += (p, v) => { var s = sync; if (s != null) s.BeginInvoke(new Action(() => End(p, v))); };
        }

        // pictures / tests
        public static GlowForm MakeAt(Rectangle r) { return new GlowForm(r); }

        static void Begin(string path)
        {
            if (!eng.S.ScanGlow || open.ContainsKey(path)) return;
            if (open.Count >= MaxGlows) return;     // highlighting a whole desktop would draw dozens of lights at once and swamp the window; the first ones show, the rest scan without a light
            early.Remove(path); open[path] = null;     // reserved while we look for the icon
            try { HoverBadge.Release(path); } catch { }
            GlowWork.Run(() =>
            {
                FoundItem r = null;
                try { r = FindItem(path); } catch { }
                sync.BeginInvoke(new Action(() =>
                {
                    if (!open.ContainsKey(path)) return;
                    if (r == null) { open.Remove(path); early.Remove(path); return; }      // not visible anywhere: nothing to light up
                    var f = new GlowForm(r.R) { Top0 = r.Top };
                    open[path] = f;
                    f.FormClosed += (s, e) => { GlowForm cur; if (open.TryGetValue(path, out cur) && cur == f) open.Remove(path); };
                    f.Progress = () => eng.ProgressOf(path);
                    f.Retrack = () => { try { return FindItem(path); } catch { return null; } };
                    f.Show();
                    Verdict? v;
                    if (early.TryGetValue(path, out v)) { early.Remove(path); f.Finish(v); }
                }));
            });
        }

        static void End(string path, Verdict v)
        {
            GlowForm f;
            if (!open.TryGetValue(path, out f)) return;
            if (f == null) early[path] = v; else f.Finish(v);
        }

        // ---------------------------------------------------------------- finding the icon on screen

        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr FindWindowEx(IntPtr parent, IntPtr after, string cls, string title);
        delegate bool EnumProc(IntPtr h, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc p, IntPtr l);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);

        static string NormDir(string d) { try { return Path.GetFullPath(d).TrimEnd('\\'); } catch { return d ?? ""; } }

        // one list of icon positions per window, reused for a moment so that scanning many files at once is cheap
        class Snap { public DateTime At; public Dictionary<string, Rectangle> Items = new Dictionary<string, Rectangle>(StringComparer.OrdinalIgnoreCase); }
        static readonly Dictionary<IntPtr, Snap> snaps = new Dictionary<IntPtr, Snap>();
        static readonly object snapLock = new object();

        static Snap SnapOf(IntPtr root)
        {
            lock (snapLock)
            {
                Snap sn;
                if (snaps.TryGetValue(root, out sn) && (DateTime.Now - sn.At).TotalMilliseconds < 700) return sn;
                sn = new Snap { At = DateTime.Now };
                try
                {
                    var el = AutomationElement.FromHandle(root);
                    var items = el.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));
                    foreach (AutomationElement it in items)
                    {
                        var b = it.Current.BoundingRectangle;
                        if (!b.IsEmpty && b.Width > 8 && b.Height > 8 && !double.IsInfinity(b.X)) sn.Items[it.Current.Name] = new Rectangle((int)b.X, (int)b.Y, (int)b.Width, (int)b.Height);
                    }
                }
                catch { }
                snaps[root] = sn;
                return sn;
            }
        }

        [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr h, int flags);

        public static FoundItem FindItem(string path)
        {
            string dir = NormDir(Path.GetDirectoryName(path)), name = Path.GetFileName(path), noext = Path.GetFileNameWithoutExtension(path);
            var roots = new List<IntPtr>();
            string desk = NormDir(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)), cdesk = NormDir(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            if (string.Equals(dir, desk, StringComparison.OrdinalIgnoreCase) || string.Equals(dir, cdesk, StringComparison.OrdinalIgnoreCase))
            {
                IntPtr lv = DesktopList(); if (lv != IntPtr.Zero) roots.Add(lv);
            }
            roots.AddRange(ExplorerWindowsShowing(dir));
            foreach (IntPtr root in roots)
            {
                var sn = SnapOf(root);
                Rectangle r;
                if (sn.Items.TryGetValue(name, out r) || sn.Items.TryGetValue(noext, out r))
                    return new FoundItem { R = r, Top = GetAncestor(root, 2) };
            }
            return null;
        }

        /// <summary>
        /// The files and folders currently selected on the Desktop and in open Explorer windows (circle a lot of icons, then ask Visually Safe).
        /// The right-click menu entry can't do this: Windows hides a menu entry like ours when more than 15 items are selected.
        /// </summary>
        public static List<string> SelectedPaths(IntPtr front = default(IntPtr))
        {
            // front: the window that was active when the hotkey was pressed. Only that window's selection is used (the Desktop, or one Explorer window); with none, everything selected anywhere counts.
            var sbc = new StringBuilder(64); string frontClass = ""; IntPtr frontTop = IntPtr.Zero;
            if (front != IntPtr.Zero) { GetClassName(front, sbc, 64); frontClass = sbc.ToString(); frontTop = GetAncestor(front, 2); }
            bool onlyDesktop = frontClass == "Progman" || frontClass == "WorkerW";
            bool onlyExplorer = frontClass == "CabinetWClass";
            var res = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Action<string> add = pth => { if (!string.IsNullOrEmpty(pth) && (File.Exists(pth) || Directory.Exists(pth)) && seen.Add(pth)) res.Add(pth); };
            // Explorer windows: the shell tells us the selected items with their full paths
            try
            {
                Type t = Type.GetTypeFromProgID("Shell.Application");
                dynamic shell = Activator.CreateInstance(t);
                if (!onlyDesktop)
                    foreach (dynamic w in shell.Windows())
                        try
                        {
                            if (onlyExplorer && new IntPtr((long)w.HWND) != frontTop) continue;
                            foreach (dynamic it in w.Document.SelectedItems()) { string pp = it.Path as string; add(pp); }
                        }
                        catch { }
            }
            catch { }
            // the Desktop: read which icons are highlighted
            try
            {
                IntPtr lv = onlyExplorer ? IntPtr.Zero : DesktopList();
                if (lv != IntPtr.Zero)
                {
                    var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    bool fast = false;
                    try
                    {
                        // one call asks the list for what is selected (a check on every icon, one by one, takes many seconds when you highlight a lot)
                        object lp;
                        if (AutomationElement.FromHandle(lv).TryGetCurrentPattern(SelectionPattern.Pattern, out lp))
                        {
                            var cr = new CacheRequest(); cr.Add(AutomationElement.NameProperty);
                            using (cr.Activate())
                                foreach (AutomationElement it in ((SelectionPattern)lp).Current.GetSelection()) names.Add(it.Cached.Name);
                            fast = true;
                        }
                    }
                    catch { names.Clear(); fast = false; }
                    if (!fast)
                    {
                        var items = AutomationElement.FromHandle(lv).FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));
                        foreach (AutomationElement it in items)
                        {
                            object pat;
                            if (it.TryGetCurrentPattern(SelectionItemPattern.Pattern, out pat) && ((SelectionItemPattern)pat).Current.IsSelected) names.Add(it.Current.Name);
                        }
                    }
                    if (names.Count > 0)
                        foreach (string dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory) })
                            try
                            {
                                foreach (string e in Directory.EnumerateFileSystemEntries(dir))
                                    if (names.Contains(Path.GetFileName(e)) || names.Contains(Path.GetFileNameWithoutExtension(e))) add(e);
                            }
                            catch { }
                }
            }
            catch { }
            return res;
        }

        /// <summary>The Desktop icon under a screen point, read from the Desktop's own icon list (a full-screen overlay such as the NVIDIA one can hide the icons from a point look-up).</summary>
        public static Tuple<string, Rectangle> DesktopItemAt(Point pt)
        {
            IntPtr lv = DesktopList(); if (lv == IntPtr.Zero) return null;
            foreach (var kv in SnapOf(lv).Items.ToList())
                if (kv.Value.Contains(pt)) return Tuple.Create(kv.Key, kv.Value);
            return null;
        }

        public static string DebugDesktop()
        {
            var lv = DesktopList(); var sb = new StringBuilder("list=" + lv);
            if (lv != IntPtr.Zero) { var sn = SnapOf(lv); sb.Append(" items=" + sn.Items.Count); foreach (var k in sn.Items) { sb.Append(" ; " + k.Key + " " + k.Value); if (sb.Length > 600) break; } }
            return sb.ToString();
        }
        public static string HoverDebug(Engine e, Point p) { return HoverBadge.Debug(e, p); }
        public static IntPtr DesktopListForTest() { return DesktopList(); }

        static IntPtr DesktopList()
        {
            IntPtr found = IntPtr.Zero;
            EnumWindows((h, l) =>
            {
                var sb = new StringBuilder(64); GetClassName(h, sb, 64);
                string c = sb.ToString();
                if (c == "Progman" || c == "WorkerW")
                {
                    IntPtr dv = FindWindowEx(h, IntPtr.Zero, "SHELLDLL_DefView", null);
                    if (dv != IntPtr.Zero) { IntPtr lv = FindWindowEx(dv, IntPtr.Zero, "SysListView32", null); if (lv != IntPtr.Zero) { found = lv; return false; } }
                }
                return true;
            }, IntPtr.Zero);
            return found;
        }

        /// <summary>Explorer windows currently showing the given folder.</summary>
        static readonly Dictionary<string, Tuple<DateTime, List<IntPtr>>> winCache = new Dictionary<string, Tuple<DateTime, List<IntPtr>>>(StringComparer.OrdinalIgnoreCase);

        static List<IntPtr> ExplorerWindowsShowing(string dir)
        {
            lock (winCache)
            {
                Tuple<DateTime, List<IntPtr>> c;
                if (winCache.TryGetValue(dir, out c) && (DateTime.Now - c.Item1).TotalMilliseconds < 1500) return c.Item2;
            }
            var res = ExplorerWindowsShowingNow(dir);
            lock (winCache) winCache[dir] = Tuple.Create(DateTime.Now, res);
            return res;
        }

        static List<IntPtr> ExplorerWindowsShowingNow(string dir)
        {
            var list = new List<IntPtr>();
            try
            {
                Type t = Type.GetTypeFromProgID("Shell.Application");
                dynamic shell = Activator.CreateInstance(t);
                foreach (dynamic w in shell.Windows())
                {
                    try
                    {
                        string p = null;
                        try { p = w.Document.Folder.Self.Path as string; } catch { }
                        if (p == null) continue;
                        if (!string.Equals(NormDir(p), dir, StringComparison.OrdinalIgnoreCase)) continue;
                        IntPtr h = new IntPtr((long)w.HWND);
                        if (IsWindowVisible(h) && !IsIconic(h)) list.Add(h);
                    }
                    catch { }
                }
            }
            catch { }
            return list;
        }
    }


    /// <summary>
    /// Rest the mouse on an icon (Desktop or an Explorer window) that Visually Safe has already scanned and its result badge shows again,
    /// for as long as you set in Settings (48 hours by default) after the scan.
    /// </summary>
    static class HoverBadge
    {
        class Hit { public string Path; public Rectangle R; public IntPtr Top; public Verdict V; }

        static Control sync; static Engine eng;
        static System.Windows.Forms.Timer timer;
        static Point last, handled = new Point(-1, -1);
        static DateTime lastMove = DateTime.Now, leftAt = DateTime.MaxValue;
        static GlowForm form; static Rectangle formRect; static string formPath; static bool resolving; static DateTime resolveAt; static int resolveGen;
        static readonly Dictionary<string, Tuple<DateTime, string[]>> dirs = new Dictionary<string, Tuple<DateTime, string[]>>(StringComparer.OrdinalIgnoreCase);

        [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(Point p);
        [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr h, int flags);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder sb, int n);

        public static void Init(Engine e, Control s)
        {
            eng = e; sync = s;
            timer = new System.Windows.Forms.Timer { Interval = 120 };
            timer.Tick += (a, b) => { try { Tick(); } catch { } };
            timer.Start();
        }

        /// <summary>A scan of this item has begun: take down its "already scanned" badge so the scan light shows instead.</summary>
        public static void Release(string path) { if (form != null && string.Equals(formPath, path, StringComparison.OrdinalIgnoreCase)) Hide(); }

        static void Hide() { var f = form; form = null; leftAt = DateTime.MaxValue; if (f != null) try { f.Close(); } catch { } }

        static void Tick()
        {
            if (!eng.S.ScanGlow || eng.S.BadgeHours <= 0) { Hide(); return; }
            var pt = Control.MousePosition;
            if (pt != last) { last = pt; lastMove = DateTime.Now; }
            if (form != null)
            {
                var r = formRect; r.Inflate(4, 4);
                if (r.Contains(pt)) leftAt = DateTime.MaxValue;
                else { if (leftAt == DateTime.MaxValue) leftAt = DateTime.Now; if ((DateTime.Now - leftAt).TotalMilliseconds > 350) Hide(); }
                return;
            }
            if (resolving && (DateTime.Now - resolveAt).TotalMilliseconds > 2500) { resolving = false; resolveGen++; }     // a look-up that hangs (Windows can stall on a frozen program) must not block the badge for good
            if (resolving || pt == handled || (DateTime.Now - lastMove).TotalMilliseconds < 250 || ScreenSaver.Active) return;
            handled = pt; resolving = true; resolveAt = DateTime.Now; int gen = ++resolveGen;
            GlowWork.Run(() =>
            {
                Hit h = null;
                try { h = Resolve(pt); } catch { }
                try
                {
                    sync.BeginInvoke(new Action(() =>
                    {
                        if (gen != resolveGen) return;      // this look-up was given up on
                        resolving = false;
                        if (h == null || form != null || ScanGlow.Lit(h.Path)) return;
                        var now = Control.MousePosition; if (Math.Abs(now.X - pt.X) > 8 || Math.Abs(now.Y - pt.Y) > 8) return;   // the mouse has moved on
                        var f = ScanGlow.MakeAt(h.R); f.Top0 = h.Top; f.ShowDone(h.V);
                        try { Wizard.OnBadge(h.V, h.Path); } catch { }
                        f.FormClosed += (s2, e2) => { if (ReferenceEquals(form, f)) { form = null; leftAt = DateTime.MaxValue; } };
                        form = f; formRect = h.R; formPath = h.Path; f.Show();
                    }));
                }
                catch { if (gen == resolveGen) resolving = false; }
            });
        }

        static string[] Entries(string dir)
        {
            Tuple<DateTime, string[]> c;
            if (dirs.TryGetValue(dir, out c) && (DateTime.Now - c.Item1).TotalSeconds < 5) return c.Item2;
            string[] list; try { list = Directory.GetFileSystemEntries(dir); } catch { list = new string[0]; }
            dirs[dir] = Tuple.Create(DateTime.Now, list);
            return list;
        }

        public static string Debug(Engine e, Point pt)
        {
            eng = e;
            try
            {
                var el = AutomationElement.FromPoint(new System.Windows.Point(pt.X, pt.Y));
                string r = "el=" + (el == null ? "null" : el.Current.ControlType.ProgrammaticName + " '" + el.Current.Name + "'");
                for (var up = el; up != null; ) { up = TreeWalker.ControlViewWalker.GetParent(up); if (up == null) break; r += " <- " + up.Current.ControlType.ProgrammaticName.Replace("ControlType.", "") + "/" + up.Current.ClassName + "/'" + up.Current.Name + "'"; if (r.Length > 900) break; }
                var h = Resolve(pt);
                return r + " | hit=" + (h == null ? "null" : h.Path + " " + h.V);
            }
            catch (Exception ex) { return "error " + ex.Message; }
        }

        static Hit Resolve(Point pt)
        {
            IntPtr top0 = GetAncestor(WindowFromPoint(pt), 2);
            var sb0 = new StringBuilder(64); GetClassName(top0, sb0, 64); string cls0 = sb0.ToString();
            string name; System.Windows.Rect b;
            var di = (cls0 == "Progman" || cls0 == "WorkerW") ? ScanGlow.DesktopItemAt(pt) : null;
            if (di != null) { name = di.Item1; b = new System.Windows.Rect(di.Item2.X, di.Item2.Y, di.Item2.Width, di.Item2.Height); }
            else
            {
            var el = AutomationElement.FromPoint(new System.Windows.Point(pt.X, pt.Y));
            for (int i = 0; i < 4 && el != null && el.Current.ControlType != ControlType.ListItem && el.Current.ControlType != ControlType.DataItem; i++) el = TreeWalker.ControlViewWalker.GetParent(el);
            if (el == null || (el.Current.ControlType != ControlType.ListItem && el.Current.ControlType != ControlType.DataItem)) return null;
            name = el.Current.Name; b = el.Current.BoundingRectangle;
            }
            if (string.IsNullOrEmpty(name) || b.IsEmpty || double.IsInfinity(b.X) || b.Width < 8 || b.Height < 8) return null;
            IntPtr top = GetAncestor(WindowFromPoint(pt), 2);
            var sb = new StringBuilder(64); GetClassName(top, sb, 64); string cls = sb.ToString();
            var folders = new List<string>();
            if (cls == "Progman" || cls == "WorkerW") { folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)); folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)); }
            else if (cls == "CabinetWClass")
            {
                try
                {
                    dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application"));
                    foreach (dynamic w in shell.Windows())
                        try { if (new IntPtr((long)w.HWND) == top) { string p = w.Document.Folder.Self.Path as string; if (!string.IsNullOrEmpty(p)) folders.Add(p); break; } } catch { }
                }
                catch { }
            }
            string path = null;
            foreach (string d in folders)
            {
                foreach (string e in Entries(d))
                {
                    string fn = Path.GetFileName(e);
                    if (string.Equals(fn, name, StringComparison.OrdinalIgnoreCase) || string.Equals(Path.GetFileNameWithoutExtension(e), name, StringComparison.OrdinalIgnoreCase)) { path = e; break; }
                }
                if (path != null) break;
            }
            if (path == null) return null;
            DateTime when; Verdict v;
            if (!eng.BadgeFor(path, out when, out v)) return null;
            if (eng.S.BadgeHours < 100000 && (DateTime.Now - when).TotalHours > eng.S.BadgeHours) return null;
            return new Hit { Path = path, R = new Rectangle((int)b.X, (int)b.Y, (int)b.Width, (int)b.Height), Top = top, V = v };
        }
    }

    /// <summary>Two dedicated threads for the slow look-ups that find an icon on screen. Windows can stall on them (a busy Explorer window), and they must never take threads away from the scanner.</summary>
    static class GlowWork
    {
        static readonly System.Collections.Concurrent.BlockingCollection<Action> q = new System.Collections.Concurrent.BlockingCollection<Action>();
        static int started;

        static void Ensure()
        {
            if (System.Threading.Interlocked.CompareExchange(ref started, 1, 0) != 0) return;
            for (int i = 0; i < 2; i++)
            {
                var t = new System.Threading.Thread(() => { foreach (var a in q.GetConsumingEnumerable()) { try { a(); } catch { } } }) { IsBackground = true, Name = "Visually Safe icon look-up" };
                t.SetApartmentState(System.Threading.ApartmentState.STA);
                t.Start();
            }
        }

        public static Task Run(Action a)
        {
            Ensure(); var tcs = new TaskCompletionSource<bool>();
            q.Add(() => { try { a(); tcs.SetResult(true); } catch (Exception e) { tcs.SetException(e); } });
            return tcs.Task;
        }

        public static Task<T> Run<T>(Func<T> f)
        {
            Ensure(); var tcs = new TaskCompletionSource<T>();
            q.Add(() => { try { tcs.SetResult(f()); } catch (Exception e) { tcs.SetException(e); } });
            return tcs.Task;
        }
    }

    class GlowForm : Form
    {
        public bool Hover;
        /// <summary>Show only the finished badge (no scan ring): used when the mouse rests on an icon that was scanned earlier.</summary>
        public void ShowDone(Verdict? v) { Hover = true; finished = true; result = v; shown = 1; resultAt = DateTime.Now; endAt = DateTime.MaxValue; }
        Rectangle item;
        const int Pad = 12;
        readonly DateTime started = DateTime.Now;
        DateTime endAt = DateTime.MaxValue, resultAt = DateTime.MaxValue;
        Verdict? result; bool finished, hidden;
        System.Windows.Forms.Timer timer;
        DateTime lastTrack = DateTime.Now;
        System.Threading.Tasks.Task<FoundItem> tracking;
        public Func<FoundItem> Retrack;
        public IntPtr Top0;
        [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(Point p);
        [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr h, int flags);
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);

        [DllImport("user32.dll", SetLastError = true)] static extern bool UpdateLayeredWindow(IntPtr hwnd, IntPtr hdcDst, ref Point pptDst, ref Size psize, IntPtr hdcSrc, ref Point pprSrc, int crKey, ref BLEND pblend, int dwFlags);
        [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
        [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
        [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr dc);
        [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr dc);
        [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr dc, IntPtr o);
        [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr o);
        [StructLayout(LayoutKind.Sequential, Pack = 1)] struct BLEND { public byte Op, Flags, Alpha, Format; }

        public GlowForm(Rectangle itemRect)
        {
            item = itemRect;
            FormBorderStyle = FormBorderStyle.None; ShowInTaskbar = false; TopMost = true; StartPosition = FormStartPosition.Manual;
            Bounds = new Rectangle(item.X - Pad, item.Y - Pad, item.Width + Pad * 2, item.Height + Pad * 2);
            timer = new System.Windows.Forms.Timer { Interval = 40 };
            timer.Tick += (s, e) => Step();
        }

        protected override bool ShowWithoutActivation { get { return true; } }
        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= 0x80000 | 0x20 | 0x80 | 0x8000000 | 0x8;   // layered, click-through, tool window, no-activate, topmost
                return cp;
            }
        }

        protected override void OnShown(EventArgs e) { base.OnShown(e); timer.Start(); Step(); }
        protected override void OnFormClosed(FormClosedEventArgs e) { timer.Stop(); timer.Dispose(); base.OnFormClosed(e); }

        /// <summary>The scan is over: show the result for a moment (the light always runs for at least a second and a half so it can be seen).</summary>
        public void Finish(Verdict? v)
        {
            if (finished) return;
            finished = true; result = v;
            resultAt = DateTime.Now > started.AddMilliseconds(900) ? DateTime.Now : started.AddMilliseconds(900);
            // a clean result fades away slowly (but only while the mouse is moving); a problem stays lit until the icon scrolls away or its window closes
            endAt = DateTime.MaxValue;
        }

        double fade;                      // 0 = fully lit, 1 = gone (clean results only)
        Point lastMouse; DateTime lastMove = DateTime.MinValue, lastStep = DateTime.Now;
        bool Clean { get { return !(result.HasValue && result.Value >= Verdict.Suspicious); } }

        void Step()
        {
            var now = DateTime.Now;
            double dt = Math.Min(0.1, (now - lastStep).TotalSeconds); lastStep = now;
            if (now > endAt || (now < resultAt && now > started.AddMinutes(30))) { Close(); return; }
            // the green result fades slowly, and only while the mouse is being moved (a still mouse means nobody is looking: keep it lit)
            var mp = Control.MousePosition;
            if (mp != lastMouse) { lastMouse = mp; lastMove = now; }
            if (!Hover && finished && Clean && now >= resultAt.AddMilliseconds(1500) && (now - lastMove).TotalMilliseconds < 700)
            {
                fade += dt / 10.0;
                if (fade >= 1) { Close(); return; }
            }
            // follow the icon if the window moves or the list scrolls
            if (Retrack != null && tracking == null && (now - lastTrack).TotalMilliseconds > 900)
            {
                lastTrack = now; var rt = Retrack; tracking = GlowWork.Run(() => rt());
            }
            if (tracking != null && tracking.IsCompleted)
            {
                var r = tracking.Status == System.Threading.Tasks.TaskStatus.RanToCompletion ? tracking.Result : null; tracking = null;
                if (r == null) { Close(); return; }       // the icon is gone (window closed, folder changed or file moved)
                Top0 = r.Top;
                if (r.R != item) { item = r.R; Bounds = new Rectangle(item.X - Pad, item.Y - Pad, item.Width + Pad * 2, item.Height + Pad * 2); }
            }
            // hide while another window covers the icon
            if (Top0 != IntPtr.Zero && IsHandleCreated)
            {
                bool covered = false;
                try
                {
                    IntPtr at = GetAncestor(WindowFromPoint(new Point(item.X + item.Width / 2, item.Y + item.Height / 2)), 2);
                    covered = at != IntPtr.Zero && at != Top0 && at != Handle;
                }
                catch { }
                if (covered != hidden) { hidden = covered; ShowWindow(Handle, covered ? 0 : 4); }
                if (covered) return;
            }
            Advance(dt, now);
            Render(now);
        }

        static float Dist(PointF a, PointF b) { float dx = b.X - a.X, dy = b.Y - a.Y; return (float)Math.Sqrt(dx * dx + dy * dy); }

        // how full the ring is: follows the real progress, never goes backwards, and keeps creeping while a slow online check is under way
        public Func<double> Progress;
        double shown; DateTime reachedAt = DateTime.MaxValue; bool waiting;
        void Advance(double dt, DateTime now)
        {
            double t = Progress != null ? Progress() : -1;
            waiting = !finished && t >= 0 && t < 0.002;
            if (finished) t = 1;
            else
            {
                if (t < 0) t = 0.9 * (1 - Math.Exp(-(now - started).TotalSeconds / 20.0));
                if (t >= 0.8)
                {
                    if (reachedAt == DateTime.MaxValue) reachedAt = now;
                    t = Math.Max(t, 0.8 + 0.17 * (1 - Math.Exp(-(now - reachedAt).TotalSeconds / 6.0)));
                }
                if (t < 0.002) t = 0.5 * (1 - Math.Exp(-(now - started).TotalSeconds / 45.0));     // never sits at 0%: creeps while waiting its turn
                t = Math.Min(t, 0.99);
            }
            if (t > shown) shown += (t - shown) * Math.Min(1.0, dt * (finished ? 10 : 5));
            if (finished && shown > 0.995) shown = 1;
        }

        static PointF Along(RectangleF r, float s)
        {
            float w = r.Width, h = r.Height, per = 2 * (w + h);
            s = ((s % per) + per) % per;
            if (s < w) return new PointF(r.Left + s, r.Top);
            s -= w; if (s < h) return new PointF(r.Right, r.Top + s);
            s -= h; if (s < w) return new PointF(r.Right - s, r.Bottom);
            s -= w; return new PointF(r.Left, r.Bottom - s);
        }

        void Render(DateTime now)
        {
            int W = Width, H = Height;
            if (W < 4 || H < 4 || !IsHandleCreated) return;
            using (var bmp = new Bitmap(W, H, PixelFormat.Format32bppArgb))
            {
                using (var g = Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Color.Transparent);
                    var box = new RectangleF(Pad - 3, Pad - 3, item.Width + 6, item.Height + 6);
                    float per = 2 * (box.Width + box.Height);
                    bool done = now >= resultAt && shown >= 0.985;
                    Color baseC = Color.FromArgb(60, 170, 255);
                    if (done)
                    {
                        // steady coloured box round the icon with a small badge on its corner
                        int kind = result.HasValue && result.Value >= Verdict.Malicious ? 2 : result.HasValue && result.Value == Verdict.Suspicious ? 1 : 0;
                        Color c = kind == 2 ? Color.FromArgb(235, 60, 60) : kind == 1 ? Color.FromArgb(245, 190, 30) : Color.FromArgb(46, 190, 100);
                        double pop = Math.Min(1.0, (now - resultAt).TotalMilliseconds / 260.0);
                        pop = 1 - Math.Pow(1 - pop, 3);
                        using (var pen = new Pen(Color.FromArgb(70, c), 9f) { LineJoin = LineJoin.Round }) using (var path = Theme.Round(box, 8)) g.DrawPath(pen, path);
                        using (var pen = new Pen(c, 3.2f) { LineJoin = LineJoin.Round }) using (var path = Theme.Round(box, 8)) g.DrawPath(pen, path);
                        float bs = (float)(Math.Max(20, Math.Min(30, item.Width * 0.24f)) * (0.4 + 0.6 * pop));
                        var bb = new RectangleF(box.Right - bs * 0.72f, box.Top - bs * 0.28f, bs, bs);
                        using (var path = Theme.Round(bb, bs * 0.22f))
                        {
                            using (var br = new SolidBrush(c)) g.FillPath(br, path);
                            using (var pen = new Pen(Color.White, 1.6f)) g.DrawPath(pen, path);
                        }
                        float cx = bb.X + bs / 2, cy = bb.Y + bs / 2, u = bs / 10f;
                        Color ink = kind == 1 ? Color.FromArgb(60, 40, 0) : Color.White;
                        using (var pen = new Pen(ink, Math.Max(2f, bs * 0.13f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                        {
                            if (kind == 0) g.DrawLines(pen, new[] { new PointF(cx - 3.2f * u, cy + 0.2f * u), new PointF(cx - 1f * u, cy + 2.6f * u), new PointF(cx + 3.4f * u, cy - 2.6f * u) });
                            else if (kind == 1) { g.DrawLine(pen, cx, cy - 3.2f * u, cx, cy + 0.8f * u); using (var ib = new SolidBrush(ink)) g.FillEllipse(ib, cx - 0.75f * u, cy + 2.2f * u, 1.5f * u, 1.5f * u); }
                            else { g.DrawLine(pen, cx - 2.8f * u, cy - 2.8f * u, cx + 2.8f * u, cy + 2.8f * u); g.DrawLine(pen, cx + 2.8f * u, cy - 2.8f * u, cx - 2.8f * u, cy + 2.8f * u); }
                        }
                    }
                    else
                    {
                        // the swirling, pulsing light runs round the icon while it is checked; the percentage sits in a little tag on the corner
                        Color fillC = Color.FromArgb((int)(baseC.R + (46 - baseC.R) * shown), (int)(baseC.G + (190 - baseC.G) * shown), (int)(baseC.B + (100 - baseC.B) * shown));
                        double sec = (now - started).TotalSeconds;
                        float pulse = (float)(0.5 + 0.5 * Math.Sin(sec * 5.0));        // 0..1, about 0.8 beats a second
                        using (var pen = new Pen(Color.FromArgb(50 + (int)(60 * pulse), baseC), 2f + 1.5f * pulse)) using (var path = Theme.Round(box, 8)) g.DrawPath(pen, path);
                        float head = (float)(sec * per / 1.6);          // one lap in about 1.6 seconds
                        float tail = per * 0.5f; int seg = 6;
                        for (float d = 0; d < tail; d += seg)
                        {
                            float k = 1f - d / tail; int a = (int)(255 * k * k);
                            var p1 = Along(box, head - d); var p2 = Along(box, head - d - seg - 1);
                            using (var pen = new Pen(Color.FromArgb(Math.Max(0, (int)(a / 3 * (0.6 + 0.8 * pulse))), 140, 210, 255), 9f + 5f * pulse) { StartCap = LineCap.Round, EndCap = LineCap.Round }) g.DrawLine(pen, p1, p2);
                            using (var pen = new Pen(Color.FromArgb(a, fillC), 4f) { StartCap = LineCap.Round, EndCap = LineCap.Round }) g.DrawLine(pen, p1, p2);
                        }
                        string pct = waiting ? "queued" : ((int)Math.Min(99, Math.Floor(shown * 100))) + "%";
                        using (var f = new Font("Segoe UI Semibold", 8f))
                        {
                            var sz = g.MeasureString(pct, f);
                            var tag = new RectangleF(box.Right - sz.Width - 4, box.Top + 4, sz.Width + 2, sz.Height - 2);
                            using (var path = Theme.Round(tag, 5)) { using (var br = new SolidBrush(Color.FromArgb(230, 25, 30, 40))) g.FillPath(br, path); using (var pen = new Pen(fillC, 1.4f)) g.DrawPath(pen, path); }
                            using (var br = new SolidBrush(Color.White)) g.DrawString(pct, f, br, tag.X + 1, tag.Y - 1);
                        }
                    }
                }
                if (fade > 0.001) FadeAlpha(bmp, 1.0 - fade);
                Blit(bmp);
            }
        }

        static void FadeAlpha(Bitmap bmp, double k)
        {
            var d = bmp.LockBits(new Rectangle(0, 0, bmp.Width, bmp.Height), ImageLockMode.ReadWrite, PixelFormat.Format32bppArgb);
            try
            {
                var buf = new byte[d.Stride * d.Height];
                Marshal.Copy(d.Scan0, buf, 0, buf.Length);
                for (int i = 3; i < buf.Length; i += 4) buf[i] = (byte)(buf[i] * k);
                Marshal.Copy(buf, 0, d.Scan0, buf.Length);
            }
            finally { bmp.UnlockBits(d); }
        }

        void Blit(Bitmap bmp)
        {
            IntPtr screen = GetDC(IntPtr.Zero), mem = CreateCompatibleDC(screen), hb = IntPtr.Zero, old = IntPtr.Zero;
            try
            {
                hb = bmp.GetHbitmap(Color.FromArgb(0));
                old = SelectObject(mem, hb);
                var size = new Size(bmp.Width, bmp.Height); var src = new Point(0, 0); var dst = new Point(Left, Top);
                var bl = new BLEND { Op = 0, Flags = 0, Alpha = 255, Format = 1 };   // AC_SRC_OVER, AC_SRC_ALPHA
                UpdateLayeredWindow(Handle, screen, ref dst, ref size, mem, ref src, 0, ref bl, 2);
            }
            finally
            {
                if (old != IntPtr.Zero) SelectObject(mem, old);
                if (hb != IntPtr.Zero) DeleteObject(hb);
                DeleteDC(mem); ReleaseDC(IntPtr.Zero, screen);
            }
        }
    }

    /// <summary>"Scan with Visually Safe" in the right-click menu of files and folders (current user only).</summary>
    static class ShellMenu
    {
        [DllImport("shell32.dll")] static extern void SHChangeNotify(int eventId, uint flags, IntPtr item1, IntPtr item2);
        static readonly string[] Roots = { @"Software\Classes\*\shell\TinyGuardScan", @"Software\Classes\Directory\shell\TinyGuardScan", @"Software\Classes\AllFilesystemObjects\shell\TinyGuardScan", @"Software\Classes\Drive\shell\TinyGuardScan", @"Software\Classes\lnkfile\shell\TinyGuardScan", @"Software\Classes\InternetShortcut\shell\TinyGuardScan" };     // shortcuts have their own class, which some (run-as-administrator ones) use instead of the general one
        static string OptOut(Engine e) { return Path.Combine(e.DataDir, "no-shellmenu.txt"); }

        public static bool Wanted(Engine e) { return !File.Exists(OptOut(e)); }

        public static void Apply(Engine e)
        {
            try
            {
                if (Wanted(e))
                {
                    bool added = false;
                    foreach (string r in Roots)
                    {
                        using (var chk = Registry.CurrentUser.OpenSubKey(r)) if (chk == null) added = true;
                        using (var k = Registry.CurrentUser.CreateSubKey(r))
                        {
                            k.SetValue("", "Scan with Visually Safe");
                            k.SetValue("Icon", "\"" + Application.ExecutablePath + "\",0");
                            using (var c = k.CreateSubKey("command")) c.SetValue("", "\"" + Application.ExecutablePath + "\" --scan-file \"%1\"");
                        }
                    }
                    if (added) try { SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero); } catch { }     // tell Explorer the file types changed, so the new menu entry shows without signing out
                }
                else
                    foreach (string r in Roots) Registry.CurrentUser.DeleteSubKeyTree(r, false);
            }
            catch { }
        }

        public static void Toggle(Engine e)
        {
            try { if (Wanted(e)) File.WriteAllText(OptOut(e), "off"); else File.Delete(OptOut(e)); } catch { }
            Apply(e);
        }
    }
}
