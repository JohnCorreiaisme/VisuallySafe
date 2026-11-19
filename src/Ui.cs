using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Security;
using System.Text;

namespace TinyGuard
{
    enum GuardState { Protected, Paused, Off, Alert }

    static class Theme
    {
        public static float K = 1f; // screen scale (1.0 at 100%)
        public static readonly Color Bg = Color.FromArgb(0x12, 0x15, 0x1C);
        public static readonly Color Side = Color.FromArgb(0x0C, 0x0F, 0x15);
        public static readonly Color Card = Color.FromArgb(0x1B, 0x20, 0x2D);
        public static readonly Color Card2 = Color.FromArgb(0x27, 0x2E, 0x40);
        public static readonly Color Line = Color.FromArgb(0x25, 0x2B, 0x3A);
        public static readonly Color Text = Color.FromArgb(0xE8, 0xEB, 0xF2);
        public static readonly Color Muted = Color.FromArgb(0x8A, 0x94, 0xA8);
        public static readonly Color Green = Color.FromArgb(0x2F, 0xC9, 0x7A);
        public static readonly Color Amber = Color.FromArgb(0xF2, 0xA9, 0x3B);
        public static readonly Color Red = Color.FromArgb(0xF0, 0x56, 0x52);
        public static readonly Color Grey = Color.FromArgb(0x6B, 0x73, 0x85);
        public static readonly Color Blue = Color.FromArgb(0x5B, 0x9B, 0xF5);

        static readonly Dictionary<string, Font> fonts = new Dictionary<string, Font>();

        /// <summary>Pixel-sized font for custom painting (painting is scaled by K as a whole).</summary>
        public static Font F(float px, bool bold = false)
        {
            string key = px + (bold ? "b" : "r");
            if (!fonts.TryGetValue(key, out Font f))
                fonts[key] = f = new Font(bold ? "Segoe UI Semibold" : "Segoe UI", px, FontStyle.Regular, GraphicsUnit.Pixel);
            return f;
        }

        public static Color Of(GuardState s)
        {
            return s == GuardState.Protected ? Green : s == GuardState.Paused ? Amber : s == GuardState.Alert ? Red : Grey;
        }

        public static Color Of(Verdict v)
        {
            switch (v)
            {
                case Verdict.Clean: return Green;
                case Verdict.KnownGood: return Blue;
                case Verdict.Unknown: return Grey;
                case Verdict.Suspicious: return Amber;
                default: return Red;
            }
        }

        public static string Label(Verdict v)
        {
            switch (v)
            {
                case Verdict.Clean: return "Safe";
                case Verdict.KnownGood: return "Known good";
                case Verdict.Unknown: return "Unknown";
                case Verdict.Suspicious: return "Suspicious";
                default: return "Malware";
            }
        }

        public static void Prep(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            g.ScaleTransform(K, K);
        }

        public static GraphicsPath Round(RectangleF r, float rad)
        {
            float d = rad * 2;
            var p = new GraphicsPath();
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static void FillRound(Graphics g, Color c, RectangleF r, float rad)
        {
            using (var p = Round(r, rad)) using (var b = new SolidBrush(c)) g.FillPath(b, p);
        }

        public static void Str(Graphics g, string s, Font f, Color c, RectangleF r, StringAlignment align = StringAlignment.Near)
        {
            using (var b = new SolidBrush(c))
            using (var sf = new StringFormat(StringFormatFlags.NoWrap) { Trimming = StringTrimming.EllipsisCharacter, Alignment = align, LineAlignment = StringAlignment.Center })
                g.DrawString(s, f, b, r, sf);
        }

        public static void DrawShield(Graphics g, RectangleF r, GuardState st)
        {
            float x = r.X, y = r.Y, w = r.Width, h = r.Height;
            using (var p = new GraphicsPath())
            {
                p.AddLine(x + w * 0.5f, y, x + w, y + h * 0.16f);
                p.AddLine(x + w, y + h * 0.16f, x + w, y + h * 0.5f);
                p.AddBezier(x + w, y + h * 0.5f, x + w, y + h * 0.78f, x + w * 0.72f, y + h * 0.93f, x + w * 0.5f, y + h);
                p.AddBezier(x + w * 0.5f, y + h, x + w * 0.28f, y + h * 0.93f, x, y + h * 0.78f, x, y + h * 0.5f);
                p.AddLine(x, y + h * 0.5f, x, y + h * 0.16f);
                p.CloseFigure();
                using (var b = new SolidBrush(Of(st))) g.FillPath(b, p);
            }
            using (var pen = new Pen(Color.White, w * 0.1f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            {
                if (st == GuardState.Protected)
                    g.DrawLines(pen, new[] { new PointF(x + w * 0.29f, y + h * 0.50f), new PointF(x + w * 0.44f, y + h * 0.64f), new PointF(x + w * 0.72f, y + h * 0.36f) });
                else if (st == GuardState.Paused)
                {
                    g.DrawLine(pen, x + w * 0.39f, y + h * 0.34f, x + w * 0.39f, y + h * 0.64f);
                    g.DrawLine(pen, x + w * 0.61f, y + h * 0.34f, x + w * 0.61f, y + h * 0.64f);
                }
                else if (st == GuardState.Off)
                    g.DrawLine(pen, x + w * 0.32f, y + h * 0.48f, x + w * 0.68f, y + h * 0.48f);
                else
                {
                    g.DrawLine(pen, x + w * 0.5f, y + h * 0.26f, x + w * 0.5f, y + h * 0.54f);
                    g.DrawLine(pen, x + w * 0.5f, y + h * 0.72f, x + w * 0.5f, y + h * 0.721f);
                }
            }
        }

        static Icon appIcon;
        /// <summary>The program's own icon (the one stored in the exe), falling back to the drawn shield.</summary>
        public static Icon AppIcon()
        {
            if (appIcon == null)
            {
                try { appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
                if (appIcon == null) appIcon = MakeIcon(GuardState.Protected);
            }
            return appIcon;
        }

        public static Icon MakeIcon(GuardState st)
        {
            using (var bmp = new Bitmap(32, 32))
            {
                using (var g = Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    DrawShield(g, new RectangleF(3, 1, 26, 30), st);
                }
                return Icon.FromHandle(bmp.GetHicon());
            }
        }
    }

    static class Native
    {
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] static extern int SetWindowTheme(IntPtr hwnd, string app, string id);

        public static void DarkTitle(IntPtr hwnd) { try { int on = 1; DwmSetWindowAttribute(hwnd, 20, ref on, 4); } catch { } }
        public static void DarkScroll(IntPtr hwnd) { try { SetWindowTheme(hwnd, "DarkMode_Explorer", null); } catch { } }
    }

    /// <summary>
    /// "Start with Windows". Normally a per-user Run key. Once TinyGuard runs as administrator (for the network
    /// monitor) it uses a logon scheduled task with highest rights instead, so it starts elevated without a prompt.
    /// </summary>
    static class Startup
    {
        const string Key = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string TaskName = "TinyGuard";
        static bool? taskCache;

        static bool RunKey()
        {
            try { using (var k = Registry.CurrentUser.OpenSubKey(Key)) return k != null && k.GetValue("TinyGuard") != null; }
            catch { return false; }
        }

        static void SetRunKey(bool on)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(Key, true))
                {
                    if (on) k.SetValue("TinyGuard", "\"" + Application.ExecutablePath + "\"");
                    else k.DeleteValue("TinyGuard", false);
                }
            }
            catch { }
        }

        static int Schtasks(string args, bool elevate = false)
        {
            try
            {
                var psi = new ProcessStartInfo("schtasks.exe", args) { CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
                if (elevate) { psi.UseShellExecute = true; psi.Verb = "runas"; }
                else { psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; }
                using (var p = Process.Start(psi))
                {
                    if (!elevate) { p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); }
                    p.WaitForExit(15000);
                    return p.ExitCode;
                }
            }
            catch { return -1; }
        }

        static bool TaskExists()
        {
            if (taskCache == null) taskCache = Schtasks("/Query /TN " + TaskName) == 0;
            return taskCache.Value;
        }

        static bool CreateTask()
        {
            // XML so the task never times out (schtasks' default would stop TinyGuard after 3 days) and runs on battery.
            string user = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            string xml =
"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
"  <RegistrationInfo><Description>Starts TinyGuard with administrator rights for its network monitor.</Description></RegistrationInfo>\r\n" +
"  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + SecurityElement.Escape(user) + "</UserId></LogonTrigger></Triggers>\r\n" +
"  <Principals><Principal id=\"Author\"><UserId>" + SecurityElement.Escape(user) + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n" +
"  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>\r\n" +
"  <Actions Context=\"Author\"><Exec><Command>" + SecurityElement.Escape(Application.ExecutablePath) + "</Command></Exec></Actions>\r\n" +
"</Task>\r\n";
            string file = Path.Combine(Path.GetTempPath(), "tinyguard-task.xml");
            File.WriteAllText(file, xml, Encoding.Unicode);
            bool ok = Schtasks("/Create /F /TN " + TaskName + " /XML \"" + file + "\"") == 0;
            try { File.Delete(file); } catch { }
            taskCache = null;
            return ok;
        }

        public static bool Get() { return RunKey() || TaskExists(); }

        public static void Set(bool on)
        {
            if (on)
            {
                if (Admin.IsAdmin && CreateTask()) SetRunKey(false);
                else SetRunKey(true);
            }
            else
            {
                SetRunKey(false);
                if (TaskExists()) Schtasks("/Delete /F /TN " + TaskName, !Admin.IsAdmin); // removing an admin task needs admin
                taskCache = null;
            }
        }

        /// <summary>When running as administrator, switch an existing Run-key startup over to the task.</summary>
        public static void UpgradeIfAdmin()
        {
            if (Admin.IsAdmin && RunKey() && CreateTask()) SetRunKey(false);
        }
    }

    class Painted : Control
    {
        public Painted()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Bg;
        }
        protected float W { get { return Width / Theme.K; } }
        protected float H { get { return Height / Theme.K; } }
    }

    /// <summary>Fixed-size labels end up scaled twice on some screens; this sets them again from the intended (unscaled) rectangle kept in their Tag.</summary>
    static class FitLabels
    {
        public static void Apply(Control root)
        {
            foreach (Control c in root.Controls)
            {
                var l = c as Label;
                if (l != null && l.Tag is Rectangle)
                {
                    var r = (Rectangle)l.Tag;
                    l.Bounds = new Rectangle((int)Math.Round(r.X * Theme.K), (int)Math.Round(r.Y * Theme.K), (int)Math.Round(r.Width * Theme.K), (int)Math.Round(r.Height * Theme.K));
                }
                Apply(c);
            }
        }
    }

    class Btn : Painted
    {
        public bool Primary, Danger;
        bool hover;

        public Btn(string text, bool primary = false) { Text = text; Primary = primary; Cursor = Cursors.Hand; }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            Theme.Prep(g);
            Color c = Primary ? Theme.Green : Theme.Card2;
            if (!Enabled) c = Theme.Card;
            else if (hover) c = ControlPaint.Light(c, 0.25f);
            Theme.FillRound(g, c, new RectangleF(0, 0, W, H), 8);
            Color t = !Enabled ? Theme.Grey : Primary ? Color.FromArgb(8, 32, 20) : Danger ? Theme.Red : Theme.Text;
            Theme.Str(g, Text, Theme.F(13, true), t, new RectangleF(0, 0, W, H - 1), StringAlignment.Center);
        }
    }

    class Toggle : Painted
    {
        public bool On;
        public event Action Toggled;

        public Toggle() { Cursor = Cursors.Hand; BackColor = Theme.Card; }

        protected override void OnClick(EventArgs e) { On = !On; Invalidate(); if (Toggled != null) Toggled(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(BackColor);
            Theme.Prep(g);
            Theme.FillRound(g, On ? Theme.Green : Theme.Grey, new RectangleF(0, 0, W, H), H / 2);
            float d = H - 8;
            using (var b = new SolidBrush(Color.White)) g.FillEllipse(b, On ? W - d - 4 : 4, 4, d, d);
        }
    }

    class DarkList : ListBox
    {
        public Action<Graphics, object, RectangleF, bool> Painter;

        public DarkList(int rowHeight)
        {
            DrawMode = DrawMode.OwnerDrawFixed;
            BorderStyle = BorderStyle.None;
            BackColor = Theme.Bg;
            IntegralHeight = false;
            ItemHeight = (int)(rowHeight * Theme.K);
            SetStyle(ControlStyles.OptimizedDoubleBuffer, true);
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkScroll(Handle); }

        // Don't let Windows wipe the list to its background before every repaint (the other cause of blinking);
        // rows paint their own full background, and the empty strip under the last row is filled in OnPaint.
        protected override void WndProc(ref Message m)
        {
            if (m.Msg == 0x14) { m.Result = (IntPtr)1; return; }
            base.WndProc(ref m);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            int used = (Items.Count - TopIndex) * ItemHeight;
            if (used < Height)
                using (var b = new SolidBrush(BackColor)) e.Graphics.FillRectangle(b, 0, Math.Max(0, used), Width, Height - Math.Max(0, used));
        }

        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            if (e.Index < 0 || e.Index >= Items.Count || Painter == null) return;
            var g = e.Graphics;
            var state = g.Save();
            g.TranslateTransform(e.Bounds.X, e.Bounds.Y);
            Theme.Prep(g);
            Painter(g, Items[e.Index], new RectangleF(0, 0, e.Bounds.Width / Theme.K, e.Bounds.Height / Theme.K),
                (e.State & DrawItemState.Selected) != 0);
            g.Restore(state);
        }

        public void Fill<T>(List<T> items)
        {
            // Same rows in the same order: leave the list alone (clearing it every second is what made it blink).
            if (Items.Count == items.Count)
            {
                bool same = true;
                for (int k = 0; k < items.Count && same; k++) same = ReferenceEquals(Items[k], items[k]);
                if (same) { Invalidate(); return; }
            }
            object selItem = SelectedItem; int top = TopIndex;
            BeginUpdate();
            Items.Clear();
            foreach (T i in items) Items.Add(i);
            if (selItem != null) { int at = Items.IndexOf(selItem); if (at >= 0) SelectedIndex = at; }
            if (top >= 0 && top < Items.Count) TopIndex = top;
            EndUpdate();
        }
    }

    class Sidebar : Painted
    {
        static readonly string[] Names = { "Status", "Activity", "Network", "Rootkit check", "AI helper", "Scan map", "Net tools", "Defrag", "Quarantine", "Settings", "Shields" };
        public int Selected;
        public bool Badge;
        public GuardState State;
        public event Action<int> Picked;

        public Sidebar() { BackColor = Theme.Side; }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            float y = e.Y / Theme.K - 92;
            int i = (int)Math.Floor(y / 34);
            if (y >= 0 && i < Names.Length && Picked != null) Picked(i);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(BackColor);
            Theme.Prep(g);
            Theme.DrawShield(g, new RectangleF(22, 26, 26, 30), State);
            Theme.Str(g, "TinyGuard", Theme.F(19, true), Theme.Text, new RectangleF(58, 24, 130, 34));
            for (int i = 0; i < Names.Length; i++)
            {
                var r = new RectangleF(12, 92 + i * 34, W - 24, 31);
                bool sel = i == Selected;
                if (sel)
                {
                    Theme.FillRound(g, Theme.Card, r, 8);
                    Theme.FillRound(g, Theme.Green, new RectangleF(12, r.Y + 9, 4, 20), 2);
                }
                Theme.Str(g, Names[i], Theme.F(14, sel), sel ? Theme.Text : Theme.Muted, new RectangleF(32, r.Y - 2, 130, 38));
                if (i == 1 && Badge)
                    using (var b = new SolidBrush(Theme.Red)) g.FillEllipse(b, W - 36, r.Y + 14, 10, 10);
            }
            string s = State == GuardState.Protected ? "Protecting" : State == GuardState.Paused ? "Paused" : State == GuardState.Off ? "Off" : "Threat found";
            using (var b = new SolidBrush(Theme.Of(State))) g.FillEllipse(b, 22, H - 53, 8, 8);
            Theme.Str(g, s, Theme.F(12), Theme.Muted, new RectangleF(36, H - 60, 140, 22));
            Theme.Str(g, "v" + Engine.Version, Theme.F(12), Theme.Grey, new RectangleF(22, H - 38, 140, 22));
        }
    }

    class StatusView : Painted
    {
        readonly Engine eng;
        readonly Func<GuardState> state;
        public readonly Toggle Switch = new Toggle();
        public readonly Btn Quick = new Btn("Quick scan", true);
        public readonly Btn ScanFile = new Btn("Scan a file…");
        public readonly Btn Review = new Btn("Review") { Visible = false };

        public StatusView(Engine eng, Func<GuardState> state)
        {
            this.eng = eng; this.state = state;
            Switch.Bounds = new Rectangle(556, 88, 60, 32);
            Quick.Bounds = new Rectangle(28, 306, 130, 38);
            ScanFile.Bounds = new Rectangle(170, 306, 130, 38);
            Review.Bounds = new Rectangle(512, 306, 130, 38);
            Controls.Add(Switch); Controls.Add(Quick); Controls.Add(ScanFile); Controls.Add(Review);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(BackColor);
            Theme.Prep(g);
            GuardState st = state();

            // hero card
            Theme.FillRound(g, Theme.Card, new RectangleF(28, 24, 614, 160), 14);
            Theme.DrawShield(g, new RectangleF(58, 50, 90, 106), st);
            string title, sub;
            int folders = eng.S.Folders.Count(Directory.Exists);
            switch (st)
            {
                case GuardState.Alert: title = "Threat found"; sub = "Open Activity to see what was caught"; break;
                case GuardState.Paused: title = "Protection paused"; sub = "Turns back on at " + eng.PausedUntil.ToString("h:mm tt"); break;
                case GuardState.Off: title = "Protection is off"; sub = "New files are not being checked"; break;
                default:
                    title = "You're protected";
                    sub = "Watching " + folders + (folders == 1 ? " folder" : " folders") + "  ·  " + Layers();
                    break;
            }
            Theme.Str(g, title, Theme.F(28, true), Theme.Text, new RectangleF(176, 62, 370, 42));
            Theme.Str(g, sub, Theme.F(14), Theme.Muted, new RectangleF(178, 108, 370, 26));
            if (st == GuardState.Protected)
                Theme.Str(g, "Programs are checked as they start  ·  network monitor " + (eng.Net != null && eng.Net.Running ? "on" : "off"),
                    Theme.F(13), Theme.Grey, new RectangleF(178, 134, 380, 24));

            // counters
            eng.Stats(out int today, out int threats, out int unknown, out int quar);
            string[] labels = { "Checked today", "Threats caught", "Unknown today", "In quarantine" };
            int[] nums = { today, threats, unknown, quar };
            Color[] cols = { Theme.Text, threats > 0 ? Theme.Red : Theme.Text, Theme.Text, quar > 0 ? Theme.Amber : Theme.Text };
            for (int i = 0; i < 4; i++)
            {
                var r = new RectangleF(28 + i * 157, 200, 143, 88);
                Theme.FillRound(g, Theme.Card, r, 12);
                Theme.Str(g, nums[i].ToString(), Theme.F(28, true), cols[i], new RectangleF(r.X + 16, r.Y + 12, 120, 38));
                Theme.Str(g, labels[i], Theme.F(12), Theme.Muted, new RectangleF(r.X + 17, r.Y + 54, 120, 22));
            }

            int q = eng.QueueLength, attention = eng.NeedAttention();
            if (eng.ScanActive)
            {
                int total = Math.Max(eng.ScanTotal, 1), done = Math.Min(eng.ScanDone, total);
                string head = (eng.ScanStopped ? "Stopping… " : "Scanning ") + done + " of " + eng.ScanTotal + " files" +
                              (eng.ScanFound > 0 ? "  ·  " + eng.ScanFound + " found" : "");
                Theme.Str(g, head, Theme.F(13, true), eng.ScanFound > 0 ? Theme.Amber : Theme.Text, new RectangleF(318, 302, 324, 22));
                Theme.FillRound(g, Theme.Card2, new RectangleF(318, 328, 324, 8), 4);
                if (done > 0) Theme.FillRound(g, Theme.Green, new RectangleF(318, 328, Math.Max(8, 324f * done / total), 8), 4);
                string cur = eng.ScanCurrent;
                if (!string.IsNullOrEmpty(cur)) Theme.Str(g, Path.GetFileName(cur), Theme.F(11), Theme.Muted, new RectangleF(318, 340, 324, 18));
            }
            else if (attention > 0)
                Theme.Str(g, attention + (attention == 1 ? " file needs" : " files need") + " attention", Theme.F(13, true), Theme.Amber, new RectangleF(318, 306, 190, 38));
            else if (eng.ScanEnded != DateTime.MinValue)
                Theme.Str(g, (eng.ScanStopped ? "Scan stopped" : "Scan finished") + ": " + eng.ScanDone + " files checked, nothing wrong found",
                    Theme.F(13), Theme.Muted, new RectangleF(318, 306, 324, 38));
            else if (q > 0) Theme.Str(g, "Checking " + q + (q == 1 ? " file…" : " files…"), Theme.F(13), Theme.Muted, new RectangleF(318, 306, 320, 38));

            // latest
            Theme.FillRound(g, Theme.Card, new RectangleF(28, 362, 614, 174), 14);
            Theme.Str(g, "Latest checks", Theme.F(14, true), Theme.Text, new RectangleF(46, 372, 300, 28));
            var recent = eng.Snapshot().Take(4).ToList();
            if (recent.Count == 0)
                Theme.Str(g, "Nothing yet. New programs and scripts in your watched folders will show up here.",
                    Theme.F(13), Theme.Muted, new RectangleF(46, 420, 580, 30));
            for (int i = 0; i < recent.Count; i++)
            {
                var r = recent[i];
                float y = 406 + i * 31;
                using (var b = new SolidBrush(Theme.Of(r.Verdict))) g.FillEllipse(b, 48, y + 10, 9, 9);
                Theme.Str(g, r.Name, Theme.F(13), Theme.Text, new RectangleF(68, y, 300, 30));
                Theme.Str(g, Theme.Label(r.Verdict) + (r.Quarantined ? " · quarantined" : ""), Theme.F(13), Theme.Of(r.Verdict), new RectangleF(374, y, 170, 30));
                Theme.Str(g, When(r.Time), Theme.F(12), Theme.Muted, new RectangleF(540, y, 86, 30), StringAlignment.Far);
            }
        }

        string Layers()
        {
            var on = new List<string>();
            if (eng.S.Cloud) on.Add("online");
            if (eng.Ai != null) on.Add("AI");
            if (eng.Yara.Ready) on.Add("YARA");
            if (on.Count == 0) return "local checks only";
            return (on.Count == 1 ? on[0] : string.Join(", ", on.Take(on.Count - 1)) + " and " + on[on.Count - 1]) + " checks on";
        }

        public static string When(DateTime t)
        {
            return t.Date == DateTime.Today ? t.ToString("h:mm tt") : t.ToString("MMM d");
        }
    }

    /// <summary>Explains the selected quarantined file and what each button does.</summary>
    class QuarDetailView : Painted
    {
        public QuarantineItem Item;

        public QuarDetailView() { BackColor = Theme.Bg; }

        static void Wrap(Graphics g, string text, Font f, Color c, RectangleF r)
        {
            using (var b = new SolidBrush(c))
            using (var sf = new StringFormat { Trimming = StringTrimming.EllipsisWord })
                g.DrawString(text, f, b, r, sf);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            Theme.Prep(g);
            Theme.FillRound(g, Theme.Card, new RectangleF(0, 0, W, H), 12);
            if (Item == null)
            {
                Theme.Str(g, "Pick a file above to see why it was locked away and what you can do with it.", Theme.F(13), Theme.Muted, new RectangleF(18, 0, W - 36, H));
                return;
            }
            var q = Item;
            using (var b = new SolidBrush(Theme.Red)) g.FillEllipse(b, 18, 15, 11, 11);
            Theme.Str(g, q.Name + " — locked away " + StatusView.When(q.Time), Theme.F(14, true), Theme.Text, new RectangleF(38, 8, W - 56, 24));
            Theme.Str(g, "Was in: " + q.OriginalPath, Theme.F(11), Theme.Grey, new RectangleF(38, 30, W - 56, 16));
            Wrap(g, "Why: " + q.Reason, Theme.F(12), Theme.Muted, new RectangleF(18, 52, W - 36, 36));
            Wrap(g, "What you can do: it can't run while it's here, so there's nothing urgent. Delete forever removes it for good. " +
                    "Restore puts it back and marks it safe, so only use that if you're sure it was a mistake. Look up online shows what other antivirus engines say.",
                Theme.F(12), Theme.Text, new RectangleF(18, 92, W - 36, 56));
        }
    }

    /// <summary>Explains the selected Activity item in plain words and says what can be done about it.</summary>
    class DetailView : Painted
    {
        public ScanRecord Rec;

        public DetailView() { BackColor = Theme.Bg; }

        public static string Advice(ScanRecord r)
        {
            if (!r.Quarantined && !File.Exists(r.FilePath))
                return "The file is gone (deleted or moved), so there's nothing left to do.";
            if (r.Quarantined)
                return "Already locked away in Quarantine, so it can't run. Open the Quarantine page to delete it for good, or restore it if you were wrong.";
            switch (r.Verdict)
            {
                case Verdict.Malicious:
                    return "Known malware. Click Quarantine now to lock it away so it can't run, then delete it from the Quarantine page. If you opened it, also run a full scan with Windows Security.";
                case Verdict.Suspicious:
                    return "TinyGuard isn't certain. If you don't recognise it or didn't expect it, click Quarantine (you can restore it later). If you made it or trust where it came from, click Mark as safe. \"Look up online\" shows what other antivirus engines say.";
                case Verdict.Unknown:
                    return "Nobody recognises this file yet, which is normal for new or home-made programs. If you made it or trust the source, click Mark as safe. If you're unsure, click Quarantine.";
                default:
                    return "Nothing to do. This file looks fine.";
            }
        }

        static void Wrap(Graphics g, string text, Font f, Color c, RectangleF r)
        {
            using (var b = new SolidBrush(c))
            using (var sf = new StringFormat { Trimming = StringTrimming.EllipsisWord })
                g.DrawString(text, f, b, r, sf);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            Theme.Prep(g);
            Theme.FillRound(g, Theme.Card, new RectangleF(0, 0, W, H), 12);
            if (Rec == null)
            {
                Theme.Str(g, "Pick an item above to see why it was flagged and what you can do about it.", Theme.F(13), Theme.Muted, new RectangleF(18, 0, W - 36, H));
                return;
            }
            var r = Rec;
            using (var b = new SolidBrush(Theme.Of(r.Verdict))) g.FillEllipse(b, 18, 15, 11, 11);
            Theme.Str(g, Theme.Label(r.Verdict) + (r.Quarantined ? " · quarantined" : "") + " — " + r.Name, Theme.F(14, true), Theme.Text, new RectangleF(38, 8, W - 56, 24));
            Theme.Str(g, r.FilePath, Theme.F(11), Theme.Grey, new RectangleF(38, 30, W - 56, 16));
            Wrap(g, "Why: " + r.Detail, Theme.F(12), Theme.Muted, new RectangleF(18, 52, W - 36, 36));
            Wrap(g, "What you can do: " + Advice(r), Theme.F(12), r.IsThreat && !r.Quarantined ? Theme.Text : Theme.Muted, new RectangleF(18, 92, W - 36, 56));
        }
    }

    class MainForm : Form
    {
        readonly Engine eng;
        readonly Sidebar side = new Sidebar();
        readonly Control[] pages = new Control[11];
        readonly NetToolsView nettools;
        readonly DefragView defrag;
        CheckBox cSaverIdle, cSaverSys, cSaverDefrag;
        Btn bSaverMinutes, bSaverNow;
        Label lSaver;
        public event Action SaverRequested, DefragSaverRequested;
        Btn bSaverMode, bDefragNow;
        readonly MapPage map;
        readonly AssistantView assistant;
        readonly RootkitView rootkit;
        readonly NetworkView network;
        public event Action ElevateRequested;
        public int CurrentPage { get; private set; }
        readonly StatusView status;
        readonly DarkList activity = new DarkList(52), quar = new DarkList(52);
        readonly Label activityEmpty, quarEmpty;
        readonly Btn bQuar = new Btn("Quarantine"), bDeleteFile = new Btn("Delete") { Danger = true }, bSafe = new Btn("Mark as safe"), bIgnore = new Btn("Ignore  ▾"),
            bShow = new Btn("Show in folder"), bLookup = new Btn("Look up online"), bQuarAll = new Btn("Quarantine all", true);
        readonly Btn bDeleteAll = new Btn("Delete all") { Danger = true }, bQLookup = new Btn("Look up online");
        readonly QuarDetailView qdetail = new QuarDetailView();
        Panel quarPage;
        readonly DetailView detail = new DetailView();
        readonly Btn bRestore = new Btn("Restore"), bDelete = new Btn("Delete forever") { Danger = true };
        readonly CheckBox cStartup, cCloud, cAuto, cDefender;
        readonly Btn bBadge;
        static string BadgeText(int h) { return h <= 0 ? "scanned badge: off  ▾" : h >= 100000 ? "scanned badge: never expires  ▾" : "scanned badge lasts " + BadgeDialog.Fmt(h) + "  ▾"; }
        readonly ListBox lFolders, lSafe;
        readonly TextBox tKey;
        readonly Label lRules;
        int seenRevision = -1;
        bool loading;

        public bool Alert;
        public bool ReallyClose;
        public event Action AlertSeen;
        public event Action ScanFileRequested;

        public GuardState State
        {
            get
            {
                if (!eng.S.Enabled) return GuardState.Off;
                if (!eng.Active) return GuardState.Paused;
                return Alert ? GuardState.Alert : GuardState.Protected;
            }
        }

        public MainForm(Engine engine)
        {
            eng = engine;
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "TinyGuard";
            ClientSize = new Size(860, 560);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = new Font("Segoe UI", 9.5f);
            Icon = Theme.AppIcon();

            side.Bounds = new Rectangle(0, 0, 190, 560);
            side.Picked += SelectPage;
            Controls.Add(side);

            // ----- Status -----
            status = new StatusView(eng, () => State);
            status.Switch.Toggled += () => { eng.SetEnabled(!eng.Active); RefreshAll(true); };
            status.Quick.Click += (s, e) => { if (eng.ScanActive) eng.StopScan(); else eng.QuickScan(); RefreshAll(true); };
            status.Review.Click += (s, e) => SelectPage(1);
            status.ScanFile.Click += (s, e) => { if (ScanFileRequested != null) ScanFileRequested(); };
            pages[0] = status;

            // ----- Activity -----
            var pa = Page("Activity", "Every program and script TinyGuard has checked. Alt+click one for properties, links and an AI fix.");
            activity.Bounds = new Rectangle(28, 84, 614, 242);
            activity.Painter = PaintRecord;
            activity.SelectedIndexChanged += (s, e) => UpdateButtons();
            activity.MouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Left || (Control.ModifierKeys & Keys.Alt) == 0) return;
                int i = activity.IndexFromPoint(e.Location);
                if (i >= 0) { activity.SelectedIndex = i; ActProperties(); }
            };
            activityEmpty = Empty("Nothing checked yet.", new Rectangle(28, 84, 614, 396));
            detail.Bounds = new Rectangle(28, 334, 614, 154);
            bQuar.Bounds = new Rectangle(28, 498, 112, 36);
            bDeleteFile.Bounds = new Rectangle(148, 498, 84, 36);
            bSafe.Bounds = new Rectangle(240, 498, 110, 36);
            bIgnore.Bounds = new Rectangle(356, 498, 92, 36);
            bShow.Bounds = new Rectangle(454, 498, 90, 36) ;
            bLookup.Bounds = new Rectangle(550, 498, 92, 36);
            bShow.Text = "Show"; bLookup.Text = "Look up";
            bIgnore.Click += (s, e) => ActIgnore();
            bQuarAll.Bounds = new Rectangle(382, 20, 260, 34);
            bQuarAll.Visible = false;
            bQuar.Click += (s, e) => ActQuarantine();
            bDeleteFile.Click += (s, e) => ActDelete();
            bSafe.Click += (s, e) => ActSafe();
            bShow.Click += (s, e) => ActShow();
            bLookup.Click += (s, e) => ActLookup(activity.SelectedItem is ScanRecord lr ? lr.Sha256 : null);
            bQuarAll.Click += (s, e) => ActQuarantineAll();

            // Right-click a row for the same actions.
            var menu = Menus.Make();
            var mQuar = new ToolStripMenuItem("Quarantine (lock it away)", null, (s, e) => ActQuarantine());
            var mDel = new ToolStripMenuItem("Delete permanently…", null, (s, e) => ActDelete());
            var mSafe = new ToolStripMenuItem("Mark as safe", null, (s, e) => ActSafe());
            var mShow = new ToolStripMenuItem("Show in folder", null, (s, e) => ActShow());
            var mLook = new ToolStripMenuItem("Look up online", null, (s, e) => ActLookup(activity.SelectedItem is ScanRecord lr ? lr.Sha256 : null));
            var mCopy = new ToolStripMenuItem("Copy path", null, (s, e) => { if (activity.SelectedItem is ScanRecord cr) try { Clipboard.SetText(cr.FilePath); } catch { } });
            var mAi = new ToolStripMenuItem("Properties and AI fix…  (Alt+click)", null, (s, e) => ActProperties());
            menu.Items.AddRange(new ToolStripItem[] { mAi, new ToolStripSeparator(), mQuar, mDel, mSafe, new ToolStripSeparator(), mShow, mLook, mCopy });
            menu.Opening += (s, e) =>
            {
                if (!(activity.SelectedItem is ScanRecord)) { e.Cancel = true; return; }
                mQuar.Enabled = bQuar.Enabled; mDel.Enabled = bDeleteFile.Enabled; mSafe.Enabled = bSafe.Enabled; mShow.Enabled = bShow.Enabled;
            };
            activity.ContextMenuStrip = menu;
            activity.MouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Right) return;
                int at = activity.IndexFromPoint(e.Location);
                if (at >= 0) activity.SelectedIndex = at;
            };
            pa.Controls.AddRange(new Control[] { activity, activityEmpty, detail, bQuar, bDeleteFile, bSafe, bIgnore, bShow, bLookup, bQuarAll });
            pages[1] = pa;


            // ----- Quarantine -----
            var pq = Page("Quarantine", "Files locked away where they can't run. Alt+click one for properties and an AI fix.");
            quarPage = pq;
            quar.Bounds = new Rectangle(28, 84, 614, 242);
            quar.Painter = PaintQuarantine;
            quar.SelectedIndexChanged += (s, e) => UpdateButtons();
            var qmenu = Menus.Make();
            qmenu.Items.Add("Properties and AI fix…  (Alt+click)", null, (s, e) => ActPropertiesQuarantined());
            qmenu.Items.Add("Restore", null, (s, e) => ActRestore());
            qmenu.Items.Add("Delete forever…", null, (s, e) => ActDeleteQuarantined(false));
            qmenu.Opening += (s, e) => { if (!(quar.SelectedItem is QuarantineItem)) e.Cancel = true; };
            quar.ContextMenuStrip = qmenu;
            quar.MouseDown += (s, e) => { if (e.Button == MouseButtons.Right) { int at = quar.IndexFromPoint(e.Location); if (at >= 0) quar.SelectedIndex = at; } };
            quar.MouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Left || (Control.ModifierKeys & Keys.Alt) == 0) return;
                int i = quar.IndexFromPoint(e.Location);
                if (i >= 0) { quar.SelectedIndex = i; ActPropertiesQuarantined(); }
            };
            quarEmpty = Empty("Quarantine is empty. Files TinyGuard locks away will appear here.", new Rectangle(28, 84, 614, 396));
            qdetail.Bounds = new Rectangle(28, 334, 614, 154);
            bRestore.Bounds = new Rectangle(28, 498, 112, 36);
            bDelete.Bounds = new Rectangle(148, 498, 150, 36);
            bDeleteAll.Bounds = new Rectangle(306, 498, 140, 36);
            bQLookup.Bounds = new Rectangle(454, 498, 138, 36);
            bRestore.Click += (s, e) => ActRestore();
            bDelete.Click += (s, e) => ActDeleteQuarantined(false);
            bDeleteAll.Click += (s, e) => ActDeleteQuarantined(true);
            bQLookup.Click += (s, e) => ActLookup(quar.SelectedItem is QuarantineItem lq ? lq.Sha256 : null);
            pq.Controls.AddRange(new Control[] { quar, quarEmpty, qdetail, bRestore, bDelete, bDeleteAll, bQLookup });
            pages[8] = pq;

            // ----- Settings -----
            var ps = Page("Settings", null);
            cStartup = Check("Start TinyGuard when Windows starts", 62);
            cStartup.Width = 330;
            cDefender = Check("Ask Microsoft Defender too", 62);
            cDefender.Bounds = new Rectangle(366, 62, 276, 24);
            cCloud = Check("Check files online and update YARA rules daily (only fingerprints are sent)", 88);
            cAuto = Check("Move known malware to quarantine automatically", 114);
            cAuto.Width = 330;
            bBadge = new Btn("") { Bounds = new Rectangle(366, 110, 276, 28) };
            Action<int> setBadge = h => { eng.S.BadgeHours = h; eng.S.Save(); bBadge.Text = BadgeText(h); bBadge.Invalidate(); };
            bBadge.Text = BadgeText(eng.S.BadgeHours);
            bBadge.Click += (s, e) => { using (var dlg = new BadgeDialog(eng)) dlg.ShowDialog(FindForm()); setBadge(eng.S.BadgeHours); };
            cStartup.CheckedChanged += (s, e) => { if (!loading) Startup.Set(cStartup.Checked); };
            cCloud.CheckedChanged += (s, e) => { if (!loading) { eng.S.Cloud = cCloud.Checked; eng.S.Save(); RefreshAll(true); } };
            cAuto.CheckedChanged += (s, e) => { if (!loading) { eng.S.AutoQuarantine = cAuto.Checked; eng.S.Save(); } };
            cDefender.CheckedChanged += (s, e) => { if (!loading) { eng.S.UseDefender = cDefender.Checked; eng.S.Save(); } };

            var lSv = Small("Screen saver", 146); lSv.Font = new Font("Segoe UI Semibold", 10f); lSv.ForeColor = Theme.Text;
            cSaverIdle = Check("Screen saver mode: deep-scan slowly when I'm away", 170);
            cSaverIdle.Width = 400;
            bSaverMinutes = new Btn("after " + eng.S.ScreensaverMinutes + " min  ▾") { Bounds = new Rectangle(436, 166, 130, 30) };
            cSaverSys = Check("Use TinyGuard as the Windows screen saver", 198);
            cSaverSys.Width = 400;
            bSaverMode = new Btn(eng.S.SaverMode == "defrag" ? "shows: defrag only  ▾" : "shows: scan, then defrag  ▾") { Bounds = new Rectangle(436, 194, 206, 30) };
            cSaverDefrag = Check("Defragment the hard drive after the deep scan finishes", 224);
            bSaverNow = new Btn("Start screen saver now", true) { Bounds = new Rectangle(28, 252, 190, 32) };
            bDefragNow = new Btn("Defrag screen saver") { Bounds = new Rectangle(226, 252, 170, 32) };
            lSaver = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(404, 258, 238, 22), AutoEllipsis = true };
            bDefragNow.Click += (s, e) => { if (DefragSaverRequested != null) DefragSaverRequested(); };
            bSaverMode.Click += (s, e) =>
            {
                var menu = Menus.Make();
                foreach (var m in new[] { new[] { "scan", "Deep scan with the network picture, then the defrag display" }, new[] { "defrag", "Only the defrag block display" } })
                {
                    string mode = m[0];
                    menu.Items.Add(new ToolStripMenuItem(m[1], null, (s2, e2) =>
                    {
                        eng.S.SaverMode = mode; eng.S.Save();
                        bSaverMode.Text = mode == "defrag" ? "shows: defrag only  ▾" : "shows: scan, then defrag  ▾"; bSaverMode.Invalidate();
                        if (eng.S.SystemSaver) { try { SystemSaver.Enable(eng.S, eng.S.ScreensaverMinutes); } catch { } }
                    }) { ForeColor = Theme.Text, Checked = eng.S.SaverMode == mode });
                }
                menu.Show(bSaverMode, new Point(0, bSaverMode.Height));
            };
            cSaverIdle.CheckedChanged += (s, e) =>
            {
                if (loading) return;
                eng.S.ScreensaverIdle = cSaverIdle.Checked;
                if (cSaverIdle.Checked && cSaverSys.Checked) cSaverSys.Checked = false;
                eng.S.Save();
            };
            cSaverSys.CheckedChanged += (s, e) =>
            {
                if (loading) return;
                try
                {
                    if (cSaverSys.Checked) { SystemSaver.Enable(eng.S, eng.S.ScreensaverMinutes); eng.S.ScreensaverIdle = false; loading = true; cSaverIdle.Checked = false; loading = false; }
                    else SystemSaver.Disable(eng.S);
                    eng.S.Save();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Couldn't change Windows' screen saver setting: " + ex.Message, "TinyGuard");
                    loading = true; cSaverSys.Checked = SystemSaver.IsRegistered(); loading = false;
                }
            };
            cSaverDefrag.CheckedChanged += (s, e) => { if (!loading) { eng.S.SaverDefrag = cSaverDefrag.Checked; eng.S.Save(); } };
            bSaverMinutes.Click += (s, e) =>
            {
                var menu = Menus.Make();
                foreach (int m in new[] { 1, 2, 3, 5, 10, 15, 30 })
                {
                    int mm = m;
                    menu.Items.Add(new ToolStripMenuItem(mm + (mm == 1 ? " minute" : " minutes") + " of no activity", null, (s2, e2) =>
                    {
                        eng.S.ScreensaverMinutes = mm; eng.S.Save();
                        bSaverMinutes.Text = "after " + mm + " min  ▾"; bSaverMinutes.Invalidate();
                        if (eng.S.SystemSaver) { try { SystemSaver.Enable(eng.S, mm); } catch { } }
                    }) { ForeColor = Theme.Text, Checked = mm == eng.S.ScreensaverMinutes });
                }
                menu.Show(bSaverMinutes, new Point(0, bSaverMinutes.Height));
            };
            bSaverNow.Click += (s, e) => { if (SaverRequested != null) SaverRequested(); };

            var l1 = Small("Watched folders", 296);
            lFolders = Plain(316);
            var a1 = new Btn("Add…") { Bounds = new Rectangle(542, 316, 100, 26) };
            var r1 = new Btn("Remove") { Bounds = new Rectangle(542, 344, 100, 26) };
            a1.Click += (s, e) => AddFolder(eng.S.Folders);
            r1.Click += (s, e) => RemoveFolder(eng.S.Folders, lFolders);

            var l2 = Small("Safe folders — never checked (good for your own game builds)", 376);
            lSafe = Plain(396);
            var a2 = new Btn("Add…") { Bounds = new Rectangle(542, 396, 100, 26) };
            var r2 = new Btn("Remove") { Bounds = new Rectangle(542, 424, 100, 26) };
            a2.Click += (s, e) => AddFolder(eng.S.SafeFolders);
            r2.Click += (s, e) => RemoveFolder(eng.S.SafeFolders, lSafe);

            var l3 = Small("MalwareBazaar key — optional extra malware list (free key from abuse.ch)", 456);
            tKey = new TextBox
            {
                Bounds = new Rectangle(28, 478, 400, 26), BackColor = Theme.Card, ForeColor = Theme.Text,
                BorderStyle = BorderStyle.FixedSingle, UseSystemPasswordChar = true
            };
            var sk = new Btn("Save key") { Bounds = new Rectangle(440, 474, 100, 32) };
            sk.Click += (s, e) => { eng.S.MbKey = tKey.Text.Trim(); eng.S.Save(); sk.Text = "Saved"; sk.Invalidate(); };

            lRules = Small("", 514);
            var bRules = new Btn("Update rules") { Bounds = new Rectangle(522, 508, 120, 30) };
            bRules.Click += (s, e) => { eng.CheckRulesNow(); RefreshAll(true); };
            var l5 = lRules;
            var l4 = Small("TinyGuard's files: " + eng.DataDir, 540);
            l4.ForeColor = Theme.Grey;
            ps.Controls.AddRange(new Control[] { cStartup, cDefender, cCloud, cAuto, bBadge, lSv, cSaverIdle, bSaverMinutes, cSaverSys, bSaverMode, cSaverDefrag, bSaverNow, bDefragNow, lSaver, l5, bRules, l1, lFolders, a1, r1, l2, lSafe, a2, r2, l3, tKey, sk, l4 });
            pages[9] = ps;
            network = new NetworkView(eng);
            network.ElevateRequested += () => { if (ElevateRequested != null) ElevateRequested(); };
            pages[2] = network;
            rootkit = new RootkitView(eng);
            pages[3] = rootkit;
            assistant = new AssistantView(eng);
            pages[4] = assistant;
            map = new MapPage(eng);
            pages[5] = map;
            nettools = new NetToolsView(eng);
            pages[6] = nettools;
            defrag = new DefragView(eng);
            pages[7] = defrag;
            pages[10] = new ShieldsView(eng);

            foreach (var p in pages) { p.Bounds = new Rectangle(190, 0, 670, 560); p.Visible = false; Controls.Add(p); }
            ResumeLayout(false);
            SelectPage(0);
        }

        // ----- small builders -----

        Panel Page(string title, string sub)
        {
            var p = new Panel { BackColor = Theme.Bg };
            p.Controls.Add(new Label { Text = title, Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            if (sub != null) p.Controls.Add(new Label { Text = sub, ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });
            return p;
        }

        Label Empty(string text, Rectangle r)
        {
            return new Label { Text = text, ForeColor = Theme.Muted, AutoSize = false, Bounds = r, TextAlign = ContentAlignment.MiddleCenter, Visible = false };
        }

        CheckBox Check(string text, int y)
        {
            return new CheckBox { Text = text, ForeColor = Theme.Text, Bounds = new Rectangle(28, y, 610, 24) };
        }

        Label Small(string text, int y)
        {
            return new Label { Text = text, ForeColor = Theme.Muted, AutoSize = true, Location = new Point(26, y) };
        }

        ListBox Plain(int y)
        {
            return new ListBox { IntegralHeight = false, BorderStyle = BorderStyle.None, BackColor = Theme.Card, ForeColor = Theme.Text, Bounds = new Rectangle(28, y, 502, 54) };
        }

        void AddFolder(List<string> list)
        {
            using (var d = new FolderBrowserDialog())
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (!list.Contains(d.SelectedPath, StringComparer.OrdinalIgnoreCase)) list.Add(d.SelectedPath);
            }
            eng.SettingsChanged();
            RefreshAll(true);
        }

        void RemoveFolder(List<string> list, ListBox box)
        {
            if (box.SelectedItem == null) return;
            list.Remove((string)box.SelectedItem);
            eng.SettingsChanged();
            RefreshAll(true);
        }

        // ----- actions on files (buttons, right-click menu) -----

        void ActProperties()
        {
            if (!(activity.SelectedItem is ScanRecord r)) return;
            Props.Show(this, eng, Props.ForRecord(eng, r));
            RefreshAll(true);
        }

        void ActPropertiesQuarantined()
        {
            if (!(quar.SelectedItem is QuarantineItem q)) return;
            Props.Show(this, eng, Props.ForQuarantine(eng, q));
            RefreshAll(true);
        }

        void ActQuarantine()
        {
            if (!(activity.SelectedItem is ScanRecord r)) return;
            if (!eng.Quarantine(r))
                MessageBox.Show(this, "Couldn't quarantine \"" + r.Name + "\". " + (File.Exists(r.FilePath)
                    ? "It may be in use right now: close the program that is using it and try again."
                    : "The file is already gone."), "TinyGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            RefreshAll(true);
        }

        void ActDelete()
        {
            if (!(activity.SelectedItem is ScanRecord r)) return;
            if (MessageBox.Show(this, "Delete \"" + r.Name + "\" permanently?\n\n" + r.FilePath + "\n\nIt will NOT go to the Recycle Bin and can't be undone.\n(Quarantine is the safer choice if you might want it back.)",
                    "Delete file", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string err = eng.DeleteFile(r);
            if (err != null) MessageBox.Show(this, "Couldn't delete it: " + err, "TinyGuard");
            RefreshAll(true);
        }

        void ActSafe()
        {
            if (!(activity.SelectedItem is ScanRecord r)) return;
            eng.MarkSafe(r);
            RefreshAll(true);
        }

        void ActIgnore()
        {
            var r = activity.SelectedItem as ScanRecord;
            var menu = Menus.Make();
            if (r != null)
            {
                string folder = Path.GetDirectoryName(r.FilePath), ext = Path.GetExtension(r.FilePath);
                menu.Items.Add(new ToolStripMenuItem("Ignore this file", null, (s, e) => { eng.AddIgnore("file", r.FilePath); RefreshAll(true); }) { ForeColor = Theme.Text });
                if (!string.IsNullOrEmpty(folder))
                    menu.Items.Add(new ToolStripMenuItem("Ignore everything in " + (folder.Length > 40 ? "…" + folder.Substring(folder.Length - 38) : folder), null, (s, e) => { eng.AddIgnore("folder", folder); RefreshAll(true); }) { ForeColor = Theme.Text });
                if (ext.Length > 0)
                    menu.Items.Add(new ToolStripMenuItem("Ignore all " + ext + " files", null, (s, e) => { eng.AddIgnore("ext", ext); RefreshAll(true); }) { ForeColor = Theme.Text });
            }
            if (eng.IgnoreCount > 0)
            {
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add(new ToolStripMenuItem("Stop ignoring anything (" + eng.IgnoreCount + " rules)", null, (s, e) => { eng.ClearIgnores(); RefreshAll(true); }) { ForeColor = Theme.Text });
            }
            menu.Show(bIgnore, new Point(0, bIgnore.Height));
        }

        void ActShow()
        {
            if (activity.SelectedItem is ScanRecord r && File.Exists(r.FilePath))
                try { Process.Start("explorer.exe", "/select,\"" + r.FilePath + "\""); } catch { }
        }

        static void ActLookup(string sha)
        {
            // Opens only the file's hash (never the file) on VirusTotal, where many antivirus engines have opinions.
            if (sha != null && sha.Length == 64)
                try { Process.Start("https://www.virustotal.com/gui/file/" + sha); } catch { }
        }

        void ActQuarantineAll()
        {
            int n = eng.NeedAttention();
            if (n == 0) return;
            if (MessageBox.Show(this, "Quarantine all " + n + " file" + (n == 1 ? "" : "s") + " that need action?\n\nThey are locked away where they can't run. You can restore any of them from the Quarantine page.",
                    "Quarantine all", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            int failed = eng.QuarantineAllThreats();
            if (failed > 0) MessageBox.Show(this, failed + " file" + (failed == 1 ? "" : "s") + " couldn't be quarantined (probably in use right now). Close the program using it and try again.", "TinyGuard");
            RefreshAll(true);
        }

        void ActRestore()
        {
            if (!(quar.SelectedItem is QuarantineItem q)) return;
            if (MessageBox.Show(this, "Put \"" + q.Name + "\" back where it was?\n\nTinyGuard will treat this file as safe from now on. Only do this if you're sure it was a false alarm.",
                    "Restore file", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string err = eng.Restore(q);
            if (err != null) MessageBox.Show(this, "Couldn't restore it: " + err, "TinyGuard");
            RefreshAll(true);
        }

        void ActDeleteQuarantined(bool all)
        {
            var items = all ? eng.QuarantineSnapshot() : new List<QuarantineItem>();
            if (!all) { if (quar.SelectedItem is QuarantineItem q) items.Add(q); else return; }
            if (items.Count == 0) return;
            string what = all ? "all " + items.Count + " quarantined file" + (items.Count == 1 ? "" : "s") + (eng.LeftoverCount() > 0 ? " and " + eng.LeftoverCount() + " leftover file" + (eng.LeftoverCount() == 1 ? "" : "s") : "") : "\"" + items[0].Name + "\"";
            if (MessageBox.Show(this, "Delete " + what + " forever? This can't be undone.", "Delete forever",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            var errors = new List<string>();
            if (all)
            {
                int failed = eng.DeleteAllQuarantined();
                if (failed > 0) errors.Add(failed + " file" + (failed == 1 ? "" : "s") + " couldn't be deleted");
            }
            else
            {
                string err = eng.DeleteQuarantined(items[0]);
                if (err != null) errors.Add("\"" + items[0].Name + "\": " + err);
            }
            if (errors.Count > 0)
                MessageBox.Show(this, "Not everything was deleted:\n\n" + string.Join("\n", errors) + "\n\nSomething may still have the file open. Close other programs and try again.", "TinyGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            RefreshAll(true);
        }

        // ----- row painting -----

        void PaintRecord(Graphics g, object item, RectangleF r, bool sel)
        {
            var rec = (ScanRecord)item;
            using (var b = new SolidBrush(sel ? Theme.Card2 : Theme.Bg)) g.FillRectangle(b, r);
            using (var b = new SolidBrush(Theme.Of(rec.Verdict))) g.FillEllipse(b, 12, 20, 11, 11);
            Theme.Str(g, rec.Name, Theme.F(14, true), Theme.Text, new RectangleF(36, 5, r.Width - 130, 24));
            bool needs = rec.IsThreat && !rec.Quarantined && File.Exists(rec.FilePath);
            Theme.Str(g, Theme.Label(rec.Verdict) + (rec.Quarantined ? " · quarantined" : "") + " · " + rec.Detail,
                Theme.F(12), rec.IsThreat ? Theme.Of(rec.Verdict) : Theme.Muted, new RectangleF(36, 27, r.Width - (needs ? 156 : 48), 20));
            if (needs)
            {
                Theme.FillRound(g, Color.FromArgb(60, Theme.Of(rec.Verdict)), new RectangleF(r.Width - 112, 26, 100, 20), 10);
                Theme.Str(g, "Needs action", Theme.F(11, true), Theme.Of(rec.Verdict), new RectangleF(r.Width - 112, 26, 100, 20), StringAlignment.Center);
            }
            Theme.Str(g, StatusView.When(rec.Time), Theme.F(12), Theme.Muted, new RectangleF(r.Width - 96, 5, 86, 24), StringAlignment.Far);
            using (var p = new Pen(Theme.Line)) g.DrawLine(p, 36, r.Height - 0.5f, r.Width, r.Height - 0.5f);
        }

        void PaintQuarantine(Graphics g, object item, RectangleF r, bool sel)
        {
            var q = (QuarantineItem)item;
            using (var b = new SolidBrush(sel ? Theme.Card2 : Theme.Bg)) g.FillRectangle(b, r);
            using (var b = new SolidBrush(Theme.Red)) g.FillEllipse(b, 12, 20, 11, 11);
            Theme.Str(g, q.Name, Theme.F(14, true), Theme.Text, new RectangleF(36, 5, r.Width - 130, 24));
            Theme.Str(g, q.Reason + " · was in " + Path.GetDirectoryName(q.OriginalPath), Theme.F(12), Theme.Muted, new RectangleF(36, 27, r.Width - 48, 20));
            Theme.Str(g, StatusView.When(q.Time), Theme.F(12), Theme.Muted, new RectangleF(r.Width - 96, 5, 86, 24), StringAlignment.Far);
            using (var p = new Pen(Theme.Line)) g.DrawLine(p, 36, r.Height - 0.5f, r.Width, r.Height - 0.5f);
        }

        // ----- behaviour -----

        public void SelectPage(int i)
        {
            for (int n = 0; n < pages.Length; n++) pages[n].Visible = n == i;
            side.Selected = i;
            CurrentPage = i;
            if (i == 1 && activity.SelectedIndex < 0)
                for (int k = 0; k < activity.Items.Count; k++)
                    if (activity.Items[k] is ScanRecord sr && sr.IsThreat && !sr.Quarantined) { activity.SelectedIndex = k; break; }
            if (pages[i] == quarPage && quar.SelectedIndex < 0 && quar.Items.Count > 0) quar.SelectedIndex = 0;
            if (i == 2) network.RefreshNow();
            if (i == 1 && Alert) { Alert = false; if (AlertSeen != null) AlertSeen(); }
            RefreshAll(true);
        }

        void UpdateButtons()
        {
            var r = activity.SelectedItem as ScanRecord;
            bool there = r != null && File.Exists(r.FilePath);
            bQuar.Enabled = r != null && !r.Quarantined && r.Verdict >= Verdict.Unknown && there;
            bDeleteFile.Enabled = r != null && !r.Quarantined && there;
            bSafe.Enabled = r != null && !r.Quarantined && r.Verdict >= Verdict.Unknown;
            bIgnore.Enabled = r != null && !r.Quarantined;
            bShow.Enabled = r != null && !r.Quarantined && there;
            bLookup.Enabled = r != null && r.Sha256.Length == 64;
            detail.Rec = r; detail.Invalidate();
            var qi = quar.SelectedItem as QuarantineItem;
            bRestore.Enabled = bDelete.Enabled = bQLookup.Enabled = qi != null;
            bDeleteAll.Enabled = quar.Items.Count > 0;
            qdetail.Item = qi; qdetail.Invalidate();
        }

        public bool RootkitDone { get { return rootkit.Done; } }

        public void RefreshNetwork() { if (Visible && CurrentPage == 2) network.RefreshNow(); }

        public void RefreshAll(bool force = false)
        {
            int rev = eng.Revision;
            if (!force && rev == seenRevision) return;
            seenRevision = rev;

            side.State = State; side.Badge = Alert || eng.NeedAttention() > 0; side.Invalidate();
            status.Switch.On = eng.Active; status.Switch.Invalidate();
            status.Quick.Text = eng.ScanActive ? "Stop scan" : "Quick scan";
            status.Quick.Primary = !eng.ScanActive; status.Quick.Danger = eng.ScanActive; status.Quick.Invalidate();
            status.Review.Visible = !eng.ScanActive && eng.NeedAttention() > 0;
            status.Invalidate();

            var recs = eng.Snapshot();
            activity.Fill(recs);
            activity.Visible = recs.Count > 0; activityEmpty.Visible = recs.Count == 0;
            var qs = eng.QuarantineSnapshot();
            quar.Fill(qs);
            quar.Visible = qs.Count > 0; quarEmpty.Visible = qs.Count == 0; qdetail.Visible = qs.Count > 0;
            if (pages[CurrentPage] == quarPage && quar.SelectedIndex < 0 && quar.Items.Count > 0) quar.SelectedIndex = 0;
            int need = eng.NeedAttention();
            bQuarAll.Visible = need > 0;
            if (need > 0) bQuarAll.Text = "Quarantine all " + need + " that need action";
            UpdateButtons();

            loading = true;
            cStartup.Checked = Startup.Get();
            cCloud.Checked = eng.S.Cloud;
            cDefender.Checked = eng.S.UseDefender;
            cAuto.Checked = eng.S.AutoQuarantine;
            cSaverIdle.Checked = eng.S.ScreensaverIdle && !eng.S.SystemSaver;
            cSaverSys.Checked = eng.S.SystemSaver;
            cSaverDefrag.Checked = eng.S.SaverDefrag;
            bSaverMinutes.Text = "after " + eng.S.ScreensaverMinutes + " min  ▾";
            bSaverMode.Text = eng.S.SaverMode == "defrag" ? "shows: defrag only  ▾" : "shows: scan, then defrag  ▾";
            var dp = eng.Deep;
            lSaver.Text = dp.Total > 0 ? "Deep scan: " + dp.Done.ToString("N0") + " of " + dp.Total.ToString("N0") + ", " + dp.Flagged + " flagged" : "No deep scan has run yet.";
            if (!tKey.Focused) tKey.Text = eng.S.MbKey;
            string rs = eng.Yara.UpdateStatus;
            if (rs.Length == 0)
                rs = eng.S.RulesChecked > 0 ? "checked " + StatusView.When(new DateTime(eng.S.RulesChecked)) : "not checked yet";
            lRules.Text = "YARA rules " + eng.Yara.RulesVersion + " · " + rs;
            Sync(lFolders, eng.S.Folders);
            Sync(lSafe, eng.S.SafeFolders);
            loading = false;
        }

        static void Sync(ListBox box, List<string> items)
        {
            if (box.Items.Count == items.Count && box.Items.Cast<string>().SequenceEqual(items)) return;
            box.Items.Clear();
            foreach (string s in items) box.Items.Add(s);
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            // List boxes don't always follow screen scaling; pin the two settings lists to their intended size.
            float k = Theme.K;
            lFolders.Bounds = new Rectangle((int)(28 * k), (int)(316 * k), (int)(502 * k), (int)(54 * k));
            lSafe.Bounds = new Rectangle((int)(28 * k), (int)(396 * k), (int)(502 * k), (int)(54 * k));
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Closing the window only hides it; TinyGuard keeps running by the clock.
            if (!ReallyClose && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); }
            base.OnFormClosing(e);
        }
    }
}
