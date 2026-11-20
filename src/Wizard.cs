using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Diagnostics;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>The wizard's pictures (rendered from the Blender model, packed inside the program). Faces right; the left-facing set is a mirror.</summary>
    static class WizardSprites
    {
        public static readonly Dictionary<string, Bitmap[]> Right = new Dictionary<string, Bitmap[]>();
        public static readonly Dictionary<string, string[]> Names = new Dictionary<string, string[]>();
        public static readonly Dictionary<string, float[]> Hands = new Dictionary<string, float[]>();     // picture name -> left hand x,y, right hand x,y (in the 192 x 256 picture)
        public static bool Ok;
        // set name, frames, mouth states (walk0 = mouth closed, walk1 = half open, walk2 = open; the mouth follows the voice)
        static readonly string[][] Sets = { new[] { "walk", "8", "3" }, new[] { "talk", "4", "3" }, new[] { "idle", "4", "1" }, new[] { "point", "1", "1" }, new[] { "wave", "2", "1" }, new[] { "fidle", "4", "1" }, new[] { "ftalk", "4", "3" }, new[] { "fwave", "2", "1" }, new[] { "fmagic", "4", "1" } };

        public static void Load()
        {
            if (Ok) return;
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                foreach (var s in Sets)
                {
                    int n = int.Parse(s[1]), mouths = int.Parse(s[2]);
                    for (int m = 0; m < mouths; m++)
                    {
                        var r = new Bitmap[n]; var nm = new string[n];
                        for (int i = 0; i < n; i++)
                        {
                            nm[i] = s[0] + i + (mouths > 1 ? "m" + m : "");
                            string res = "wiz." + nm[i] + ".png";
                            using (var st = asm.GetManifestResourceStream(res))
                            {
                                if (st == null) return;
                                using (var tmp = new Bitmap(st)) { r[i] = new Bitmap(tmp); }
                            }
                        }
                        string key = mouths > 1 ? s[0] + m : s[0];
                        Right[key] = r; Names[key] = nm;
                    }
                }
                try
                {
                    using (var st = asm.GetManifestResourceStream("wiz.hands.csv"))
                    using (var rd = new StreamReader(st))
                        for (string line; (line = rd.ReadLine()) != null;)
                        {
                            var p = line.Split(',');
                            if (p.Length == 5) Hands[p[0]] = new[] { float.Parse(p[1], System.Globalization.CultureInfo.InvariantCulture), float.Parse(p[2], System.Globalization.CultureInfo.InvariantCulture), float.Parse(p[3], System.Globalization.CultureInfo.InvariantCulture), float.Parse(p[4], System.Globalization.CultureInfo.InvariantCulture) };
                        }
                }
                catch { }
                Ok = true;
            }
            catch { Ok = false; }
        }
    }

    /// <summary>The wizard himself: a see-through window that walks along the top of the taskbar (or the bottom of the screen if the taskbar is at the side or top).</summary>
    class WizardForm : Form
    {
        [StructLayout(LayoutKind.Sequential)] struct WPoint { public int x, y; }
        [StructLayout(LayoutKind.Sequential)] struct WSize { public int cx, cy; }
        [StructLayout(LayoutKind.Sequential)] struct WBlend { public byte Op, Flags, Alpha, Format; }
        [DllImport("user32.dll")] static extern bool UpdateLayeredWindow(IntPtr h, IntPtr dst, ref WPoint pt, ref WSize sz, IntPtr src, ref WPoint ps, int key, ref WBlend bl, int flags);
        [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
        [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
        [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr dc);
        [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr dc, IntPtr o);
        [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr o);
        [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr dc);

        [StructLayout(LayoutKind.Sequential)] struct BmpHeader { public int biSize, biWidth, biHeight; public short biPlanes, biBitCount; public int biCompression, biSizeImage, biXPels, biYPels, biClrUsed, biClrImportant; }
        [DllImport("gdi32.dll")] static extern IntPtr CreateDIBSection(IntPtr hdc, ref BmpHeader bi, uint usage, out IntPtr bits, IntPtr section, uint offset);
        IntPtr memDc, dib, oldObj; Bitmap buf; Graphics bg;
        readonly Dictionary<Bitmap, Bitmap> scaledR = new Dictionary<Bitmap, Bitmap>(), scaledL = new Dictionary<Bitmap, Bitmap>();

        void EnsureBuffer()
        {
            if (buf != null) return;
            int w = W + 2 * P, h = H + 2 * P;
            var hd = new BmpHeader { biSize = 40, biWidth = w, biHeight = -h, biPlanes = 1, biBitCount = 32 };
            IntPtr screen = GetDC(IntPtr.Zero); memDc = CreateCompatibleDC(screen);
            IntPtr bits; dib = CreateDIBSection(screen, ref hd, 0, out bits, IntPtr.Zero, 0);
            ReleaseDC(IntPtr.Zero, screen);
            oldObj = SelectObject(memDc, dib);
            buf = new Bitmap(w, h, w * 4, PixelFormat.Format32bppPArgb, bits);     // GDI+ draws straight into the window's own memory
            bg = Graphics.FromImage(buf); bg.InterpolationMode = InterpolationMode.NearestNeighbor; bg.CompositingMode = CompositingMode.SourceOver;
        }

        /// <summary>The picture at the size it is shown, made once (and mirrored once) and kept.</summary>
        Bitmap Scaled(Bitmap src, bool mirrored)
        {
            var cache = mirrored ? scaledL : scaledR; Bitmap b;
            if (cache.TryGetValue(src, out b)) return b;
            b = new Bitmap(W, H, PixelFormat.Format32bppPArgb);
            using (var g = Graphics.FromImage(b))
            {
                g.InterpolationMode = InterpolationMode.HighQualityBicubic; g.SmoothingMode = SmoothingMode.HighQuality; g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                if (mirrored) g.DrawImage(src, new[] { new PointF(W, 0), new PointF(0, 0), new PointF(W, H) }); else g.DrawImage(src, 0, 0, W, H);
            }
            cache[src] = b; return b;
        }

        public readonly int W, H, P;
        readonly float scale;
        readonly System.Windows.Forms.Timer timer;
        readonly Random rnd = new Random();
        float x; int dir = 1;
        int tick; float vx, phase, target; bool hasTarget;
        DateTime lastStep = DateTime.Now, pauseUntil = DateTime.MinValue, gestureUntil = DateTime.MinValue, nextGesture = DateTime.MinValue;
        public DateTime WaveUntil = DateTime.MinValue, PointUntil = DateTime.MinValue, RestUntil = DateTime.MinValue;
        public bool Holding;                       // true while the question window is open: stand still
        bool drag, dragMoved; Point downPt; float dragDx, dragDy, lift, liftV;     // lift: how far above the floor line he is (while carried, then falling)
        public DateTime CastUntil = DateTime.MinValue, CastStart = DateTime.MinValue;     // a spell: green eyes and holograms in his palms
        bool casting;
        public bool BubbleOpen;                    // a speech bubble is up: stand still unless he is talking (then he paces)
        DateTime lastFull = DateTime.MinValue; bool full;
        int baseY;

        public Point Head { get { return new Point((int)x + W / 2, Top0()); } }
        int Top0() { return baseY - (int)lift - (int)(H * 0.90); }
        public int FootY { get { return baseY - (int)lift; } }

        public WizardForm()
        {
            float sc; using (var g = Graphics.FromHwnd(IntPtr.Zero)) sc = g.DpiX / 96f;
            W = (int)(168 * sc); H = (int)(224 * sc); P = (int)(46 * sc); scale = sc;
            FormBorderStyle = FormBorderStyle.None; ShowInTaskbar = false; TopMost = true; StartPosition = FormStartPosition.Manual;
            Size = new Size(W + 2 * P, H + 2 * P); Text = "Visually Safe wizard";
            var wa = Screen.PrimaryScreen.WorkingArea; x = wa.Left + wa.Width * 0.3f;
            var menu = Menus.Make();
            menu.Items.Add("Ask the wizard…", null, (s, e) => Wizard.OpenAsk());
            menu.Items.Add("What do the boxes mean?", null, (s, e) => Wizard.Say(Wizard.BoxesText(), false, null));
            menu.Items.Add("Support Visually Safe (Ko-fi)", null, (s, e) => { try { Process.Start(new ProcessStartInfo("https://ko-fi.com/johncorreia9791") { UseShellExecute = true }); } catch { } });
            menu.Items.Add("Close the wizard (Alt+click)", null, (s, e) => Wizard.Dismiss());
            menu.Items.Add("Let the wizard sleep for 48 hours", null, (s, e) => Wizard.Sleep(48));
            ContextMenuStrip = menu;
            // pick him up and carry him anywhere; let go and he drops back onto the taskbar. A plain click opens the question window.
            MouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Left || (ModifierKeys & Keys.Alt) != 0) return;
                drag = true; dragMoved = false; downPt = Cursor.Position; dragDx = Cursor.Position.X - x; dragDy = Cursor.Position.Y - (baseY - lift); Capture = true;
            };
            MouseMove += (s, e) =>
            {
                if (!drag) return;
                var c = Cursor.Position;
                if (!dragMoved && Math.Abs(c.X - downPt.X) + Math.Abs(c.Y - downPt.Y) < 6) return;
                dragMoved = true; vx = 0; liftV = 0; x = c.X - dragDx;
                float top = Screen.PrimaryScreen.Bounds.Top + 4;
                lift = Math.Max(0, Math.Min(baseY - H * 0.90f - top, baseY - (c.Y - dragDy)));
            };
            MouseUp += (s, e) =>
            {
                if (e.Button == MouseButtons.Left && (ModifierKeys & Keys.Alt) != 0) { Wizard.Dismiss(); return; }      // Alt+click closes him (he is back next time Visually Safe starts, or when called from the AI helper page)
                if (e.Button != MouseButtons.Left || !drag) return; drag = false; Capture = false; if (!dragMoved) Wizard.OpenAsk(); };
            timer = new System.Windows.Forms.Timer { Interval = 70 };
            timer.Tick += (s, e) => Step();
            timer.Start();
        }

        protected override bool ShowWithoutActivation { get { return true; } }
        protected override CreateParams CreateParams { get { var cp = base.CreateParams; cp.ExStyle |= 0x80000 | 0x80 | 0x08000000; return cp; } }

        void Area(out int minX, out int maxX)
        {
            Rectangle b = Screen.PrimaryScreen.Bounds, wa = Screen.PrimaryScreen.WorkingArea;
            bool bottomBar = wa.Bottom < b.Bottom;
            baseY = bottomBar ? wa.Bottom : b.Bottom;       // on top of a bottom taskbar, else on the bottom edge of the screen
            minX = bottomBar ? b.Left : wa.Left; maxX = (bottomBar ? b.Right : wa.Right) - W;
        }

        void Step()
        {
            tick++;
            var now = DateTime.Now;
            float dt = (float)Math.Min(0.25, (now - lastStep).TotalSeconds); lastStep = now;
            if (now < RestUntil) { if (Visible) Hide(); timer.Interval = 500; return; }
            if ((now - lastFull).TotalSeconds > 2) { lastFull = now; try { full = IdleInfo.FullscreenAppActive(); } catch { full = false; } }
            if (full || ScreenSaver.Active) { if (Visible) Hide(); timer.Interval = 500; return; }      // never over a game, a video or the screen saver
            if (!Visible) { Show(); }
            int minX, maxX; Area(out minX, out maxX);
            float sc = W / 168f, margin = 30 * sc;
            if (!drag && lift > 0) { liftV += 2400 * sc * dt; lift -= liftV * dt; if (lift <= 0) { lift = 0; liftV = 0; } }     // let go: he drops back to the floor
            bool airborne = drag || lift > 0;
            casting = now < CastUntil && !airborne;
            bool pacing = Wizard.Talking && !airborne;                              // while he talks he strolls from one side of the screen to the other, and back
            bool still = airborne || casting || (BubbleOpen && !Wizard.Talking) || now < WaveUntil || now < PointUntil;
            float want = 0;                                                         // the speed he is heading for (always positive; dir says which way)
            int goDir = dir;
            float cruise = (pacing ? 24 : 40) * sc, accel = 150 * sc;
            if (!still)
            {
                if (pacing)
                {
                    if (!hasTarget || Math.Abs(x - target) < 12 * sc)
                    {
                        if (hasTarget) dir = -dir;                                  // reached a side: turn round and keep going
                        else dir = x < (minX + maxX) / 2f ? 1 : -1;
                        hasTarget = true; target = dir > 0 ? maxX - margin : minX + margin; goDir = dir;
                        nextGesture = now.AddSeconds(3 + rnd.Next(4));
                    }
                    goDir = target > x ? 1 : -1;
                    if (now >= nextGesture && now >= gestureUntil) { gestureUntil = now.AddSeconds(1.6 + rnd.NextDouble()); nextGesture = gestureUntil.AddSeconds(5 + rnd.Next(5)); }
                    if (now < gestureUntil) want = 0; else want = cruise;           // now and then he stops and gestures while he explains
                }
                else
                {
                    hasTarget = hasTarget && !Wizard.Talking;
                    if (now < pauseUntil) want = 0;
                    else
                    {
                        if (!hasTarget || Math.Abs(x - target) < 10 * sc)
                        {
                            if (hasTarget) { pauseUntil = now.AddSeconds(2.5 + rnd.NextDouble() * 7); hasTarget = false; }
                            else
                            {
                                float lo = minX + margin, hi = maxX - margin;
                                for (int tries = 0; tries < 8; tries++) { target = lo + (float)rnd.NextDouble() * (hi - lo); if (Math.Abs(target - x) > 220 * sc) break; }
                                hasTarget = true;
                            }
                        }
                        if (hasTarget) { goDir = target > x ? 1 : -1; want = cruise; }
                    }
                }
                if (hasTarget) want = Math.Min(want, (float)Math.Sqrt(2 * accel * Math.Max(0, Math.Abs(target - x) - 4 * sc)) + 4 * sc);     // ease to a stop at the end of the walk
            }
            // turning: slow to a stop, turn on the spot, then set off the other way
            if (goDir != (vx >= 0 ? 1 : -1) && Math.Abs(vx) > 1.5f * sc) want = 0;
            else if (Math.Abs(vx) <= 1.5f * sc && want > 0) dir = goDir;
            float vt = want * (Math.Abs(vx) <= 1.5f * sc ? goDir : (vx >= 0 ? 1 : -1));
            if (want == 0) vt = 0;
            float dv = accel * dt;
            vx = vx < vt ? Math.Min(vt, vx + dv) : Math.Max(vt, vx - dv);
            if (Math.Abs(vx) < 0.5f && want == 0) vx = 0;
            x += vx * dt;
            if (x < minX) { x = minX; vx = 0; } else if (x > maxX) { x = maxX; vx = 0; }
            if (vx > 1.5f * sc) dir = 1; else if (vx < -1.5f * sc) dir = -1;
            bool moving = Math.Abs(vx) > 3 * sc;
            if (moving) phase += Math.Abs(vx) * dt / (5.4f * sc);

            int mouth = Wizard.Talking ? Wizard.MouthNow(tick) : 0;          // 0 closed, 1 half open, 2 open: follows the words he is saying
            string pick; int idx;
            // walking shows him from the side; standing, talking and waving turn him to face you
            if (casting) { pick = "fmagic"; idx = (tick / 5) % 4; }
            else if (now < WaveUntil) { pick = "fwave"; idx = (tick / 3) % 2; }
            else if (now < PointUntil) { pick = "point"; idx = 0; }
            else if (airborne) { pick = "fidle"; idx = (tick / 3) % 4; }
            else if (moving) { pick = "walk" + mouth; idx = (int)phase % 8; }
            else if (Wizard.Talking) { pick = "ftalk" + mouth; idx = (tick / 8) % 4; }
            else { pick = "fidle"; idx = (tick / 6) % 4; }
            var set = WizardSprites.Right[pick];
            var src = set[idx % set.Length];
            string picName = WizardSprites.Names.ContainsKey(pick) ? WizardSprites.Names[pick][idx % set.Length] : pick + idx;
            orbT += dt;
            int px = (int)Math.Round(x), py = baseY - (int)lift - (int)(H * 0.90);
            StepSparks(dt, casting ? 50 : Wizard.Talking ? 24 : moving ? 11 : 6);
            EnsureBuffer();
            bg.Clear(Color.Transparent);
            bg.DrawImage(Scaled(src, dir < 0), P, P, W, H);
            if (casting) DrawMagic(bg, now); else DrawOrbs(bg, picName, dir < 0);
            DrawSparks(bg);
            Push(px - P, py - P);
            timer.Interval = (moving || Wizard.Talking || casting || airborne) ? 55 : 110;      // smooth while he moves, gentle while he stands
            Wizard.Moved(new Point(px + W / 2, py));
        }

        // ---- little glowing orbs that circle above each hand all the time
        float orbT;
        static readonly Color[] OrbColors = { Color.FromArgb(255, 70, 100), Color.FromArgb(190, 90, 255), Color.FromArgb(255, 130, 215) };

        void DrawOrbs(Graphics g, string pic, bool mirrored)
        {
            float[] h; if (!WizardSprites.Hands.TryGetValue(pic, out h)) return;
            float k = W / 192f;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            for (int hand = 0; hand < 2; hand++)
            {
                float hx = h[hand * 2], hy = h[hand * 2 + 1]; if (mirrored) hx = 192f - hx;
                float cx = P + hx * k, cy = P + (hy - 13f) * k;
                Color aura = hand == 0 ? OrbColors[0] : OrbColors[1];
                float pulse = 0.75f + 0.25f * (float)Math.Sin(orbT * 3.4 + hand * 2);
                for (int ring = 3; ring >= 1; ring--)                                  // a soft pool of red or purple light around each hand
                {
                    float ar = 17f * k * pulse * ring / 3f;
                    using (var br = new SolidBrush(Color.FromArgb(34, aura))) g.FillEllipse(br, cx - ar, cy - ar * 0.8f, ar * 2, ar * 1.6f);
                }
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 4; j >= 1; j--)                                         // a fading trail behind each orb
                    {
                        double ta = orbT * (hand == 0 ? 3.1 : -2.7) + i * 2.094 + hand * 1.3 - Math.Sign(hand == 0 ? 3.1 : -2.7) * j * 0.2;
                        float tx = cx + (float)Math.Cos(ta) * 8.5f * k, ty = cy + (float)Math.Sin(ta) * 3.2f * k - 2f * k * (float)Math.Sin(orbT * 2 + i), tr = (1.9f - j * 0.25f) * k;
                        using (var br = new SolidBrush(Color.FromArgb(140 - j * 28, OrbColors[(i + hand) % 3]))) g.FillEllipse(br, tx - tr, ty - tr, tr * 2, tr * 2);
                    }
                    double a = orbT * (hand == 0 ? 3.1 : -2.7) + i * 2.094 + hand * 1.3;
                    float depth = (float)Math.Sin(a);                       // above 0: in front of the hand, below: behind
                    float ox = cx + (float)Math.Cos(a) * 8.5f * k, oy = cy + depth * 3.2f * k - 2f * k * (float)Math.Sin(orbT * 2 + i);
                    float r = (2.6f + 0.9f * depth) * k;
                    Color c = OrbColors[(i + hand) % 3];
                    int al = (int)(190 + 60 * depth);
                    for (int ring = 2; ring >= 1; ring--)
                    {
                        float gr = r * (1f + ring * 0.8f);
                        using (var gb = new SolidBrush(Color.FromArgb(al / 5, c))) g.FillEllipse(gb, ox - gr, oy - gr, gr * 2, gr * 2);
                    }
                    using (var br = new SolidBrush(Color.FromArgb(Math.Min(255, al), c))) g.FillEllipse(br, ox - r, oy - r, r * 2, r * 2);
                    using (var br = new SolidBrush(Color.FromArgb(Math.Min(255, al), 255, 255, 255))) g.FillEllipse(br, ox - r * 0.35f, oy - r * 0.45f, r * 0.7f, r * 0.7f);     // a little highlight so they look like glass balls
                }
            }
        }

        // ---- the spell: his eyes glow green and a little holographic cube spins above each palm
        static readonly float[][] CubeV = { new[] { -1f, -1f, -1f }, new[] { 1f, -1f, -1f }, new[] { 1f, 1f, -1f }, new[] { -1f, 1f, -1f }, new[] { -1f, -1f, 1f }, new[] { 1f, -1f, 1f }, new[] { 1f, 1f, 1f }, new[] { -1f, 1f, 1f } };
        static readonly int[][] CubeE = { new[] { 0, 1 }, new[] { 1, 2 }, new[] { 2, 3 }, new[] { 3, 0 }, new[] { 4, 5 }, new[] { 5, 6 }, new[] { 6, 7 }, new[] { 7, 4 }, new[] { 0, 4 }, new[] { 1, 5 }, new[] { 2, 6 }, new[] { 3, 7 } };

        void DrawMagic(Graphics g, DateTime now)
        {
            double total = (CastUntil - CastStart).TotalSeconds, el = (now - CastStart).TotalSeconds;
            float e = (float)Math.Max(0, Math.Min(1, Math.Min(el / 0.35, (total - el) / 0.5)));
            if (e < 0.04f) return;
            float k = W / 192f;                                // sprite pixels to screen pixels
            g.SmoothingMode = SmoothingMode.AntiAlias;
            foreach (float ex in new[] { 90.3f, 101.7f })      // the eyes
            {
                float cx = P + ex * k, cy = P + 72.8f * k, r = 6.5f * k * e * (0.88f + 0.12f * (float)Math.Sin(el * 14));
                using (var path = new GraphicsPath())
                {
                    path.AddEllipse(cx - r * 1.9f, cy - r * 1.9f, r * 3.8f, r * 3.8f);
                    using (var pgb = new PathGradientBrush(path) { CenterColor = Color.FromArgb((int)(170 * e), 90, 255, 130), SurroundColors = new[] { Color.FromArgb(0, 90, 255, 130) } }) g.FillPath(pgb, path);
                }
                using (var br = new SolidBrush(Color.FromArgb((int)(255 * e), 170, 255, 185))) g.FillEllipse(br, cx - r * 0.42f, cy - r * 0.42f, r * 0.84f, r * 0.84f);
                float tw = r * (1.7f + 0.6f * (float)Math.Sin(el * 11 + ex));
                using (var pen = new Pen(Color.FromArgb((int)(230 * e), 210, 255, 220), Math.Max(1f, k * 0.9f))) { g.DrawLine(pen, cx - tw, cy, cx + tw, cy); g.DrawLine(pen, cx, cy - tw, cx, cy + tw); }
            }
            foreach (float hx in new[] { 60f, 133f }) Hologram(g, P + hx * k, P + 121f * k, k, (float)el, e, hx > 100 ? 1 : -1);
        }

        void Hologram(Graphics g, float cx, float cy, float k, float t, float e, int dir)
        {
            float s = 10.5f * k * e, hy = cy - 15f * k * e - 2f * k * (float)Math.Sin(t * 4 + dir);
            Color c = dir > 0 ? Color.FromArgb(110, 255, 225) : Color.FromArgb(130, 255, 190);
            using (var path = new GraphicsPath())                // a pool of light on the palm
            {
                path.AddEllipse(cx - 14f * k * e, cy - 3.5f * k * e, 28f * k * e, 7f * k * e);
                using (var pgb = new PathGradientBrush(path) { CenterColor = Color.FromArgb((int)(150 * e), c), SurroundColors = new[] { Color.FromArgb(0, c) } }) g.FillPath(pgb, path);
            }
            using (var br = new LinearGradientBrush(new PointF(cx, cy), new PointF(cx, hy - s), Color.FromArgb((int)(80 * e), c), Color.FromArgb(0, c)))     // a faint beam up from the hand
                g.FillPolygon(br, new[] { new PointF(cx - 5 * k * e, cy), new PointF(cx + 5 * k * e, cy), new PointF(cx + s * 0.9f, hy - s), new PointF(cx - s * 0.9f, hy - s) });
            Cube(g, cx, hy, s, t * 1.7f * dir, 0.55f + 0.25f * (float)Math.Sin(t * 2), c, e, k);          // outer cube
            Cube(g, cx, hy, s * 0.5f, -t * 2.6f * dir, 0.4f, Color.FromArgb(220, 255, 240), e, k);          // inner cube turning the other way
            // a ring with three bright dots circling the cube
            var ring = new PointF[40];
            for (int i = 0; i < ring.Length; i++) { double a = i * 2 * Math.PI / ring.Length + t * dir; ring[i] = new PointF(cx + (float)Math.Cos(a) * s * 1.7f, hy + (float)Math.Sin(a) * s * 0.55f); }
            using (var pen = new Pen(Color.FromArgb((int)(120 * e), c), Math.Max(1f, 1.1f * k))) g.DrawPolygon(pen, ring);
            for (int d = 0; d < 3; d++)
            {
                double a = t * 2.2 * dir + d * 2.094;
                float dx = cx + (float)Math.Cos(a) * s * 1.7f, dy = hy + (float)Math.Sin(a) * s * 0.55f, r = 1.7f * k * e;
                using (var br = new SolidBrush(Color.FromArgb((int)(240 * e), 235, 255, 245))) g.FillEllipse(br, dx - r, dy - r, r * 2, r * 2);
            }
        }

        static void Cube(Graphics g, float cx, float cy, float size, float ay, float ax, Color c, float e, float k)
        {
            var pts = new PointF[8];
            float cy1 = (float)Math.Cos(ay), sy1 = (float)Math.Sin(ay), cx1 = (float)Math.Cos(ax), sx1 = (float)Math.Sin(ax);
            for (int i = 0; i < 8; i++)
            {
                float x = CubeV[i][0], y = CubeV[i][1], z = CubeV[i][2];
                float x1 = x * cy1 + z * sy1, z1 = -x * sy1 + z * cy1;          // turn about the upright axis
                float y2 = y * cx1 - z1 * sx1, z2 = y * sx1 + z1 * cx1;          // then tip it
                float p = 1f / (1f - z2 * 0.12f);
                pts[i] = new PointF(cx + x1 * size * 0.62f * p, cy + y2 * size * 0.62f * p);
            }
            using (var wide = new Pen(Color.FromArgb((int)(70 * e), c), Math.Max(2f, 3.2f * k)))
            using (var thin = new Pen(Color.FromArgb((int)(235 * e), c), Math.Max(1f, 1.2f * k)))
                foreach (var ed in CubeE) { g.DrawLine(wide, pts[ed[0]], pts[ed[1]]); g.DrawLine(thin, pts[ed[0]], pts[ed[1]]); }
        }

        // ---- sparkles: little gold, white, blue and violet stars drift up around him
        sealed class Spark { public float X, Y, VX, VY, Age, Life, Size; public int Kind; }
        readonly List<Spark> sparks = new List<Spark>(); float spawnAcc;

        void StepSparks(float dt, float rate)
        {
            spawnAcc += rate * dt;
            while (spawnAcc >= 1 && sparks.Count < 80)
            {
                spawnAcc -= 1;
                double a = rnd.NextDouble() * Math.PI * 2;
                float cx = P + W * 0.5f, cy = P + H * 0.5f;
                float rx = W * (0.34f + (float)rnd.NextDouble() * 0.34f), ry = H * (0.30f + (float)rnd.NextDouble() * 0.28f);
                float sx = cx + (float)Math.Cos(a) * rx, sy = cy + (float)Math.Sin(a) * ry - H * 0.04f;
                if (casting && rnd.Next(2) == 0)       // while he casts, many of the sparks rise from his hands
                {
                    float k2 = W / 192f; bool left = rnd.Next(2) == 0;
                    sx = P + (left ? 60f : 133f) * k2 + ((float)rnd.NextDouble() - 0.5f) * 20 * k2; sy = P + 118f * k2 - (float)rnd.NextDouble() * 22 * k2;
                }
                sparks.Add(new Spark
                {
                    X = sx, Y = sy,
                    VX = ((float)rnd.NextDouble() - 0.5f) * 16 * scale, VY = -(8 + (float)rnd.NextDouble() * 24) * scale,
                    Life = 0.9f + (float)rnd.NextDouble() * 0.9f, Size = (3.5f + (float)rnd.NextDouble() * 5f) * scale, Kind = casting ? 4 + rnd.Next(3) : rnd.Next(4)
                });
            }
            for (int i = sparks.Count - 1; i >= 0; i--)
            {
                var k = sparks[i]; k.Age += dt; k.X += k.VX * dt; k.Y += k.VY * dt;
                if (k.Age >= k.Life) sparks.RemoveAt(i);
            }
        }

        static readonly Color[] SparkColors = { Color.FromArgb(255, 224, 110), Color.FromArgb(255, 255, 255), Color.FromArgb(150, 210, 255), Color.FromArgb(205, 160, 255), Color.FromArgb(90, 255, 140), Color.FromArgb(120, 255, 230), Color.FromArgb(210, 255, 200) };

        void DrawSparks(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            foreach (var k in sparks)
            {
                float a = (float)Math.Sin(Math.PI * k.Age / k.Life);
                int al = Math.Max(0, Math.Min(235, (int)(235 * a)));
                float sz = k.Size * (0.6f + 0.8f * a), n = sz * 0.22f;
                Color c = SparkColors[k.Kind];
                using (var glow = new SolidBrush(Color.FromArgb(al / 5, c))) g.FillEllipse(glow, k.X - sz * 1.6f, k.Y - sz * 1.6f, sz * 3.2f, sz * 3.2f);
                using (var br = new SolidBrush(Color.FromArgb(al, c)))
                    g.FillPolygon(br, new[]
                    {
                        new PointF(k.X, k.Y - sz), new PointF(k.X + n, k.Y - n), new PointF(k.X + sz, k.Y), new PointF(k.X + n, k.Y + n),
                        new PointF(k.X, k.Y + sz), new PointF(k.X - n, k.Y + n), new PointF(k.X - sz, k.Y), new PointF(k.X - n, k.Y - n)
                    });
            }
        }

        void Push(int px, int py)
        {
            if (!IsHandleCreated || buf == null) return;
            bg.Flush();
            var size = new WSize { cx = buf.Width, cy = buf.Height }; var src = new WPoint(); var dst = new WPoint { x = px, y = py };
            var bl = new WBlend { Op = 0, Flags = 0, Alpha = 255, Format = 1 };
            UpdateLayeredWindow(Handle, IntPtr.Zero, ref dst, ref size, memDc, ref src, 0, ref bl, 2);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (timer != null) timer.Dispose();
                if (bg != null) { bg.Dispose(); bg = null; }
                if (buf != null) { buf.Dispose(); buf = null; }
                if (memDc != IntPtr.Zero) { SelectObject(memDc, oldObj); DeleteObject(dib); DeleteDC(memDc); memDc = IntPtr.Zero; }
                foreach (var b in scaledR.Values) b.Dispose();
                foreach (var b in scaledL.Values) b.Dispose();
                scaledR.Clear(); scaledL.Clear();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>A big, easy-to-read speech bubble over the wizard. It speaks the words with the Windows voice.</summary>
    class WizardBubble : Form
    {
        readonly string text; readonly string code;
        readonly Button bOk, bHelp, bAsk;
        readonly System.Windows.Forms.Timer auto;
        int tailX; readonly int bw0, bh0;
        static Font Px(float px, FontStyle st) { return new Font("Segoe UI", px, st, GraphicsUnit.Pixel); }

        public WizardBubble(string text, bool help, string code, Point head, int footY)
        {
            this.text = text; this.code = code;
            FormBorderStyle = FormBorderStyle.None; ShowInTaskbar = false; TopMost = true; StartPosition = FormStartPosition.Manual;
            DoubleBuffered = true; BackColor = Color.Magenta; TransparencyKey = Color.Magenta; Icon = Theme.AppIcon();
            var wa = Screen.PrimaryScreen.Bounds;
            int w = Math.Min(640, wa.Width - 40), h = code != null ? 470 : 330;
            Size = new Size(w, h);
            int bx = Math.Max(wa.Left + 10, Math.Min(wa.Right - w - 10, head.X - w / 2 + 120));
            int by = Math.Max(wa.Top + 10, head.Y + 30 - h);
            Location = new Point(bx, by);
            tailX = Math.Max(60, Math.Min(w - 60, head.X - bx)); bw0 = w; bh0 = h;

            bOk = MakeBtn("OK", Color.FromArgb(34, 139, 70)); bOk.Click += (s, e) => Close(); Controls.Add(bOk);
            int bw = 150, bh = 56, y = h - bh - 40, right = w - 30;
            bOk.SetBounds(right - bw, y, bw, bh);
            bAsk = MakeBtn("Ask me", Color.FromArgb(110, 70, 170)); bAsk.Click += (s, e) => { Close(); Wizard.OpenAsk(); }; Controls.Add(bAsk);
            bAsk.SetBounds(right - bw * 2 - 12, y, bw, bh);
            if (help)
            {
                bHelp = MakeBtn("I need help", Color.FromArgb(30, 90, 190)); bHelp.Click += (s, e) => { Close(); Helper.RequestHelp(); }; Controls.Add(bHelp);
                bHelp.SetBounds(right - bw * 3 - 24, y, bw, bh);
            }
            auto = new System.Windows.Forms.Timer { Interval = code != null ? 600000 : 90000 };
            auto.Tick += (s, e) => Close(); auto.Start();
        }

        Button MakeBtn(string t, Color c)
        {
            var b = new Button { Text = t, FlatStyle = FlatStyle.Flat, BackColor = c, ForeColor = Color.White, Font = Px(22, FontStyle.Bold), Cursor = Cursors.Hand, TabStop = true };
            b.FlatAppearance.BorderSize = 0; return b;
        }

        protected override bool ShowWithoutActivation { get { return true; } }
        protected override CreateParams CreateParams { get { var cp = base.CreateParams; cp.ExStyle |= 0x08000000 | 0x80; return cp; } }
        protected override void OnFormClosed(FormClosedEventArgs e) { auto.Dispose(); base.OnFormClosed(e); }

        public void CloseSoon() { if (code != null || IsDisposed) return; auto.Stop(); auto.Interval = 7000; auto.Start(); }

        /// <summary>Keep the bubble above the wizard's head as he walks.</summary>
        public void Follow(Point head)
        {
            var wa = Screen.PrimaryScreen.Bounds;
            int bx = Math.Max(wa.Left + 10, Math.Min(wa.Right - bw0 - 10, head.X - bw0 / 2));
            int by = Math.Max(wa.Top + 10, head.Y + 30 - bh0);
            int tx = Math.Max(60, Math.Min(bw0 - 60, head.X - bx));
            if (Location.X != bx || Location.Y != by) Location = new Point(bx, by);
            if (tx != tailX) { tailX = tx; Invalidate(); }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias; g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            var box = new RectangleF(4, 4, Width - 8, Height - 40);
            var tail = new[] { new PointF(tailX - 26, box.Bottom - 2), new PointF(tailX + 8, box.Bottom + 32), new PointF(tailX + 26, box.Bottom - 2) };
            using (var path = Theme.Round(box, 30))
            {
                using (var br = new SolidBrush(Color.FromArgb(255, 252, 232))) { g.FillPath(br, path); g.FillPolygon(br, tail); }
                using (var pen = new Pen(Color.FromArgb(40, 40, 40), 5)) { g.DrawPath(pen, path); }
            }
            using (var br = new SolidBrush(Color.FromArgb(255, 252, 232))) g.FillRectangle(br, tailX - 22, box.Bottom - 6, 44, 8);
            using (var pen = new Pen(Color.FromArgb(40, 40, 40), 5)) g.DrawLines(pen, tail);
            var area = new RectangleF(box.X + 28, box.Y + 20, box.Width - 56, (code != null ? 130 : box.Height - 110));
            float size = 36; Font f = null;
            using (var fmt = new StringFormat { Trimming = StringTrimming.Word })
            {
                for (; size >= 18; size -= 2)
                {
                    if (f != null) f.Dispose();
                    f = Px(size, FontStyle.Bold);
                    if (g.MeasureString(text, f, (int)area.Width, fmt).Height <= area.Height) break;
                }
                g.DrawString(text, f, Brushes.Black, area, fmt); f.Dispose();
            }
            if (code != null)
                using (var cf = Px(120, FontStyle.Bold)) using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                using (var br = new SolidBrush(Color.FromArgb(20, 60, 170)))
                    g.DrawString(code, cf, br, new RectangleF(box.X, box.Y + 130, box.Width, 150), sf);
        }
    }

    /// <summary>The window where the person types or speaks a question.</summary>
    class WizardAsk : Form
    {
        readonly TextBox tIn, lAns; readonly Button bAsk, bMic; Button bFix;
        System.Speech.Recognition.SpeechRecognitionEngine rec;
        static Font Px(float px, FontStyle st) { return new Font("Segoe UI", px, st, GraphicsUnit.Pixel); }

        public WizardAsk()
        {
            Text = "Ask the wizard"; Icon = Theme.AppIcon(); TopMost = true; StartPosition = FormStartPosition.Manual;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; ShowInTaskbar = false;
            BackColor = Color.FromArgb(255, 252, 232); ForeColor = Color.Black;
            var wa = Screen.PrimaryScreen.WorkingArea; int w = Math.Min(760, wa.Width - 40), h = 626;
            ClientSize = new Size(w, h); Location = new Point(wa.Left + (wa.Width - w) / 2, Math.Max(wa.Top + 10, wa.Bottom - h - 280));
            Controls.Add(new Label { Text = "Ask me anything about your computer", Font = Px(26, FontStyle.Bold), Left = 20, Top = 14, Width = w - 40, Height = 40 });
            lAns = new TextBox { Font = Px(22, FontStyle.Regular), Left = 20, Top = 62, Width = w - 40, Height = 230, BackColor = Color.White, ForeColor = Color.Black, BorderStyle = BorderStyle.FixedSingle, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Text = "Hello! I am your wizard. Type a question below, or press the microphone and speak." };
            tIn = new TextBox { Font = Px(26, FontStyle.Regular), Left = 20, Top = 304, Width = w - 40 };
            bAsk = Mk("Ask", Color.FromArgb(34, 139, 70), 20, 356, 150); bMic = Mk("🎤 Speak", Color.FromArgb(110, 70, 170), 182, 356, 180);
            var bBoxes = Mk("What do the boxes mean?", Color.FromArgb(30, 90, 190), 20, 424, 340);
            var bSafe = Mk("Is my computer okay?", Color.FromArgb(30, 90, 190), 372, 424, 340);
            var bDesk = Mk("Scan my computer", Color.FromArgb(30, 90, 190), 20, 486, 340);
            var bItems = Mk("Check my Desktop now", Color.FromArgb(30, 90, 190), 372, 486, 340);
            bFix = Mk("Fix it", Color.FromArgb(200, 60, 40), 374, 356, 170); bFix.Visible = false;
            var bClose = Mk("Close", Color.FromArgb(90, 90, 90), 556, 356, 184);
            var bTopics = Mk("Common problems  \u25BE", Color.FromArgb(110, 70, 170), 20, 548, 340);
            var bSleep = Mk("Sleep for 48 hours", Color.FromArgb(90, 90, 90), 372, 548, 340);
            Controls.AddRange(new Control[] { lAns, tIn, bAsk, bMic, bBoxes, bSafe, bDesk, bItems, bFix, bClose, bTopics, bSleep });
            bSleep.Click += (s, e) => { Wizard.Sleep(48); Close(); };
            bTopics.Click += (s, e) =>
            {
                var m = new ContextMenuStrip { Font = Px(19, FontStyle.Regular) };
                foreach (var grp in WizardHelp.Topics.GroupBy(t => t.Category))
                {
                    var sub = new ToolStripMenuItem(grp.Key);
                    foreach (var t in grp) { var tt = t; sub.DropDownItems.Add(tt.Title, null, (s2, e2) => Show(tt.Text.Replace("{who}", Wizard.Who))); }
                    m.Items.Add(sub);
                }
                m.Show(bTopics, new Point(0, -m.Items.Count * 34));
            };
            AcceptButton = bAsk;
            bAsk.Click += (s, e) => Go(tIn.Text);
            bBoxes.Click += (s, e) => Go("What do the boxes around my icons mean?");
            bSafe.Click += (s, e) => GoHealth();
            bFix.Click += (s, e) => { bFix.Visible = false; Show(Wizard.Fix()); };
            bItems.Click += (s, e) => { Wizard.CheckDesktop(); Show("Okay, I am looking at everything on your Desktop now. Watch the boxes appear around your icons."); };
            bDesk.Click += (s, e) => Show(Wizard.ScanComputer());
            bClose.Click += (s, e) => Close();
            bMic.Click += (s, e) => Listen();
            Shown += (s, e) => { tIn.Focus(); Wizard.Speak("Hello! I am your wizard. Ask me anything, and I will keep you posted on what your computer is doing."); };
        }

        Button Mk(string t, Color c, int x, int y, int w)
        {
            var b = new Button { Text = t, FlatStyle = FlatStyle.Flat, BackColor = c, ForeColor = Color.White, Font = Px(22, FontStyle.Bold), Cursor = Cursors.Hand, Left = x, Top = y, Width = w, Height = 52 };
            b.FlatAppearance.BorderSize = 0; return b;
        }

        void Show(string answer)
        {
            lAns.Text = answer.Replace("\r\n", "\n").Replace("\n", "\r\n"); bAsk.Enabled = true;
            Wizard.Speak(answer);
        }

        /// <summary>The "Is my computer okay?" answer: a colour, a sentence, and a Fix it button when there is something the wizard can do.</summary>
        void GoHealth()
        {
            lAns.Text = "Let me look…"; lAns.BackColor = Color.White; bFix.Visible = false; Wizard.Cast(2.6);
            Task.Run(() => { int lvl; bool fx; string t = Wizard.HealthText(out lvl, out fx); return Tuple.Create(lvl, fx, t); }).ContinueWith(t =>
            {
                try
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (t.Status != TaskStatus.RanToCompletion) { Show("I could not check just now. Please try again."); return; }
                        Show(t.Result.Item3);
                        lAns.BackColor = t.Result.Item1 == 0 ? Color.FromArgb(214, 245, 222) : t.Result.Item1 == 1 ? Color.FromArgb(255, 241, 196) : Color.FromArgb(255, 212, 208);
                        bFix.Visible = t.Result.Item1 > 0 && t.Result.Item2;
                    }));
                }
                catch { }
            });
        }

        void Go(string q)
        {
            q = (q ?? "").Trim(); if (q.Length == 0) return;
            if (System.Text.RegularExpressions.Regex.IsMatch(q, "(?i)^(is my (computer|pc)|am i)( | ?)(okay|ok|safe|protected|fine)|virus|infect")) { GoHealth(); tIn.Text = ""; return; }
            lAns.BackColor = Color.White; lAns.Text = "Let me think…"; bAsk.Enabled = false; tIn.Text = "";
            Task.Run(() => Wizard.Answer(q)).ContinueWith(t =>
            {
                string a = t.Status == TaskStatus.RanToCompletion ? t.Result : "I am sorry, something went wrong. Please ask " + Wizard.Who + ".";
                try { BeginInvoke(new Action(() => Show(a))); } catch { }
            });
        }

        void Listen()
        {
            try
            {
                Wizard.StopSpeaking();
                if (rec != null) { rec.Dispose(); rec = null; }
                rec = new System.Speech.Recognition.SpeechRecognitionEngine();
                rec.SetInputToDefaultAudioDevice();
                rec.LoadGrammar(new System.Speech.Recognition.DictationGrammar());
                rec.InitialSilenceTimeout = TimeSpan.FromSeconds(8);
                rec.SpeechRecognized += (s, e) => { string t = e.Result.Text; try { BeginInvoke(new Action(() => { tIn.Text = t; Go(t); })); } catch { } };
                rec.RecognizeCompleted += (s, e) => { try { BeginInvoke(new Action(() => { bMic.Text = "🎤 Speak"; })); } catch { } };
                bMic.Text = "Listening…"; lAns.Text = "I am listening. Please speak now.";
                rec.RecognizeAsync(System.Speech.Recognition.RecognizeMode.Single);
            }
            catch { lAns.Text = "I could not use the microphone. Please type your question instead."; bMic.Text = "🎤 Speak"; }
        }

        protected override void OnFormClosed(FormClosedEventArgs e) { try { if (rec != null) rec.Dispose(); } catch { } Wizard.AskClosed(); base.OnFormClosed(e); }
    }

    /// <summary>Everything the wizard says and does: speech, the question window, the explanations, and answers from the user's chosen AI.</summary>
    static class Wizard
    {
        sealed class Item { public string Text, Code; public bool Help; }
        static Engine eng; static Control sync; static WizardForm form; static WizardBubble bubble; static WizardAsk ask;
        static readonly Queue<Item> queue = new Queue<Item>();
        static System.Speech.Synthesis.SpeechSynthesizer voice;
        static readonly Dictionary<string, DateTime> said = new Dictionary<string, DateTime>();
        static System.Windows.Forms.Timer tipTimer; static int tipIndex; static DateTime lastTip = DateTime.Now;
        public static volatile bool Talking;
        public static volatile int Mouth; static int lastViseme;
        public static bool Forced;
        public static bool Asleep { get { return Helper.Cfg != null && Helper.Cfg.SleepUntil > DateTime.Now.Ticks; } }

        /// <summary>Send him to sleep: hidden and silent for the given hours, even after a restart.</summary>
        public static void Sleep(double hours)
        {
            if (Helper.Cfg == null) return;
            Helper.Cfg.SleepUntil = DateTime.Now.AddHours(hours).Ticks; Forced = false;
            try { Helper.Cfg.Save(eng.DataDir); } catch { }
            StopSpeaking();
            if (sync != null) sync.BeginInvoke(new Action(Sync));
        }

        public static void Wake()
        {
            if (Helper.Cfg == null) return;
            Helper.Cfg.SleepUntil = 0; Dismissed = false;
            try { Helper.Cfg.Save(eng.DataDir); } catch { }
            if (sync != null) sync.BeginInvoke(new Action(Sync));
        }

        public static bool Dismissed;              // closed with Alt+click: gone until Visually Safe starts again, or until he is called from the AI helper page
        public static void Dismiss() { Dismissed = true; StopSpeaking(); if (sync != null) sync.BeginInvoke(new Action(Sync)); }                 // summoned with the big button even though family helper mode is off
        static System.Windows.Forms.Timer narrateTimer;
        static bool nQuick, nManual; static int qMile, manualAtt; static DateTime lastThreatSay = DateTime.MinValue;

        /// <summary>How open the mouth is (0 closed, 1 half, 2 open), taken from the voice's own mouth shapes.</summary>
        public static int MouthNow(int tick)
        {
            if (Environment.TickCount - lastViseme < 300) return Mouth;
            return (tick / 2) % 3;                // a voice that sends no mouth shapes: just flap
        }
        static int OpenOf(int v)
        {
            switch (v) { case 1: case 2: case 3: case 9: case 11: return 2; case 0: case 15: case 17: case 18: case 19: case 20: case 21: return 0; default: return 1; }
        }

        public static string Who { get { return Helper.Cfg != null ? Helper.Cfg.Name : "your family"; } }
        public static bool Enabled { get { WizardSprites.Load(); return Helper.Cfg != null && !Dismissed && !Asleep && (Forced || Helper.Cfg.Wizard) && WizardSprites.Ok; } }

        /// <summary>Bring him out on the screen, without opening the question window.</summary>
        public static void Appear()
        {
            if (sync == null) return;
            sync.BeginInvoke(new Action(() => { Dismissed = false; Forced = true; if (Helper.Cfg != null) Helper.Cfg.SleepUntil = 0; Sync(); if (form != null) form.WaveUntil = DateTime.Now.AddSeconds(3); }));
        }

        /// <summary>The big button: bring the wizard out and open the question window.</summary>
        public static void Summon()
        {
            if (sync == null) return;
            sync.BeginInvoke(new Action(() => { Dismissed = false; Forced = true; if (Helper.Cfg != null) Helper.Cfg.SleepUntil = 0; Sync(); if (form != null) form.WaveUntil = DateTime.Now.AddSeconds(3); OpenAsk(); }));
        }

        public static void Start(Engine e, Control s)
        {
            eng = e; sync = s;
            tipTimer = new System.Windows.Forms.Timer { Interval = 60000 };
            tipTimer.Tick += (a, b) => { Sync(); Tip(); };
            tipTimer.Start();
            narrateTimer = new System.Windows.Forms.Timer { Interval = 4000 };
            narrateTimer.Tick += (a, b) => { try { Narrate(); } catch { } };
            narrateTimer.Start();
            eng.Threat += OnThreat;
            eng.Shield.Alert += (title, text, severe) => { if (Enabled && Due("shield" + title, 5)) Say(title + ". " + First(text) + " Please ask " + Who + " if you are not sure.", true, null); };
            Persistence.Found += (title, text) => { if (Enabled) Say("A new program was set to start with Windows. If you did not install something, please ask " + Who + ".", true, null); };
            Sync();
        }

        /// <summary>Show or hide the wizard to match the settings.</summary>
        public static void Sync()
        {
            if (sync == null) return;
            if (Enabled && form == null) { form = new WizardForm(); form.FormClosed += (s, e) => form = null; form.Show(); form.WaveUntil = DateTime.Now.AddSeconds(4); if (queue.Count > 0 && (bubble == null || bubble.IsDisposed)) Next(); }
            else if (!Enabled && form != null) { form.Close(); form = null; }
        }

        static bool Due(string key, double minutes)
        {
            DateTime t; if (said.TryGetValue(key, out t) && (DateTime.Now - t).TotalMinutes < minutes) return false;
            said[key] = DateTime.Now; return true;
        }

        // ------------------------------------------------------------ speaking

        public static void Speak(string text)
        {
            try
            {
                if (voice == null)
                {
                    voice = new System.Speech.Synthesis.SpeechSynthesizer { Rate = -2, Volume = 100 };
                    voice.SpeakStarted += (s, ev) => Talking = true;
                    voice.VisemeReached += (s, ev) => { Mouth = OpenOf(ev.Viseme); lastViseme = Environment.TickCount; };
                    voice.SpeakCompleted += (s, ev) =>
                    {
                        if (ev.Cancelled) return;
                        Talking = false; Mouth = 0;
                        var b = bubble; if (b != null && !b.IsDisposed) try { b.BeginInvoke(new Action(b.CloseSoon)); } catch { }
                    };
                }
                voice.SpeakAsyncCancelAll();
                voice.SpeakAsync(text);
            }
            catch { }
        }

        public static void StopSpeaking() { try { if (voice != null) voice.SpeakAsyncCancelAll(); } catch { } Talking = false; }

        /// <summary>He does a spell: green eyes, holograms in his palms. Used when he starts something for the person.</summary>
        public static void Cast(double seconds)
        {
            var f = form; if (f == null) return;
            f.CastStart = DateTime.Now; f.CastUntil = DateTime.Now.AddSeconds(seconds);
        }

        public static void Moved(Point head) { var b = bubble; if (b != null && !b.IsDisposed) b.Follow(head); }

        public static void Say(string text, bool help, string code)
        {
            if (sync == null) return;
            Action go = () =>
            {
                queue.Enqueue(new Item { Text = text, Help = help, Code = code });
                if (bubble == null || bubble.IsDisposed) Next();
            };
            if (sync.InvokeRequired) sync.BeginInvoke(go); else go();
        }

        static void Next()
        {
            if (queue.Count == 0 || form == null) { if (form != null) form.Holding = ask != null; return; }
            try { if (IdleInfo.FullscreenAppActive()) { Task.Delay(15000).ContinueWith(t => { try { sync.BeginInvoke(new Action(Next)); } catch { } }); return; } } catch { }     // never talk over a game or a video: wait until it ends
            if (ask != null && Talking) { Task.Delay(3000).ContinueWith(t => { try { sync.BeginInvoke(new Action(Next)); } catch { } }); return; }     // never cut off an answer he is speaking: wait for it to finish
            var it = queue.Dequeue();
            form.BubbleOpen = true;
            bubble = new WizardBubble(it.Text, it.Help, it.Code, form.Head, form.FootY);
            bubble.FormClosed += (s, e) => { bubble = null; StopSpeaking(); if (queue.Count > 0) sync.BeginInvoke(new Action(Next)); else if (form != null) form.BubbleOpen = false; };
            bubble.Show();
            string say = it.Text;
            if (it.Code != null) say += " " + string.Join(", ", it.Code.Select(ch => ch.ToString())) + ". Again: " + string.Join(", ", it.Code.Select(ch => ch.ToString())) + ".";
            Speak(say);
        }

        public static void OpenAsk()
        {
            if (sync == null) return;
            sync.BeginInvoke(new Action(() =>
            {
                if (ask != null && !ask.IsDisposed) { ask.Activate(); return; }
                if (bubble != null && !bubble.IsDisposed) bubble.Close();
                ask = new WizardAsk(); if (form != null) form.Holding = true;
                ask.Show(); ask.Activate();
            }));
        }
        public static void AskClosed() { ask = null; if (form != null && (bubble == null || bubble.IsDisposed)) form.Holding = false; StopSpeaking(); }

        // ------------------------------------------------------------ what he says

        static string First(string t)
        {
            if (string.IsNullOrEmpty(t)) return "";
            int i = t.IndexOfAny(new[] { '.', '\n' }); t = i > 0 ? t.Substring(0, i) : t;
            return t.Length > 160 ? t.Substring(0, 160) : t.Trim() + ".";
        }

        static void OnThreat(ScanRecord r)
        {
            if (!Enabled || (DateTime.Now - lastThreatSay).TotalSeconds < 25) return;
            lastThreatSay = DateTime.Now;
            bool mal = r.Verdict == Verdict.Malicious;
            if (mal) Say("Danger! I found a harmful file called " + r.Name + ". " + (r.Quarantined ? "I locked it away, so it cannot hurt your computer. " : "Please do not open it. ") + "Please tell " + Who + ".", true, null);
            else Say("I found something suspicious called " + r.Name + ". Please do not open it until " + Who + " has looked at it.", true, null);
        }

        /// <summary>Tells the person what the computer is doing: scans starting, how far along they are, and when they finish.</summary>
        static void Narrate()
        {
            if (!Enabled || form == null || eng == null || ScreenSaver.Active) return;
            try { if (IdleInfo.FullscreenAppActive()) return; } catch { }
            if (eng.ScanActive)
            {
                if (!nQuick) { nQuick = true; qMile = 25; Cast(2.8); Say("I am starting a scan of your files.", false, null); }
                else if (eng.ScanTotal >= 20)
                {
                    int pct = (int)(100L * eng.ScanDone / Math.Max(1, eng.ScanTotal));
                    if (pct >= qMile && pct < 100)
                    {
                        Say("The scan is " + pct + " percent done. " + (eng.ScanFound == 0 ? "No problems so far." : eng.ScanFound + (eng.ScanFound == 1 ? " problem" : " problems") + " so far."), false, null);
                        qMile = (pct / 25 + 1) * 25;
                    }
                }
            }
            else if (nQuick)
            {
                nQuick = false;
                if (eng.ScanStopped) Say("The scan was stopped.", false, null);
                else Say("The scan is finished. I checked " + eng.ScanDone + " files and found " + (eng.ScanFound == 0 ? "no problems. Everything looks fine." : eng.ScanFound + (eng.ScanFound == 1 ? " problem" : " problems") + ". Please ask " + Who + " to take a look."), eng.ScanFound > 0, null);
            }
            if (!healthDone && (DateTime.Now - startedAt).TotalSeconds > 25)
            {
                healthDone = true;
                Task.Run(() => { int lvl; bool fx; string t = HealthText(out lvl, out fx); if (lvl > 0) Say(t, true, null); });       // say so at start-up only when something is wrong
            }
            if ((DateTime.Now - lastDefPoll).TotalMinutes >= 5) { lastDefPoll = DateTime.Now; Task.Run(() => PollDefender()); }
            if (AutoCheck.Running) return;                          // the twice-weekly check reports for itself
            int mp = eng.ManualPending;
            if (mp > 0 && !nManual) { nManual = true; manualAtt = eng.NeedAttention(); Cast(2.8); Say("I am checking " + (mp == 1 ? "the item you picked" : mp + " items you picked") + ". Watch for the boxes around the icons.", false, null); }
            else if (mp == 0 && nManual)
            {
                nManual = false; int att = eng.NeedAttention();
                Say(att > manualAtt ? "I finished checking. I found something that needs attention. Please ask " + Who + "." : "I finished checking. Everything you picked looks fine.", att > manualAtt, null);
            }
        }

        public static string BoxesText()
        {
            return "The boxes around your icons are my notes. A blue glow that swirls, with a number, means I am checking it right now. A green box with a tick means I checked it and it is safe. A yellow box with an exclamation mark means it looks a little odd, so please do not open it yet. A red box means danger. Do not open it, and tell " + Who + ".";
        }

        /// <summary>One honest answer to "is my computer okay?": level 0 green, 1 yellow, 2 red.</summary>
        public static string HealthText(out int level, out bool fixable)
        {
            var h = DefenderLink.GetHealth();
            int att = eng != null ? eng.NeedAttention() : 0;
            level = 0; fixable = false;
            if (!h.Installed && !h.Enabled)
            {
                level = 1;
                return "I cannot see Windows' own protection on this computer. You may use another protection program. Please ask " + Who + " to check.";
            }
            if (!h.Enabled || !h.RealTime)
            {
                level = 2; fixable = true;
                return "Windows' protection is switched off. Press Fix it and I will open the Windows Security window, then please ask " + Who + " to turn it on.";
            }
            if (h.Active.Count > 0 || att > 0)
            {
                level = 2;
                string what = h.Active.Count > 0 ? "Windows found " + DefenderLink.Plain(h.Active[0]) : "I found something that needs attention";
                return what + ". Please do not open anything strange, and ask " + Who + " to take a look.";
            }
            var bits = new List<string>();
            if (h.SigAgeDays >= 3) { level = 1; fixable = true; bits.Add("Windows' protection list is " + h.SigAgeDays + " days old. Press Fix it and I will update it."); }
            if (h.QuickAgeDays < 0 || h.QuickAgeDays > 14) { level = Math.Max(level, 1); fixable = true; bits.Add(h.QuickAgeDays < 0 ? "Windows has not scanned your computer lately. Press Fix it and I will start a scan." : "It has been " + h.QuickAgeDays + " days since Windows scanned your computer. Press Fix it and I will start a scan."); }
            if (bits.Count > 0) return "Mostly okay, but " + string.Join(" ", bits);
            return "Yes, your computer is okay. Windows' protection is on and up to date, " + (h.QuickAgeDays == 0 ? "it scanned today" : "its last scan was " + h.QuickAgeDays + (h.QuickAgeDays == 1 ? " day ago" : " days ago")) + ", and nothing needs your attention.";
        }

        /// <summary>The Fix it button: only things that are safe to do for the person. It never changes Windows' security settings.</summary>
        public static string Fix()
        {
            var h = DefenderLink.GetHealth();
            if (!h.Enabled || !h.RealTime)
            {
                try { Process.Start("windowsdefender:"); } catch { }
                return "I opened the Windows Security window. Please ask " + Who + " to switch the protection on. It is a setting only you or your family should change.";
            }
            Cast(3.2);
            Task.Run(() =>
            {
                string upd = DefenderLink.UpdateSignatures();
                Say(upd != null ? "I updated Windows' protection list." : "I could not update the protection list right now. Please check the internet connection.", false, null);
                if (h.QuickAgeDays < 0 || h.QuickAgeDays > 14) ScanComputerCore();
            });
            return "Okay, I am updating Windows' protection and checking when it last scanned. I will tell you what happens.";
        }

        public static string ScanComputer()
        {
            if (!DefenderLink.Available) return "I cannot find Windows' own protection, so I cannot start its scan. Please ask " + Who + ".";
            if (eng.ScanActive) return "A scan is already running, so I will not start another one. When it finishes, ask me again.";
            Cast(3.2);
            Task.Run(() => ScanComputerCore());
            return "I asked Windows to scan your computer. This takes a few minutes, and your computer keeps working while it runs. I will tell you when it is done.";
        }

        static int defScanning;
        static void ScanComputerCore()
        {
            if (System.Threading.Interlocked.Exchange(ref defScanning, 1) == 1) return;
            try
            {
                string r = DefenderLink.Scan(true, min => Say("Windows is still scanning. It has been " + (min < 1 ? "a minute or two" : min + (min == 1 ? " minute" : " minutes")) + " so far.", false, null));
                if (r == "clean") Say("Windows finished scanning your computer. It found nothing wrong.", false, null);
                else if (r == "threats")
                {
                    var h = DefenderLink.GetHealth();
                    string what = h.Active.Count > 0 ? DefenderLink.Plain(h.Active[0]) : "something harmful";
                    Say("Windows finished scanning and found " + what + ". It has dealt with what it could. Please ask " + Who + " to take a look.", true, null);
                    Helper.Notify("Windows protection found something on " + Environment.MachineName, "A scan found: " + string.Join(", ", h.Active) + ".");
                }
                else if (r == "stopped") Say("Okay, I stopped the Windows scan.", false, null);
                else Say("I could not finish the Windows scan. Please ask " + Who + " to take a look.", true, null);
            }
            finally { defScanning = 0; }
        }

        static DateTime lastDefPoll = DateTime.Now.AddMinutes(-4), startedAt = DateTime.Now; static bool healthDone;

        /// <summary>Windows finds things all by itself (real-time protection): read its history and tell the person.</summary>
        static void PollDefender()
        {
            try
            {
                if (eng.S.DefenderSeen == 0) { eng.S.DefenderSeen = DateTime.Now.Ticks; eng.S.Save(); return; }      // first time: what is already in the history is old news
                var dets = DefenderLink.Detections(new DateTime(eng.S.DefenderSeen)).Where(d => d.Where.IndexOf("VisuallySafe", StringComparison.OrdinalIgnoreCase) < 0 && d.Where.IndexOf("TinyGuard", StringComparison.OrdinalIgnoreCase) < 0).ToList();
                var all = DefenderLink.Detections(new DateTime(eng.S.DefenderSeen));
                if (all.Count > 0) { eng.S.DefenderSeen = all.Max(d => d.When).Ticks; eng.S.Save(); }
                if (dets.Count == 0) return;
                Say("Windows' own protection just found " + DefenderLink.Plain(dets[0].Name) + (dets.Count > 1 ? ", and " + (dets.Count - 1) + " more" : "") + ". It has dealt with it, but please tell " + Who + ".", true, null);
                Helper.Notify("Windows protection found something on " + Environment.MachineName, string.Join("\r\n", dets.Select(d => d.When + ": " + d.Name + " " + d.Where)));
            }
            catch { }
        }

        static string Status()
        {
            if (eng == null) return "";
            int c, t, u, q; eng.Stats(out c, out t, out u, out q);
            int att = eng.NeedAttention();
            string s = "Today I checked " + c + " files. " + (att == 0 ? "Nothing needs your attention." : att + (att == 1 ? " thing needs" : " things need") + " your attention, so please ask " + Who + " to look.");
            long last = eng.S.LastAutoCheck;
            if (last > 0) s += " My last full check was " + (DateTime.Now - new DateTime(last)).TotalDays.ToString("0") + " days ago.";
            return s;
        }

        static void Tip()
        {
            if (!Enabled || form == null || bubble != null || ask != null) return;
            if ((DateTime.Now - lastTip).TotalMinutes < 45 || ScreenSaver.Active) return;
            try { if (IdleInfo.FullscreenAppActive()) return; } catch { }
            lastTip = DateTime.Now;
            Say(WizardHelp.NextTip(Who), ++tipIndex % 2 == 0, null);
        }

        /// <summary>Called when the mouse rests on an icon and the badge appears.</summary>
        public static void OnBadge(Verdict v, string path)
        {
            if (!Enabled || form == null || bubble != null || ask != null) return;
            int kind = v >= Verdict.Malicious ? 2 : v == Verdict.Suspicious ? 1 : 0;
            if (!Due("badge" + kind, 20)) return;
            if (kind == 0) Say("That green box with the tick means I checked it, and it is safe.", false, null);
            else if (kind == 1) Say("Yellow means this one looks a little odd. Please do not open it until " + Who + " has had a look.", true, null);
            else Say("Red means danger! Please do not open this. Tell " + Who + " right away.", true, null);
        }

        /// <summary>Every icon on the Desktop, one by one, so each gets its own scanning ring.</summary>
        public static List<string> DesktopItems()
        {
            var l = new List<string>();
            foreach (var sf in new[] { Environment.SpecialFolder.DesktopDirectory, Environment.SpecialFolder.CommonDesktopDirectory })
                try { l.AddRange(Directory.GetFileSystemEntries(Environment.GetFolderPath(sf)).Where(f => !Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))); } catch { }
            return l;
        }

        public static void CheckDesktop()
        {
            Cast(3.2);
            if (!eng.ScanActive) foreach (string f in DesktopItems()) try { eng.ScanNow(f); } catch { }
        }

        // ------------------------------------------------------------ answers

        static string Facts()
        {
            string worst = "";
            try
            {
                var r = eng.Snapshot().FirstOrDefault(x => x.IsThreat && !x.Quarantined);
                if (r != null) worst = "The most serious thing found right now: " + r.Name + " (" + r.Detail + ").";
            }
            catch { }
            return "FACTS ABOUT THIS COMPUTER AND THE VISUALLY SAFE PROGRAM:\n" + BoxesText() + "\n" + Status() + "\n" + worst +
                "\nVisually Safe also works alongside Microsoft Defender. It checks new programs, the Desktop and Downloads twice a week (Monday and Thursday), and keeps its protection updated by itself.";
        }

        public static string Answer(string q)
        {
            string ql = q.ToLowerInvariant();
            if (Regex.IsMatch(ql, @"\b(virus|infect\w*|hacked|protected|am i safe|is my (computer|pc) (safe|ok|okay))\b")) { int lv; bool fx; return HealthText(out lv, out fx); }
            var topic = WizardHelp.Find(q);
            string helpText = topic != null ? topic.Text.Replace("{who}", Who) : null;
            try
            {
                var ep = Llm.Preferred;
                if (ep == null) { var scan = Llm.Discover(); ep = scan.Models.FirstOrDefault(); Llm.Preferred = ep; }
                if (ep != null)
                {
                    string sys = "You are a kind, patient old wizard who lives on the screen of an elderly person's computer and helps them stay safe. " +
                        (helpText != null ? "Explain the steps you are given clearly, one step at a time, in plain everyday words and no markdown. " : "Answer in at most three short, simple sentences, in plain everyday words, with no jargon, no lists and no markdown. ") +
                        "Never tell them to type commands, change settings or delete files. If you are not sure, or it sounds dangerous, tell them to ask " + Who + " or press the I need help button. " +
                        "Use these facts when they are relevant and never contradict them.\n" + Facts() + (helpText != null ? "\nSTEPS TO EXPLAIN (keep every step, in order):\n" + helpText : "");
                    using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60)))
                    {
                        string a = Llm.StripThinking(Llm.Chat(ep, sys, q, cts.Token));
                        a = Regex.Replace(a, @"[*#`_]+", "").Trim();
                        if (a.Length > 0) return a;
                    }
                }
            }
            catch { }
            // no AI available: use the program's own detailed answers
            if (helpText != null) return helpText;
            if (Regex.IsMatch(ql, "box|square|green|yellow|red|ring|glow|tick|check mark|mean")) return BoxesText();
            if (Regex.IsMatch(ql, "safe|virus|infect|hack|ok|okay|fine|problem")) return Status();
            if (Regex.IsMatch(ql, "scan|check"))
                return "To check something, click it once, then press the Ctrl, Alt and S keys together. I will put a box around it when I am done.";
            if (Regex.IsMatch(ql, "help|stuck|broke|wrong"))
                return "Press the I need help button when I talk to you, and " + Who + " will be told.";
            return "I am not sure about that one. I cannot reach my thinking helper right now. Please ask " + Who + ", or wait and try me again.";
        }
    }

    /// <summary>The massive "Talk to the wizard" button on the AI helper page.</summary>
    class WizardLanding : Painted
    {
        bool hover; int frame;
        readonly System.Windows.Forms.Timer anim = new System.Windows.Forms.Timer { Interval = 110 };
        readonly Random rnd = new Random(7);
        readonly float[][] stars = new float[26][];       // x, y, phase, size
        public event Action Pressed;

        public WizardLanding()
        {
            Cursor = Cursors.Hand;
            for (int i = 0; i < stars.Length; i++) stars[i] = new[] { (float)rnd.NextDouble(), (float)rnd.NextDouble(), (float)(rnd.NextDouble() * 6.28), 3 + (float)rnd.NextDouble() * 6 };
            anim.Tick += (s, e) => { frame++; if (Visible) Invalidate(); };
            anim.Start();
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnClick(EventArgs e) { base.OnClick(e); if (Pressed != null) Pressed(); }
        protected override void Dispose(bool d) { if (d) anim.Dispose(); base.Dispose(d); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Parent != null ? Parent.BackColor : Theme.Bg);
            Theme.Prep(g);
            var card = new RectangleF(0, 0, W, H);
            using (var path = Theme.Round(new RectangleF(2, 2, W - 4, H - 4), 26))
            {
                using (var br = new LinearGradientBrush(card, hover ? Color.FromArgb(58, 66, 150) : Color.FromArgb(34, 42, 110), hover ? Color.FromArgb(130, 70, 190) : Color.FromArgb(88, 48, 150), 60f)) g.FillPath(br, path);
                using (var pen = new Pen(Color.FromArgb(hover ? 255 : 200, 255, 214, 102), hover ? 5f : 3.5f)) g.DrawPath(pen, path);
            }
            // twinkling stars
            foreach (var st in stars)
            {
                float a = (float)(0.5 + 0.5 * Math.Sin(frame * 0.18 + st[2])), sz = st[3] * (0.5f + a);
                float x = 14 + st[0] * (W - 28), y = 14 + st[1] * (H - 28);
                using (var br = new SolidBrush(Color.FromArgb((int)(60 + 170 * a), 255, 236, 160)))
                    g.FillPolygon(br, new[] { new PointF(x, y - sz), new PointF(x + sz * 0.22f, y - sz * 0.22f), new PointF(x + sz, y), new PointF(x + sz * 0.22f, y + sz * 0.22f), new PointF(x, y + sz), new PointF(x - sz * 0.22f, y + sz * 0.22f), new PointF(x - sz, y), new PointF(x - sz * 0.22f, y - sz * 0.22f) });
            }
            // him
            WizardSprites.Load();
            if (WizardSprites.Ok)
            {
                var set = WizardSprites.Right["idle"]; var img = set[(frame / 5) % set.Length];
                float h = H - 24, w = h * 0.75f;
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.DrawImage(img, 18, 12, w, h);
            }
            // big letters
            float tx = H * 0.75f * 0.82f + 20, tw = W - tx - 18;
            Theme.Str(g, "TALK TO", Theme.F(30, true), Color.FromArgb(255, 214, 102), new RectangleF(tx, 40, tw, 50), StringAlignment.Center);
            Theme.Str(g, "THE WIZARD", Theme.F(38, true), Color.White, new RectangleF(tx, 92, tw, 62), StringAlignment.Center);
            Theme.Str(g, "Ask me anything. I tell you what your computer is doing, and I warn you about problems.", Theme.F(13, false), Color.FromArgb(225, 230, 250), new RectangleF(tx + 4, 170, tw - 8, 70), StringAlignment.Center);
            var pill = new RectangleF(tx + 20, H - 96, tw - 40, 56);
            Theme.FillRound(g, hover ? Color.FromArgb(70, 210, 120) : Color.FromArgb(46, 190, 100), pill, 28);
            Theme.Str(g, "CLICK HERE", Theme.F(24, true), Color.FromArgb(8, 40, 22), pill, StringAlignment.Center);
        }
    }
}
