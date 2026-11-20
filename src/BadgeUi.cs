using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>A stepped slider: drag it (or use the arrow keys) to pick one of a list of values.</summary>
    class StepSlider : Painted
    {
        public int[] Steps; public int Index;
        public event Action Changed;

        public StepSlider(int[] steps, int index) { Steps = steps; Index = index; TabStop = true; Cursor = Cursors.Hand; BackColor = Theme.Card; }

        float X(int i) { return 14 + (W - 28) * i / (Steps.Length - 1); }

        void Pick(int px)
        {
            float x = px / Theme.K; int best = 0; float bd = float.MaxValue;
            for (int i = 0; i < Steps.Length; i++) { float d = Math.Abs(X(i) - x); if (d < bd) { bd = d; best = i; } }
            if (best != Index) { Index = best; Invalidate(); if (Changed != null) Changed(); }
        }

        protected override void OnMouseDown(MouseEventArgs e) { Focus(); if (e.Button == MouseButtons.Left) Pick(e.X); base.OnMouseDown(e); }
        protected override void OnMouseMove(MouseEventArgs e) { if (e.Button == MouseButtons.Left) Pick(e.X); base.OnMouseMove(e); }
        protected override bool IsInputKey(Keys k) { return k == Keys.Left || k == Keys.Right || base.IsInputKey(k); }
        protected override void OnKeyDown(KeyEventArgs e)
        {
            int n = Index + (e.KeyCode == Keys.Right ? 1 : e.KeyCode == Keys.Left ? -1 : 0);
            if (n != Index && n >= 0 && n < Steps.Length) { Index = n; Invalidate(); if (Changed != null) Changed(); }
            base.OnKeyDown(e);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics; g.Clear(BackColor); Theme.Prep(g);
            float cy = H / 2;
            Theme.FillRound(g, Theme.Grey, new RectangleF(14, cy - 3, W - 28, 6), 3);
            if (Enabled) Theme.FillRound(g, Theme.Green, new RectangleF(14, cy - 3, X(Index) - 14, 6), 3);
            using (var p = new Pen(Theme.Muted, 1.5f))
                for (int i = 0; i < Steps.Length; i++) g.DrawLine(p, X(i), cy + 8, X(i), cy + 13);
            using (var b = new SolidBrush(Enabled ? Color.White : Theme.Muted)) g.FillEllipse(b, X(Index) - 9, cy - 9, 18, 18);
            using (var p = new Pen(Enabled ? Theme.Green : Theme.Grey, 2.5f)) g.DrawEllipse(p, X(Index) - 9, cy - 9, 18, 18);
        }
    }

    /// <summary>How long the "scanned" badge shows when the mouse rests on an icon, and a button to forget what was scanned.</summary>
    class BadgeDialog : Form
    {
        public static readonly int[] Hours = { 1, 2, 3, 6, 12, 24, 48, 72, 96, 120, 144, 168, 336, 504, 672, 1344, 100000 };

        public static string Fmt(int h)
        {
            if (h <= 0) return "off";
            if (h >= 100000) return "never expires";
            if (h >= 168 && h % 168 == 0) return (h / 168) + (h / 168 == 1 ? " week" : " weeks");
            if (h >= 24 && h % 24 == 0) return (h / 24) + (h / 24 == 1 ? " day" : " days");
            return h + (h == 1 ? " hour" : " hours");
        }

        readonly Engine eng; readonly StepSlider slider; readonly Label big, hint, note; readonly CheckBox off;

        static int Nearest(int h)
        {
            int best = 0; for (int i = 0; i < Hours.Length; i++) if (Math.Abs(Hours[i] - h) < Math.Abs(Hours[best] - h)) best = i;
            return best;
        }

        public BadgeDialog(Engine e)
        {
            eng = e;
            Text = "Scanned badge"; Icon = Theme.AppIcon(); BackColor = Theme.Card; ForeColor = Theme.Text;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; ShowInTaskbar = false; StartPosition = FormStartPosition.CenterParent;
            float k = Theme.K; ClientSize = new Size((int)(440 * k), (int)(318 * k));

            Func<float, float, float, float, Rectangle> R = (x, y, w, h) => new Rectangle((int)(x * k), (int)(y * k), (int)(w * k), (int)(h * k));
            var head = new Label { Text = "Scanned badge", Font = new Font("Segoe UI Semibold", 13f), ForeColor = Theme.Text, BackColor = Theme.Card, Bounds = R(20, 14, 400, 30) };
            hint = new Label { Text = "When the mouse rests on an icon you scanned, a green, yellow or red box shows for this long after the scan.", Font = new Font("Segoe UI", 9.5f), ForeColor = Theme.Muted, BackColor = Theme.Card, Bounds = R(20, 46, 400, 40) };
            big = new Label { Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Green, BackColor = Theme.Card, Bounds = R(20, 92, 400, 34), TextAlign = ContentAlignment.MiddleCenter };
            slider = new StepSlider(Hours, Nearest(e.S.BadgeHours > 0 ? e.S.BadgeHours : 48)) { Bounds = R(20, 128, 400, 44) };
            var lo = new Label { Text = "1 hour", Font = new Font("Segoe UI", 9f), ForeColor = Theme.Muted, BackColor = Theme.Card, Bounds = R(20, 172, 120, 20) };
            var mid = new Label { Text = "days  ·  weeks", Font = new Font("Segoe UI", 9f), ForeColor = Theme.Muted, BackColor = Theme.Card, Bounds = R(150, 172, 140, 20), TextAlign = ContentAlignment.MiddleCenter };
            var hi = new Label { Text = "never expires", Font = new Font("Segoe UI", 9f), ForeColor = Theme.Muted, BackColor = Theme.Card, Bounds = R(300, 172, 120, 20), TextAlign = ContentAlignment.MiddleRight };
            off = new CheckBox { Text = "Don't show the badge at all", ForeColor = Theme.Text, BackColor = Theme.Card, FlatStyle = FlatStyle.Standard, Bounds = R(20, 200, 400, 24), Checked = e.S.BadgeHours <= 0 };
            var reset = new Btn("Reset scanned icons") { Danger = true, Bounds = R(20, 238, 190, 34) };
            var close = new Btn("Close", true) { Bounds = R(330, 238, 90, 34) };
            note = new Label { Font = new Font("Segoe UI", 9f), ForeColor = Theme.Muted, BackColor = Theme.Card, Bounds = R(20, 278, 400, 32) };

            Action apply = () =>
            {
                int h = off.Checked ? 0 : Hours[slider.Index];
                eng.S.BadgeHours = h; eng.S.Save();
                big.Text = off.Checked ? "Badge is off" : "Badge lasts " + Fmt(h);
                big.ForeColor = off.Checked ? Theme.Muted : Theme.Green;
                slider.Enabled = !off.Checked; slider.Invalidate();
            };
            slider.Changed += apply; off.CheckedChanged += (s, ev) => apply();
            reset.Click += (s, ev) =>
            {
                eng.S.BadgeResetAt = DateTime.Now.Ticks; eng.S.Save();
                note.Text = "Done. Icons show a badge again only after their next scan.";
            };
            close.Click += (s, ev) => Close();
            apply();
            Controls.AddRange(new Control[] { head, hint, big, slider, lo, mid, hi, off, reset, close, note });
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }
    }
}
