using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>The window that appears when a file turns out to be dangerous and has been quarantined: big friendly bubble letters, one plain sentence, and a link to have an AI helper fix things.</summary>
    class ThreatPopup : Form
    {
        static ThreatPopup open;
        readonly Engine eng;
        readonly ScanRecord rec;
        readonly LinkLabel fix = new LinkLabel();
        readonly Btn ok = new Btn("OK, thanks", true);

        /// <summary>Shows the window unless one is already up (then the caller falls back to the tray balloon). Returns true when shown.</summary>
        public static bool ShowFor(Engine eng, ScanRecord r)
        {
            if (open != null && !open.IsDisposed) return false;
            open = new ThreatPopup(eng, r);
            open.Show();
            return true;
        }

        /// <summary>Developer check: draws the window to a picture without showing it (--popup-shot out.png).</summary>
        public static void Snap(string file)
        {
            var r = new ScanRecord { FilePath = @"C:\Users\Example\Downloads\invoice-march.exe", Verdict = Verdict.Malicious, Quarantined = true, Detail = "Microsoft Defender: Trojan:Win32/Example.A!ml" };
            using (var f = new ThreatPopup(null, r))
            {
                f.CreateControl();
                using (var bmp = new Bitmap(f.ClientSize.Width, f.ClientSize.Height))
                { f.DrawToBitmap(bmp, new Rectangle(0, 0, bmp.Width, bmp.Height)); bmp.Save(file, System.Drawing.Imaging.ImageFormat.Png); }
            }
        }

        static int S(int v) { return (int)Math.Round(v * Theme.K); }

        ThreatPopup(Engine eng, ScanRecord r)
        {
            this.eng = eng; rec = r;
            Text = "Visually Safe";
            ClientSize = new Size(S(700), S(430));
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle; MaximizeBox = false; MinimizeBox = false;
            TopMost = true; ShowInTaskbar = true;
            BackColor = Color.FromArgb(0x1A, 0x10, 0x14);
            DoubleBuffered = true;

            ok.Bounds = new Rectangle(S(470), S(364), S(190), S(46));
            ok.Click += (s, e) => Close();
            fix.Text = "Fix it with an AI helper";
            fix.Font = new Font("Segoe UI Semibold", 15f * Theme.K, FontStyle.Underline, GraphicsUnit.Pixel);
            fix.LinkColor = Theme.Blue; fix.ActiveLinkColor = Color.White; fix.VisitedLinkColor = Theme.Blue; fix.LinkBehavior = LinkBehavior.AlwaysUnderline;
            fix.BackColor = BackColor; fix.AutoSize = false; fix.TextAlign = ContentAlignment.MiddleLeft;
            fix.Bounds = new Rectangle(S(40), S(364), S(380), S(46));
            fix.Cursor = Cursors.Hand;
            fix.LinkClicked += (s, e) =>
            {
                try { AgentMenu.Show(this, fix, eng, rec.Name, () => AgentPrompt.ForItem(eng, Props.ForRecord(eng, rec))); } catch { }
            };
            Controls.Add(ok); Controls.Add(fix);
            FormClosed += (s, e) => { if (open == this) open = null; };
        }

        // Appears without taking the keyboard away from whatever the person was typing.
        protected override bool ShowWithoutActivation { get { return true; } }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias; g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            using (var br = new LinearGradientBrush(new Rectangle(0, 0, ClientSize.Width, ClientSize.Height), Color.FromArgb(0x4A, 0x14, 0x1C), Color.FromArgb(0x1A, 0x10, 0x14), 90f))
                g.FillRectangle(br, 0, 0, ClientSize.Width, ClientSize.Height);

            BubbleText(g, "Quarantined!", new RectangleF(S(20), S(20), ClientSize.Width - S(40), S(130)));

            string name = rec.Name;
            using (var f = new Font("Segoe UI Semibold", 22f * Theme.K, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var sf = new StringFormat { Alignment = StringAlignment.Center, Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap })
                g.DrawString(name, f, Brushes.White, new RectangleF(S(30), S(160), ClientSize.Width - S(60), S(36)), sf);

            using (var f = new Font("Segoe UI", 20f * Theme.K, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var sf = new StringFormat { Alignment = StringAlignment.Center })
                g.DrawString("It can't hurt your computer. Visually Safe has locked it away in a safe place.", f, new SolidBrush(Color.FromArgb(0xF3, 0xE6, 0xE8)),
                    new RectangleF(S(50), S(204), ClientSize.Width - S(100), S(80)), sf);

            string why = rec.Detail ?? "";
            if (why.StartsWith("Microsoft Defender:", StringComparison.OrdinalIgnoreCase)) why = "Microsoft Defender agrees:" + why.Substring("Microsoft Defender:".Length);
            else if (why.IndexOf("Microsoft Defender", StringComparison.OrdinalIgnoreCase) >= 0) why = "Microsoft Defender agrees. " + why;
            if (why.Length > 130) why = why.Substring(0, 127) + "…";
            using (var f = new Font("Segoe UI", 15f * Theme.K, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var sf = new StringFormat { Alignment = StringAlignment.Center })
                g.DrawString(why, f, new SolidBrush(Color.FromArgb(0xB8, 0xA0, 0xA6)), new RectangleF(S(50), S(282), ClientSize.Width - S(100), S(60)), sf);
        }

        /// <summary>Puffy, glossy, slightly bouncing letters: a white sticker outline, a dark red edge and a red-to-orange fill with a shine.</summary>
        static void BubbleText(Graphics g, string text, RectangleF area)
        {
            float px = 96f * Theme.K;
            FontFamily fam = null;
            foreach (string n in new[] { "Arial Rounded MT Bold", "Segoe UI Black", "Arial Black", "Segoe UI" })
            { try { fam = new FontFamily(n); break; } catch { } }
            if (fam == null) fam = FontFamily.GenericSansSerif;
            using (fam)
            {
                // measure the whole word to centre it
                float total = 0; var adv = new float[text.Length];
                using (var sf = StringFormat.GenericTypographic)
                    for (int i = 0; i < text.Length; i++)
                    {
                        using (var p = new GraphicsPath()) { p.AddString(text.Substring(i, 1), fam, (int)FontStyle.Bold, px, new PointF(0, 0), sf); var b = p.GetBounds(); adv[i] = text[i] == ' ' ? px * 0.3f : Math.Max(b.Width, px * 0.25f) + px * 0.08f; }
                        total += adv[i];
                    }
                float scale = Math.Min(1f, (area.Width - 20) / total);
                float x = area.X + (area.Width - total * scale) / 2f, y = area.Y + area.Height / 2f - px * 0.62f * scale;
                for (int i = 0; i < text.Length; i++)
                {
                    float bounce = (i % 2 == 0 ? -1 : 1) * px * 0.04f * scale, angle = (i % 2 == 0 ? -4f : 4f);
                    using (var p = new GraphicsPath())
                    {
                        using (var sf = StringFormat.GenericTypographic) p.AddString(text.Substring(i, 1), fam, (int)FontStyle.Bold, px, new PointF(0, 0), sf);
                        var b = p.GetBounds();
                        using (var m = new Matrix())
                        {
                            m.Translate(x + (adv[i] * scale) / 2f, y + bounce + b.Height * scale / 2f + px * 0.2f * scale);
                            m.Rotate(angle); m.Scale(scale, scale);
                            m.Translate(-(b.X + b.Width / 2f), -(b.Y + b.Height / 2f));
                            p.Transform(m);
                        }
                        var bb = p.GetBounds();
                        using (var sh = new GraphicsPath()) { sh.AddPath(p, false); using (var m2 = new Matrix()) { m2.Translate(5f * Theme.K, 7f * Theme.K); sh.Transform(m2); }
                            using (var pen = new Pen(Color.FromArgb(120, 0, 0, 0), 22f * Theme.K * scale) { LineJoin = LineJoin.Round }) g.DrawPath(pen, sh); }
                        using (var pen = new Pen(Color.White, 20f * Theme.K * scale) { LineJoin = LineJoin.Round }) g.DrawPath(pen, p);       // sticker outline
                        using (var pen = new Pen(Color.FromArgb(0x7A, 0x0E, 0x14), 11f * Theme.K * scale) { LineJoin = LineJoin.Round }) g.DrawPath(pen, p);
                        using (var br = new LinearGradientBrush(new RectangleF(bb.X, bb.Y - 1, bb.Width, bb.Height + 2), Color.FromArgb(0xFF, 0x7A, 0x4A), Color.FromArgb(0xD8, 0x1E, 0x2A), 90f)) g.FillPath(br, p);
                        var st = g.Save();
                        g.SetClip(p, CombineMode.Intersect);
                        using (var shine = new LinearGradientBrush(new RectangleF(bb.X, bb.Y, bb.Width, bb.Height * 0.5f), Color.FromArgb(140, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 90f))
                            g.FillRectangle(shine, bb.X, bb.Y, bb.Width, bb.Height * 0.5f);
                        g.Restore(st);
                    }
                    x += adv[i] * scale;
                }
            }
        }
    }
}
