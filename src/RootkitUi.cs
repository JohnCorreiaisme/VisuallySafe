using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TinyGuard
{
    /// <summary>Explains the selected rootkit-check finding and what to do about it.</summary>
    class FindingDetail : Painted
    {
        public Finding F;
        public FindingDetail() { BackColor = Theme.Bg; }

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
            if (F == null)
            {
                Theme.Str(g, "Pick a finding above to see what it means and what you can do.", Theme.F(13), Theme.Muted, new RectangleF(18, 0, W - 36, H));
                return;
            }
            using (var b = new SolidBrush(RootkitView.Color(F.Sev))) g.FillEllipse(b, 18, 15, 11, 11);
            Theme.Str(g, F.Title, Theme.F(14, true), Theme.Text, new RectangleF(38, 8, W - 56, 24));
            Wrap(g, F.Detail + (F.Path.Length > 0 ? "\n" + F.Path : ""), Theme.F(12), Theme.Muted, new RectangleF(18, 34, W - 36, 44));
            Wrap(g, "What you can do: " + F.Advice, Theme.F(12), Theme.Text, new RectangleF(18, 80, W - 36, 44));
        }
    }

    /// <summary>Rootkit check page: runs the checks, lists what looks wrong, and starts Defender Offline.</summary>
    class RootkitView : Panel
    {
        readonly Engine eng;
        readonly RootkitCheck check;
        readonly Btn bRun = new Btn("Run check", true), bOffline = new Btn("Defender Offline scan…"), bShow = new Btn("Show in folder");
        readonly DarkList list = new DarkList(52);
        readonly Label status, sub, empty;
        readonly ToolTip tip = new ToolTip();
        readonly FindingDetail detail = new FindingDetail();
        readonly Timer timer = new Timer { Interval = 400 };
        List<Finding> shown;

        public static Color Color(Sev s) { return s == Sev.Bad ? Theme.Red : s == Sev.Warn ? Theme.Amber : Theme.Grey; }
        static string Word(Sev s) { return s == Sev.Bad ? "Serious" : s == Sev.Warn ? "Warning" : "Note"; }

        public RootkitView(Engine engine)
        {
            eng = engine;
            check = eng.Rootkit;
            BackColor = Theme.Bg;
            Controls.Add(new Label { Text = "Rootkit check", Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            Controls.Add(new Label { Text = "Signs of hidden malware. Alt+click a finding for its properties and an AI fix.", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });

            bRun.Bounds = new Rectangle(28, 84, 140, 38);
            status = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(180, 82, 462, 22), TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, Font = new Font("Segoe UI Semibold", 10f) };
            sub = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(180, 104, 462, 20), TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
            list.Bounds = new Rectangle(28, 134, 614, 220);
            list.Painter = PaintRow;
            list.SelectedIndexChanged += (s, e) => UpdateButtons();
            list.MouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Left || (Control.ModifierKeys & Keys.Alt) == 0) return;
                int i = list.IndexFromPoint(e.Location);
                if (i < 0 || !(list.Items[i] is Finding f)) return;
                list.SelectedIndex = i;
                Props.Show(FindForm(), eng, Props.ForFinding(f));
            };
            var menu = Menus.Make();
            menu.Items.Add("Properties and AI fix…  (Alt+click)", null, (s, e) => { if (list.SelectedItem is Finding sf) Props.Show(FindForm(), eng, Props.ForFinding(sf)); });
            menu.Opening += (s, e) => { if (!(list.SelectedItem is Finding)) e.Cancel = true; };
            list.ContextMenuStrip = menu;
            list.MouseDown += (s, e) => { if (e.Button == MouseButtons.Right) { int at = list.IndexFromPoint(e.Location); if (at >= 0) list.SelectedIndex = at; } };
            empty = new Label
            {
                ForeColor = Theme.Muted, AutoSize = false, Bounds = list.Bounds, TextAlign = ContentAlignment.MiddleCenter,
                Text = "Click \"Run check\". It takes about a minute and changes nothing on your PC.\n\n" +
                       "It checks every loaded driver (against a list of known-bad ones too), looks for programs hidden\n" +
                       "from Windows' process lists, and checks startup entries and the hosts file."
            };
            detail.Bounds = new Rectangle(28, 362, 614, 126);
            bOffline.Bounds = new Rectangle(28, 498, 210, 36);
            bShow.Bounds = new Rectangle(246, 498, 140, 36);
            var note = new Label { Text = "A clean result can't prove there is no rootkit.", ForeColor = Theme.Grey, Bounds = new Rectangle(396, 498, 246, 36), TextAlign = ContentAlignment.MiddleRight };

            bRun.Click += (s, e) => Start();
            bOffline.Click += (s, e) => Offline();
            bShow.Click += (s, e) =>
            {
                if (list.SelectedItem is Finding f && File.Exists(f.Path))
                    try { Process.Start("explorer.exe", "/select,\"" + f.Path + "\""); } catch { }
            };
            Controls.AddRange(new Control[] { bRun, status, sub, list, empty, detail, bOffline, bShow, note });
            timer.Tick += (s, e) => Refresh2();
            timer.Start();
            UpdateButtons();
        }

        void Start()
        {
            if (check.Running) return;
            Task.Run(() => check.Run(eng.S.Cloud));
            Refresh2();
        }

        void Offline()
        {
            if (MessageBox.Show(FindForm(),
                    "Microsoft Defender Offline scans your PC before Windows loads, which is the best way to find a rootkit.\n\n" +
                    "Your PC will RESTART IMMEDIATELY and the scan can take 15 minutes or more. Save your work and close your programs first.\n\n" +
                    "Restart and scan now?", "Defender Offline scan", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string err = RootkitCheck.StartDefenderOffline();
            if (err != null) MessageBox.Show(FindForm(), "Couldn't start it: " + err + "\n\nDefender Offline only works when Microsoft Defender is your active antivirus.", "TinyGuard");
        }

        void UpdateButtons()
        {
            var f = list.SelectedItem as Finding;
            bShow.Enabled = f != null && f.Path.Length > 0 && File.Exists(f.Path);
            detail.F = f; detail.Invalidate();
        }

        void PaintRow(Graphics g, object item, RectangleF r, bool sel)
        {
            var f = (Finding)item;
            using (var b = new SolidBrush(sel ? Theme.Card2 : Theme.Bg)) g.FillRectangle(b, r);
            using (var b = new SolidBrush(Color(f.Sev))) g.FillEllipse(b, 12, 20, 11, 11);
            Theme.Str(g, f.Title, Theme.F(14, true), Theme.Text, new RectangleF(36, 5, r.Width - 130, 24));
            Theme.Str(g, f.Detail, Theme.F(12), Theme.Muted, new RectangleF(36, 27, r.Width - 48, 20));
            Theme.Str(g, Word(f.Sev), Theme.F(12, true), Color(f.Sev), new RectangleF(r.Width - 96, 5, 86, 24), StringAlignment.Far);
            using (var p = new Pen(Theme.Line)) g.DrawLine(p, 36, r.Height - 0.5f, r.Width, r.Height - 0.5f);
        }

        public bool Done { get { return check.Finished != DateTime.MinValue; } }

        void Refresh2()
        {
            if (!Visible) return;
            // developer aid: start the check by itself so a screenshot can show results
            if (Environment.GetEnvironmentVariable("TINYGUARD_ROOTKITDEMO") == "1" && !check.Running && !Done) Start();
            if (check.Running)
            {
                status.ForeColor = Theme.Text;
                status.Text = "Step " + check.StepNo + " of " + RootkitCheck.Steps; sub.Text = check.Step;
                bRun.Text = "Checking…"; bRun.Enabled = false; bRun.Invalidate();
                empty.Visible = false; list.Visible = false; detail.Visible = false;
                return;
            }
            bRun.Text = check.Finished == DateTime.MinValue ? "Run check" : "Run again"; bRun.Enabled = true; bRun.Invalidate();
            if (check.Finished == DateTime.MinValue) { empty.Visible = true; list.Visible = false; detail.Visible = false; status.Text = ""; sub.Text = ""; return; }

            var fs = check.Findings;
            int bad = fs.Count(x => x.Sev == Sev.Bad), warn = fs.Count(x => x.Sev == Sev.Warn), note = fs.Count(x => x.Sev == Sev.Note);
            status.ForeColor = bad > 0 ? Theme.Red : warn > 0 ? Theme.Amber : Theme.Green;
            status.Text = bad + warn + note == 0 ? "Nothing suspicious found" : bad + " serious · " + warn + " warning" + (warn == 1 ? "" : "s") + " · " + note + " note" + (note == 1 ? "" : "s");
            sub.Text = check.Coverage;
            tip.SetToolTip(sub, check.Notes); tip.SetToolTip(status, check.Notes);
            list.Visible = fs.Count > 0; detail.Visible = fs.Count > 0;
            empty.Visible = fs.Count == 0;
            if (fs.Count == 0) empty.Text = "Nothing suspicious found.\n\nThat's good news, but a rootkit that hides deep in Windows can fool a check like this.\nFor real certainty, run the Defender Offline scan below.";
            if (!ReferenceEquals(shown, fs)) { shown = fs; list.Fill(fs); if (fs.Count > 0 && list.SelectedIndex < 0) list.SelectedIndex = 0; UpdateButtons(); }
        }
    }
}
