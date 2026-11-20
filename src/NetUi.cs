using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>Network page: live download/upload per program with a one-minute graph, and Block/Unblock.</summary>
    class NetworkView : Panel
    {
        readonly Engine eng;
        readonly DarkList list = new DarkList(52);
        readonly Label totals, empty;
        readonly Btn bBlock = new Btn("Block internet") { Danger = true }, bUnblock = new Btn("Unblock"), bShow = new Btn("Show in folder");
        readonly Panel needAdmin;
        HashSet<string> blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DateTime blockedRead = DateTime.MinValue, sorted = DateTime.MinValue;
        List<AppTraffic> order = new List<AppTraffic>();
        public event Action ElevateRequested;

        static readonly Color Down = Theme.Blue, Up = Theme.Amber;

        public NetworkView(Engine engine)
        {
            eng = engine;
            BackColor = Theme.Bg;
            Controls.Add(new Label { Text = "Network", Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            Controls.Add(new Label { Text = "What each program is downloading and uploading right now. Alt+click (or right-click) a program to pause just that program's internet (the rest of the PC stays online).", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });
            totals = new Label { ForeColor = Theme.Text, Font = new Font("Segoe UI Semibold", 10f), TextAlign = ContentAlignment.MiddleRight, Bounds = new Rectangle(380, 22, 262, 24) };
            Controls.Add(totals);

            list.Bounds = new Rectangle(28, 84, 614, 396);
            list.Painter = PaintRow;
            list.SelectedIndexChanged += (s, e) => UpdateButtons();
            list.MouseDown += (s, e) =>
            {
                bool alt = (Control.ModifierKeys & Keys.Alt) != 0;
                if (!(e.Button == MouseButtons.Right || (e.Button == MouseButtons.Left && alt))) return;
                int i = list.IndexFromPoint(e.Location);
                if (i < 0 || !(list.Items[i] is AppTraffic a)) return;
                list.SelectedIndex = i;
                ShowMenu(a, e.Location);
            };
            list.KeyDown += (s, e) => { if (e.KeyCode == Keys.Apps && list.SelectedItem is AppTraffic ka) { ShowMenu(ka, new Point(40, 40)); e.Handled = true; } };
            empty = new Label { Text = "No network activity yet.", ForeColor = Theme.Muted, Bounds = list.Bounds, TextAlign = ContentAlignment.MiddleCenter };
            bBlock.Bounds = new Rectangle(28, 498, 140, 36);
            bUnblock.Bounds = new Rectangle(180, 498, 110, 36);
            bShow.Bounds = new Rectangle(302, 498, 140, 36);
            bBlock.Click += (s, e) => DoBlock(true);
            bUnblock.Click += (s, e) => DoBlock(false);
            bShow.Click += (s, e) =>
            {
                if (list.SelectedItem is AppTraffic a && File.Exists(a.Path))
                    try { Process.Start("explorer.exe", "/select,\"" + a.Path + "\""); } catch { }
            };
            Controls.AddRange(new Control[] { list, empty, bBlock, bUnblock, bShow });

            // Shown instead of the list when Visually Safe isn't running with administrator rights.
            needAdmin = new Panel { Bounds = new Rectangle(28, 100, 614, 210), BackColor = Theme.Card };
            var why = new Label
            {
                Text = "Seeing each program's traffic and blocking programs from the internet both use Windows' own " +
                       "network tools, which need administrator rights.\n\nVisually Safe will restart as administrator " +
                       "(Windows asks you once). If \"Start with Windows\" is on, it will start that way from then on.",
                ForeColor = Theme.Text, AutoSize = true
            };
            needAdmin.Controls.Add(why);
            var go = new Btn("Turn on network monitor", true) { Bounds = new Rectangle(22, 142, 220, 40) };
            // Wrap the text to the card's real (screen-scaled) width and keep the button under it.
            needAdmin.Layout += (s, e) =>
            {
                int pad = (int)(22 * Theme.K);
                why.MaximumSize = new Size(needAdmin.ClientSize.Width - 2 * pad, 0);
                why.Location = new Point(pad, (int)(18 * Theme.K));
                go.Location = new Point(pad, why.Bottom + (int)(18 * Theme.K));
                needAdmin.Height = go.Bottom + pad;
            };
            go.Click += (s, e) => { if (ElevateRequested != null) ElevateRequested(); };
            needAdmin.Controls.Add(go);
            Controls.Add(needAdmin);
            needAdmin.BringToFront();
        }

        // ---- pausing a program's internet for a while (alt+click or right-click a row)
        readonly Dictionary<string, DateTime> pausedUntil = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        string PauseFile { get { return Path.Combine(eng.DataDir, "paused.tsv"); } }
        bool pauseLoaded;

        void LoadPauses()
        {
            if (pauseLoaded) return; pauseLoaded = true;
            try
            {
                foreach (string l in File.ReadAllLines(PauseFile))
                {
                    string[] p = l.Split('\t'); long t;
                    if (p.Length == 2 && long.TryParse(p[1], out t)) pausedUntil[p[0]] = new DateTime(t);
                }
            }
            catch { }
        }

        void SavePauses()
        {
            try { File.WriteAllLines(PauseFile, pausedUntil.Select(kv => kv.Key + "\t" + kv.Value.Ticks)); } catch { }
        }

        void Pause(AppTraffic a, TimeSpan? span)
        {
            if (!a.CanBlock) return;
            if (string.Equals(a.Path, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase)) { MessageBox.Show(FindForm(), "Visually Safe can't pause its own internet.", "Visually Safe"); return; }
            if (!(eng.Net != null && eng.Net.Running)) { MessageBox.Show(FindForm(), "Pausing needs Visually Safe to run as administrator.", "Visually Safe"); return; }
            string err = Firewall.Block(a.Path);
            if (err != null) { MessageBox.Show(FindForm(), "Windows Firewall said: " + err, "Visually Safe"); return; }
            LoadPauses();
            if (span.HasValue) pausedUntil[a.Path] = DateTime.Now + span.Value; else pausedUntil.Remove(a.Path);
            SavePauses();
            blockedRead = DateTime.MinValue; RefreshNow();
        }

        void Resume(AppTraffic a)
        {
            string err = Firewall.Unblock(a.Path);
            if (err != null) MessageBox.Show(FindForm(), "Windows Firewall said: " + err, "Visually Safe");
            LoadPauses(); pausedUntil.Remove(a.Path); SavePauses();
            blockedRead = DateTime.MinValue; RefreshNow();
        }

        /// <summary>Resume anything whose pause time is up.</summary>
        void CheckPauses()
        {
            LoadPauses();
            if (pausedUntil.Count == 0) return;
            foreach (var kv in pausedUntil.Where(x => x.Value <= DateTime.Now).ToList())
            {
                Firewall.Unblock(kv.Key); pausedUntil.Remove(kv.Key); blockedRead = DateTime.MinValue;
            }
            SavePauses();
        }

        void ShowMenu(AppTraffic a, Point at)
        {
            LoadPauses();
            var menu = Menus.Make();
            Func<string, Action, ToolStripMenuItem> item = (t, act) => new ToolStripMenuItem(t, null, (s2, e2) => act()) { ForeColor = Theme.Text };
            if (a.Blocked)
            {
                DateTime until;
                menu.Items.Add(new ToolStripMenuItem(pausedUntil.TryGetValue(a.Path, out until) ? "Paused until " + until.ToString("h:mm tt") : "Blocked") { Enabled = false, ForeColor = Theme.Muted });
                menu.Items.Add(item("Resume THIS program's internet", () => Resume(a)));
            }
            else if (a.CanBlock)
            {
                menu.Items.Add(item("Pause THIS program's internet for 5 minutes", () => Pause(a, TimeSpan.FromMinutes(5))));
                menu.Items.Add(item("Pause THIS program's internet for 30 minutes", () => Pause(a, TimeSpan.FromMinutes(30))));
                menu.Items.Add(item("Pause THIS program's internet for 2 hours", () => Pause(a, TimeSpan.FromHours(2))));
                menu.Items.Add(item("Block THIS program's internet until I unblock it", () => Pause(a, null)));
            }
            menu.Items.Add(new ToolStripSeparator());
            if (a.CanBlock)
            {
                string shown = a.Path.Length > 60 ? a.Path.Substring(0, 25) + "…" + a.Path.Substring(a.Path.Length - 33) : a.Path;
                var link = item(shown, () => { try { if (File.Exists(a.Path)) Process.Start("explorer.exe", "/select,\"" + a.Path + "\""); else Process.Start("explorer.exe", "\"" + Path.GetDirectoryName(a.Path) + "\""); } catch { } });
                link.ForeColor = Theme.Blue; link.ToolTipText = "Open where it is on disk: " + a.Path;
                menu.Items.Add(link);
                menu.Items.Add(item("Copy path", () => { try { Clipboard.SetText(a.Path); } catch { } }));
            }
            menu.Items.Add(item("Properties…", () => Props.Show(FindForm(), eng, Props.ForApp(a))));
            menu.Items.Add(item("Ask AI about this program (repair / is it safe)…", () => AgentMenu.Show(FindForm(), list, eng, a.Name, () => AgentPrompt.ForItem(eng, Props.ForApp(a)))));
            menu.Show(list, at);
        }

        void DoBlock(bool block)
        {
            if (!(list.SelectedItem is AppTraffic a) || !a.CanBlock) return;
            if (block && string.Equals(a.Path, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase)) return;
            if (block && MessageBox.Show(FindForm(), "Block \"" + a.Name + "\" from the internet?\n\n" + a.Path +
                    "\n\nIt won't be able to download or upload until you unblock it here. Connections it already has open may last until it restarts.",
                    "Block internet", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            string err = block ? Firewall.Block(a.Path) : Firewall.Unblock(a.Path);
            if (err != null) MessageBox.Show(FindForm(), "Windows Firewall said: " + err, "Visually Safe");
            blockedRead = DateTime.MinValue;
            RefreshNow();
        }

        void UpdateButtons()
        {
            var a = list.SelectedItem as AppTraffic;
            bool admin = eng.Net != null && eng.Net.Running;
            bBlock.Enabled = admin && a != null && a.CanBlock && !a.Blocked;
            bUnblock.Enabled = admin && a != null && a.Blocked;
            bShow.Enabled = a != null && a.CanBlock;
        }

        public void RefreshNow()
        {
            bool on = eng.Net != null && eng.Net.Running;
            needAdmin.Visible = !on;
            list.Visible = on; bBlock.Visible = bUnblock.Visible = bShow.Visible = on;
            if (on) { try { CheckPauses(); } catch { } }
            if (!on) { empty.Visible = false; totals.Text = eng.Net != null && eng.Net.Error != null ? "Monitor off: " + eng.Net.Error : ""; return; }

            if ((DateTime.Now - blockedRead).TotalSeconds > 10) { blocked = Firewall.Blocked(); blockedRead = DateTime.Now; }
            if (Environment.GetEnvironmentVariable("VISUALLYSAFE_NETDEMO") == "1") blocked.Add(@"C:\Users\Example\Downloads\mystery-tool.exe");
            var fresh = eng.Net.Snapshot(blocked);
            // Keep rows where they are: re-sort (busiest first) only when a program appears/leaves or every 6 s,
            // otherwise rows would jump around every second.
            bool sameSet = fresh.Count == order.Count && fresh.All(order.Contains);
            if (!sameSet || (DateTime.Now - sorted).TotalSeconds > 6)
            {
                order = fresh.OrderByDescending(a => a.Recent).ThenByDescending(a => a.TotalIn + a.TotalOut).ToList();
                sorted = DateTime.Now;
            }
            var rows = order;
            list.Fill(rows);
            empty.Visible = rows.Count == 0;
            long down, up;
            eng.Net.Totals(out down, out up);
            totals.Text = "↓ " + Rate(down) + "    ↑ " + Rate(up);
            UpdateButtons();
        }

        public static string Rate(long bytesPerSec)
        {
            if (bytesPerSec < 1024) return bytesPerSec + " B/s";
            if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024.0).ToString("0.#") + " KB/s";
            return (bytesPerSec / 1048576.0).ToString("0.0") + " MB/s";
        }

        static string Size(long b)
        {
            if (b < 1048576) return (b / 1024.0).ToString("0") + " KB";
            if (b < 1073741824) return (b / 1048576.0).ToString("0.0") + " MB";
            return (b / 1073741824.0).ToString("0.00") + " GB";
        }

        void PaintRow(Graphics g, object item, RectangleF r, bool sel)
        {
            var a = (AppTraffic)item;
            using (var b = new SolidBrush(sel ? Theme.Card2 : Theme.Bg)) g.FillRectangle(b, r);
            Color dot = a.Blocked ? Theme.Red : a.Recent > 0 ? Theme.Green : Theme.Grey;
            using (var b = new SolidBrush(dot)) g.FillEllipse(b, 12, 20, 11, 11);

            float right = r.Width - 10;
            float textW = right - 36 - 250;
            Theme.Str(g, a.Name, Theme.F(14, true), a.Blocked ? Theme.Red : Theme.Text, new RectangleF(36, 5, textW, 24));
            DateTime pu; string sub = (a.Blocked ? (pausedUntil.TryGetValue(a.Path, out pu) ? "Paused until " + pu.ToString("h:mm tt") + " · " : "Blocked · ") : "") + "total ↓ " + Size(a.TotalIn) + "  ↑ " + Size(a.TotalOut);
            Theme.Str(g, sub, Theme.F(12), a.Blocked ? Theme.Red : Theme.Muted, new RectangleF(36, 27, textW, 20));

            // one-minute sparkline: download as a filled area, upload as a line
            var gr = new RectangleF(right - 240, 8, 128, 36);
            Theme.FillRound(g, Theme.Card, gr, 5);
            long max = 8 * 1024;
            for (int i = 0; i < AppTraffic.Seconds; i++) max = Math.Max(max, Math.Max(a.InHist[i], a.OutHist[i]));
            var down = Points(a.InHist, gr, max);
            using (var path = new GraphicsPath())
            {
                path.AddLine(gr.X + 2, gr.Bottom - 2, down[0].X, down[0].Y);
                path.AddLines(down);
                path.AddLine(down[down.Length - 1].X, down[down.Length - 1].Y, gr.Right - 2, gr.Bottom - 2);
                path.CloseFigure();
                using (var b = new SolidBrush(Color.FromArgb(90, Down))) g.FillPath(b, path);
            }
            using (var p = new Pen(Down, 1.4f)) g.DrawLines(p, down);
            using (var p = new Pen(Up, 1.4f)) g.DrawLines(p, Points(a.OutHist, gr, max));

            Theme.Str(g, "↓ " + Rate(a.RateIn), Theme.F(12, true), Down, new RectangleF(right - 104, 6, 104, 20), StringAlignment.Far);
            Theme.Str(g, "↑ " + Rate(a.RateOut), Theme.F(12, true), Up, new RectangleF(right - 104, 26, 104, 20), StringAlignment.Far);
            using (var p = new Pen(Theme.Line)) g.DrawLine(p, 36, r.Height - 0.5f, r.Width, r.Height - 0.5f);
        }

        static PointF[] Points(long[] h, RectangleF box, long max)
        {
            var pts = new PointF[h.Length];
            float w = box.Width - 4, ht = box.Height - 5;
            for (int i = 0; i < h.Length; i++)
                pts[i] = new PointF(box.X + 2 + w * i / (h.Length - 1), box.Bottom - 2 - ht * (float)h[i] / max);
            return pts;
        }
    }
}
