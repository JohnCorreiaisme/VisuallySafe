using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace TinyGuard
{
    /// <summary>Net tools page: health check, open ports on this PC, device finder, port scanner, ping, traceroute and DNS lookup.</summary>
    class NetToolsView : Panel
    {
        readonly Engine eng;
        readonly NetTools tools;
        readonly TextBox tTarget = new TextBox { Text = "127.0.0.1", BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.FixedSingle };
        readonly TextBox tPorts = new TextBox { Text = "top100", BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.FixedSingle };
        readonly Btn bScan = new Btn("Port scan", true), bPing = new Btn("Ping"), bTrace = new Btn("Trace route"), bDns = new Btn("DNS lookup"), bCancel = new Btn("Cancel") { Danger = true };
        readonly Btn bHealth = new Btn("Health check"), bListen = new Btn("Open ports on this PC"), bDevices = new Btn("Find devices"), bLog = new Btn("Open log");
        readonly Btn bCopy = new Btn("Copy results");
        readonly Label status;
        readonly DarkList list = new DarkList(52);
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 300 };
        int seenVersion = -1;

        static Color Color(NSev s) { return s == NSev.Ok ? Theme.Green : s == NSev.Warn ? Theme.Amber : s == NSev.Fail ? Theme.Red : Theme.Grey; }
        static string Word(NSev s) { return s == NSev.Ok ? "OK" : s == NSev.Warn ? "Warning" : s == NSev.Fail ? "Problem" : "Info"; }

        public NetToolsView(Engine engine)
        {
            eng = engine; tools = eng.Tools;
            BackColor = Theme.Bg;
            Controls.Add(new Label { Text = "Net tools", Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            Controls.Add(new Label { Text = "Test your network for problems. Results are saved to the network log. Alt+click a result for AI repair or Ignore.", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });

            Controls.Add(new Label { Text = "Target", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 90) });
            tTarget.Bounds = new Rectangle(80, 86, 232, 26);
            Controls.Add(new Label { Text = "Ports", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(326, 90) });
            tPorts.Bounds = new Rectangle(366, 86, 166, 26);
            bCancel.Bounds = new Rectangle(542, 82, 100, 34); bCancel.Visible = false;

            bScan.Bounds = new Rectangle(28, 124, 112, 36);
            bPing.Bounds = new Rectangle(148, 124, 72, 36);
            bTrace.Bounds = new Rectangle(228, 124, 112, 36);
            bDns.Bounds = new Rectangle(348, 124, 112, 36);
            bHealth.Bounds = new Rectangle(28, 166, 132, 36);
            bListen.Bounds = new Rectangle(168, 166, 192, 36);
            bDevices.Bounds = new Rectangle(368, 166, 132, 36);
            bLog.Bounds = new Rectangle(508, 166, 134, 36);

            status = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(28, 208, 614, 22), AutoEllipsis = true, TextAlign = ContentAlignment.TopLeft };
            list.Bounds = new Rectangle(28, 234, 614, 254);
            list.Painter = PaintRow;
            list.MouseDown += (s, e) =>
            {
                bool alt = (Control.ModifierKeys & Keys.Alt) != 0;
                if (!(e.Button == MouseButtons.Right || (e.Button == MouseButtons.Left && alt))) return;
                int i = list.IndexFromPoint(e.Location);
                if (i < 0 || !(list.Items[i] is NetResult nr)) return;
                list.SelectedIndex = i;
                ShowMenu(nr, e.Location);
            };
            bCopy.Bounds = new Rectangle(28, 498, 132, 36);
            var note = new Label { Text = "Only scan networks and devices you own or may test.", ForeColor = Theme.Grey, AutoSize = false, Bounds = new Rectangle(170, 498, 472, 36), TextAlign = ContentAlignment.MiddleRight };

            bScan.Click += (s, e) => DoScan();
            bPing.Click += (s, e) => tools.RunPing(tTarget.Text);
            bTrace.Click += (s, e) => tools.RunTrace(tTarget.Text);
            bDns.Click += (s, e) => tools.RunDns(tTarget.Text);
            bHealth.Click += (s, e) => tools.RunHealth();
            bListen.Click += (s, e) => tools.RunListening();
            bDevices.Click += (s, e) => tools.RunDevices();
            bCancel.Click += (s, e) => tools.Cancel();
            bLog.Click += (s, e) =>
            {
                if (File.Exists(tools.LogFile)) try { Process.Start("notepad.exe", "\"" + tools.LogFile + "\""); } catch { }
                else MessageBox.Show(FindForm(), "There's no log yet. Run a test first.", "TinyGuard");
            };
            bCopy.Click += (s, e) =>
            {
                var rs = tools.Results;
                if (rs.Count == 0) return;
                try { Clipboard.SetText(string.Join(Environment.NewLine, rs.Select(r => "[" + Word(r.Sev) + "] " + r.Title + (r.Detail.Length > 0 ? " — " + r.Detail : "")))); } catch { }
            };
            Controls.AddRange(new Control[] { tTarget, tPorts, bCancel, bScan, bPing, bTrace, bDns, bHealth, bListen, bDevices, bLog, status, list, bCopy, note });
            timer.Tick += (s, e) => Refresh2();
            timer.Start();
        }

        // keep the results list clear of the status line whatever the screen scaling does to the label's height
        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            if (status == null || bCopy == null) return;
            int h = TextRenderer.MeasureText("Ag", status.Font).Height + 4;
            status.Height = h;
            int top = status.Bottom + (int)(6 * Theme.K);
            if (list.Top != top || list.Bottom != bCopy.Top - (int)(8 * Theme.K))
            {
                int bottom = bCopy.Top - (int)(8 * Theme.K);
                list.Top = top; list.Height = Math.Max(40, bottom - top);
            }
        }

        void ShowMenu(NetResult r, Point at)
        {
            var menu = Menus.Make();
            Func<string, Action, ToolStripMenuItem> item = (t, act) => new ToolStripMenuItem(t, null, (s2, e2) => act()) { ForeColor = Theme.Text };
            var ai = item("Repair with AI…  (ask Claude Code or Codex)", () => AgentMenu.Show(FindForm(), list, eng, r.Title, () => AgentPrompt.ForNetResult(eng, r.Title, r.Detail)));
            ai.ForeColor = System.Drawing.Color.FromArgb(120, 230, 160);
            menu.Items.Add(ai);
            var pm = System.Text.RegularExpressions.Regex.Match(r.Title + " " + r.Detail, @"[A-Za-z]:\\[^·|]*?\.exe", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (pm.Success)
            {
                string exe = pm.Value.Trim();
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add(item("Block THIS program's internet", () =>
                {
                    if (string.Equals(exe, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase)) { MessageBox.Show(FindForm(), "TinyGuard can't block itself.", "TinyGuard"); return; }
                    if (!(eng.Net != null && eng.Net.Running)) { MessageBox.Show(FindForm(), "Blocking needs TinyGuard to run as administrator.", "TinyGuard"); return; }
                    string err = Firewall.Block(exe);
                    MessageBox.Show(FindForm(), err == null ? "Blocked: " + exe + "\n\nUndo it from the Network page (Alt+click the program > Resume)." : "Windows Firewall said: " + err, "TinyGuard");
                }));
                menu.Items.Add(item("Show where it is on disk", () => { try { if (File.Exists(exe)) Process.Start("explorer.exe", "/select,\"" + exe + "\""); } catch { } }));
            }
            if (r.Port > 0)
            {
                menu.Items.Add(new ToolStripSeparator());
                string pr = NetTools.PortRule(r.Proto, r.Port), gr = r.Prog.Length > 0 ? NetTools.ProgRule(r.Prog) : null;
                var rules = tools.IgnoreRules();
                bool portIgnored = rules.Contains(pr, StringComparer.OrdinalIgnoreCase), progIgnored = gr != null && rules.Contains(gr, StringComparer.OrdinalIgnoreCase);
                string again = "Run the test again to update the list.";
                if (portIgnored || progIgnored)
                    menu.Items.Add(item("Stop ignoring this " + (portIgnored ? "port" : "program"), () => { tools.RemoveIgnore(portIgnored ? pr : gr); MessageBox.Show(FindForm(), "Done. " + again, "TinyGuard"); }));
                else
                {
                    menu.Items.Add(item("Ignore this port (" + r.Proto + " " + r.Port + ")", () => { tools.AddIgnore(pr); MessageBox.Show(FindForm(), r.Proto + " " + r.Port + " will show as ignored, not a warning. " + again, "TinyGuard"); }));
                    if (gr != null) menu.Items.Add(item("Ignore this program (" + System.IO.Path.GetFileName(r.Prog) + ")", () => { tools.AddIgnore(gr); MessageBox.Show(FindForm(), System.IO.Path.GetFileName(r.Prog) + " will show as ignored. " + again, "TinyGuard"); }));
                }
                if (r.Ignored && !portIgnored && !progIgnored)
                    menu.Items.Add(item("Turn off the built-in Windows ignore list", () => { tools.AddIgnore("nodefaults"); MessageBox.Show(FindForm(), "Common Windows ports and programs will be flagged again next time.", "TinyGuard"); }));
            }
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(item("Copy this result", () => { try { Clipboard.SetText(r.Title + (r.Detail.Length > 0 ? " — " + r.Detail : "")); } catch { } }));
            menu.Show(list, at);
        }

        void DoScan()
        {
            string err;
            var hosts = NetTools.ParseTargets(tTarget.Text, out err);
            bool allowPublic = false;
            if (hosts != null && hosts.Any(h => !NetTools.IsPrivate(h)))
            {
                if (MessageBox.Show(FindForm(), "\"" + tTarget.Text.Trim() + "\" is on the public internet, not your own network.\n\nOnly scan systems you own or have permission to test. Scanning other people's systems can be illegal and may get your connection blocked.\n\nDo you own it, or have permission to scan it?",
                        "Scan a public address", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                allowPublic = true;
            }
            tools.RunPortScan(tTarget.Text, tPorts.Text, allowPublic);
        }

        void PaintRow(Graphics g, object item, RectangleF r, bool sel)
        {
            var n = (NetResult)item;
            using (var b = new SolidBrush(sel ? Theme.Card2 : Theme.Bg)) g.FillRectangle(b, r);
            using (var b = new SolidBrush(Color(n.Sev))) g.FillEllipse(b, 12, 20, 11, 11);
            Theme.Str(g, n.Title, Theme.F(14, true), Theme.Text, new RectangleF(36, 5, r.Width - 130, 24));
            Theme.Str(g, n.Detail, Theme.F(12), n.Sev == NSev.Fail ? Theme.Red : Theme.Muted, new RectangleF(36, 27, r.Width - 48, 20));
            Theme.Str(g, Word(n.Sev), Theme.F(12, true), Color(n.Sev), new RectangleF(r.Width - 96, 5, 86, 24), StringAlignment.Far);
            using (var p = new Pen(Theme.Line)) g.DrawLine(p, 36, r.Height - 0.5f, r.Width, r.Height - 0.5f);
        }

        void Refresh2()
        {
            if (!Visible) return;
            bool run = tools.Running;
            foreach (var b in new[] { bScan, bPing, bTrace, bDns, bHealth, bListen, bDevices }) { if (b.Enabled == run) { b.Enabled = !run; b.Invalidate(); } }
            bCancel.Visible = run;
            if (run) { status.ForeColor = Theme.Text; status.Text = tools.Status + (tools.Total > 0 ? "   " + Math.Min(tools.Done, tools.Total) + " of " + tools.Total : ""); }
            else if (tools.LastRun != DateTime.MinValue)
            {
                var rs = tools.Results;
                int fail = rs.Count(x => x.Sev == NSev.Fail), warn = rs.Count(x => x.Sev == NSev.Warn);
                status.ForeColor = fail > 0 ? Theme.Red : warn > 0 ? Theme.Amber : Theme.Green;
                status.Text = tools.Status + "  ·  " + fail + " problem" + (fail == 1 ? "" : "s") + ", " + warn + " warning" + (warn == 1 ? "" : "s");
            }
            else { status.ForeColor = Theme.Muted; status.Text = "Pick a test. Health check is a good first one."; }

            int v = tools.Version;
            if (v == seenVersion) return;
            seenVersion = v;
            var results = tools.Results;
            bool atEnd = list.Items.Count == 0 || list.TopIndex + list.Height / Math.Max(1, list.ItemHeight) >= list.Items.Count - 1;
            list.Fill(results);
            if (run && atEnd && list.SelectedIndex < 0) list.TopIndex = Math.Max(0, list.Items.Count - Math.Max(1, list.Height / Math.Max(1, list.ItemHeight)));
        }
    }
}
