using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace VisuallySafe
{
    class DarkColors : ProfessionalColorTable
    {
        public override Color ToolStripDropDownBackground { get { return Theme.Card; } }
        public override Color ImageMarginGradientBegin { get { return Theme.Card; } }
        public override Color ImageMarginGradientMiddle { get { return Theme.Card; } }
        public override Color ImageMarginGradientEnd { get { return Theme.Card; } }
        public override Color MenuItemSelected { get { return Color.FromArgb(37, 99, 235); } }
        public override Color MenuItemSelectedGradientBegin { get { return Color.FromArgb(37, 99, 235); } }
        public override Color MenuItemSelectedGradientEnd { get { return Color.FromArgb(37, 99, 235); } }
        public override Color MenuItemBorder { get { return Color.FromArgb(96, 150, 255); } }
        public override Color MenuBorder { get { return Color.FromArgb(96, 150, 255); } }
        public override Color SeparatorDark { get { return Theme.Line; } }
    }


    /// <summary>Every right-click / Alt+click menu: large, high-contrast text with a vivid highlight.</summary>
    static class Menus
    {
        public static ContextMenuStrip Make()
        {
            var m = new ContextMenuStrip { Renderer = new ToolStripProfessionalRenderer(new DarkColors()) { RoundedEdges = false }, ShowImageMargin = false, Font = new Font("Segoe UI Semibold", 12f), BackColor = Theme.Card };
            m.ItemAdded += (s, e) =>
            {
                var it = e.Item as ToolStripMenuItem;
                if (it == null) return;
                it.Padding = new Padding(10, 9, 14, 9);
                if (it.ForeColor == SystemColors.ControlText || it.ForeColor == SystemColors.MenuText) it.ForeColor = Color.White;
                it.ForeColor = it.ForeColor == Theme.Muted ? Color.FromArgb(190, 200, 215) : it.ForeColor;
            };
            return m;
        }
    }

    /// <summary>One agent (Claude Code or Codex): its name and whether it is installed.</summary>
    class AgentCard : Painted
    {
        public string Name = "", Status = "Looking…";
        public bool Found, Known;
        public AgentCard() { BackColor = Theme.Bg; }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Theme.Bg);
            Theme.Prep(g);
            Theme.FillRound(g, Theme.Card, new RectangleF(0, 0, W, H), 12);
            Color dot = !Known ? Theme.Grey : Found ? Theme.Green : Theme.Amber;
            using (var b = new SolidBrush(dot)) g.FillEllipse(b, 16, H / 2 - 6, 12, 12);
            Theme.Str(g, Name, Theme.F(15, true), Theme.Text, new RectangleF(38, 6, W - 200, 24));
            Theme.Str(g, Status, Theme.F(12), Theme.Muted, new RectangleF(38, 28, W - 200, 18));
        }
    }

    /// <summary>
    /// AI helper page: hand everything Visually Safe found to Claude Code or Codex, or paste an answer from any other AI and approve its proposed fixes.
    /// </summary>
    class AssistantView : Panel
    {
        readonly Engine eng;
        readonly AgentCard cClaude = new AgentCard { Name = "Claude Code" }, cCodex = new AgentCard { Name = "Codex" };
        readonly Btn bClaude = new Btn("Fix with Claude Code", true), bCodex = new Btn("Fix with Codex", true);
        readonly Btn bCopy = new Btn("Copy prompt for any AI"), bPaste = new Btn("Paste the AI's reply");
        readonly Btn bApply = new Btn("Apply approved", true), bClear = new Btn("Clear ticks");
        readonly Label status, listTitle, hint;
        readonly TextBox reply = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None };
        readonly DarkList list = new DarkList(52);
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 500 };

        readonly Label lBrain = new Label(); readonly ComboBox cBrain = new ComboBox(); bool syncingBrain;
        static readonly string[] BrainIds = { "auto", "local", "claude", "codex" };
        readonly WizardLanding landing; readonly Btn bTools, bWiz; CheckBox cWizStart; bool syncingWizBox;
        void FillBrain(bool detected)
        {
            if (Helper.Cfg == null) return;
            syncingBrain = true;
            try
            {
                bool hc = true, hx = true;
                if (detected) { var ag = Agents.Detect(); hc = ag.Any(a => a.Id == "claude" && a.Found); hx = ag.Any(a => a.Id == "codex" && a.Found); }
                cBrain.Items.Clear();
                cBrain.Items.AddRange(new object[] { "Automatic (a local AI if one is running)", "My local AI (LM Studio, Ollama and so on)", "Claude Code" + (hc ? "" : "  (not found on this PC)"), "Codex" + (hx ? "" : "  (not found on this PC)") });
                cBrain.SelectedIndex = Math.Max(0, Array.IndexOf(BrainIds, Helper.Cfg.Brain));
            }
            finally { syncingBrain = false; }
        }

        void ShowTools(bool on) { landing.Visible = bTools.Visible = cWizStart.Visible = lBrain.Visible = cBrain.Visible = !on; bWiz.Visible = on; if (!on) { landing.BringToFront(); cWizStart.BringToFront(); bTools.BringToFront(); } }

        AssistantContext ctx;
        List<ProposedAction> actions = new List<ProposedAction>();
        volatile bool detecting, detected;
        bool started;

        public AssistantView(Engine engine)
        {
            eng = engine;
            BackColor = Theme.Bg;
            Controls.Add(new Label { Text = "AI helper", Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            Controls.Add(new Label { Text = "Hand what Visually Safe found to Claude Code or Codex. You choose how it runs and approve it first.", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });

            cClaude.Bounds = new Rectangle(28, 86, 614, 52);
            cCodex.Bounds = new Rectangle(28, 146, 614, 52);
            bClaude.Bounds = new Rectangle(472, 94, 160, 36);
            bCodex.Bounds = new Rectangle(472, 154, 160, 36);
            hint = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(28, 204, 614, 24), AutoEllipsis = true, UseCompatibleTextRendering = false };

            bCopy.Bounds = new Rectangle(28, 244, 210, 40);
            bPaste.Bounds = new Rectangle(246, 244, 180, 40);
            Controls.Add(new Label { Text = "or use any other AI", ForeColor = Theme.Grey, AutoSize = true, Location = new Point(438, 254) });
            status = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(28, 292, 614, 22), AutoEllipsis = true };
            reply.Bounds = new Rectangle(28, 318, 614, 70);
            listTitle = new Label { Text = "Proposed fixes. Tick the ones you approve:", ForeColor = Theme.Text, Font = new Font("Segoe UI Semibold", 9.5f), AutoSize = true, Location = new Point(28, 394) };
            list.Bounds = new Rectangle(28, 416, 614, 76);
            list.Painter = PaintRow;
            bApply.Bounds = new Rectangle(28, 498, 200, 36);
            bClear.Bounds = new Rectangle(236, 498, 110, 36);
            reply.HandleCreated += (s, e) => Native.DarkScroll(reply.Handle);

            bClaude.Click += (s, e) => StartAgent("claude");
            bCodex.Click += (s, e) => StartAgent("codex");
            bCopy.Click += (s, e) => CopyPrompt();
            bPaste.Click += (s, e) => PasteReply();
            bApply.Click += (s, e) => ApplyApproved();
            bClear.Click += (s, e) => { foreach (var a in actions) a.Checked = false; list.Invalidate(); UpdateApply(); };
            list.MouseDown += (s, e) =>
            {
                int i = list.IndexFromPoint(e.Location);
                if (i < 0) return;
                list.SelectedIndex = i;
                if (e.X < 48 * Theme.K) Toggle(i);
            };
            list.DoubleClick += (s, e) => { if (list.SelectedIndex >= 0) Toggle(list.SelectedIndex); };
            list.KeyDown += (s, e) => { if (e.KeyCode == Keys.Space && list.SelectedIndex >= 0) { Toggle(list.SelectedIndex); e.Handled = true; } };

            Controls.AddRange(new Control[] { cClaude, cCodex, bClaude, bCodex, hint, bCopy, bPaste, status, reply, listTitle, list, bApply, bClear });
            bCopy.BringToFront(); bPaste.BringToFront();    // nothing may sit on top of these two
            // the big wizard button covers the fix-it tools until you ask for them
            landing = new WizardLanding { Bounds = new Rectangle(28, 84, 614, 322) };
            cWizStart = new CheckBox { Text = "Show the wizard when Visually Safe starts", Bounds = new Rectangle(28, 452, 614, 28), ForeColor = Theme.Text, BackColor = Theme.Bg, Font = new Font("Segoe UI", 11f), Cursor = Cursors.Hand };
            cWizStart.CheckedChanged += (s, e) =>
            {
                if (syncingWizBox || Helper.Cfg == null) return;
                Helper.Cfg.Wizard = cWizStart.Checked;
                try { Helper.Cfg.Save(eng.DataDir); } catch { }
                Wizard.Sync();
            };
            // what the wizard answers with
            lBrain.Text = "The wizard answers using:"; lBrain.ForeColor = Theme.Text; lBrain.BackColor = Theme.Bg; lBrain.Font = new Font("Segoe UI Semibold", 11f); lBrain.Bounds = new Rectangle(28, 414, 220, 30); lBrain.TextAlign = ContentAlignment.MiddleLeft;
            cBrain.DropDownStyle = ComboBoxStyle.DropDownList; cBrain.FlatStyle = FlatStyle.Flat; cBrain.BackColor = Theme.Card; cBrain.ForeColor = Theme.Text; cBrain.Font = new Font("Segoe UI", 11f); cBrain.Bounds = new Rectangle(252, 414, 390, 30);
            cBrain.SelectedIndexChanged += (s, e) =>
            {
                if (syncingBrain || Helper.Cfg == null || cBrain.SelectedIndex < 0) return;
                Helper.Cfg.Brain = BrainIds[cBrain.SelectedIndex];
                try { Helper.Cfg.Save(eng.DataDir); } catch { }
            };
            Controls.Add(lBrain); Controls.Add(cBrain);
            VisibleChanged += (s, e) => { if (Visible) FillBrain(false); if (Visible) System.Threading.Tasks.Task.Run(() => Agents.Detect()).ContinueWith(t => { try { BeginInvoke(new Action(() => FillBrain(true))); } catch { } }); };
            VisibleChanged += (s, e) => { if (Visible && Helper.Cfg != null) { syncingWizBox = true; cWizStart.Checked = Helper.Cfg.Wizard; syncingWizBox = false; } };
            landing.Pressed += () => Wizard.Summon();
            bTools = new Btn("Fix problems with Claude Code or Codex   ▸") { Bounds = new Rectangle(28, 486, 614, 48) };
            bTools.Click += (s, e) => ShowTools(true);
            bWiz = new Btn("◂ Wizard") { Bounds = new Rectangle(300, 14, 100, 34), Visible = false };
            bWiz.Click += (s, e) => ShowTools(false);
            Controls.AddRange(new Control[] { landing, cWizStart, bTools, bWiz });
            landing.BringToFront(); cWizStart.BringToFront(); bTools.BringToFront(); bWiz.BringToFront();
            timer.Tick += (s, e) => Tick();
            timer.Start();
            reply.Visible = listTitle.Visible = list.Visible = bApply.Visible = bClear.Visible = false;
            UpdateApply();
        }

        // The two text lines under the cards ended up scaled twice on some screens (a very wide label that covered the buttons),
        // so their size is set again here from the screen scale whenever the page is laid out.
        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            Func<int, int, int, int, Rectangle> S = (x, y, w, h) => new Rectangle((int)Math.Round(x * Theme.K), (int)Math.Round(y * Theme.K), (int)Math.Round(w * Theme.K), (int)Math.Round(h * Theme.K));
            if (hint != null && hint.Bounds != S(28, 204, 614, 24)) hint.Bounds = S(28, 204, 614, 24);
            if (status != null && status.Bounds != S(28, 292, 614, 22)) status.Bounds = S(28, 292, 614, 22);
        }

        // ---------------------------------------------------------------- agents

        void Detect()
        {
            if (detecting) return;
            detecting = true; detected = false;
            Task.Run(() => { try { Agents.Detect(true); } catch { } detecting = false; detected = true; });
        }

        void ShowAgents()
        {
            foreach (var a in Agents.Detect())
            {
                var card = a.Id == "claude" ? cClaude : cCodex; var btn = a.Id == "claude" ? bClaude : bCodex;
                card.Known = true; card.Found = a.Found;
                card.Status = a.Found ? "Installed" + (a.Version.Length > 0 ? " · " + a.Version : "") : "Not installed. Visually Safe can install it for you.";
                btn.Text = a.Found ? "Fix with " + a.Name : "Install " + a.Name;
                btn.Primary = true; btn.Invalidate(); card.Invalidate();
            }
            int need = eng.NeedAttention();
            hint.Text = need > 0 ? need + " file" + (need == 1 ? "" : "s") + " need your attention. The agent gets all of them, plus the rootkit check, network tests and quarantine." : "Nothing needs action right now. You can still hand over the full report.";
        }

        void StartAgent(string id)
        {
            var a = Agents.Detect().FirstOrDefault(x => x.Id == id);
            if (a == null) return;
            AgentMenu.Launch(FindForm(), (id == "claude" ? bClaude : bCodex), eng, a, "everything Visually Safe found", () => AgentPrompt.ForReport(eng));
            Detect();
        }

        // ---------------------------------------------------------------- any other AI

        void CopyPrompt()
        {
            ctx = AssistantContext.Capture(eng);
            try
            {
                Clipboard.SetText(Assistant.FullPrompt(ctx));
                status.ForeColor = Theme.Green;
                status.Text = "Copied. Paste it into any AI, then click Paste the AI's reply. It contains file names and paths from this PC, so only use an AI you trust.";
            }
            catch (Exception ex) { status.ForeColor = Theme.Red; status.Text = "Couldn't copy: " + ex.Message; }
        }

        void PasteReply()
        {
            string text = null;
            try { text = Clipboard.GetText(); } catch { }
            if (string.IsNullOrWhiteSpace(text)) { status.ForeColor = Theme.Amber; status.Text = "The clipboard is empty. Copy the AI's reply first."; return; }
            ctx = AssistantContext.Capture(eng);
            Show(text);
        }

        void Show(string text)
        {
            var r = Assistant.Parse(text, ctx);
            reply.Text = (r.Explanation.Length > 0 ? r.Explanation : "(the AI gave no explanation)") + (r.Problem.Length > 0 ? "\r\n\r\n" + r.Problem : "");
            reply.SelectionStart = 0; reply.SelectionLength = 0; reply.ScrollToCaret();   // show it from the top, not scrolled to the end
            actions = r.Actions;
            list.Fill(actions);
            bool any = actions.Count > 0;
            reply.Visible = true;
            list.Visible = listTitle.Visible = bApply.Visible = bClear.Visible = any;
            if (!any && r.Problem.Length == 0) reply.Text += "\r\n\r\nThe AI doesn't think anything needs doing.";
            status.ForeColor = Theme.Muted;
            status.Text = any ? actions.Count + " fix" + (actions.Count == 1 ? "" : "es") + " proposed. Nothing has been done yet." : "No fixes proposed.";
            UpdateApply();
        }

        // ---------------------------------------------------------------- approving

        void Toggle(int i)
        {
            if (i < 0 || i >= actions.Count || actions[i].State != ActState.Pending) return;
            actions[i].Checked = !actions[i].Checked;
            list.Invalidate();
            UpdateApply();
        }

        void UpdateApply()
        {
            int n = actions.Count(a => a.Checked && a.State == ActState.Pending);
            bApply.Text = n == 0 ? "Apply approved" : "Apply approved (" + n + ")";
            bApply.Enabled = n > 0;
        }

        void ApplyApproved()
        {
            var todo = actions.Where(a => a.Checked && a.State == ActState.Pending).ToList();
            if (todo.Count == 0) return;
            bool perm = todo.Any(a => a.Permanent);
            string text = "Apply " + todo.Count + " approved action" + (todo.Count == 1 ? "" : "s") + "?\n\n" + string.Join("\n", todo.Select(a => "• " + a.Title + (a.Permanent ? "  (PERMANENT)" : "")))
                          + (perm ? "\n\nPermanent actions can't be undone." : "");
            if (MessageBox.Show(FindForm(), text, "Apply AI's fixes", MessageBoxButtons.YesNo, perm ? MessageBoxIcon.Warning : MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            foreach (var a in todo) Assistant.Apply(a, eng);
            list.Invalidate();
            UpdateApply();
            int ok = todo.Count(a => a.State == ActState.Done);
            status.ForeColor = ok == todo.Count ? Theme.Green : Theme.Amber;
            status.Text = ok + " of " + todo.Count + " done." + (ok < todo.Count ? " See the list for what failed." : "");
        }

        // ---------------------------------------------------------------- drawing + timer

        void PaintRow(Graphics g, object item, RectangleF r, bool sel)
        {
            var a = (ProposedAction)item;
            using (var b = new SolidBrush(sel ? Theme.Card2 : Theme.Bg)) g.FillRectangle(b, r);
            var box = new RectangleF(14, 16, 20, 20);
            bool rejected = a.State == ActState.Rejected;
            Color boxColor = a.Checked ? Theme.Green : rejected ? Theme.Line : Theme.Muted;
            if (a.Checked) Theme.FillRound(g, Theme.Green, box, 5);
            else using (var p = new Pen(boxColor, 1.6f)) using (var path = Theme.Round(box, 5)) g.DrawPath(p, path);
            if (a.Checked)
                using (var p = new Pen(Color.FromArgb(8, 32, 20), 2.2f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round })
                    g.DrawLines(p, new[] { new PointF(18.5f, 26), new PointF(22.5f, 30), new PointF(29.5f, 21.5f) });

            Color title = rejected ? Theme.Grey : a.State == ActState.Done ? Theme.Green : Theme.Text;
            Theme.Str(g, a.Title, Theme.F(14, true), title, new RectangleF(46, 5, r.Width - 190, 24));
            string sub = a.State == ActState.Pending ? a.Reason : a.Message + (a.State == ActState.Rejected && a.Reason.Length > 0 ? " · " + a.Reason : "");
            Theme.Str(g, sub, Theme.F(12), a.State == ActState.Failed ? Theme.Red : Theme.Muted, new RectangleF(46, 27, r.Width - 58, 20));
            string tag = a.State == ActState.Pending ? a.Risk : a.State == ActState.Done ? "Done" : a.State == ActState.Failed ? "Failed" : "Rejected";
            Color tagColor = a.State == ActState.Pending ? (a.Permanent ? Theme.Red : Theme.Muted) : a.State == ActState.Done ? Theme.Green : a.State == ActState.Failed ? Theme.Red : Theme.Grey;
            Theme.Str(g, tag, Theme.F(11, true), tagColor, new RectangleF(r.Width - 200, 5, 190, 24), StringAlignment.Far);
            using (var p = new Pen(Theme.Line)) g.DrawLine(p, 46, r.Height - 0.5f, r.Width, r.Height - 0.5f);
        }

        void Tick()
        {
            if (!Visible) return;
            if (!started) { started = true; Detect(); }
            if (detected) { detected = false; ShowAgents(); }
        }
    }
}
