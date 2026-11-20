using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>
    /// "Update Visually Safe with AI": copies the source, tells an AI agent what Visually Safe does and asks it whether Visually Safe needs more,
    /// then builds and tests the result, shows the owner what changed, and installs it only on approval. PROTECTED CODE (see SelfUpdate.cs).
    /// </summary>
    class SelfUpdateForm : Form
    {
        public static event Action RestartRequested;

        readonly Engine eng;
        readonly Btn bPrep = new Btn("1. Make a working copy", true), bClaude = new Btn("2. Ask Claude Code"), bCodex = new Btn("2. Ask Codex"),
            bCopy = new Btn("Copy prompt (any AI)"), bOpen = new Btn("Open folder"), bCheck = new Btn("3. Check and build", true),
            bInstall = new Btn("4. Install and restart", true), bDiscard = new Btn("Discard");
        readonly TextBox log = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None, Font = new Font("Consolas", 9.5f) };
        readonly Label info;
        UpdateSession session; UpdateReport report; bool built, busy;
        CancellationTokenSource cts;
        List<Agent> agents = new List<Agent>();

        public SelfUpdateForm(Engine engine)
        {
            eng = engine;
            SuspendLayout();
            Text = "Update Visually Safe with AI"; Icon = Theme.AppIcon();
            AutoScaleDimensions = new SizeF(96F, 96F); AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(700, 600); BackColor = Theme.Bg; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9f);

            Controls.Add(new Label { Text = "Update Visually Safe with AI", Font = new Font("Segoe UI Semibold", 14f), ForeColor = Theme.Text, AutoSize = false, Bounds = new Rectangle(22, 14, 650, 34), Tag = new Rectangle(22, 14, 650, 34) });
            info = new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = new Rectangle(24, 52, 652, 62), Tag = new Rectangle(24, 52, 652, 62),
                Text = "An AI agent is told what Visually Safe does and asked whether it needs updates to do more as an antivirus. It works only on a COPY of the source. Visually Safe then builds and tests the result and shows you what changed. Nothing is installed until you click Install, and the old program is kept and comes back by itself if the new one doesn't start properly." };
            bPrep.Bounds = new Rectangle(24, 122, 190, 38);
            bClaude.Bounds = new Rectangle(222, 122, 150, 38);
            bCodex.Bounds = new Rectangle(380, 122, 130, 38);
            bCopy.Bounds = new Rectangle(518, 122, 158, 38);
            log.Bounds = new Rectangle(24, 172, 652, 342);
            bOpen.Bounds = new Rectangle(24, 530, 110, 40);
            bCheck.Bounds = new Rectangle(142, 530, 178, 40);
            bInstall.Bounds = new Rectangle(328, 530, 190, 40);
            bDiscard.Bounds = new Rectangle(526, 530, 150, 40);
            Controls.AddRange(new Control[] { info, bPrep, bClaude, bCodex, bCopy, log, bOpen, bCheck, bInstall, bDiscard });

            bPrep.Click += (s, e) => Prepare();
            bClaude.Click += (s, e) => RunAgent("claude");
            bCodex.Click += (s, e) => RunAgent("codex");
            bCopy.Click += (s, e) => CopyPrompt();
            bOpen.Click += (s, e) => { if (session != null) try { Process.Start("explorer.exe", "\"" + session.Work + "\""); } catch { } };
            bCheck.Click += (s, e) => Check();
            bInstall.Click += (s, e) => InstallNow();
            bDiscard.Click += (s, e) => { if (cts != null) cts.Cancel(); Close(); };
            FormClosing += (s, e) => { if (busy && MessageBox.Show(this, "Something is still running. Stop it and close?", "Visually Safe", MessageBoxButtons.YesNo) != DialogResult.Yes) e.Cancel = true; else if (cts != null) cts.Cancel(); };
            Shown += (s, e) =>
            {
                FitLabels.Apply(this);
                string src = SelfUpdate.SourceDir();
                if (src == null) Say("The source code wasn't found next to this copy of Visually Safe, so it can't update itself. (It looks for a folder with VisuallySafe.csproj above the program's folder.)");
                else Say("Source code: " + src);
                if (SelfUpdate.DotNet() == null) Say("The .NET SDK wasn't found. Without it Visually Safe can't build an update.");
                Task.Run(() => { try { agents = Agents.Detect(); } catch { } BeginInvoke(new Action(Refresh2)); });
                Refresh2();
            };
            Refresh2();
            ResumeLayout(false);
        }

        void Say(string t)
        {
            if (IsDisposed) return;
            if (InvokeRequired) { try { BeginInvoke(new Action(() => Say(t))); } catch { } return; }
            log.AppendText(t + "\r\n");
        }

        void Refresh2()
        {
            bool have = session != null;
            bool src = SelfUpdate.SourceDir() != null;
            bPrep.Enabled = !busy && src && !have;
            bool cl = agents.Any(a => a.Id == "claude" && a.Found), cx = agents.Any(a => a.Id == "codex" && a.Found);
            bClaude.Enabled = !busy && have && cl; bCodex.Enabled = !busy && have && cx;
            bCopy.Enabled = !busy && have; bOpen.Enabled = have;
            bCheck.Enabled = !busy && have;
            bInstall.Enabled = !busy && have && built && report != null && report.Ok;
            foreach (Control c in Controls) c.Invalidate();
        }

        void Run(Action work, Action done = null)
        {
            busy = true; Refresh2();
            Task.Run(() => { try { work(); } catch (Exception ex) { Say("Error: " + ex.Message); } }).ContinueWith(t => { if (IsDisposed) return; BeginInvoke(new Action(() => { busy = false; Refresh2(); if (done != null) done(); })); });
        }

        void Prepare()
        {
            Run(() => { session = SelfUpdate.Prepare(eng); Say("Working copy ready:\r\n  " + session.Work); Say("Now pick an AI: Claude Code or Codex can work on it for you, or copy the prompt and use any other AI on that folder."); });
        }

        void CopyPrompt()
        {
            try { Clipboard.SetText(SelfUpdate.Prompt(eng, session)); Say("Prompt copied. Give it to any AI together with the working folder (use Open folder), then click Check and build."); }
            catch (Exception ex) { Say("Couldn't copy: " + ex.Message); }
        }

        void RunAgent(string id)
        {
            var a = agents.FirstOrDefault(x => x.Id == id); if (a == null) return;
            if (MessageBox.Show(this, a.Name + " will read and change files in the working copy only (" + session.Work + "). It gets no command line, so it can't run anything. This can take several minutes.\r\n\r\nStart?", "Ask " + a.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            cts = new CancellationTokenSource();
            Run(() =>
            {
                string prompt = SelfUpdate.Prompt(eng, session);
                Say("Asking " + a.Name + " ... (it writes ASSESSMENT.md and, if worthwhile, makes changes)");
                int code = SelfUpdate.RunAgent(a, session, prompt, line => { if (line.Trim().Length > 0) Say("  " + (line.Length > 300 ? line.Substring(0, 300) : line)); }, cts.Token);
                Say(code == 0 ? a.Name + " finished. Click Check and build." : a.Name + " stopped (code " + code + "). You can still click Check and build to see what it did.");
            });
        }

        void Check()
        {
            built = false; report = null;
            Run(() =>
            {
                Say("");
                Say("---- Checking what changed ----");
                var r = SelfUpdate.Inspect(session);
                report = r;
                if (r.Assessment.Length > 0) Say("AI's assessment:\r\n" + Cut(r.Assessment, 1800));
                if (r.Changed.Count + r.Added.Count > 0) Say("Changed: " + string.Join(", ", r.Changed) + (r.Added.Count > 0 ? "   Added: " + string.Join(", ", r.Added) : ""));
                if (r.Changes.Length > 0) Say("What it says it did:\r\n" + Cut(r.Changes, 2500));
                foreach (string w in r.Warnings) Say("WATCH OUT: " + w);
                foreach (string b in r.Blockers) Say("BLOCKED: " + b);
                if (!r.Ok) { Say("This update can't be installed."); return; }
                if (r.Changed.Count + r.Added.Count == 0) { Say("Nothing to install."); return; }
                Say("---- Building ----");
                if (!SelfUpdate.Build(session, Say)) { Say("The build failed, so nothing can be installed. Ask the AI to fix it and check again."); return; }
                Say("Build OK.");
                Say("---- Testing the new program ----");
                if (!SelfUpdate.SelfTestNew(session, Say)) { Say("The new program failed its tests, so it can't be installed."); return; }
                built = true;
                Say("");
                Say("All checks passed. Read the changes above" + (r.Warnings.Count > 0 ? ", especially the WATCH OUT lines," : "") + " then click Install if you agree. These tests are a safety net; your reading is the real check.");
            });
        }

        static string Cut(string s, int n) { s = s.Trim(); return s.Length > n ? s.Substring(0, n) + "\r\n...(shortened; the full text is in the working folder)" : s; }

        void InstallNow()
        {
            if (report == null || !built) return;
            string msg = "Install this update?\r\n\r\nVisually Safe will:\r\n- keep a copy of the current source and program,\r\n- put the new source in the project folder (not committed to git),\r\n- restart as the new version.\r\n\r\nIf the new version doesn't stay running, the old one comes back by itself." +
                         (report.Warnings.Count > 0 ? "\r\n\r\nThere were " + report.Warnings.Count + " WATCH OUT notes. Have you read them?" : "");
            if (MessageBox.Show(this, msg, "Install update", MessageBoxButtons.YesNo, report.Warnings.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string err = SelfUpdate.Install(eng, session, report);
            if (err != null) { Say(err); return; }
            Say("Installed. Restarting Visually Safe ...");
            Task.Delay(800).ContinueWith(t => { var h = RestartRequested; if (h != null) BeginInvoke(new Action(() => h())); });
        }
    }
}
