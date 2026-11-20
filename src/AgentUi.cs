using System;
using System.Collections.Concurrent;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>The approval box shown before an agent is started: what it is, how it will run, and exactly what it will be told.</summary>
    class AgentDialog : Form
    {
        public AgentMode Mode = AgentMode.Terminal;
        readonly Btn bGo = new Btn("Open terminal", true), bCancel = new Btn("Cancel");

        static int S(int v) { return (int)Math.Round(v * Theme.K); }

        public AgentDialog(Agent agent, string title, string prompt)
        {
            AutoScaleMode = AutoScaleMode.None;
            Text = "Fix with " + agent.Name;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Bg; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9.5f); KeyPreview = true;
            Icon = Theme.MakeIcon(GuardState.Protected);

            int w = S(600), x = S(20), y = S(16);
            var head = new Label { Text = "Let " + agent.Name + " fix \"" + (title.Length > 46 ? title.Substring(0, 46) + "…" : title) + "\"?", Font = new Font("Segoe UI Semibold", 13f), AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y) };
            Controls.Add(head); y += head.PreferredHeight + S(6);
            var info = new Label { Text = agent.Name + (agent.Version.Length > 0 ? " " + agent.Version : "") + " · " + agent.Path, ForeColor = Theme.Grey, AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y) };
            Controls.Add(info); y += info.PreferredHeight + S(10);
            var cloud = new Label
            {
                Text = "The instructions below are sent to " + agent.Vendor + " by the " + agent.Name + " you have installed and signed in to. They contain file names and paths from this PC.",
                ForeColor = Theme.Amber, AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y)
            };
            Controls.Add(cloud); y += cloud.PreferredHeight + S(12);

            string[] titles =
            {
                "Open it in a terminal window (recommended)",
                "Let it investigate and report back (read-only)",
                "Let it fix it for me, without asking again"
            };
            string[] subs =
            {
                "A console window opens with " + agent.Name + " running. You see everything it does and approve each step inside it.",
                "It runs in the background and can only look around, not change anything. Its findings appear here.",
                "It runs in the background and may change files and settings on this PC on its own. Only choose this if you've read the instructions below."
            };
            var radios = new RadioButton[3];
            for (int i = 0; i < 3; i++)
            {
                radios[i] = new RadioButton { Text = titles[i], AutoSize = true, MaximumSize = new Size(w, 0), Font = new Font("Segoe UI Semibold", 10f), ForeColor = i == 2 ? Theme.Red : Theme.Text, BackColor = Theme.Bg, Location = new Point(x, y) };
                Controls.Add(radios[i]); y += radios[i].PreferredSize.Height + S(2);
                var sl = new Label { Text = subs[i], ForeColor = Theme.Muted, AutoSize = true, MaximumSize = new Size(w - S(22), 0), Location = new Point(x + S(22), y) };
                Controls.Add(sl); y += sl.PreferredHeight + S(8);
                int idx = i;
                radios[i].CheckedChanged += (s, e) =>
                {
                    if (!radios[idx].Checked) return;
                    Mode = (AgentMode)idx;
                    bGo.Text = idx == 0 ? "Open terminal" : idx == 1 ? "Investigate" : "Fix it now";
                    bGo.Primary = idx != 2; bGo.Danger = idx == 2; bGo.Invalidate();
                };
            }
            radios[0].Checked = true;
            if (Admin.IsAdmin)
            {
                var adm = new Label { Text = "Visually Safe is running as administrator, so the agent starts with administrator rights too.", ForeColor = Theme.Red, AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y) };
                Controls.Add(adm); y += adm.PreferredHeight + S(8);
            }

            var pl = new Label { Text = "Exactly what it will be told:", Font = new Font("Segoe UI Semibold", 9.5f), AutoSize = true, Location = new Point(x, y) };
            Controls.Add(pl); y += pl.PreferredHeight + S(4);
            var box = new TextBox
            {
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None,
                Font = new Font("Consolas", 9f), Text = prompt, Bounds = new Rectangle(x, y, w, S(150))
            };
            box.HandleCreated += (s, e) => Native.DarkScroll(box.Handle);
            Controls.Add(box); y += S(150) + S(14);

            bGo.Bounds = new Rectangle(x + w - S(130) - S(8) - S(190), y, S(190), S(38));
            bCancel.Bounds = new Rectangle(x + w - S(130), y, S(130), S(38));
            bGo.Click += (s, e) => DialogResult = DialogResult.OK;
            bCancel.Click += (s, e) => DialogResult = DialogResult.Cancel;
            Controls.Add(bGo); Controls.Add(bCancel);
            ClientSize = new Size(S(640), y + S(38) + S(18));
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }
        protected override void OnKeyDown(KeyEventArgs e) { if (e.KeyCode == Keys.Escape) DialogResult = DialogResult.Cancel; base.OnKeyDown(e); }
    }

    /// <summary>Shows what a background agent prints while it works.</summary>
    class AgentOutputForm : Form
    {
        readonly TextBox output = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None, Font = new Font("Consolas", 9.5f) };
        readonly Label status = new Label { ForeColor = Theme.Muted, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft };
        readonly Btn bStop = new Btn("Stop") { Danger = true }, bCopy = new Btn("Copy"), bClose = new Btn("Close", true);
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 250 };
        readonly ConcurrentQueue<string> lines = new ConcurrentQueue<string>();
        readonly CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMinutes(30));
        readonly DateTime start = DateTime.Now;
        readonly string name;
        volatile bool finished; int exit;

        static int S(int v) { return (int)Math.Round(v * Theme.K); }

        public AgentOutputForm(Agent agent, AgentMode mode, string workDir, string prompt)
        {
            name = agent.Name;
            AutoScaleMode = AutoScaleMode.None;
            Text = agent.Name + (mode == AgentMode.Fix ? " is fixing it" : " is investigating");
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Bg; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9.5f);
            Icon = Theme.MakeIcon(GuardState.Protected);
            ClientSize = new Size(S(680), S(520));
            status.Bounds = new Rectangle(S(16), S(10), S(648), S(26));
            output.Bounds = new Rectangle(S(16), S(42), S(648), S(410));
            output.HandleCreated += (s, e) => Native.DarkScroll(output.Handle);
            bStop.Bounds = new Rectangle(S(16), S(466), S(110), S(38));
            bCopy.Bounds = new Rectangle(S(134), S(466), S(110), S(38));
            bClose.Bounds = new Rectangle(S(554), S(466), S(110), S(38));
            Controls.AddRange(new Control[] { status, output, bStop, bCopy, bClose });
            bStop.Click += (s, e) => cts.Cancel();
            bCopy.Click += (s, e) => { try { Clipboard.SetText(output.Text); } catch { } };
            bClose.Click += (s, e) => Close();
            timer.Tick += (s, e) => Pump();
            timer.Start();
            Task.Run(() =>
            {
                try { exit = AgentRunner.RunHeadless(agent, mode, workDir, prompt, l => lines.Enqueue(l), cts.Token); }
                catch (Exception ex) { lines.Enqueue("Couldn't run " + agent.Name + ": " + ex.GetBaseException().Message); exit = -2; }
                finished = true;
            });
        }

        void Pump()
        {
            var sb = new StringBuilder(); string l;
            while (lines.TryDequeue(out l)) sb.AppendLine(l);
            if (sb.Length > 0) { output.AppendText(sb.ToString()); }
            if (!finished) { status.ForeColor = Theme.Text; status.Text = name + " is working…  " + (int)(DateTime.Now - start).TotalSeconds + " s"; }
            else
            {
                bStop.Enabled = false; bStop.Invalidate();
                status.ForeColor = exit == 0 ? Theme.Green : Theme.Amber;
                status.Text = exit == 0 ? "Finished. Run the rootkit check or a scan again to confirm." : exit == -1 ? "Stopped." : "Finished with a problem (exit code " + exit + "). See the text below.";
                timer.Stop();
            }
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }
        protected override void OnFormClosing(FormClosingEventArgs e) { if (!finished) cts.Cancel(); timer.Stop(); base.OnFormClosing(e); }
    }

    /// <summary>Runs install commands for the user and shows their output.</summary>
    class InstallForm : Form
    {
        readonly TextBox output = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None, Font = new Font("Consolas", 9.5f) };
        readonly Label status = new Label { ForeColor = Theme.Muted, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft };
        readonly Btn bStop = new Btn("Stop") { Danger = true }, bClose = new Btn("Close", true);
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 250 };
        readonly ConcurrentQueue<string> lines = new ConcurrentQueue<string>();
        readonly CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMinutes(20));
        readonly DateTime start = DateTime.Now;
        readonly string name;
        volatile bool finished;
        public bool Succeeded;

        static int S(int v) { return (int)Math.Round(v * Theme.K); }

        public InstallForm(string agentName, System.Collections.Generic.List<string[]> steps)
        {
            name = agentName;
            AutoScaleMode = AutoScaleMode.None;
            Text = "Installing " + agentName;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Bg; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9.5f);
            Icon = Theme.MakeIcon(GuardState.Protected);
            ClientSize = new Size(S(680), S(500));
            status.Bounds = new Rectangle(S(16), S(10), S(648), S(26));
            output.Bounds = new Rectangle(S(16), S(42), S(648), S(390));
            output.HandleCreated += (s, e) => Native.DarkScroll(output.Handle);
            bStop.Bounds = new Rectangle(S(16), S(446), S(110), S(38));
            bClose.Bounds = new Rectangle(S(554), S(446), S(110), S(38)); bClose.Enabled = false;
            Controls.AddRange(new Control[] { status, output, bStop, bClose });
            bStop.Click += (s, e) => cts.Cancel();
            bClose.Click += (s, e) => Close();
            timer.Tick += (s, e) => Pump();
            timer.Start();
            Task.Run(() =>
            {
                bool ok = true;
                foreach (var st in steps)
                {
                    if (cts.IsCancellationRequested) { ok = false; break; }
                    string exe = st[0] == "@npm" ? Agents.FindNpm() : st[0];
                    if (string.IsNullOrEmpty(exe)) { lines.Enqueue("npm still can't be found after installing Node.js. Restart Visually Safe and try again."); ok = false; break; }
                    lines.Enqueue("> " + System.IO.Path.GetFileName(exe) + " " + st[1]);
                    try
                    {
                        var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", Agents.CmdArgs(exe, st[1], false))
                        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
                        using (var p = System.Diagnostics.Process.Start(psi))
                        {
                            p.OutputDataReceived += (s2, e2) => { if (e2.Data != null) lines.Enqueue(e2.Data); };
                            p.ErrorDataReceived += (s2, e2) => { if (e2.Data != null) lines.Enqueue(e2.Data); };
                            p.BeginOutputReadLine(); p.BeginErrorReadLine();
                            while (!p.WaitForExit(300)) if (cts.IsCancellationRequested) { AgentRunner.Kill(p); break; }
                            p.WaitForExit();
                            if (p.ExitCode != 0) { lines.Enqueue("(exit code " + p.ExitCode + ")"); ok = false; break; }
                        }
                    }
                    catch (Exception ex) { lines.Enqueue("Couldn't run it: " + ex.GetBaseException().Message); ok = false; break; }
                }
                Succeeded = ok && !cts.IsCancellationRequested;
                finished = true;
            });
        }

        void Pump()
        {
            var sb = new StringBuilder(); string l;
            while (lines.TryDequeue(out l)) sb.AppendLine(l);
            if (sb.Length > 0) output.AppendText(sb.ToString());
            if (!finished) { status.ForeColor = Theme.Text; status.Text = "Installing " + name + "…  " + (int)(DateTime.Now - start).TotalSeconds + " s"; return; }
            timer.Stop(); bStop.Enabled = false; bClose.Enabled = true; bStop.Invalidate(); bClose.Invalidate();
            status.ForeColor = Succeeded ? Theme.Green : Theme.Amber;
            status.Text = Succeeded ? "Installed." : "The install didn't finish. See the text below.";
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }
        protected override void OnFormClosing(FormClosingEventArgs e) { if (!finished) { e.Cancel = true; return; } timer.Stop(); base.OnFormClosing(e); }
    }

    /// <summary>The "Fix with agent" menu: lists the agents found on this PC and starts the one you pick, after the approval box.</summary>
    static class AgentMenu
    {
        public static void Show(Form owner, Control anchor, Engine eng, string title, Func<string> buildPrompt)
        {
            var agents = Agents.Detect();
            var menu = Menus.Make();
            foreach (var a in agents)
            {
                var agent = a;
                string text = agent.Found ? "Fix with " + agent.Name + (agent.Version.Length > 0 ? "  (" + agent.Version + ")" : "") : "Install " + agent.Name + " for me…";
                menu.Items.Add(new ToolStripMenuItem(text, null, (s, e) => Launch(owner, anchor, eng, agent, title, buildPrompt)) { ForeColor = agent.Found ? Theme.Text : Theme.Muted });
            }
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(new ToolStripMenuItem("Look again for installed agents", null, (s, e) => { Agents.Detect(true); }) { ForeColor = Theme.Muted });
            menu.Show(anchor, new Point(0, anchor.Height));
        }

        /// <summary>Starts an agent: installs it first (after asking) if it isn't on this PC, then shows the approval box.</summary>
        public static void Launch(Form owner, Control anchor, Engine eng, Agent agent, string title, Func<string> buildPrompt)
        {
            if (!agent.Found)
            {
                if (!Install(owner, eng, agent)) return;
                agent = Agents.Detect().First(x => x.Id == agent.Id);
                if (!agent.Found) return;
            }
            Run(owner, eng, agent, title, buildPrompt);
        }

        /// <summary>Installs the agent after asking. Returns true if it is now installed.</summary>
        static bool Install(Form owner, Engine eng, Agent agent)
        {
            string summary;
            var steps = Agents.InstallSteps(agent, out summary);
            if (steps == null) { MessageBox.Show(owner, summary + "\n\n" + agent.Install, agent.Name, MessageBoxButtons.OK, MessageBoxIcon.Information); return false; }
            if (MessageBox.Show(owner, "Install " + agent.Name + " on this PC?\n\nVisually Safe will:\n" + summary +
                    "\n\nThis downloads the official " + agent.Vendor + " package from the npm registry and installs it for your Windows user. You'll be asked to sign in to " + agent.Name + " afterwards.",
                    "Install " + agent.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return false;
            bool ok;
            using (var f = new InstallForm(agent.Name, steps)) { f.ShowDialog(owner); ok = f.Succeeded; }
            var now = Agents.Detect(true).First(x => x.Id == agent.Id);
            if (!ok || !now.Found)
            {
                MessageBox.Show(owner, agent.Name + " wasn't installed. The text in the install window says why.", "Visually Safe", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if (MessageBox.Show(owner, agent.Name + " is installed (" + now.Version + ").\n\nIt needs you to sign in once. Open it now to sign in?", "Installed", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
            {
                try
                {
                    string work = AgentRunner.WorkDir(eng.DataDir);
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", "/k \"cd /d \"" + work + "\" && \"" + now.Path + "\"\"") { UseShellExecute = true, WorkingDirectory = work });
                }
                catch { }
                return false;   // finish signing in first, then use the menu again
            }
            return true;
        }

        static void Run(Form owner, Engine eng, Agent agent, string title, Func<string> buildPrompt)
        {
            string prompt = buildPrompt();
            AgentMode mode;
            using (var d = new AgentDialog(agent, title, prompt))
            {
                if (d.ShowDialog(owner) != DialogResult.OK) return;
                mode = d.Mode;
            }
            string work = AgentRunner.WorkDir(eng.DataDir);
            string file = AgentRunner.WritePrompt(eng.DataDir, prompt);
            try
            {
                if (mode == AgentMode.Terminal) { AgentRunner.LaunchTerminal(agent, work, file); return; }
                using (var f = new AgentOutputForm(agent, mode, work, prompt)) f.ShowDialog(owner);
            }
            catch (Exception ex)
            {
                MessageBox.Show(owner, "Couldn't start " + agent.Name + ":\n\n" + ex.GetBaseException().Message, "Visually Safe", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
