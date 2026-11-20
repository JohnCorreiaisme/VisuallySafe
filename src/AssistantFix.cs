using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TinyGuard
{
    /// <summary>The choice box: lists what can be done about an item and lets the user pick exactly one (or cancel).</summary>
    class FixOptionsForm : Form
    {
        public ProposedAction Chosen;
        readonly Btn bDo = new Btn("Do it", true), bCancel = new Btn("Cancel");
        readonly List<KeyValuePair<RadioButton, ProposedAction>> radios = new List<KeyValuePair<RadioButton, ProposedAction>>();

        static int S(int v) { return (int)Math.Round(v * Theme.K); }

        public FixOptionsForm(string title, string explanation, List<ProposedAction> options)
        {
            AutoScaleMode = AutoScaleMode.None;
            Text = "Fix: " + title;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Bg; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9.5f); KeyPreview = true;
            Icon = Theme.MakeIcon(GuardState.Protected);

            int w = S(560), x = S(20), y = S(16);
            var head = new Label { Text = "How should \"" + (title.Length > 50 ? title.Substring(0, 50) + "…" : title) + "\" be fixed?", Font = new Font("Segoe UI Semibold", 13f), AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y) };
            Controls.Add(head); y += head.PreferredHeight + S(10);

            if (!string.IsNullOrWhiteSpace(explanation))
            {
                var ex = new Label { Text = explanation.Trim().Length > 600 ? explanation.Trim().Substring(0, 600) + "…" : explanation.Trim(), ForeColor = Theme.Muted, AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y) };
                Controls.Add(ex); y += ex.PreferredHeight + S(14);
            }
            var pick = new Label { Text = "Choose one. Nothing happens until you click the button at the bottom.", Font = new Font("Segoe UI Semibold", 9.5f), AutoSize = true, Location = new Point(x, y) };
            Controls.Add(pick); y += pick.PreferredHeight + S(10);

            ProposedAction pre = options.FirstOrDefault(o => o.Recommended) ?? options.FirstOrDefault(o => !o.Permanent) ?? options.First();
            foreach (var o in options)
            {
                var rb = new RadioButton
                {
                    Text = o.Title + (o.Recommended ? "     ← AI recommends" : ""), AutoSize = true, MaximumSize = new Size(w - S(10), 0),
                    ForeColor = o.Permanent ? Theme.Red : Theme.Text, Font = new Font("Segoe UI Semibold", 10f), Location = new Point(x, y), BackColor = Theme.Bg
                };
                Controls.Add(rb); y += rb.PreferredSize.Height + S(2);
                string sub = (o.Reason.Length > 0 ? o.Reason + "  ·  " : "") + o.Risk;
                var sl = new Label { Text = sub, ForeColor = Theme.Muted, AutoSize = true, MaximumSize = new Size(w - S(26), 0), Location = new Point(x + S(22), y) };
                Controls.Add(sl); y += sl.PreferredHeight + S(12);
                var act = o;
                rb.CheckedChanged += (s, e) => { if (rb.Checked) { Chosen = act; bDo.Text = act.Permanent ? "Do it (permanent)" : "Do it"; bDo.Primary = !act.Permanent; bDo.Danger = act.Permanent; bDo.Invalidate(); } };
                radios.Add(new KeyValuePair<RadioButton, ProposedAction>(rb, o));
                if (o == pre) rb.Checked = true;
            }

            y += S(6);
            bDo.Bounds = new Rectangle(w + x - S(130) - S(8) - S(200), y, S(200), S(38));
            bCancel.Bounds = new Rectangle(w + x - S(130), y, S(130), S(38));
            bDo.Click += (s, e) => { if (Chosen != null) DialogResult = DialogResult.OK; };
            bCancel.Click += (s, e) => DialogResult = DialogResult.Cancel;
            Controls.Add(bDo); Controls.Add(bCancel);
            ClientSize = new Size(S(600), y + S(38) + S(18));
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }
        protected override void OnKeyDown(KeyEventArgs e) { if (e.KeyCode == Keys.Escape) DialogResult = DialogResult.Cancel; base.OnKeyDown(e); }
    }

    /// <summary>Runs slow work behind a small "please wait" window, and shows the choice box for AI fixes.</summary>
    static class AiFix
    {
        class Waiting : Form
        {
            readonly Label text = new Label { ForeColor = Theme.Text, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Dock = DockStyle.Top, Height = 70 };
            readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 300 };
            readonly string baseText;
            readonly DateTime start = DateTime.Now;
            public readonly CancellationTokenSource Cts = new CancellationTokenSource(TimeSpan.FromMinutes(20));
            public volatile bool Finished;

            public Waiting(string message)
            {
                baseText = message;
                Text = "Visually Safe";
                FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; ShowInTaskbar = false;
                StartPosition = FormStartPosition.CenterParent;
                BackColor = Theme.Bg; ForeColor = Theme.Text;
                ClientSize = new Size(440, 130);
                text.Text = message;
                var cancel = new Btn("Cancel") { Bounds = new Rectangle(160, 78, 120, 36) };
                cancel.Click += (s, e) => { Cts.Cancel(); DialogResult = DialogResult.Cancel; };
                Controls.Add(cancel); Controls.Add(text);
                timer.Tick += (s, e) =>
                {
                    text.Text = baseText + "\n" + (int)(DateTime.Now - start).TotalSeconds + " s";
                    if (Finished) { timer.Stop(); DialogResult = DialogResult.OK; }
                };
                timer.Start();
            }

            protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }
            protected override void OnFormClosed(FormClosedEventArgs e) { timer.Stop(); base.OnFormClosed(e); }
        }

        /// <summary>Runs a job on a background thread while showing a small "waiting" window with Cancel.</summary>
        public static T Work<T>(Form owner, string message, Func<CancellationToken, T> job, out string error) where T : class
        {
            T result = null; string err = null;
            using (var w = new Waiting(message))
            {
                Task.Run(() =>
                {
                    try { result = job(w.Cts.Token); }
                    catch (OperationCanceledException) { err = "stopped."; }
                    catch (Exception ex) { err = ex.GetBaseException().Message; }
                    w.Finished = true;
                });
                w.ShowDialog(owner);
                if (result == null && err == null) { w.Cts.Cancel(); err = "stopped."; }
            }
            error = err;
            return result;
        }

        /// <summary>
        /// Shows the options (update, ignore, quarantine, delete...), lets the user pick one, and does it.
        /// Returns true if the chosen fix was carried out.
        /// </summary>
        public static bool ChooseAndApply(Form owner, Engine eng, string title, string explanation, List<ProposedAction> pending)
        {
            if (pending.Count == 0) return false;
            ProposedAction chosen;
            using (var f = new FixOptionsForm(title, explanation, pending))
            {
                if (f.ShowDialog(owner) != DialogResult.OK || f.Chosen == null) return false;
                chosen = f.Chosen;
            }

            if (chosen.Type == "update")
            {
                string e;
                Work(owner, "Updating " + (chosen.Pkg != null ? chosen.Pkg.Name : "the program") + "…\nThis can take a few minutes, and Windows may ask for permission.",
                    ct => { Assistant.Apply(chosen, eng, ct); return "done"; }, out e);
                if (chosen.State == ActState.Pending) { chosen.State = ActState.Failed; chosen.Message = "Stopped before it finished"; }
            }
            else Assistant.Apply(chosen, eng);

            bool ok = chosen.State == ActState.Done;
            string note = !ok ? "" : chosen.Type == "update" ? "\n\nRestart the program (or the PC, for a driver) so the new version is used."
                                   : chosen.Type == "ignore" ? "\n\nTinyGuard won't flag this again."
                                   : "\n\nRun the rootkit check again if you want to confirm it's fixed.";
            MessageBox.Show(owner, (ok ? "✔ " : "✘ ") + chosen.Title + (ok ? "" : "\n\n" + chosen.Message) + note,
                ok ? "Fixed" : "Couldn't finish", MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            return ok;
        }
    }
}
