using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TinyGuard
{
    /// <summary>The Shields page: ransomware shield, web blocklist, malware fingerprint feed and self-protection.</summary>
    class ShieldsView : Panel
    {
        readonly Engine eng;
        readonly CheckBox cRansom, cStop, cWeb, cGuard, cProtect;
        readonly Label lRansom, lWeb, lWebResult, lFeed, lGuard;
        readonly ListBox events = new ListBox { IntegralHeight = false, BorderStyle = BorderStyle.None, BackColor = Theme.Card, ForeColor = Theme.Text };
        readonly TextBox tDomain = new TextBox { BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.FixedSingle };
        readonly Btn bTest = new Btn("Test it safely"), bUpdate = new Btn("Update now"), bRemove = new Btn("Remove all"), bCheck = new Btn("Check"), bBlock = new Btn("Block"), bAllow = new Btn("Allow"), bFeed = new Btn("Update now");
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 1500 };
        bool loading, fitted; DateTime watchdogAsked = DateTime.MinValue; bool watchdog;

        static Label Head(string t, int y) { return new Label { Text = t, Font = new Font("Segoe UI Semibold", 11f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(26, y) }; }
        static Label Small(int y, int w = 614) { var r = new Rectangle(30, y, w, 22); return new Label { ForeColor = Theme.Muted, AutoSize = false, Bounds = r, Tag = r, AutoEllipsis = true }; }
        static CheckBox Check(string text, int y) { return new CheckBox { Text = text, ForeColor = Theme.Text, Bounds = new Rectangle(28, y, 610, 24) }; }

        public ShieldsView(Engine engine)
        {
            eng = engine; BackColor = Theme.Bg;
            Controls.Add(new Label { Text = "Shields", Font = new Font("Segoe UI Semibold", 16f), ForeColor = Theme.Text, AutoSize = true, Location = new Point(24, 18) });
            Controls.Add(new Label { Text = "Extra protection that works beside the file scanner.", ForeColor = Theme.Muted, AutoSize = true, Location = new Point(28, 54) });

            Controls.Add(Head("Ransomware shield", 82));
            cRansom = Check("Watch my Documents, Pictures, Desktop, Videos and Music", 106);
            cStop = Check("If ransomware is caught, stop the program, cut its internet and quarantine it", 130);
            lRansom = Small(156);
            events.Bounds = new Rectangle(30, 180, 612, 58); events.Tag = events.Bounds;
            bTest.Bounds = new Rectangle(500, 78, 142, 28);

            Controls.Add(Head("Web blocklist", 248));
            cWeb = Check("Block known malware and phishing websites (for every program)", 272);
            lWeb = Small(298);
            bUpdate.Bounds = new Rectangle(28, 322, 106, 28); bRemove.Bounds = new Rectangle(142, 322, 106, 28);
            tDomain.Bounds = new Rectangle(262, 324, 172, 24);
            bCheck.Bounds = new Rectangle(442, 322, 62, 28); bBlock.Bounds = new Rectangle(510, 322, 62, 28); bAllow.Bounds = new Rectangle(578, 322, 64, 28);
            lWebResult = Small(354);

            Controls.Add(Head("Malware fingerprint feed", 382));
            lFeed = Small(406, 470);
            bFeed.Bounds = new Rectangle(510, 378, 132, 28);

            Controls.Add(Head("Self-protection", 436));
            cGuard = Check("Warn if Visually Safe's files or settings are changed, and restart it if it is killed", 460);
            cProtect = Check("Stop other programs from ending Visually Safe (advanced; use the tray menu's Exit)", 484);
            lGuard = Small(510);

            Controls.AddRange(new Control[] { cRansom, cStop, lRansom, events, bTest, cWeb, lWeb, bUpdate, bRemove, tDomain, bCheck, bBlock, bAllow, lWebResult, lFeed, bFeed, cGuard, cProtect, lGuard });

            cRansom.CheckedChanged += (s, e) =>
            {
                if (loading) return;
                eng.S.RansomShield = cRansom.Checked; eng.S.Save();
                if (cRansom.Checked) eng.Shield.Ransom.Start(null); else { eng.Shield.Ransom.Stop(); eng.Shield.Ransom.RemoveCanaries(); }
            };
            cStop.CheckedChanged += (s, e) => { if (!loading) { eng.S.RansomAutoStop = cStop.Checked; eng.S.Save(); } };
            bTest.Click += (s, e) =>
            {
                bTest.Enabled = false; lRansom.Text = "Testing with made-up files in a throw-away folder…";
                Task.Run(() => RansomShield.SelfTest(eng.Shield, eng)).ContinueWith(t =>
                {
                    try { BeginInvoke(new Action(() => { bTest.Enabled = true; MessageBox.Show(FindForm(), t.Status == TaskStatus.RanToCompletion ? t.Result : "The test couldn't run: " + t.Exception.GetBaseException().Message, "Ransomware shield test"); })); } catch { }
                });
            };

            cWeb.CheckedChanged += (s, e) =>
            {
                if (loading) return;
                if (cWeb.Checked)
                {
                    if (!Admin.IsAdmin) { MessageBox.Show(FindForm(), "Blocking websites changes the Windows hosts file, which needs Visually Safe to run as administrator.", "Visually Safe"); loading = true; cWeb.Checked = false; loading = false; return; }
                    eng.S.WebShield = true; eng.S.Save(); eng.Shield.UpdateFeeds(true, false);
                }
                else { eng.S.WebShield = false; eng.S.Save(); string err = eng.Shield.Web.Remove(); if (err != null) MessageBox.Show(FindForm(), err, "Visually Safe"); }
            };
            bUpdate.Click += (s, e) => { if (!Admin.IsAdmin) { MessageBox.Show(FindForm(), "This needs Visually Safe to run as administrator.", "Visually Safe"); return; } eng.S.WebShield = true; eng.S.Save(); eng.Shield.UpdateFeeds(true, false); lWeb.Text = "Downloading the lists…"; };
            bRemove.Click += (s, e) => { string err = eng.Shield.Web.Remove(); eng.S.WebShield = false; eng.S.Save(); if (err != null) MessageBox.Show(FindForm(), err, "Visually Safe"); };
            bCheck.Click += (s, e) =>
            {
                string d = tDomain.Text.Trim().ToLowerInvariant();
                if (!WebShield.ValidDomain(d)) { lWebResult.ForeColor = Theme.Amber; lWebResult.Text = "Type a website name such as example.com"; return; }
                bool b = eng.Shield.Web.IsBlocked(d);
                lWebResult.ForeColor = b ? Theme.Red : Theme.Green;
                lWebResult.Text = d + (b ? " is on the block list." : " is not on the block list.");
            };
            bBlock.Click += (s, e) => Custom(true);
            bAllow.Click += (s, e) => Custom(false);

            bFeed.Click += (s, e) => { if (eng.S.MbKey.Length == 0) { MessageBox.Show(FindForm(), "This list needs your free abuse.ch key. Paste it on the Settings page (\"MalwareBazaar key\").", "Visually Safe"); return; } eng.Shield.UpdateFeeds(false, true); lFeed.Text = "Downloading…"; };

            cGuard.CheckedChanged += (s, e) => { if (loading) return; eng.S.SelfGuard = cGuard.Checked; eng.S.Save(); if (Admin.IsAdmin) Task.Run(() => eng.Shield.Guard.EnsureWatchdog(cGuard.Checked)); watchdogAsked = DateTime.MinValue; };
            cProtect.CheckedChanged += (s, e) => { if (loading) return; eng.S.ProtectProcess = cProtect.Checked; eng.S.Save(); eng.Shield.Guard.ApplyProcessProtection(cProtect.Checked); };

            timer.Tick += (s, e) => RefreshNow();
            timer.Start();
            VisibleChanged += (s, e) =>
            {
                if (Visible && !fitted)
                {
                    // fixed-size labels and the list end up scaled twice on some screens: set them again from their intended size
                    fitted = true;
                    foreach (Control c in Controls)
                        if (c.Tag is Rectangle) { var r = (Rectangle)c.Tag; c.Bounds = new Rectangle((int)Math.Round(r.X * Theme.K), (int)Math.Round(r.Y * Theme.K), (int)Math.Round(r.Width * Theme.K), (int)Math.Round(r.Height * Theme.K)); }
                }
                if (Visible) RefreshNow();
            };
        }

        void Custom(bool block)
        {
            string d = tDomain.Text.Trim().ToLowerInvariant();
            if (!WebShield.ValidDomain(d)) { lWebResult.ForeColor = Theme.Amber; lWebResult.Text = "Type a website name such as example.com"; return; }
            if (block) eng.Shield.Web.AddCustom(d); else eng.Shield.Web.AddAllow(d);
            lWebResult.ForeColor = Theme.Green; lWebResult.Text = d + (block ? " will be blocked" : " is allowed") + (Admin.IsAdmin && eng.S.WebShield ? " (updating…)" : " (switch the web blocklist on to apply it)");
            if (Admin.IsAdmin && eng.S.WebShield) Task.Run(() => eng.Shield.Web.Reapply());
        }

        public void RefreshNow()
        {
            if (!Visible) return;
            loading = true;
            try
            {
                cRansom.Checked = eng.S.RansomShield; cStop.Checked = eng.S.RansomAutoStop; cWeb.Checked = eng.S.WebShield;
                cGuard.Checked = eng.S.SelfGuard; cProtect.Checked = eng.S.ProtectProcess;
                var r = eng.Shield.Ransom;
                lRansom.ForeColor = r.Running ? Theme.Green : Theme.Muted;
                lRansom.Text = r.Running ? "Watching " + r.Folders.Count + " folder" + (r.Folders.Count == 1 ? "" : "s") + " with " + r.CanaryCount + " hidden canary file" + (r.CanaryCount == 1 ? "" : "s") + (r.Triggers > 0 ? " · caught " + r.Triggers + " time" + (r.Triggers == 1 ? "" : "s") : "") : "Off";
                var ev = eng.Shield.Events().Take(30).Select(x => (object)x).ToArray();
                if (ev.Length != events.Items.Count || (ev.Length > 0 && !ReferenceEquals(events.Items[0], ev[0]))) { events.BeginUpdate(); events.Items.Clear(); events.Items.AddRange(ev); events.EndUpdate(); }

                var w = eng.Shield.Web;
                int n = w.Installed();
                lWeb.ForeColor = n > 0 ? Theme.Green : Theme.Muted;
                lWeb.Text = eng.Shield.Updating ? "Working…" : n > 0 ? n.ToString("N0") + " sites blocked · free lists from URLhaus and Phishing Army, refreshed daily" : (w.Status.Length > 0 ? w.Status : "Off. Needs administrator rights to change the Windows hosts file.");
                bUpdate.Enabled = !eng.Shield.Updating; bRemove.Enabled = n > 0 && !eng.Shield.Updating;
                lFeed.Text = eng.S.MbKey.Length == 0 ? "Off. Add your free abuse.ch key on the Settings page to pull the newest malware fingerprints every 12 hours." : (eng.Shield.FeedStatus.Length > 0 ? eng.Shield.FeedStatus : "On. Refreshes every 12 hours.");
                lFeed.ForeColor = eng.S.MbKey.Length == 0 ? Theme.Muted : Theme.Green;

                if (Admin.IsAdmin && (DateTime.Now - watchdogAsked).TotalSeconds > 30) { watchdogAsked = DateTime.Now; Task.Run(() => { bool ex = SelfGuard.WatchdogExists(); watchdog = ex; }); }
                lGuard.Text = !Admin.IsAdmin ? "Run Visually Safe as administrator for the restart-if-killed guard." : eng.S.SelfGuard ? (watchdog ? "Guard is on: a scheduled task starts Visually Safe again within 2 minutes if something kills it (not if you use Exit)." : "Setting up the restart guard…") : "Off";
                lGuard.ForeColor = Admin.IsAdmin && eng.S.SelfGuard && watchdog ? Theme.Green : Theme.Muted;
            }
            finally { loading = false; }
            foreach (Control c in Controls) c.Invalidate();
        }

        protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }
    }
}
