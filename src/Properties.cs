using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace VisuallySafe
{
    class PropLink { public string Text = "", Url = ""; }

    /// <summary>Everything the Properties window shows about one item.</summary>
    class PropInfo
    {
        public string Title = "", Verdict = "", Path = "", Sha = "";
        public Color VerdictColor = Theme.Muted;
        public List<KeyValuePair<string, string>> Rows = new List<KeyValuePair<string, string>>();
        public List<PropLink> Links = new List<PropLink>();
        public ScanRecord Rec; public Finding F; public QuarantineItem Q;
        public bool IsApp;
        public string AiItem, AiPath;   // what to tell the AI; AiItem == null means "no AI section"

        public void Add(string k, string v) { if (!string.IsNullOrEmpty(v)) Rows.Add(new KeyValuePair<string, string>(k, v)); }
        public void Link(string text, string url) { if (!Links.Any(l => l.Url == url)) Links.Add(new PropLink { Text = text, Url = url }); }
    }

    static class Props
    {
        static string Enc(string s) { return Uri.EscapeDataString(s ?? ""); }

        static string Size(long b)
        {
            if (b < 1024) return b + " bytes";
            if (b < 1048576) return (b / 1024.0).ToString("0.#") + " KB";
            if (b < 1073741824) return (b / 1048576.0).ToString("0.0") + " MB";
            return (b / 1073741824.0).ToString("0.00") + " GB";
        }

        static void FileRows(PropInfo p, string path)
        {
            try
            {
                var fi = new FileInfo(path);
                p.Add("Size", Size(fi.Length));
                p.Add("Last changed", fi.LastWriteTime.ToString("f"));
                string signer = null;
                try { signer = Trust.TrustedSigner(path); } catch { }
                p.Add("Signature", signer != null ? "Signed by " + signer : "Not signed");
                var v = FileVersionInfo.GetVersionInfo(path);
                p.Add("Made by", v.CompanyName);
                p.Add("Description", v.FileDescription);
            }
            catch { }
        }

        static string HashOf(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || fi.Length > 64L * 1024 * 1024) return "";
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var h = SHA256.Create())
                {
                    var sb = new StringBuilder();
                    foreach (byte b in h.ComputeHash(fs)) sb.Append(b.ToString("x2"));
                    return sb.ToString();
                }
            }
            catch { return ""; }
        }

        static void HashLinks(PropInfo p)
        {
            if (p.Sha.Length != 64) return;
            p.Link("VirusTotal — what about 70 antivirus engines say about this file", "https://www.virustotal.com/gui/file/" + p.Sha);
            p.Link("MalwareBazaar — is this file in abuse.ch's malware collection?", "https://bazaar.abuse.ch/sample/" + p.Sha + "/");
            p.Link("Hybrid Analysis — behaviour reports for files with this fingerprint", "https://www.hybrid-analysis.com/search?query=" + p.Sha);
        }

        static void Search(PropInfo p, string text, string query) { p.Link("Web search — " + text, "https://duckduckgo.com/?q=" + Enc(query)); }

        /// <summary>Links that explain the reason Visually Safe flagged something.</summary>
        static void ReasonLinks(PropInfo p, string text, string lolLink)
        {
            string t = text ?? "";
            Func<string, bool> has = pat => Regex.IsMatch(t, pat, RegexOptions.IgnoreCase);
            var m = Regex.Match(t, @"YARA rule (\w+)", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                Search(p, "what the YARA rule " + m.Groups[1].Value + " detects", "YARA rule " + m.Groups[1].Value + " malware");
                p.Link("YARA-Forge — the rule collection this rule comes from", "https://github.com/YARAHQ/yara-forge");
            }
            if (has("pretends to be|double extension")) p.Link("MITRE ATT&CK — why a fake file extension is a malware trick", "https://attack.mitre.org/techniques/T1036/007/");
            if (has("packed or scrambled")) p.Link("MITRE ATT&CK — packed (scrambled) programs and why malware uses them", "https://attack.mitre.org/techniques/T1027/002/");
            if (has("starts automatically|every time Windows starts|startup folder|startup list|startup entry|Startup entry")) p.Link("MITRE ATT&CK — how malware makes itself start with Windows", "https://attack.mitre.org/techniques/T1547/001/");
            if (has("vulnerable driver|malicious driver"))
            {
                p.Link("LOLDrivers — this driver's entry and why it's dangerous", string.IsNullOrEmpty(lolLink) ? "https://www.loldrivers.io/" : lolLink);
                Search(p, "vulnerable driver explained", "vulnerable driver BYOVD attack explained");
            }
            if (has("Hidden program|hidden from|shown by only one")) p.Link("MITRE ATT&CK — rootkits and how they hide programs", "https://attack.mitre.org/techniques/T1014/");
            if (has("login shell|login program|Winlogon")) p.Link("MITRE ATT&CK — Winlogon changes used to run at every login", "https://attack.mitre.org/techniques/T1547/004/");
            if (has("AppInit")) p.Link("MITRE ATT&CK — AppInit DLLs", "https://attack.mitre.org/techniques/T1546/010/");
            if (has("launch is redirected|Image File Execution")) p.Link("MITRE ATT&CK — Image File Execution Options hijacking", "https://attack.mitre.org/techniques/T1546/012/");
            if (has("hosts file")) Search(p, "hosts file hijacking by malware", "hosts file hijacking malware blocks antivirus updates");
            if (has("unsigned driver|no file on disk")) Search(p, "unsigned or hidden drivers", "unsigned kernel driver rootkit sign");
            if (has("Team Cymru")) p.Link("Team Cymru — the Malware Hash Registry that listed this file", "https://team-cymru.com/community-services/mhr/");
            if (has("EICAR")) p.Link("EICAR — the harmless antivirus test file", "https://www.eicar.org/download-anti-malware-testfile/");
        }

        // ------------------------------------------------------------------ builders

        public static PropInfo ForRecord(Engine eng, ScanRecord r)
        {
            var p = new PropInfo
            {
                Rec = r, Title = r.Name, Path = r.FilePath, Sha = r.Sha256,
                Verdict = Theme.Label(r.Verdict) + (r.Quarantined ? " · quarantined" : ""), VerdictColor = Theme.Of(r.Verdict),
                AiItem = "[" + Theme.Label(r.Verdict) + (r.Quarantined ? ", quarantined" : "") + "] " + r.FilePath + " | sha256 " + r.Sha256 + " | " + r.Detail, AiPath = r.FilePath
            };
            p.Add("Why it was flagged", r.Detail);
            p.Add("Location", System.IO.Path.GetDirectoryName(r.FilePath));
            p.Add("Full path", r.FilePath);
            if (File.Exists(r.FilePath)) FileRows(p, r.FilePath);
            else p.Add("File", r.Quarantined ? "Not here any more: it is locked away in quarantine" : "No longer exists at this location");
            if (r.Quarantined)
            {
                var q = eng.QuarantineSnapshot().FirstOrDefault(x => x.Sha256 == r.Sha256);
                if (q != null) p.Add("Stored as", System.IO.Path.Combine(eng.QuarDir, q.Id + ".quar") + " (scrambled so it can't run)");
            }
            p.Add("SHA-256", r.Sha256);
            p.Add("Checked", r.Time.ToString("f"));
            HashLinks(p);
            ReasonLinks(p, r.Detail, null);
            Search(p, "is " + r.Name + " safe?", r.Name + " is it safe or malware");
            return p;
        }

        public static PropInfo ForQuarantine(Engine eng, QuarantineItem q)
        {
            var p = new PropInfo
            {
                Q = q, Title = q.Name, Path = q.OriginalPath, Sha = q.Sha256, Verdict = "In quarantine (can't run)", VerdictColor = Theme.Red,
                AiItem = "[in quarantine] " + q.OriginalPath + " | locked away " + q.Time.ToString("yyyy-MM-dd") + " | " + q.Reason, AiPath = q.OriginalPath
            };
            p.Add("Why it was locked away", q.Reason);
            p.Add("Was located in", System.IO.Path.GetDirectoryName(q.OriginalPath));
            p.Add("Original path", q.OriginalPath);
            p.Add("Stored as", System.IO.Path.Combine(eng.QuarDir, q.Id + ".quar") + " (scrambled so it can't run)");
            p.Add("Locked away", q.Time.ToString("f"));
            p.Add("SHA-256", q.Sha256);
            HashLinks(p);
            ReasonLinks(p, q.Reason, null);
            Search(p, "is " + q.Name + " safe?", q.Name + " is it safe or malware");
            return p;
        }

        public static PropInfo ForFinding(Finding f)
        {
            var p = new PropInfo
            {
                F = f, Title = f.Title, Path = f.Path, Verdict = f.Sev == Sev.Bad ? "Serious" : f.Sev == Sev.Warn ? "Warning" : "Note", VerdictColor = RootkitView.Color(f.Sev),
                AiItem = "[" + f.Sev + "] " + f.Title + " | " + f.Detail + (f.Path.Length > 0 ? " | " + f.Path : "") + (f.RegRoot != 0 ? " | [startup entry]" : ""), AiPath = f.Path
            };
            p.Add("What it means", f.Detail);
            if (f.Path.Length > 0)
            {
                p.Add("Location", System.IO.Path.GetDirectoryName(f.Path));
                p.Add("Full path", f.Path);
                if (File.Exists(f.Path)) { FileRows(p, f.Path); p.Sha = HashOf(f.Path); p.Add("SHA-256", p.Sha); }
                else p.Add("File", "Not found at this location");
            }
            if (f.RegRoot != 0) p.Add("Startup entry", (f.RegRoot == 1 ? "HKEY_CURRENT_USER\\" : "HKEY_LOCAL_MACHINE\\") + f.RegSub + "   (value: " + f.RegValue + ")");
            p.Add("What you can do", f.Advice);
            HashLinks(p);
            ReasonLinks(p, f.Title + " " + f.Detail, f.Link);
            if (f.Path.Length > 0) Search(p, "is " + System.IO.Path.GetFileName(f.Path) + " safe?", System.IO.Path.GetFileName(f.Path) + " is it safe or malware");
            return p;
        }

        public static PropInfo ForApp(AppTraffic a)
        {
            var p = new PropInfo
            {
                IsApp = true, Title = a.Name, Path = a.CanBlock ? a.Path : "", Verdict = a.Blocked ? "Blocked from the internet" : "Allowed on the internet", VerdictColor = a.Blocked ? Theme.Red : Theme.Green,
                AiItem = "[network program] " + a.Path + " | downloaded " + a.TotalIn / 1024 + " KB, uploaded " + a.TotalOut / 1024 + " KB" + (a.Blocked ? " | BLOCKED" : ""), AiPath = a.CanBlock ? a.Path : null
            };
            if (a.CanBlock)
            {
                p.Add("Location", System.IO.Path.GetDirectoryName(a.Path));
                p.Add("Full path", a.Path);
                if (File.Exists(a.Path)) { FileRows(p, a.Path); p.Sha = HashOf(a.Path); p.Add("SHA-256", p.Sha); }
            }
            else p.Add("Program", a.Path);
            p.Add("Downloaded", Size(a.TotalIn) + "  (" + NetworkView.Rate(a.RateIn) + " right now)");
            p.Add("Uploaded", Size(a.TotalOut) + "  (" + NetworkView.Rate(a.RateOut) + " right now)");
            HashLinks(p);
            Search(p, "is " + a.Name + " safe?", a.Name + " network traffic is it safe");
            return p;
        }

        public static bool Show(Form owner, Engine eng, PropInfo info)
        {
            using (var f = new PropertiesForm(eng, info)) { f.ShowDialog(owner); return f.Fixed; }
        }
    }

    // ---------------------------------------------------------------------------------------------------------

    /// <summary>
    /// Properties window: where the item is, links explaining why it may be bad, Visually Safe's own fix options
    /// (Fix… asks which one to use), and a button to hand the problem to Claude Code or Codex.
    /// </summary>
    class PropertiesForm : Form
    {
        readonly Engine eng;
        readonly PropInfo info;
        readonly Panel content = new Panel { AutoScroll = true, BackColor = Theme.Bg, Dock = DockStyle.Fill };
        readonly Panel bottom = new Panel { Dock = DockStyle.Bottom, BackColor = Theme.Side };
        readonly Btn bOpen = new Btn("Open folder"), bCopy = new Btn("Copy path"), bFix = new Btn("Fix…", true), bAgent = new Btn("Fix with agent  ▾"), bClose = new Btn("Close");
        Label fixHeader, fixStatus, fixList;
        int fixTop;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 300 };

        AssistantContext ctx;
        List<ProposedAction> options = new List<ProposedAction>();
        volatile bool ready;
        CancellationTokenSource cts;
        public bool Fixed;

        static int S(int v) { return (int)Math.Round(v * Theme.K); }

        public PropertiesForm(Engine e, PropInfo p)
        {
            eng = e; info = p;
            AutoScaleMode = AutoScaleMode.None;
            Text = "Properties: " + p.Title;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Bg; ForeColor = Theme.Text; Font = new Font("Segoe UI", 9.5f); KeyPreview = true;
            Icon = Theme.MakeIcon(GuardState.Protected);

            int w = S(600), x = S(20), y = S(16);
            bottom.Height = S(60);
            Controls.Add(content);
            Controls.Add(bottom);

            var title = new Label { Text = p.Title, Font = new Font("Segoe UI Semibold", 15f), AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y), ForeColor = Theme.Text };
            content.Controls.Add(title); y += title.PreferredHeight + S(2);
            var verdict = new Label { Text = "●  " + p.Verdict, Font = new Font("Segoe UI Semibold", 10f), AutoSize = true, Location = new Point(x, y), ForeColor = p.VerdictColor };
            content.Controls.Add(verdict); y += verdict.PreferredHeight + S(16);

            int labelW = S(130);
            foreach (var kv in p.Rows)
            {
                var lk = new Label { Text = kv.Key, ForeColor = Theme.Muted, AutoSize = true, Location = new Point(x, y) };
                var lv = new Label { Text = kv.Value, ForeColor = Theme.Text, AutoSize = true, MaximumSize = new Size(w - labelW, 0), Location = new Point(x + labelW, y) };
                content.Controls.Add(lk); content.Controls.Add(lv);
                y += Math.Max(lk.PreferredHeight, lv.PreferredSize.Height) + S(8);
            }

            if (p.Links.Count > 0)
            {
                y += S(8);
                var h = new Label { Text = "Learn more online (opens your web browser)", Font = new Font("Segoe UI Semibold", 10f), AutoSize = true, Location = new Point(x, y), ForeColor = Theme.Text };
                content.Controls.Add(h); y += h.PreferredHeight + S(6);
                foreach (var l in p.Links)
                {
                    var ll = new LinkLabel { Text = l.Text, AutoSize = true, MaximumSize = new Size(w, 0), Location = new Point(x, y), LinkColor = Theme.Blue, ActiveLinkColor = Theme.Text, VisitedLinkColor = Theme.Blue, LinkBehavior = LinkBehavior.HoverUnderline, BackColor = Theme.Bg };
                    string url = l.Url;
                    ll.LinkClicked += (s, ev) => { if (url.StartsWith("https://")) try { Process.Start(url); } catch { } };
                    content.Controls.Add(ll); y += ll.PreferredHeight + S(6);
                }
            }

            y += S(14);
            fixTop = y;
            fixHeader = new Label { Text = "How to fix it", Font = new Font("Segoe UI Semibold", 10f), AutoSize = true, ForeColor = Theme.Text, Location = new Point(x, y) };
            fixStatus = new Label { AutoSize = true, MaximumSize = new Size(w, 0), ForeColor = Theme.Muted, Text = "Checking what can be done…" };
            fixList = new Label { AutoSize = true, MaximumSize = new Size(w, 0), ForeColor = Theme.Text };
            content.Controls.AddRange(new Control[] { fixHeader, fixStatus, fixList });
            LayoutFix();
            y += S(170);

            ClientSize = new Size(S(640), Math.Max(S(460), Math.Min(S(760), y + S(24) + S(60))));

            bOpen.Bounds = new Rectangle(S(14), S(12), S(100), S(36));
            bCopy.Bounds = new Rectangle(S(122), S(12), S(92), S(36));
            bFix.Bounds = new Rectangle(S(222), S(12), S(100), S(36));
            bAgent.Bounds = new Rectangle(S(330), S(12), S(170), S(36));
            bClose.Bounds = new Rectangle(S(508), S(12), S(110), S(36));
            bottom.Controls.AddRange(new Control[] { bOpen, bCopy, bFix, bAgent, bClose });
            bFix.Enabled = false;

            string target = p.Path;
            bool there = !string.IsNullOrEmpty(target) && (File.Exists(target) || Directory.Exists(System.IO.Path.GetDirectoryName(target) ?? ""));
            bOpen.Enabled = there; bCopy.Enabled = !string.IsNullOrEmpty(target);
            bOpen.Click += (s, ev) =>
            {
                try
                {
                    if (File.Exists(target)) Process.Start("explorer.exe", "/select,\"" + target + "\"");
                    else Process.Start("explorer.exe", "\"" + System.IO.Path.GetDirectoryName(target) + "\"");
                }
                catch { }
            };
            bCopy.Click += (s, ev) => { try { Clipboard.SetText(target); } catch { } };
            bClose.Click += (s, ev) => Close();
            bFix.Click += (s, ev) => DoFix();
            bAgent.Click += (s, ev) => AgentMenu.Show(this, bAgent, eng, info.Title, () => AgentPrompt.ForItem(eng, info));
            timer.Tick += (s, ev) => Tick();
            timer.Start();
            Shown += (s, ev) => StartOptions();
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Native.DarkTitle(Handle); }
        protected override void OnKeyDown(KeyEventArgs e) { if (e.KeyCode == Keys.Escape) Close(); base.OnKeyDown(e); }
        protected override void OnFormClosing(FormClosingEventArgs e) { timer.Stop(); if (cts != null) cts.Cancel(); base.OnFormClosing(e); }

        void LayoutFix()
        {
            int x = S(20), y = fixTop + S(24);
            fixHeader.Location = new Point(x, fixTop);
            fixStatus.Location = new Point(x, y); y += fixStatus.PreferredHeight + S(6);
            fixList.Location = new Point(x, y);
        }

        // ------------------------------------------------------------------ Visually Safe's own fix options (no AI needed)

        void StartOptions()
        {
            ctx = AssistantContext.Capture(eng);
            ctx.FocusRecord = info.Rec; ctx.FocusFinding = info.F; ctx.FocusPath = string.IsNullOrEmpty(info.AiPath) ? null : info.AiPath;
            cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var token = cts.Token;
            System.Threading.Tasks.Task.Run(() =>
            {
                try { options = BuildOptions(token); } catch { options = new List<ProposedAction>(); }
                ready = true;
            });
        }

        List<ProposedAction> BuildOptions(CancellationToken ct)
        {
            var list = new List<ProposedAction>();
            string path = ctx.FocusPath;
            Action<string, string, bool> add = (type, reason, recommended) =>
            {
                var a = Assistant.Make(type, path ?? "", reason, ctx);
                if (a.State == ActState.Pending) { a.Recommended = recommended; list.Add(a); }
            };

            if (info.Q != null)
            {
                add("restore", "Put it back where it was, and trust it.", false);
                add("delete_quarantined", "Remove it from this PC for good.", false);
                return list;
            }

            bool bad = (info.Rec != null && info.Rec.Verdict >= Verdict.Suspicious) || (info.F != null && info.F.Sev >= Sev.Warn);
            bool startup = info.F != null && info.F.RegRoot != 0;
            if (startup) add("remove_startup_entry", "Stops it starting with Windows. A backup of the entry is kept.", bad);
            add("quarantine", "Locks the file away so it can't run. You can undo this.", bad && !startup);

            // a newer version, if winget knows one
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                string err;
                var ups = Updater.Upgrades(ct, out err);
                var pkg = ups == null ? null : Updater.Find(path, ups);
                if (pkg != null)
                {
                    var u = Assistant.Make("update", path, "A newer version may fix the problem.", ctx);
                    if (u.State == ActState.Pending) { u.Pkg = pkg; u.Risk = "Installs the newer version with winget"; list.Add(u); }
                }
            }

            if (info.IsApp) add(info.Verdict.StartsWith("Blocked") ? "unblock_internet" : "block_internet", info.Verdict.StartsWith("Blocked") ? "Let it use the internet again." : "Stops it using the internet. You can undo this.", false);

            if (info.Rec != null || info.F != null)
                list.Add(new ProposedAction
                {
                    Type = "ignore", Reason = "You decide this one is fine.", Rec = info.Rec, F = info.Rec == null ? info.F : null, Recommended = !bad,
                    Risk = info.Rec != null ? "Visually Safe will trust this file" : "Hidden from future rootkit checks"
                });
            add("delete", "Removes the file for good.", false);
            return list;
        }

        void Tick()
        {
            if (!ready) return;
            ready = false;
            var todo = options.Where(a => a.State == ActState.Pending).ToList();
            if (todo.Count > 0)
            {
                fixStatus.ForeColor = Theme.Green;
                fixStatus.Text = "Click Fix… and pick one of these:";
                fixList.Text = string.Join("\n", todo.Select(a => "  •  " + a.Title + (a.Recommended ? "   (suggested)" : "") + "   [" + a.Risk + "]"));
            }
            else
            {
                fixStatus.ForeColor = Theme.Amber;
                fixStatus.Text = "Visually Safe has no automatic fix for this one.";
                fixList.Text = "Use \"Fix with agent\" to hand it to Claude Code or Codex, which can investigate and fix it on this PC.";
            }
            bFix.Enabled = todo.Count > 0;
            LayoutFix();
        }

        void DoFix()
        {
            var todo = options.Where(a => a.State == ActState.Pending).ToList();
            if (todo.Count == 0) return;
            if (!AiFix.ChooseAndApply(this, eng, info.Title, "", todo)) return;
            Fixed = true;
            var done = todo.FirstOrDefault(a => a.State != ActState.Pending);
            fixStatus.ForeColor = Theme.Green; fixStatus.Text = "Done:";
            fixList.Text = done == null ? "" : (done.State == ActState.Done ? "  ✔  " : "  ✘  ") + done.Title;
            bFix.Enabled = false;
            LayoutFix();
        }
    }
}
