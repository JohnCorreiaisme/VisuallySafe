using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace VisuallySafe
{
    /// <summary>Keeps Visually Safe up to date from its GitHub releases: looks for a newer version now and then, downloads the installer, checks it against the fingerprint published with the release, and offers a big friendly "Update now" window. Nothing is installed until the person agrees.</summary>
    static class UpdateCheck
    {
        const string Api = "https://api.github.com/repos/JohnCorreiaisme/VisuallySafe/releases/latest";
        const string DownloadPrefix = "https://github.com/JohnCorreiaisme/VisuallySafe/releases/download/";
        static Engine eng; static Control ui; static System.Threading.Timer timer;
        static volatile bool busy;
        static UpdatePrompt open;

        public static void Start(Engine e, Control control)
        {
            eng = e; ui = control;
            timer = new System.Threading.Timer(_ => Run(false), null, TimeSpan.FromSeconds(100), TimeSpan.FromHours(6));
        }

        /// <summary>"Check for updates now" in the tray menu.</summary>
        public static void CheckNow() { Task.Run(() => Run(true)); }

        /// <summary>Developer check (--update-test out.txt): what the newest release is and whether its installer could be verified.</summary>
        public static void Test(string file)
        {
            string tag, body, url, name, sha;
            bool ok = Latest(out tag, out body, out url, out name, out sha);
            File.WriteAllText(file, string.Join(((char)10).ToString(), new[] { "ok=" + ok, "current=" + Engine.Version, "latest=" + tag, "file=" + name, "sha=" + sha, "notes:", Notes(body) }));
        }

        static void Say(string text)
        {
            try { ui.BeginInvoke(new Action(() => MessageBox.Show(text, "Visually Safe"))); } catch { }
        }

        static void Run(bool manual)
        {
            if (busy) return;
            if (!manual && (eng == null || !eng.S.AutoUpdate || !eng.S.Cloud)) return;
            busy = true;
            try
            {
                string tag, body, url, name, sha;
                if (!Latest(out tag, out body, out url, out name, out sha))
                {
                    if (manual) Say("Visually Safe could not check for updates just now. Please try again in a little while.");
                    return;
                }
                Version v, cur;
                if (!Version.TryParse(tag.TrimStart('v', 'V'), out v) || !Version.TryParse(Engine.Version, out cur)) return;
                if (v <= cur) { if (manual) Say("Visually Safe is up to date (version " + Engine.Version + ")."); return; }

                string dir = Path.Combine(Path.GetTempPath(), "VisuallySafe-update");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, name);
                if (!File.Exists(path) || !Hash(path).Equals(sha, StringComparison.OrdinalIgnoreCase))
                {
                    byte[] data;
                    using (var http = Http()) { http.Timeout = TimeSpan.FromMinutes(3); data = http.GetByteArrayAsync(url).GetAwaiter().GetResult(); }
                    string tmp = path + ".part";
                    File.WriteAllBytes(tmp, data);
                    if (!Hash(tmp).Equals(sha, StringComparison.OrdinalIgnoreCase)) { try { File.Delete(tmp); } catch { } if (manual) Say("The update did not download correctly, so nothing was changed."); return; }
                    if (File.Exists(path)) File.Delete(path);
                    File.Move(tmp, path);
                }
                string notes = Notes(body);
                ui.BeginInvoke(new Action(() =>
                {
                    if (open != null && !open.IsDisposed) return;
                    open = new UpdatePrompt(v.ToString(), notes, path, sha);
                    open.Show();
                }));
            }
            catch { if (manual) Say("Visually Safe could not check for updates just now. Please try again in a little while."); }
            finally { busy = false; }
        }

        static HttpClient Http()
        {
            var h = new HttpClient();
            h.DefaultRequestHeaders.UserAgent.ParseAdd("VisuallySafe/" + Engine.Version);
            h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            return h;
        }

        static bool Latest(out string tag, out string body, out string url, out string name, out string sha)
        {
            tag = body = url = name = sha = "";
            string json;
            using (var http = Http()) { http.Timeout = TimeSpan.FromSeconds(20); json = http.GetStringAsync(Api).GetAwaiter().GetResult(); }
            var d = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(json) as Dictionary<string, object>;
            if (d == null || !d.ContainsKey("tag_name")) return false;
            tag = Convert.ToString(d["tag_name"]); body = d.ContainsKey("body") ? Convert.ToString(d["body"]) : "";
            if (!d.ContainsKey("assets")) return false;
            foreach (var o in ((System.Collections.IEnumerable)d["assets"]).Cast<object>())
            {
                var a = o as Dictionary<string, object>; if (a == null) continue;
                string n = Convert.ToString(a["name"]), u = Convert.ToString(a["browser_download_url"]);
                if (!Regex.IsMatch(n, @"^VisuallySafeSetup-[0-9.]+\.exe$") || !u.StartsWith(DownloadPrefix, StringComparison.Ordinal)) continue;
                name = n; url = u;
                string dg = a.ContainsKey("digest") ? Convert.ToString(a["digest"]) : "";
                if (dg.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) sha = dg.Substring(7);
                else { var m = Regex.Match(body, "SHA-256 of " + Regex.Escape(n) + @":\s*([0-9a-fA-F]{64})"); if (m.Success) sha = m.Groups[1].Value; }
                return sha.Length == 64;       // without a fingerprint to check against, nothing is downloaded
            }
            return false;
        }

        static string Hash(string file)
        {
            using (var s = File.OpenRead(file)) return HashOf(s);
        }

        internal static string HashOf(Stream s)
        {
            using (var h = SHA256.Create()) return string.Concat(h.ComputeHash(s).Select(b => b.ToString("x2")));
        }

        // The checked installer stays open (others may read and run it, nobody may change, replace or delete it) until Visually Safe closes.
        // The installer asks Windows for permission and starts itself again from this same file, so it must not be swappable in between.
        static FileStream held;

        /// <summary>Checks the installer once more and starts it. False if it no longer matches its published fingerprint.</summary>
        internal static bool StartInstaller(string path, string sha)
        {
            var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!HashOf(fs).Equals(sha, StringComparison.OrdinalIgnoreCase)) { fs.Dispose(); try { File.Delete(path); } catch { } return false; }
            if (held != null) try { held.Dispose(); } catch { }
            held = fs;
            Process.Start(new ProcessStartInfo(path, "--update") { UseShellExecute = true });
            return true;
        }

        /// <summary>A few plain lines from the release notes: the bullet points, without markdown.</summary>
        internal static string Notes(string body)
        {
            var lines = new List<string>();
            foreach (string raw in (body ?? "").Replace("\r", "").Split((char)10))
            {
                string l = raw.Trim();
                if (!l.StartsWith("- ") || l.StartsWith("- SHA")) continue;
                l = Regex.Replace(l.Substring(2), @"[*`_]+", "").Trim();
                if (l.Length > 170) l = l.Substring(0, 167) + "…";
                lines.Add("•  " + l);
                if (lines.Count == 4) break;
            }
            return string.Join(((char)10).ToString(), lines);
        }
    }

    /// <summary>The window offering the update: big text, one clear button.</summary>
    class UpdatePrompt : Form
    {
        readonly string version, notes, path, sha;
        readonly Btn go = new Btn("Update now", true), later = new Btn("Not now");

        static int S(int v) { return (int)Math.Round(v * Theme.K); }

        public UpdatePrompt(string version, string notes, string path, string sha)
        {
            this.version = version; this.notes = notes; this.path = path; this.sha = sha;
            Text = "Visually Safe update"; Icon = Theme.AppIcon();
            ClientSize = new Size(S(680), S(420));
            StartPosition = FormStartPosition.CenterScreen; FormBorderStyle = FormBorderStyle.FixedSingle; MaximizeBox = false; MinimizeBox = false;
            TopMost = true; BackColor = Theme.Bg; DoubleBuffered = true;
            go.Bounds = new Rectangle(S(300), S(346), S(200), S(50)); later.Bounds = new Rectangle(S(512), S(346), S(140), S(50));
            go.Click += (s, e) =>
            {
                try
                {
                    if (!UpdateCheck.StartInstaller(path, sha))
                        MessageBox.Show(this, "The downloaded update was changed after it was checked, so it was not started. Visually Safe will download it again later.", "Visually Safe");
                }
                catch { }
                Close();
            };
            later.Click += (s, e) => Close();
            Controls.Add(go); Controls.Add(later);
        }

        /// <summary>Developer check: draws the window to a picture (--update-shot out.png).</summary>
        public static void Snap(string file)
        {
            using (var f = new UpdatePrompt("1.0.90", UpdateCheck.Notes("- Bigger text in the wizard." + (char)10 + "- Updates itself from GitHub."), "x", ""))
            {
                f.Opacity = 0; f.ShowInTaskbar = false; f.Show(); Application.DoEvents();
                using (var bmp = new Bitmap(f.ClientSize.Width, f.ClientSize.Height))
                { f.DrawToBitmap(bmp, new Rectangle(0, 0, bmp.Width, bmp.Height)); bmp.Save(file, System.Drawing.Imaging.ImageFormat.Png); }
            }
        }

        protected override bool ShowWithoutActivation { get { return true; } }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias; g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            Theme.DrawShield(g, new RectangleF(S(30), S(26), S(54), S(62)), GuardState.Protected);
            using (var f = new Font("Segoe UI Semibold", 30f * Theme.K, FontStyle.Regular, GraphicsUnit.Pixel))
                g.DrawString("A new version is ready", f, Brushes.White, S(100), S(26));
            using (var f = new Font("Segoe UI", 20f * Theme.K, FontStyle.Regular, GraphicsUnit.Pixel))
            {
                g.DrawString("Visually Safe " + version + " is ready to install. Your settings and history are kept.", f, new SolidBrush(Theme.Text), new RectangleF(S(30), S(108), S(620), S(60)));
                using (var f2 = new Font("Segoe UI", 17f * Theme.K, FontStyle.Regular, GraphicsUnit.Pixel))
                    g.DrawString(notes, f2, new SolidBrush(Theme.Muted), new RectangleF(S(30), S(176), S(620), S(150)));
            }
        }
    }
}
