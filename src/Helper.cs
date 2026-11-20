using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace TinyGuard
{
    /// <summary>Settings for the family helper ("old person's") mode. Kept in helper.ini; the mail password is protected with Windows DPAPI.</summary>
    class HelperConfig
    {
        public bool On, Wizard, AutoCheck = true, IntroDone;
        public long SleepUntil;      // the wizard is asleep (silent and hidden) until this moment
        public string Name = "your kid", Email = "", Smtp = "", User = "", Pass = "", Server = "";
        public int Port = 587;

        static string FileOf(string dir) { return Path.Combine(dir, "helper.ini"); }

        public static HelperConfig Load(string dir)
        {
            var c = new HelperConfig(); bool sawWizard = false;
            try
            {
                foreach (string l in File.ReadAllLines(FileOf(dir)))
                {
                    int i = l.IndexOf('='); if (i <= 0) continue;
                    string k = l.Substring(0, i), v = l.Substring(i + 1);
                    switch (k)
                    {
                        case "on": c.On = v == "1"; break;
                        case "wizard": c.Wizard = v != "0"; sawWizard = true; break;
                        case "sleepUntil": long.TryParse(v, out c.SleepUntil); break;
                        case "autoCheck": c.AutoCheck = v != "0"; break;
                        case "intro": c.IntroDone = v == "1"; break;
                        case "name": if (v.Trim().Length > 0) c.Name = v.Trim(); break;
                        case "email": c.Email = v.Trim(); break;
                        case "smtp": c.Smtp = v.Trim(); break;
                        case "port": int p; if (int.TryParse(v, out p) && p > 0 && p < 65536) c.Port = p; break;
                        case "user": c.User = v.Trim(); break;
                        case "pass": try { c.Pass = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(v), null, DataProtectionScope.CurrentUser)); } catch { } break;
                        case "server": c.Server = v.Trim(); break;
                    }
                }
            }
            catch { }
            if (!sawWizard) c.Wizard = c.On;       // set up before the wizard existed: he shows up with helper mode
            return c;
        }

        public void Save(string dir)
        {
            string pw = "";
            try { if (Pass.Length > 0) pw = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(Pass), null, DataProtectionScope.CurrentUser)); } catch { }
            File.WriteAllLines(FileOf(dir), new[] { "on=" + (On ? "1" : "0"), "wizard=" + (Wizard ? "1" : "0"), "sleepUntil=" + SleepUntil, "autoCheck=" + (AutoCheck ? "1" : "0"), "intro=" + (IntroDone ? "1" : "0"), "name=" + Name, "email=" + Email, "smtp=" + Smtp, "port=" + Port, "user=" + User, "pass=" + pw, "server=" + Server });
        }

        public bool MailReady { get { return Email.Length > 3 && Smtp.Length > 0; } }
    }

    /// <summary>
    /// Family helper mode: a friendly, always-visible on-screen helper that speaks with the Windows voice.
    /// It checks the network cable/Wi-Fi, warns about piles of unnamed text files and a full C drive, and lets the
    /// person press a big "I need help" button to get a remote-help code that is also emailed to the family member.
    /// It only talks and reports to the person sitting there; it never deletes anything and never connects by itself.
    /// </summary>
    static class Helper
    {
        public static HelperConfig Cfg;
        static Engine eng;
        static Control sync;
        static System.Windows.Forms.Timer timer;
        static readonly Dictionary<string, DateTime> said = new Dictionary<string, DateTime>();
        static int offlineStreak;
        public static bool DryRun;   // pictures only: no voice, no emails

        public static void Start(Engine e)
        {
            eng = e; Cfg = HelperConfig.Load(eng.DataDir);
            sync = new Control(); var h = sync.Handle;
            timer = new System.Windows.Forms.Timer { Interval = 30000 };
            timer.Tick += (s, ev) => Tick();
            timer.Start();
            Wizard.Start(eng, sync); AutoCheck.Start(eng);
            if (Cfg.On) { Task.Delay(8000).ContinueWith(t => sync.BeginInvoke(new Action(() => Greet(false)))); }
        }

        /// <summary>Apply new settings. Turning the mode on also turns on the screen saver (idle and Windows-registered).</summary>
        public static void Apply(HelperConfig c)
        {
            Cfg = c; c.Save(eng.DataDir);
            Wizard.Sync();
            if (c.On)
            {
                eng.S.ScreensaverIdle = true; eng.S.SystemSaver = true; eng.S.Save();
                try { SystemSaver.Enable(eng.S, eng.S.ScreensaverMinutes); } catch { }
            }
        }

        static bool Due(string key, double minutes)
        {
            DateTime t;
            if (said.TryGetValue(key, out t) && (DateTime.Now - t).TotalMinutes < minutes) return false;
            said[key] = DateTime.Now; return true;
        }

        static string Who { get { return Cfg.Name; } }
        static string WhoCap { get { string n = Cfg.Name; return n.Length == 0 ? n : char.ToUpper(n[0]) + n.Substring(1); } }

        public static void Greet(bool force)
        {
            if (!force && !Due("greet", 240)) return;
            Say("Hello! I am your wizard. " + WhoCap + " asked me to watch over your computer. If anything looks wrong, please contact " + Who + ".", true);
            if (!Cfg.IntroDone && Wizard.Enabled)
            {
                Say(Wizard.BoxesText(), false);
                Cfg.IntroDone = true; try { Cfg.Save(eng.DataDir); } catch { }
            }
        }

        static void Tick()
        {
            if (!Cfg.On || ScreenSaver.Active) return;
            try { AutoCheck.Tick(); } catch { }
            Task.Run(() =>
            {
                try
                {
                    bool online = Online();
                    int unnamed = CountUnnamedText(); double free = FreeFraction();
                    sync.BeginInvoke(new Action(() => React(online, unnamed, free)));
                }
                catch { }
            });
        }

        static void React(bool online, int unnamed, double free)
        {
            if (!Cfg.On) return;
            offlineStreak = online ? 0 : offlineStreak + 1;
            if (offlineStreak >= 2 && Due("offline", 10))
            {
                Say("Your computer is not connected to the internet. Please plug in the network cable, or turn on your wireless connection. If you can't, please contact " + Who + ".", true);
                return;
            }
            if (unnamed >= 10 && Due("txt", 24 * 60))
                Say(WhoCap + " wants me to be sure you're not filling up the C drive with unnamed text files. You have " + unnamed + " of them. Please ask " + Who + " to help you tidy up.", true);
            else if (free >= 0 && free < 0.10 && Due("full", 12 * 60))
                Say("Your C drive is almost full. Please contact " + Who + " so they can help you free up some room.", true);
        }

        public static bool Online()
        {
            try
            {
                if (!NetworkInterface.GetIsNetworkAvailable()) return false;
                using (var p = new Ping())
                    foreach (string ip in new[] { "1.1.1.1", "8.8.8.8" })
                        if (p.Send(ip, 1500).Status == IPStatus.Success) return true;
            }
            catch { }
            return false;
        }

        public static int CountUnnamedText()
        {
            int n = 0;
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var dirs = new[] { Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), Path.Combine(home, "Downloads"), home };
            foreach (string d in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
                try
                {
                    foreach (string f in Directory.EnumerateFiles(d, "*.txt", SearchOption.TopDirectoryOnly).Take(5000))
                    {
                        string name = Path.GetFileNameWithoutExtension(f);
                        if (name.StartsWith("New Text Document", StringComparison.OrdinalIgnoreCase) || name.StartsWith("Untitled", StringComparison.OrdinalIgnoreCase) || name.StartsWith("New Document", StringComparison.OrdinalIgnoreCase)) n++;
                    }
                }
                catch { }
            return n;
        }

        public static double FreeFraction()
        {
            try { var d = new DriveInfo("C"); return (double)d.AvailableFreeSpace / d.TotalSize; } catch { return -1; }
        }

        // ---------------------------------------------------------------- showing the helper

        /// <summary>Everything is said by the wizard. If he is asleep or turned off, nothing pops up, except a remote-help code, which has to be shown: that brings him out.</summary>
        public static void Say(string text, bool withHelpButton, string code = null, Action extra = null)
        {
            if (Wizard.Asleep && code == null) return;
            if (!Wizard.Enabled)
            {
                if (code == null) return;
                Wizard.Appear();                                                  // he appears just to show the code
            }
            Wizard.Say(text, withHelpButton, code);
        }

        // ---------------------------------------------------------------- remote help

        public static void RequestHelp()
        {
            Say("One moment, I'm getting help for you.", false);
            Task.Run(() =>
            {
                string code = null, err = null;
                if (Cfg.Server.Length > 0)
                {
                    try
                    {
                        using (var wc = new WebClient())
                        {
                            wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                            string body = new JavaScriptSerializer().Serialize(new Dictionary<string, string> { { "computer", Environment.MachineName }, { "user", Environment.UserName }, { "version", Engine.Version } });
                            code = ParseCode(wc.UploadString(Cfg.Server, body));
                            if (code == null) err = "the server did not send a code";
                        }
                    }
                    catch (Exception ex) { err = ex.Message; }
                }
                else err = "no remote server is set";

                if (code != null)
                {
                    string c = code;
                    Mail("Remote help code from " + Environment.MachineName, Environment.UserName + " on " + Environment.MachineName + " asked for help.\r\n\r\nRemote help code: " + c + "\r\nTime: " + DateTime.Now);
                    sync.BeginInvoke(new Action(() => Say("Please read this code to " + Who + ":", false, c)));
                }
                else
                {
                    try { Process.Start("quickassist"); } catch { }
                    Mail("Help requested from " + Environment.MachineName, Environment.UserName + " on " + Environment.MachineName + " pressed the help button at " + DateTime.Now + ".\r\n\r\nNo code could be made (" + err + "). Quick Assist was opened on that computer; ask them to read you the code it shows.");
                    sync.BeginInvoke(new Action(() => Say("I opened a program called Quick Assist. Please read the six numbers it shows to " + Who + " over the phone.", false)));
                }
            });
        }

        static string ParseCode(string resp)
        {
            if (resp == null) return null;
            resp = resp.Trim();
            try
            {
                var d = new JavaScriptSerializer().DeserializeObject(resp) as Dictionary<string, object>;
                object v;
                if (d != null && d.TryGetValue("code", out v) && v != null) { string s = v.ToString().Trim(); if (s.Length > 0 && s.Length <= 24) return s; }
            }
            catch { }
            if (resp.Length > 0 && resp.Length <= 24 && resp.IndexOfAny(new[] { '<', '{', '\n' }) < 0) return resp;
            return null;
        }

        public static string TestMail()
        {
            return SendMail("Visually Safe helper test", "This is a test message from the family helper on " + Environment.MachineName + ".");
        }

        public static void Notify(string subject, string body) { Mail(subject, body); }
        static void Mail(string subject, string body) { if (DryRun) return; try { SendMail(subject, body); } catch { } }

        /// <returns>null on success, otherwise the error text</returns>
        static string SendMail(string subject, string body)
        {
            if (!Cfg.MailReady) return "email is not set up";
            try
            {
                using (var smtp = new SmtpClient(Cfg.Smtp, Cfg.Port) { EnableSsl = Cfg.Port != 25, Timeout = 15000 })
                {
                    if (Cfg.User.Length > 0) smtp.Credentials = new NetworkCredential(Cfg.User, Cfg.Pass);
                    string from = Cfg.User.Contains("@") ? Cfg.User : Cfg.Email;
                    smtp.Send(new MailMessage(from, Cfg.Email, subject, body));
                }
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }
    }

    /// <summary>The setup window for family helper mode.</summary>
    class HelperSetupForm : Form
    {
        readonly TextBox tName, tEmail, tSmtp, tPort, tUser, tPass, tServer;
        readonly CheckBox cOn, cWiz, cAuto;
        readonly Label lMsg;

        public HelperSetupForm(Engine eng)
        {
            var c = Helper.Cfg ?? HelperConfig.Load(eng.DataDir);
            SuspendLayout();
            Text = "Family helper mode"; Icon = Theme.AppIcon();
            AutoScaleDimensions = new SizeF(96F, 96F); AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(640, 640); BackColor = Color.FromArgb(18, 22, 32); ForeColor = Color.FromArgb(225, 230, 240);
            Font = new Font("Segoe UI", 10f);
            int y = 16;
            Action<string> note = t => { Controls.Add(new Label { Text = t, Left = 24, Top = y, Width = 592, Height = 46, Tag = new Rectangle(24, y, 592, 46), ForeColor = Color.FromArgb(150, 160, 180) }); y += 50; };
            cOn = new CheckBox { Text = "Turn on family helper mode (also turns on the screen saver)", Left = 24, Top = y, Width = 592, Height = 28, Checked = c.On, Font = new Font("Segoe UI", 11f, FontStyle.Bold) };
            Controls.Add(cOn); y += 36;
            cWiz = new CheckBox { Text = "Show the wizard (walks along the taskbar, talks, answers questions)", Left = 24, Top = y, Width = 592, Height = 26, Checked = c.Wizard };
            Controls.Add(cWiz); y += 30;
            cAuto = new CheckBox { Text = "Check this PC and update its protection every Monday and Thursday", Left = 24, Top = y, Width = 592, Height = 26, Checked = c.AutoCheck };
            Controls.Add(cAuto); y += 34;
            note("A friendly helper appears on the screen and speaks with the Windows voice. It reminds about the network cable or Wi-Fi, unnamed text files piling up and a full C drive, and has a big \"I need help\" button. It never deletes anything or connects by itself.");
            tName = Field("What the helper calls you (the family member)", c.Name, ref y);
            tEmail = Field("Your email (gets the help code and alerts)", c.Email, ref y);
            tSmtp = Field("Mail server (SMTP), e.g. smtp.gmail.com", c.Smtp, ref y);
            tPort = Field("Mail server port (587 is usual)", c.Port.ToString(), ref y);
            tUser = Field("Mail login (usually your email address)", c.User, ref y);
            tPass = Field("Mail password (gmail needs an app password)", c.Pass, ref y); tPass.UseSystemPasswordChar = true;
            tServer = Field("Remote help server address (optional, your own server that returns a code)", c.Server, ref y);
            lMsg = new Label { Left = 24, Top = y, Width = 592, Height = 44, Tag = new Rectangle(24, y, 592, 44), ForeColor = Color.FromArgb(255, 200, 100) };
            Controls.Add(lMsg); y += 50;
            var bSave = new Btn("Save", true) { Bounds = new Rectangle(24, y, 120, 38) };
            var bTest = new Btn("Meet the wizard") { Bounds = new Rectangle(154, y, 150, 38) };
            var bMail = new Btn("Send test email") { Bounds = new Rectangle(314, y, 150, 38) };
            var bCancel = new Btn("Close") { Bounds = new Rectangle(496, y, 120, 38) };
            Controls.AddRange(new Control[] { bSave, bTest, bMail, bCancel });
            Func<HelperConfig> read = () =>
            {
                int port; if (!int.TryParse(tPort.Text.Trim(), out port)) port = 587;
                return new HelperConfig { On = cOn.Checked, Wizard = cWiz.Checked, AutoCheck = cAuto.Checked, IntroDone = c.IntroDone, SleepUntil = c.SleepUntil, Name = tName.Text.Trim().Length > 0 ? tName.Text.Trim() : "your kid", Email = tEmail.Text.Trim(), Smtp = tSmtp.Text.Trim(), Port = port, User = tUser.Text.Trim(), Pass = tPass.Text, Server = tServer.Text.Trim() };
            };
            bSave.Click += (s, e) => { Helper.Apply(read()); lMsg.Text = cOn.Checked ? "Saved. Family helper mode is on and the screen saver is turned on." : "Saved. Family helper mode is off."; };
            bTest.Click += (s, e) => { Helper.Apply(read()); Wizard.Appear(); Helper.Greet(true); };
            bMail.Click += (s, e) =>
            {
                Helper.Apply(read()); lMsg.Text = "Sending...";
                Task.Run(() => Helper.TestMail()).ContinueWith(t => BeginInvoke(new Action(() => lMsg.Text = t.Result == null ? "Test email sent. Check your inbox." : "Could not send: " + t.Result)));
            };
            bCancel.Click += (s, e) => Close();
            ClientSize = new Size(640, y + 64);
            ResumeLayout(false);
            Shown += (s, e) => FitLabels.Apply(this);
        }

        TextBox Field(string label, string value, ref int y)
        {
            Controls.Add(new Label { Text = label, Left = 24, Top = y, Width = 592, Height = 20, Tag = new Rectangle(24, y, 592, 20), ForeColor = Color.FromArgb(170, 180, 200) });
            var t = new TextBox { Left = 24, Top = y + 22, Width = 592, Text = value, BackColor = Color.FromArgb(30, 36, 50), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            Controls.Add(t); y += 56;
            return t;
        }
    }
}
