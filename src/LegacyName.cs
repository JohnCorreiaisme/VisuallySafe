using System;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;

namespace VisuallySafe
{
    /// <summary>The program used to be called TinyGuard. This carries an old install's data, startup entry, right-click menu and screen saver over to the new name.</summary>
    static class LegacyName
    {
        const string Old = "TinyGuard";

        /// <summary>Moves (or, if something is locked, copies) the old data folder when the new one doesn't exist yet.</summary>
        public static void MigrateData(string newDir)
        {
            try
            {
                string oldDir = Path.Combine(Path.GetDirectoryName(newDir), Old);
                if (Directory.Exists(newDir) || !Directory.Exists(oldDir)) return;
                try { Directory.Move(oldDir, newDir); }
                catch { CopyAll(oldDir, newDir); }
            }
            catch { }
        }

        static void CopyAll(string from, string to)
        {
            Directory.CreateDirectory(to);
            foreach (string f in Directory.GetFiles(from))
                try { File.Copy(f, Path.Combine(to, Path.GetFileName(f)), true); } catch { }
            foreach (string d in Directory.GetDirectories(from)) CopyAll(d, Path.Combine(to, Path.GetFileName(d)));
        }

        /// <summary>Per-user leftovers: the Windows startup entry, the right-click menu entries and the screen saver setting.</summary>
        public static void CleanUser()
        {
            try
            {
                string exe = System.Windows.Forms.Application.ExecutablePath;
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    if (k != null && k.GetValue(Old) != null)
                    {
                        k.DeleteValue(Old, false);
                        k.SetValue("VisuallySafe", "\"" + exe + "\"");     // it was starting with Windows: keep it that way under the new name
                    }
            }
            catch { }
            try
            {
                foreach (string r in new[] { "*", "Directory", "AllFilesystemObjects", "Drive", "lnkfile", "InternetShortcut" })
                    Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\" + r + @"\shell\" + Old + "Scan", false);     // ShellMenu.Apply adds the new ones
            }
            catch { }
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop", true))
                {
                    string cur = k == null ? null : k.GetValue("SCRNSAVE.EXE") as string;
                    if (cur == null) return;
                    string name = Path.GetFileName(cur);
                    string mode = string.Equals(name, Old + "Defrag.scr", StringComparison.OrdinalIgnoreCase) ? "defrag" : string.Equals(name, Old + ".scr", StringComparison.OrdinalIgnoreCase) ? "scan" : null;
                    if (mode == null) return;
                    string now = SystemSaver.ScrPathFor(mode);
                    if (File.Exists(now)) k.SetValue("SCRNSAVE.EXE", now);
                }
            }
            catch { }
        }
    }
}
