using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace VisuallySafe
{
    /// <summary>Lets the wizard answer with Claude Code or Codex, the same two helpers that can fix problems. They are run once, with no tools and no file access (read-only), just to answer one question in words.</summary>
    static class AgentChat
    {
        /// <summary>Asks the agent ("claude" or "codex") and returns its answer. Throws when the agent isn't installed, isn't signed in, or takes too long.</summary>
        public static string Ask(string agentId, string system, string question, int timeoutSeconds)
        {
            var agent = Agents.Detect().FirstOrDefault(a => a.Id == agentId && a.Found);
            if (agent == null) throw new InvalidOperationException(agentId + " is not installed");

            string args = agentId == "claude"
                ? "-p --tools \"\" --no-session-persistence --output-format text"
                : "exec --sandbox read-only --skip-git-repo-check --ephemeral -";
            string prompt = system + "\n\nTHE PERSON ASKS:\n" + question + "\n\nAnswer now, as the wizard, in plain words only. Add nothing else: no tips, no notes, no headings.";

            string work = Path.Combine(Path.GetTempPath(), "VisuallySafe-ask");
            Directory.CreateDirectory(work);       // an empty folder: the helper has nothing to look at

            var psi = new ProcessStartInfo("cmd.exe", Agents.CmdArgs(agent.Path, args, false))
            {
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = work,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
            using (var p = Process.Start(psi))
            {
                var o = p.StandardOutput.ReadToEndAsync(); var er = p.StandardError.ReadToEndAsync();
                try { var bytes = new UTF8Encoding(false).GetBytes(prompt); p.StandardInput.BaseStream.Write(bytes, 0, bytes.Length); p.StandardInput.Close(); } catch { }
                if (!p.WaitForExit(timeoutSeconds * 1000))
                {
                    try { Kill(p.Id); } catch { }
                    throw new TimeoutException("the helper took too long");
                }
                string text = Clean(o.Result);
                if (p.ExitCode != 0 && text.Length == 0) throw new InvalidOperationException(Clean(er.Result));
                return text;
            }
        }

        static string Clean(string s)
        {
            s = Regex.Replace(s ?? "", "\u001b\\[[0-9;?]*[A-Za-z]", "");
            // the person's own Claude settings can add a footer line of their own: keep only the answer
            string cr = ((char)13).ToString(), lf = ((char)10).ToString();
            s = string.Join(lf, s.Replace(cr, "").Split((char)10).Where(l => l.IndexOf("Context tip", StringComparison.OrdinalIgnoreCase) < 0));
            return s.Trim();
        }

        // End the helper and anything it started (only the process we launched, by its own id).
        static void Kill(int pid)
        {
            var psi = new ProcessStartInfo("taskkill.exe", "/PID " + pid + " /T /F") { CreateNoWindow = true, UseShellExecute = false };
            using (var k = Process.Start(psi)) k.WaitForExit(5000);
        }
    }
}
