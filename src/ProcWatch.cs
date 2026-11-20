using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace VisuallySafe
{
    /// <summary>
    /// Notices programs as they start (polls the process list once a second; works without admin rights)
    /// and hands each new one to the engine. Also the shared PID -> program path lookup.
    /// </summary>
    class ProcWatch : IDisposable
    {
        [DllImport("psapi.dll", SetLastError = true)] static extern bool EnumProcesses([Out] int[] ids, int size, out int needed);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);

        const uint QueryLimited = 0x1000, Terminate = 0x0001, Synchronize = 0x00100000;

        readonly Action<int, string, bool> started;
        bool firstPass = true;
        readonly Timer timer;
        HashSet<int> known = new HashSet<int>();
        int[] buf = new int[4096];
        int busy;

        public ProcWatch(Action<int, string, bool> onStarted)
        {
            started = onStarted;
            // First pass reports what is already running, so something started before Visually Safe is checked too.
            timer = new Timer(_ => Poll(), null, 3000, 1000);
        }

        void Poll()
        {
            if (Interlocked.Exchange(ref busy, 1) == 1) return;
            try
            {
                int needed;
                while (true)
                {
                    if (!EnumProcesses(buf, buf.Length * 4, out needed)) return;
                    if (needed < buf.Length * 4) break;
                    buf = new int[buf.Length * 2];
                }
                var now = new HashSet<int>();
                for (int i = 0; i < needed / 4; i++)
                {
                    int pid = buf[i];
                    now.Add(pid);
                    if (pid <= 4 || known.Contains(pid)) continue;
                    string path = PathOf(pid);
                    if (path != null && !firstPass) started(pid, path, false);     // programs already running when Visually Safe starts are not scanned: nothing scans until a new program starts or you ask
                }
                known = now;
                firstPass = false;
            }
            catch { }
            finally { busy = 0; }
        }

        /// <summary>Full path of a running program, or null (ended, or not allowed to look).</summary>
        public static string PathOf(int pid)
        {
            IntPtr h = OpenProcess(QueryLimited, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }

        /// <summary>
        /// Ends one process by its ID, but only if it is still running the program we judged
        /// (IDs get reused, so the path is checked first).
        /// </summary>
        public static bool Kill(int pid, string expectedPath)
        {
            IntPtr h = OpenProcess(QueryLimited | Terminate | Synchronize, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (!QueryFullProcessImageName(h, 0, sb, ref size)) return false;
                if (!string.Equals(sb.ToString(), expectedPath, StringComparison.OrdinalIgnoreCase)) return false;
                if (!TerminateProcess(h, 1)) return false;
                WaitForSingleObject(h, 3000);
                return true;
            }
            finally { CloseHandle(h); }
        }

        public void Dispose() { timer.Dispose(); }
    }
}
