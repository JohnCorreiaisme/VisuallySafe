using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace TinyGuard
{
    enum NSev { Ok, Info, Warn, Fail }

    class NetResult { public NSev Sev; public string Title = "", Detail = ""; public string Proto = "", Prog = ""; public int Port; public bool Ignored; public string IgnoreWhy = ""; }

    /// <summary>
    /// TinyGuard's own network toolbox: health check, listening ports, device finder, port scanner, ping, traceroute, DNS lookup.
    /// Every result is also written to network-log.txt in the data folder.
    /// </summary>
    class NetTools
    {
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern int GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, int reserved);
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern int GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int tableClass, int reserved);

        public volatile bool Running;
        public string Status = "";
        public int Done, Total, Version;
        public DateTime LastRun = DateTime.MinValue;
        public List<NetResult> LastHealth = new List<NetResult>();   // kept for the AI helper's report
        readonly List<NetResult> results = new List<NetResult>();
        readonly object gate = new object(), logGate = new object();
        CancellationTokenSource cts;
        readonly string logFile;
        public string LogFile { get { return logFile; } }

        public NetTools(string dataDir) { logFile = Path.Combine(dataDir, "network-log.txt"); }

        public List<NetResult> Results { get { lock (gate) return results.ToList(); } }
        public void Cancel() { var c = cts; if (c != null) c.Cancel(); }

        void Log(string level, string text)
        {
            try
            {
                lock (logGate)
                {
                    File.AppendAllText(logFile, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " [" + level + "] " + text.Replace('\r', ' ').Replace('\n', ' ') + Environment.NewLine);
                    if (new FileInfo(logFile).Length > 2 * 1024 * 1024)
                    {
                        var lines = File.ReadAllLines(logFile);
                        File.WriteAllLines(logFile, lines.Skip(lines.Length / 2));
                    }
                }
            }
            catch { }
        }

        // ---- ignore list: ports and programs you (or the built-in Windows list) say are fine, so they don't show as warnings
        string IgnoreFile { get { return Path.Combine(Path.GetDirectoryName(logFile), "net-ignore.txt"); } }
        static readonly int[] CommonWindowsPorts = { 53, 67, 68, 123, 135, 137, 138, 139, 445, 500, 1900, 3702, 4500, 5040, 5353, 5355, 5357, 5358, 7680 };

        public List<string> IgnoreRules() { try { return File.ReadAllLines(IgnoreFile).Select(l => l.Trim()).Where(l => l.Length > 0).ToList(); } catch { return new List<string>(); } }
        public void AddIgnore(string rule) { var l = IgnoreRules(); if (!l.Contains(rule, StringComparer.OrdinalIgnoreCase)) { l.Add(rule); try { File.WriteAllLines(IgnoreFile, l); } catch { } } }
        public void RemoveIgnore(string rule) { var l = IgnoreRules().Where(x => !string.Equals(x, rule, StringComparison.OrdinalIgnoreCase)).ToList(); try { File.WriteAllLines(IgnoreFile, l); } catch { } }
        public static string PortRule(string proto, int port) { return "port:" + proto + ":" + port; }
        public static string ProgRule(string path) { return "prog:" + path.ToLowerInvariant(); }

        /// <summary>Why a port is ignored (a rule of yours, or the built-in list of common Windows ports and programs), or null.</summary>
        public string IgnoredBecause(string proto, int port, string path, List<string> rules)
        {
            bool isPath = !string.IsNullOrEmpty(path) && path.Contains("\\");
            if (rules.Contains(PortRule(proto, port), StringComparer.OrdinalIgnoreCase) || rules.Contains(PortRule("*", port), StringComparer.OrdinalIgnoreCase)) return "you ignored this port";
            if (isPath && rules.Contains(ProgRule(path), StringComparer.OrdinalIgnoreCase)) return "you ignored this program";
            if (rules.Contains("nodefaults", StringComparer.OrdinalIgnoreCase)) return null;
            bool windows = path == "System" || (isPath && path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase));
            if (!windows) return null;
            if (Array.IndexOf(CommonWindowsPorts, port) >= 0) return "common Windows port";
            if (port >= 49152 && isPath) return "Windows' own dynamic port";
            if (isPath) return "a Windows program";
            return null;
        }

        void Add(NSev sev, string title, string detail = "", NetResult extra = null)
        {
            lock (gate) results.Add(new NetResult { Sev = sev, Title = title, Detail = detail, Proto = extra == null ? "" : extra.Proto, Port = extra == null ? 0 : extra.Port, Prog = extra == null ? "" : extra.Prog, Ignored = extra != null && extra.Ignored, IgnoreWhy = extra == null ? "" : extra.IgnoreWhy });
            Interlocked.Increment(ref Version);
            Log(sev == NSev.Ok ? "OK" : sev == NSev.Info ? "INFO" : sev == NSev.Warn ? "WARN" : "FAIL", title + (detail.Length > 0 ? " — " + detail : ""));
        }

        bool Start(string title, bool keepAsHealth, Action<CancellationToken> job)
        {
            if (Running) return false;
            lock (gate) results.Clear();
            Interlocked.Increment(ref Version);
            Running = true; Status = title; Done = Total = 0;
            cts = new CancellationTokenSource();
            var token = cts.Token;
            Task.Run(() =>
            {
                try { Log("INFO", "=== " + title + " ==="); job(token); }
                catch (OperationCanceledException) { Add(NSev.Info, "Stopped"); }
                catch (Exception ex) { Add(NSev.Fail, "The test stopped early", ex.GetBaseException().Message); }
                finally
                {
                    LastRun = DateTime.Now;
                    if (keepAsHealth) lock (gate) LastHealth = results.ToList();
                    Status = "Finished: " + title; Running = false; Interlocked.Increment(ref Version);
                }
            });
            return true;
        }

        // ------------------------------------------------------------------ helpers

        static readonly Dictionary<int, string> Services = new Dictionary<int, string>
        {
            {20,"ftp-data"},{21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},{67,"dhcp"},{80,"http"},{88,"kerberos"},{110,"pop3"},{111,"rpcbind"},{123,"ntp"},
            {135,"msrpc"},{137,"netbios-ns"},{138,"netbios-dgm"},{139,"netbios-ssn"},{143,"imap"},{161,"snmp"},{389,"ldap"},{443,"https"},{445,"smb"},{465,"smtps"},
            {500,"ike"},{514,"syslog"},{515,"printer"},{554,"rtsp"},{587,"submission"},{631,"ipp"},{993,"imaps"},{995,"pop3s"},{1433,"mssql"},{1521,"oracle"},{1723,"pptp"},
            {1900,"upnp"},{2049,"nfs"},{3000,"dev-server"},{3306,"mysql"},{3389,"rdp"},{5000,"upnp/dev"},{5040,"windows"},{5353,"mdns"},{5357,"wsd"},{5432,"postgres"},
            {5900,"vnc"},{5985,"winrm"},{5986,"winrm-ssl"},{6379,"redis"},{8000,"http-alt"},{8008,"http-alt"},{8080,"http-proxy"},{8081,"http-alt"},{8443,"https-alt"},
            {8888,"http-alt"},{9100,"jetdirect"},{9200,"elasticsearch"},{27017,"mongodb"}
        };

        static readonly Dictionary<int, string> Risky = new Dictionary<int, string>
        {
            {21,"FTP sends passwords in plain text."},{23,"Telnet sends everything, including passwords, in plain text."},{135,"Legacy Windows networking; rarely needed from other devices."},
            {139,"Legacy Windows file sharing."},{445,"Windows file sharing (SMB): a common route for ransomware and worms."},{1433,"A database (SQL Server) open to the network."},
            {3306,"A database (MySQL) open to the network."},{3389,"Remote Desktop: a top target for attackers if exposed."},{5432,"A database (PostgreSQL) open to the network."},
            {5900,"VNC remote control, often weakly protected."},{5985,"Windows remote management (WinRM)."},{5986,"Windows remote management (WinRM)."},
            {6379,"Redis database, often open with no password."},{9200,"Elasticsearch, often open with no password."},{27017,"MongoDB database open to the network."}
        };

        public const string Top100 = "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157";

        static string Svc(int port) { string s; return Services.TryGetValue(port, out s) ? s : "unknown"; }

        public static bool IsPrivate(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return true;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6) { var b6 = ip.GetAddressBytes(); return ip.IsIPv6LinkLocal || (b6[0] & 0xFE) == 0xFC; }
            var b = ip.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }

        static void ForEachParallel<T>(IEnumerable<T> items, int dop, CancellationToken ct, Action<T> work)
        {
            var q = new ConcurrentQueue<T>(items);
            var threads = new List<Thread>();
            for (int i = 0; i < Math.Min(dop, Math.Max(1, q.Count)); i++)
            {
                var t = new Thread(() => { T it; while (!ct.IsCancellationRequested && q.TryDequeue(out it)) { try { work(it); } catch { } } }) { IsBackground = true };
                t.Start(); threads.Add(t);
            }
            foreach (var t in threads) t.Join();
            ct.ThrowIfCancellationRequested();
        }

        class PingStat { public int Sent, Ok, Min = int.MaxValue, Max; public long Sum; public int Avg { get { return Ok == 0 ? 0 : (int)(Sum / Ok); } } public string Addr = ""; }

        static PingStat PingHost(string host, int count, int timeout, CancellationToken ct)
        {
            var st = new PingStat();
            using (var p = new Ping())
                for (int i = 0; i < count && !ct.IsCancellationRequested; i++)
                {
                    st.Sent++;
                    try
                    {
                        var r = p.Send(host, timeout);
                        if (r.Status == IPStatus.Success) { st.Ok++; int ms = (int)r.RoundtripTime; st.Sum += ms; st.Min = Math.Min(st.Min, ms); st.Max = Math.Max(st.Max, ms); st.Addr = r.Address.ToString(); }
                    }
                    catch { }
                    if (i < count - 1) Thread.Sleep(120);
                }
            return st;
        }

        static bool TcpOpen(IPAddress ip, int port, int timeoutMs)
        {
            try
            {
                using (var c = new TcpClient(ip.AddressFamily))
                {
                    var t = c.ConnectAsync(ip, port);
                    return t.Wait(timeoutMs) && c.Connected;
                }
            }
            catch { return false; }
        }

        static string Banner(IPAddress ip, int port, int timeoutMs)
        {
            try
            {
                using (var c = new TcpClient(ip.AddressFamily))
                {
                    if (!c.ConnectAsync(ip, port).Wait(timeoutMs) || !c.Connected) return null;
                    var s = c.GetStream(); s.ReadTimeout = 500; s.WriteTimeout = 500;
                    bool http = port == 80 || port == 8000 || port == 8008 || port == 8080 || port == 8081 || port == 8888 || port == 3000 || port == 5000;
                    if (http) { var req = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n"); s.Write(req, 0, req.Length); }
                    var buf = new byte[300]; int n = 0;
                    try { n = s.Read(buf, 0, buf.Length); } catch { }
                    if (n <= 0) return "";
                    string text = Encoding.ASCII.GetString(buf, 0, n);
                    if (http)
                    {
                        var m = Regex.Match(text, @"(?im)^Server:\s*(.+)$");
                        return m.Success ? "Server: " + m.Groups[1].Value.Trim() : text.Split('\n')[0].Trim();
                    }
                    string first = text.Split('\n')[0].Trim();
                    return new string(first.Where(ch => ch >= 32 && ch < 127).ToArray());
                }
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------ 1. health check

        public bool RunHealth() { return Start("Network health check", true, HealthJob); }

        void HealthJob(CancellationToken ct)
        {
            Status = "Checking your network adapters…";
            var nics = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel).ToList();
            IPAddress gateway = null; var dnsServers = new List<IPAddress>();
            if (nics.Count == 0) Add(NSev.Fail, "No network connection", "No network adapter is connected. Check the cable, Wi-Fi, or airplane mode.");
            foreach (var nic in nics)
            {
                var ip = nic.GetIPProperties();
                var v4 = ip.UnicastAddresses.Select(a => a.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
                var gws = ip.GatewayAddresses.Select(g => g.Address).Where(g => g.AddressFamily == AddressFamily.InterNetwork && !g.Equals(IPAddress.Any)).ToList();
                var dns = ip.DnsAddresses.Where(d => d.AddressFamily == AddressFamily.InterNetwork).ToList();
                bool virt = nic.Name.StartsWith("vEthernet", StringComparison.OrdinalIgnoreCase) || nic.Description.IndexOf("Hyper-V", StringComparison.OrdinalIgnoreCase) >= 0
                            || nic.Description.IndexOf("VMware", StringComparison.OrdinalIgnoreCase) >= 0 || nic.Description.IndexOf("VirtualBox", StringComparison.OrdinalIgnoreCase) >= 0
                            || nic.Description.IndexOf("WSL", StringComparison.OrdinalIgnoreCase) >= 0;
                bool apipa = v4.Any(a => a.GetAddressBytes()[0] == 169 && a.GetAddressBytes()[1] == 254);
                string line = nic.NetworkInterfaceType + ", " + (nic.Speed > 0 ? nic.Speed / 1000000 + " Mbps" : "speed unknown") + " · IP " + string.Join(", ", v4) +
                              " · gateway " + (gws.Count > 0 ? string.Join(", ", gws) : "none") + " · DNS " + (dns.Count > 0 ? string.Join(", ", dns) : "none");
                if (virt) { Add(NSev.Info, nic.Name + " (virtual adapter)", line); continue; }
                if (apipa) Add(NSev.Fail, nic.Name + " has no valid address", "It only has a 169.254.x.x address, meaning the router didn't hand out an address (a DHCP problem). Restart the router, or run \"ipconfig /renew\".");
                else if (v4.Count == 0) Add(NSev.Warn, nic.Name + " has no IPv4 address", line);
                else Add(NSev.Ok, nic.Name + " is connected", line);
                if (!apipa && v4.Count > 0 && gws.Count == 0) Add(NSev.Warn, nic.Name + " has no default gateway", "Without a gateway this adapter can only reach devices on its own network, not the internet.");
                if (!apipa && v4.Count > 0 && dns.Count == 0) Add(NSev.Warn, nic.Name + " has no DNS server", "Websites won't load by name without one.");
                if (nic.Speed > 0 && nic.Speed < 10000000 && v4.Count > 0) Add(NSev.Warn, nic.Name + " link is slow", "Only " + nic.Speed / 1000000 + " Mbps. Check the cable or Wi-Fi signal.");
                if (gateway == null && gws.Count > 0 && !apipa) gateway = gws[0];
                foreach (var d in dns) if (!dnsServers.Contains(d)) dnsServers.Add(d);
            }
            ct.ThrowIfCancellationRequested();
            if (nics.Select(n => n.GetIPProperties().GatewayAddresses.Count(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))).Sum() > 1 && nics.Count > 1)
                Add(NSev.Info, "More than one gateway", "Several adapters are connected at once (for example Wi-Fi and Ethernet). Windows picks one; that can cause odd slowdowns.");

            if (gateway != null)
            {
                Status = "Pinging your router (" + gateway + ")…";
                var g = PingHost(gateway.ToString(), 4, 1500, ct);
                if (g.Ok == 0) Add(NSev.Fail, "Your router (" + gateway + ") doesn't answer", "No ping replies. Some routers ignore ping, but if the internet is also down, check the router and cables.");
                else if (g.Ok < g.Sent) Add(NSev.Warn, "Packet loss to your router", g.Sent - g.Ok + " of " + g.Sent + " pings were lost. That points to a bad cable or weak Wi-Fi.");
                else if (g.Avg > 30) Add(NSev.Warn, "Your router answers slowly", "Average " + g.Avg + " ms (it should be under 10 ms on a wired network). Wi-Fi interference is a common cause.");
                else Add(NSev.Ok, "Your router answers", "Average " + g.Avg + " ms, no lost pings.");
            }

            Status = "Testing the internet connection…";
            bool icmpOk = false, tcpOk = false;
            foreach (string target in new[] { "1.1.1.1", "8.8.8.8" })
            {
                ct.ThrowIfCancellationRequested();
                var p = PingHost(target, 3, 2000, ct);
                if (p.Ok > 0) { icmpOk = true; Add(p.Ok < p.Sent || p.Avg > 120 ? NSev.Warn : NSev.Ok, "Internet reachable by ping (" + target + ")", p.Ok + " of " + p.Sent + " replies, average " + p.Avg + " ms"); }
                bool t = TcpOpen(IPAddress.Parse(target), 443, 3000);
                if (t) tcpOk = true;
            }
            if (!icmpOk && !tcpOk) Add(NSev.Fail, "No internet connection", "Couldn't reach 1.1.1.1 or 8.8.8.8 by ping or by a normal web connection. The problem is between your router and the internet (or the router is offline).");
            else if (!icmpOk) Add(NSev.Info, "Ping is blocked, but the internet works", "Web connections to 1.1.1.1 succeed; something on your network blocks ping, which is harmless.");
            else if (!tcpOk) Add(NSev.Warn, "Ping works but web connections fail", "A firewall, proxy or filter may be blocking normal web traffic (port 443).");
            else Add(NSev.Ok, "Web connections work", "Connected to 1.1.1.1 and/or 8.8.8.8 on port 443.");

            Status = "Testing DNS (looking up website names)…";
            int dnsOk = 0, dnsTotal = 0; var times = new List<int>();
            foreach (string name in new[] { "example.com", "microsoft.com", "cloudflare.com" })
            {
                ct.ThrowIfCancellationRequested();
                dnsTotal++;
                var sw = Stopwatch.StartNew();
                var t = Task.Run(() => Dns.GetHostAddresses(name));
                bool ok = false; try { ok = t.Wait(4000) && t.Result.Length > 0; } catch { }
                if (ok) { dnsOk++; times.Add((int)sw.ElapsedMilliseconds); }
            }
            if (dnsOk == 0) Add(tcpOk || icmpOk ? NSev.Fail : NSev.Warn, "DNS isn't working", tcpOk || icmpOk ? "The internet is reachable but names can't be looked up. Try a different DNS server (such as 1.1.1.1) in your adapter settings." : "Names couldn't be looked up (expected, since the internet is down).");
            else if (dnsOk < dnsTotal) Add(NSev.Warn, "DNS is unreliable", dnsOk + " of " + dnsTotal + " lookups worked.");
            else if (times.Average() > 400) Add(NSev.Warn, "DNS is slow", "Lookups take about " + (int)times.Average() + " ms. A faster DNS server would make pages start loading sooner.");
            else Add(NSev.Ok, "DNS works", "Names resolve in about " + (int)times.Average() + " ms.");

            foreach (var d in dnsServers.Take(4))
            {
                ct.ThrowIfCancellationRequested();
                int ms;
                if (DnsQuery(d, "example.com", 2000, out ms)) Add(NSev.Ok, "DNS server " + d + " answers", ms + " ms");
                else Add(dnsOk > 0 ? NSev.Warn : NSev.Fail, "DNS server " + d + " doesn't answer", "It didn't reply to a direct question." + (dnsOk > 0 ? " Other servers are working, but this one may slow lookups down." : ""));
            }

            Status = "Checking for a captive portal or proxy…";
            try
            {
                using (var h = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(6) })
                {
                    var r = h.GetAsync("http://www.msftconnecttest.com/connecttest.txt", ct).GetAwaiter().GetResult();
                    string body = r.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    if (r.IsSuccessStatusCode && body.Contains("Microsoft Connect Test")) Add(NSev.Ok, "Normal internet access", "Microsoft's connection test page loaded correctly.");
                    else Add(NSev.Warn, "Something is intercepting web traffic", "The test page came back changed (status " + (int)r.StatusCode + "). A sign-in page (captive portal) or a filter may be in the way.");
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { if (tcpOk) Add(NSev.Warn, "The web test failed", ex.GetBaseException().Message); }
            try
            {
                var proxy = WebRequest.GetSystemWebProxy().GetProxy(new Uri("http://example.com"));
                if (proxy != null && proxy.Host != "example.com") Add(NSev.Info, "A web proxy is set", proxy.ToString() + " (fine if your workplace or school uses one; unexpected otherwise)");
            }
            catch { }

            try
            {
                dynamic fw = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                int types = fw.CurrentProfileTypes;
                foreach (int bit in new[] { 1, 2, 4 })
                {
                    if ((types & bit) == 0) continue;
                    string nm = bit == 1 ? "domain" : bit == 2 ? "private" : "public";
                    bool on = fw.FirewallEnabled[bit];
                    Add(on ? NSev.Ok : NSev.Warn, on ? "Windows Firewall is on (" + nm + " network)" : "Windows Firewall is OFF for your " + nm + " network", on ? "" : "Other devices on this network can reach this PC's services. Turn it back on in Windows Security.");
                }
            }
            catch { }

            int fails, warns;
            lock (gate) { fails = results.Count(r => r.Sev == NSev.Fail); warns = results.Count(r => r.Sev == NSev.Warn); }
            Add(fails > 0 ? NSev.Fail : warns > 0 ? NSev.Warn : NSev.Ok, fails + warns == 0 ? "Everything looks healthy" : fails + " problem" + (fails == 1 ? "" : "s") + " and " + warns + " warning" + (warns == 1 ? "" : "s") + " found", "Results are saved in the network log.");
        }

        static bool DnsQuery(IPAddress server, string name, int timeoutMs, out int ms)
        {
            ms = 0;
            try
            {
                var id = (ushort)new Random().Next(1, 65535);
                var pkt = new List<byte> { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
                foreach (string label in name.Split('.')) { pkt.Add((byte)label.Length); pkt.AddRange(Encoding.ASCII.GetBytes(label)); }
                pkt.AddRange(new byte[] { 0, 0, 1, 0, 1 });
                var sw = Stopwatch.StartNew();
                using (var u = new UdpClient(server.AddressFamily) { Client = { ReceiveTimeout = timeoutMs, SendTimeout = timeoutMs } })
                {
                    u.Connect(server, 53);
                    u.Send(pkt.ToArray(), pkt.Count);
                    var ep = new IPEndPoint(IPAddress.Any, 0);
                    var resp = u.Receive(ref ep);
                    ms = (int)sw.ElapsedMilliseconds;
                    return resp.Length > 12 && resp[0] == (byte)(id >> 8) && resp[1] == (byte)id && (resp[3] & 0x0F) == 0 && (resp[6] != 0 || resp[7] != 0);
                }
            }
            catch { return false; }
        }

        // ------------------------------------------------------------------ 2. what's listening on this PC

        class Listener { public string Proto = ""; public IPAddress Addr; public int Port, Pid; public bool Exposed { get { return !IPAddress.IsLoopback(Addr); } } }

        static int NetPort(int raw) { return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF); }

        static List<Listener> ReadTable(bool udp, bool v6)
        {
            var list = new List<Listener>();
            int af = v6 ? 23 : 2, size = 0;
            Func<IntPtr, int> call = p => udp ? GetExtendedUdpTable(p, ref size, true, af, 1, 0) : GetExtendedTcpTable(p, ref size, true, af, 3, 0);
            call(IntPtr.Zero);
            IntPtr buf = Marshal.AllocHGlobal(size + 64);
            try
            {
                if (call(buf) != 0) return list;
                int n = Marshal.ReadInt32(buf);
                int row = udp ? (v6 ? 28 : 12) : (v6 ? 56 : 24);
                for (int i = 0; i < n; i++)
                {
                    IntPtr r = buf + 4 + i * row;
                    var l = new Listener { Proto = udp ? "UDP" : "TCP" };
                    if (!v6)
                    {
                        int o = udp ? 0 : 4;
                        l.Addr = new IPAddress((uint)Marshal.ReadInt32(r, o) & 0xFFFFFFFFu);
                        l.Port = NetPort(Marshal.ReadInt32(r, o + 4));
                        l.Pid = Marshal.ReadInt32(r, udp ? 8 : 20);
                    }
                    else
                    {
                        var a = new byte[16]; Marshal.Copy(r, a, 0, 16);
                        l.Addr = new IPAddress(a);
                        l.Port = NetPort(Marshal.ReadInt32(r, 20));
                        l.Pid = Marshal.ReadInt32(r, udp ? 24 : 52);
                    }
                    list.Add(l);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return list;
        }

        public bool RunListening() { return Start("What is listening on this PC", true, ListeningJob); }

        void ListeningJob(CancellationToken ct)
        {
            Status = "Reading open ports…";
            var all = new List<Listener>();
            all.AddRange(ReadTable(false, false)); all.AddRange(ReadTable(false, true));
            all.AddRange(ReadTable(true, false)); all.AddRange(ReadTable(true, true));
            var signed = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            var rows = new List<Tuple<NSev, bool, int, string, string, NetResult>>();   // severity, exposed, port, title, detail, info for the menu
            var rules = IgnoreRules();
            var seen = new HashSet<string>();
            Total = all.Count; Done = 0;
            foreach (var l in all)
            {
                ct.ThrowIfCancellationRequested();
                Done++;
                string path = l.Pid == 0 || l.Pid == 4 ? "System" : ProcWatch.PathOf(l.Pid);
                string name = path == null ? "process " + l.Pid : path.Contains("\\") ? Path.GetFileName(path) : path;
                if (!seen.Add(l.Proto + "|" + l.Port + "|" + l.Exposed + "|" + name)) continue;
                string svc = Svc(l.Port);
                string title = l.Proto + " " + l.Port + (svc != "unknown" ? " (" + svc + ")" : "") + " · " + name;
                string detail = (l.Exposed ? "reachable from other devices" : "this PC only") + (path != null && path.Contains("\\") ? " · " + path : "");
                NSev sev = NSev.Info;
                if (l.Exposed)
                {
                    string advice;
                    if (Risky.TryGetValue(l.Port, out advice)) { sev = NSev.Warn; detail = advice + " " + detail; }
                    else if (path != null && path.Contains("\\") && l.Proto == "TCP")
                    {
                        bool sg;
                        if (!signed.TryGetValue(path, out sg)) { try { sg = Trust.TrustedSigner(path) != null; } catch { sg = false; } signed[path] = sg; }
                        if (!sg && !path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)) { sev = NSev.Warn; detail = "An unsigned program is listening for connections from the network. " + detail; }
                    }
                }
                var ex = new NetResult { Proto = l.Proto, Port = l.Port, Prog = path != null && path.Contains("\\") ? path : "" };
                string why = IgnoredBecause(l.Proto, l.Port, path, rules);
                if (why != null) { ex.Ignored = true; ex.IgnoreWhy = why; sev = NSev.Info; title += "  · ignored (" + why + ")"; }
                rows.Add(Tuple.Create(sev, l.Exposed, l.Port, title, detail, ex));
            }
            int exposedCount = rows.Count(r => r.Item2);
            foreach (var r in rows.OrderByDescending(x => x.Item1).ThenByDescending(x => x.Item2).ThenBy(x => x.Item3)) Add(r.Item1, r.Item4, r.Item5, r.Item6);
            Add(exposedCount > 0 ? NSev.Info : NSev.Ok, rows.Count + " listening ports, " + exposedCount + " reachable from other devices",
                "Ports reachable from other devices are blocked by Windows Firewall unless a rule allows them. \"This PC only\" ports are safe.");
        }

        // ------------------------------------------------------------------ 3. devices on the network

        public bool RunDevices() { return Start("Find devices on my network", true, DevicesJob); }

        static IPAddress LocalIPv4(out IPAddress gateway, out int prefix)
        {
            gateway = null; prefix = 24;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var ip = nic.GetIPProperties();
                var gw = ip.GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
                if (gw == null) continue;
                var ua = ip.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                if (ua == null) continue;
                gateway = gw.Address; prefix = ua.PrefixLength; return ua.Address;
            }
            return null;
        }

        void DevicesJob(CancellationToken ct)
        {
            IPAddress gw; int prefix;
            var me = LocalIPv4(out gw, out prefix);
            if (me == null) { Add(NSev.Fail, "No network to look at", "This PC isn't connected to a network with a gateway."); return; }
            if (prefix < 24) prefix = 24;   // never sweep more than 254 addresses
            var b = me.GetAddressBytes();
            var hosts = Enumerable.Range(1, 254).Select(i => new IPAddress(new[] { b[0], b[1], b[2], (byte)i })).Where(a => !a.Equals(me)).ToList();
            Total = hosts.Count; Done = 0; Status = "Looking for devices on " + b[0] + "." + b[1] + "." + b[2] + ".x …";
            var up = new ConcurrentDictionary<string, int>();
            ForEachParallel(hosts, 64, ct, h =>
            {
                using (var p = new Ping()) { try { var r = p.Send(h, 500); if (r.Status == IPStatus.Success) up[h.ToString()] = (int)r.RoundtripTime; } catch { } }
                Interlocked.Increment(ref Done);
            });

            // devices that ignore ping still show up in the ARP table
            var macs = new Dictionary<string, string>();
            try
            {
                var psi = new ProcessStartInfo("arp.exe", "-a") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
                using (var p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd(); p.WaitForExit(4000);
                    foreach (Match m in Regex.Matches(o, @"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+dynamic", RegexOptions.IgnoreCase))
                    {
                        string a = m.Groups[1].Value;
                        if (a.StartsWith(b[0] + "." + b[1] + "." + b[2] + ".")) { macs[a] = m.Groups[2].Value.ToUpperInvariant().Replace('-', ':'); if (!up.ContainsKey(a)) up[a] = -1; }
                    }
                }
            }
            catch { }

            Status = "Looking up device names…";
            var names = new ConcurrentDictionary<string, string>();
            ForEachParallel(up.Keys.ToList(), 16, ct, a =>
            {
                try { var t = Task.Run(() => Dns.GetHostEntry(a).HostName); if (t.Wait(1500)) names[a] = t.Result; } catch { }
            });

            foreach (var a in up.Keys.OrderBy(x => IPAddress.Parse(x).GetAddressBytes()[3]))
            {
                string nm; names.TryGetValue(a, out nm); string mac; macs.TryGetValue(a, out mac);
                bool isGw = gw != null && gw.ToString() == a;
                Add(isGw ? NSev.Ok : NSev.Info, a + (isGw ? "  (your router)" : "") + (string.IsNullOrEmpty(nm) ? "" : " · " + nm),
                    (up[a] >= 0 ? "answers ping in " + up[a] + " ms" : "doesn't answer ping, but is on the network") + (mac != null ? " · MAC " + mac : ""));
            }
            Add(NSev.Info, up.Count + " other device" + (up.Count == 1 ? "" : "s") + " found", "Check this list for anything you don't recognise. Phones with a private Wi-Fi address and sleeping devices may not show up.");
        }

        // ------------------------------------------------------------------ 4. port scanner

        public static List<int> ParsePorts(string spec, out string error)
        {
            error = null;
            var ports = new SortedSet<int>();
            string s = (spec ?? "").Trim().ToLowerInvariant();
            if (s.Length == 0 || s == "top100" || s == "top") s = Top100;
            if (s == "common") s = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443";
            foreach (string part in s.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var m = Regex.Match(part, @"^(\d+)(?:-(\d+))?$");
                if (!m.Success) { error = "\"" + part + "\" isn't a port. Use numbers like 22,80,443 or a range like 1-1024, or top100."; return null; }
                int a = int.Parse(m.Groups[1].Value), b = m.Groups[2].Success ? int.Parse(m.Groups[2].Value) : a;
                if (a < 1 || b > 65535 || b < a) { error = "Ports must be between 1 and 65535."; return null; }
                for (int p = a; p <= b; p++) ports.Add(p);
            }
            return ports.ToList();
        }

        /// <summary>Turns "host", "1.2.3.4" or "192.168.1.0/24" into addresses. Returns null with an error message when it can't.</summary>
        public static List<IPAddress> ParseTargets(string target, out string error)
        {
            error = null;
            string t = (target ?? "").Trim();
            if (t.Length == 0) { error = "Type a target: a host name, an IP address, or a network like 192.168.1.0/24."; return null; }
            var cidr = Regex.Match(t, @"^(\d+\.\d+\.\d+\.\d+)/(\d+)$");
            try
            {
                if (cidr.Success)
                {
                    int nn = int.Parse(cidr.Groups[2].Value);
                    if (nn < 22 || nn > 32) { error = "Networks bigger than /22 (1024 addresses) aren't allowed."; return null; }
                    uint ip = BitConverter.ToUInt32(IPAddress.Parse(cidr.Groups[1].Value).GetAddressBytes().Reverse().ToArray(), 0);
                    uint mask = nn == 0 ? 0 : 0xFFFFFFFFu << (32 - nn);
                    uint net = ip & mask, last = net | ~mask;
                    var list = new List<IPAddress>();
                    for (uint a = nn >= 31 ? net : net + 1; a <= (nn >= 31 ? last : last - 1) && list.Count < 1024; a++) list.Add(new IPAddress(BitConverter.GetBytes(a).Reverse().ToArray()));
                    return list;
                }
                IPAddress single;
                if (IPAddress.TryParse(t, out single)) return new List<IPAddress> { single };
                var addrs = Dns.GetHostAddresses(t).Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
                if (addrs.Count == 0) { error = "\"" + t + "\" has no IPv4 address."; return null; }
                return new List<IPAddress> { addrs[0] };
            }
            catch (Exception ex) { error = "Couldn't understand \"" + t + "\": " + ex.GetBaseException().Message; return null; }
        }

        public bool RunPortScan(string target, string ports, bool allowPublic)
        {
            return Start("Port scan of " + target, false, ct =>
            {
                string err;
                var pl = ParsePorts(ports, out err);
                if (pl == null) { Add(NSev.Fail, "Can't scan", err); return; }
                var hosts = ParseTargets(target, out err);
                if (hosts == null) { Add(NSev.Fail, "Can't scan", err); return; }
                if (!allowPublic && hosts.Any(h => !IsPrivate(h))) { Add(NSev.Fail, "Blocked: not a private address", "That address is on the public internet. Only scan systems you own or have permission to test."); return; }
                if ((long)hosts.Count * pl.Count > 250000) { Add(NSev.Fail, "That's too many probes", hosts.Count + " hosts × " + pl.Count + " ports. Pick fewer ports or a smaller network."); return; }

                if (hosts.Count > 1)
                {
                    Status = "Finding which of the " + hosts.Count + " addresses are alive…"; Total = hosts.Count; Done = 0;
                    var alive = new ConcurrentBag<IPAddress>();
                    ForEachParallel(hosts, 64, ct, h => { using (var p = new Ping()) { try { if (p.Send(h, 600).Status == IPStatus.Success) alive.Add(h); } catch { } } Interlocked.Increment(ref Done); });
                    hosts = alive.OrderBy(a => a.GetAddressBytes()[3]).ToList();
                    Add(NSev.Info, hosts.Count + " live host" + (hosts.Count == 1 ? "" : "s") + " to scan", string.Join(", ", hosts.Take(20)) + (hosts.Count > 20 ? "…" : ""));
                }

                var scanRules = IgnoreRules();
                int openTotal = 0, hostsDone = 0;
                Total = hosts.Count * pl.Count; Done = 0;
                foreach (var host in hosts)
                {
                    ct.ThrowIfCancellationRequested();
                    Status = "Scanning " + host + " (" + (++hostsDone) + " of " + hosts.Count + ")…";
                    var open = new ConcurrentBag<int>();
                    int timeout = IPAddress.IsLoopback(host) ? 250 : 700;
                    ForEachParallel(pl, 128, ct, port => { if (TcpOpen(host, port, timeout)) open.Add(port); Interlocked.Increment(ref Done); });
                    foreach (int port in open.OrderBy(x => x))
                    {
                        string banner = Banner(host, port, 800);
                        string advice; bool risky = Risky.TryGetValue(port, out advice);
                        string iwhy = IgnoredBecause("TCP", port, IPAddress.IsLoopback(host) ? "System" : null, scanRules);
                        var sx = new NetResult { Proto = "TCP", Port = port, Ignored = iwhy != null, IgnoreWhy = iwhy ?? "" };
                        Add(risky && iwhy == null ? NSev.Warn : NSev.Info, host + ":" + port + " open · " + Svc(port) + (iwhy != null ? "  · ignored (" + iwhy + ")" : ""), (banner != null && banner.Length > 0 ? "\"" + (banner.Length > 80 ? banner.Substring(0, 80) : banner) + "\" " : "") + (risky && iwhy == null ? advice : ""), sx);
                        openTotal++;
                    }
                    if (!open.Any()) Add(NSev.Ok, host + " has no open ports among the " + pl.Count + " checked", "Closed or filtered by a firewall.");
                }
                Add(NSev.Info, "Scan finished: " + openTotal + " open port" + (openTotal == 1 ? "" : "s") + " on " + hosts.Count + " host" + (hosts.Count == 1 ? "" : "s"), "TCP only. Anything open that you don't expect is worth investigating.");
            });
        }

        // ------------------------------------------------------------------ 5. ping, traceroute, DNS lookup

        public bool RunPing(string host)
        {
            return Start("Ping " + host, false, ct =>
            {
                string h = (host ?? "").Trim();
                if (h.Length == 0) { Add(NSev.Fail, "Type a host name or IP address first"); return; }
                Total = 4; Done = 0;
                var st = new PingStat();
                using (var p = new Ping())
                    for (int i = 0; i < 4; i++)
                    {
                        ct.ThrowIfCancellationRequested();
                        Status = "Pinging " + h + "…"; Done = i;
                        try
                        {
                            var r = p.Send(h, 2000); st.Sent++;
                            if (r.Status == IPStatus.Success) { st.Ok++; st.Sum += r.RoundtripTime; st.Min = Math.Min(st.Min, (int)r.RoundtripTime); st.Max = Math.Max(st.Max, (int)r.RoundtripTime); Add(NSev.Ok, "Reply from " + r.Address + ": " + r.RoundtripTime + " ms", "TTL " + (r.Options != null ? r.Options.Ttl.ToString() : "?")); }
                            else Add(NSev.Warn, h + ": " + r.Status, "No reply to ping " + (i + 1));
                        }
                        catch (Exception ex) { st.Sent++; Add(NSev.Fail, "Couldn't ping " + h, ex.GetBaseException().Message); break; }
                        Thread.Sleep(300);
                    }
                Add(st.Ok == st.Sent && st.Sent > 0 ? NSev.Ok : st.Ok == 0 ? NSev.Fail : NSev.Warn, st.Ok + " of " + st.Sent + " replies" + (st.Ok > 0 ? ", " + st.Min + "–" + st.Max + " ms (average " + st.Avg + " ms)" : ""));
            });
        }

        public bool RunTrace(string host)
        {
            return Start("Trace route to " + host, false, ct =>
            {
                string h = (host ?? "").Trim();
                if (h.Length == 0) { Add(NSev.Fail, "Type a host name or IP address first"); return; }
                IPAddress dest;
                try { dest = IPAddress.TryParse(h, out dest) ? dest : Dns.GetHostAddresses(h).First(a => a.AddressFamily == AddressFamily.InterNetwork); }
                catch (Exception ex) { Add(NSev.Fail, "Can't find " + h, ex.GetBaseException().Message); return; }
                Total = 30; Done = 0; int silent = 0;
                using (var p = new Ping())
                    for (int ttl = 1; ttl <= 30; ttl++)
                    {
                        ct.ThrowIfCancellationRequested();
                        Done = ttl; Status = "Hop " + ttl + " towards " + dest + "…";
                        PingReply r = null;
                        try { r = p.Send(dest, 2000, new byte[32], new PingOptions(ttl, true)); } catch { }
                        if (r == null || (r.Status != IPStatus.TtlExpired && r.Status != IPStatus.Success)) { silent++; Add(NSev.Warn, "Hop " + ttl + ": no answer", "This router doesn't reply (common), or the path is blocked."); if (silent >= 5) { Add(NSev.Fail, "Gave up after 5 silent hops", "Something along the path isn't forwarding or answering."); return; } continue; }
                        silent = 0;
                        string name = ""; try { var t = Task.Run(() => Dns.GetHostEntry(r.Address).HostName); if (t.Wait(800)) name = " · " + t.Result; } catch { }
                        Add(r.Status == IPStatus.Success ? NSev.Ok : NSev.Info, "Hop " + ttl + ": " + r.Address + name, r.RoundtripTime + " ms");
                        if (r.Status == IPStatus.Success) { Add(NSev.Ok, "Reached " + dest + " in " + ttl + " hops"); return; }
                    }
                Add(NSev.Warn, "Didn't reach " + dest + " within 30 hops");
            });
        }

        public bool RunDns(string host)
        {
            return Start("DNS lookup of " + host, false, ct =>
            {
                string h = (host ?? "").Trim();
                if (h.Length == 0) { Add(NSev.Fail, "Type a host name or IP address first"); return; }
                IPAddress ip;
                var sw = Stopwatch.StartNew();
                try
                {
                    if (IPAddress.TryParse(h, out ip))
                    {
                        var e = Dns.GetHostEntry(ip);
                        Add(NSev.Ok, ip + " is named " + e.HostName, sw.ElapsedMilliseconds + " ms (reverse lookup)");
                    }
                    else
                    {
                        var e = Dns.GetHostEntry(h);
                        Add(NSev.Ok, h + " → " + string.Join(", ", e.AddressList.Select(a => a.ToString())), sw.ElapsedMilliseconds + " ms" + (e.HostName != h ? " · canonical name " + e.HostName : ""));
                    }
                }
                catch (Exception ex) { Add(NSev.Fail, "Lookup of " + h + " failed", ex.GetBaseException().Message); }
                // ask each DNS server directly too, to find one that's broken
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up))
                    foreach (var d in nic.GetIPProperties().DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Distinct().Take(3))
                    {
                        int ms;
                        if (!IPAddress.TryParse(h, out ip) && DnsQuery(d, h, 2000, out ms)) Add(NSev.Ok, "DNS server " + d + " resolves it", ms + " ms");
                        else if (!IPAddress.TryParse(h, out ip)) Add(NSev.Warn, "DNS server " + d + " didn't answer", "No reply to a direct question.");
                    }
            });
        }
    }
}
