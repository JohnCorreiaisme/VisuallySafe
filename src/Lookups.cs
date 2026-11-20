using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;

namespace VisuallySafe
{
    /// <summary>Checks a file's Authenticode signature with Windows' own trust engine.</summary>
    static class Trust
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData, pSIPClientData;
            public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData, pwszURLReference;
            public uint dwProvFlags, dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct, dwCatalogVersion;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
            public IntPtr hMemberFile, pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext, hCatAdmin;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string hashAlg, IntPtr policy, uint flags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref uint cb, byte[] hash, uint flags);
        [DllImport("wintrust.dll")] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint cb, uint flags, IntPtr prev);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern bool CryptCATCatalogInfoFromContext(IntPtr cat, ref CATALOG_INFO info, uint flags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr cat, uint flags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
        [DllImport("wintrust.dll", ExactSpelling = true)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, IntPtr data);

        /// <summary>
        /// Most of Windows' own programs aren't signed inside the file; their hashes are listed in signed
        /// catalog files instead. True when the file is in such a catalog and the catalog checks out.
        /// </summary>
        static bool CatalogSigned(string path)
        {
            foreach (string alg in new[] { "SHA256", null })
            {
                IntPtr admin;
                if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
                IntPtr cat = IntPtr.Zero;
                try
                {
                    byte[] hash = new byte[64]; uint cb = (uint)hash.Length;
                    using (var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete))
                        if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle.DangerousGetHandle(), ref cb, hash, 0)) continue;
                    Array.Resize(ref hash, (int)cb);
                    cat = CryptCATAdminEnumCatalogFromHash(admin, hash, cb, 0, IntPtr.Zero);
                    if (cat == IntPtr.Zero) continue;
                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO)) };
                    if (!CryptCATCatalogInfoFromContext(cat, ref info, 0)) continue;

                    var sb = new System.Text.StringBuilder();
                    foreach (byte b in hash) sb.Append(b.ToString("X2"));
                    var ci = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)),
                        pcwszCatalogFilePath = info.wszCatalogFile,
                        pcwszMemberTag = sb.ToString(),
                        pcwszMemberFilePath = path,
                        hCatAdmin = admin
                    };
                    IntPtr pCi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                    IntPtr pData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
                    try
                    {
                        Marshal.StructureToPtr(ci, pCi, false);
                        var d = new WINTRUST_DATA
                        {
                            cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                            dwUIChoice = 2, dwUnionChoice = 2, // catalog
                            pFile = pCi,
                            dwProvFlags = 0x1000 | 0x10
                        };
                        Marshal.StructureToPtr(d, pData, false);
                        Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                        if (WinVerifyTrust(new IntPtr(-1), ref action, pData) == 0) return true;
                    }
                    finally
                    {
                        Marshal.DestroyStructure(pCi, typeof(WINTRUST_CATALOG_INFO));
                        Marshal.FreeHGlobal(pCi); Marshal.FreeHGlobal(pData);
                    }
                }
                catch { }
                finally
                {
                    if (cat != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                    CryptCATAdminReleaseContext(admin, 0);
                }
            }
            return false;
        }

        /// <summary>Returns the signer's name when the file carries a valid, trusted signature; otherwise null.</summary>
        public static string TrustedSigner(string path)
        {
            var fi = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = path
            };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            try
            {
                Marshal.StructureToPtr(fi, pFile, false);
                var d = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = 2,          // no UI
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 1,       // file
                    pFile = pFile,
                    dwStateAction = 0,
                    dwProvFlags = 0x1000 | 0x10 // cache-only retrieval, no revocation (stay offline and fast)
                };
                Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                if (WinVerifyTrust(new IntPtr(-1), ref action, ref d) != 0) return CatalogSigned(path) ? "Windows (catalog signature)" : null;
                try
                {
                    using (var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
                    {
                        string n = cert.GetNameInfo(X509NameType.SimpleName, false);
                        return string.IsNullOrEmpty(n) ? "a trusted publisher" : n;
                    }
                }
                catch { return "a trusted publisher"; }
            }
            catch { return null; }
            finally
            {
                Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pFile);
            }
        }
    }

    enum CloudAnswer { NotFound, Good, Bad }

    /// <summary>Free online hash lookups. Only hashes leave the PC, never file contents or names.</summary>
    static class Cloud
    {
        static readonly HttpClient http = Make();

        static HttpClient Make()
        {
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("VisuallySafe/" + Engine.Version);
            return h;
        }

        /// <summary>Team Cymru Malware Hash Registry over DNS (MD5). True when listed as malware.</summary>
        public static bool CymruListed(string md5)
        {
            try
            {
                return Dns.GetHostAddresses(md5 + ".malware.hash.cymru.com")
                          .Any(a => a.ToString().StartsWith("127.0.0."));
            }
            catch (SocketException) { return false; }
        }

        /// <summary>CIRCL hashlookup: big database of known files; flags the known-malicious ones.</summary>
        public static CloudAnswer Circl(string sha256, out string detail)
        {
            detail = "";
            using (var resp = http.GetAsync("https://hashlookup.circl.lu/lookup/sha256/" + sha256).GetAwaiter().GetResult())
            {
                if (resp.StatusCode == HttpStatusCode.NotFound) return CloudAnswer.NotFound;
                resp.EnsureSuccessStatusCode();
                string json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json);
                if (d == null) return CloudAnswer.NotFound;
                if (d.TryGetValue("KnownMalicious", out object bad) && bad != null)
                {
                    detail = "Listed as malware (" + bad + ", via CIRCL)";
                    return CloudAnswer.Bad;
                }
                string product = null;
                if (d.TryGetValue("ProductCode", out object pc) && pc is Dictionary<string, object> pd
                    && pd.TryGetValue("ProductName", out object pn)) product = pn as string;
                detail = string.IsNullOrEmpty(product)
                    ? "Known file in the CIRCL database"
                    : "Known file: part of " + product;
                return CloudAnswer.Good;
            }
        }

        /// <summary>abuse.ch MalwareBazaar (needs the user's free key). Returns a family name, "" if listed without one, or null.</summary>
        public static string MalwareBazaar(string sha256, string key)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/");
            req.Headers.Add("Auth-Key", key);
            req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "query", "get_info" }, { "hash", sha256 }
            });
            using (var resp = http.SendAsync(req).GetAwaiter().GetResult())
            {
                resp.EnsureSuccessStatusCode();
                string json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json);
                if (d == null || !d.TryGetValue("query_status", out object st) || (st as string) != "ok") return null;
                try
                {
                    var first = ((System.Collections.ArrayList)d["data"])[0] as Dictionary<string, object>;
                    return first != null && first.TryGetValue("signature", out object sig) && sig != null ? sig.ToString() : "";
                }
                catch { return ""; }
            }
        }
    }
}
