using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace TinyGuard
{
    /// <summary>
    /// Small offline malware model (gradient-boosted trees trained on EMBER 2018, see train/train.py).
    /// Features must match train.py exactly: byte histogram, byte-entropy histogram, string stats, log size.
    /// </summary>
    class AiModel
    {
        public const int NFeat = 617;
        const long MaxBytes = 64L * 1024 * 1024;

        class Tree { public int[] Feat, Left, Right; public double[] Thr, Leaf; }
        readonly List<Tree> trees = new List<Tree>();

        static readonly Regex StrRx = new Regex("[\x20-\x7f]{5,}", RegexOptions.Compiled);
        static readonly Regex PathRx = new Regex(@"c:\\", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex UrlRx = new Regex("https?://", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex RegRx = new Regex("HKEY_", RegexOptions.Compiled);
        static readonly Regex MzRx = new Regex("MZ", RegexOptions.Compiled);

        public static AiModel TryLoad(string path)
        {
            try { return File.Exists(path) ? new AiModel(path) : null; } catch { return null; }
        }

        AiModel(string path)
        {
            var ci = CultureInfo.InvariantCulture;
            using (var r = new StreamReader(path))
            {
                string[] head = r.ReadLine().Split(' ');
                if (head[0] != "TGMODEL" || int.Parse(head[2]) != NFeat) throw new InvalidDataException("bad model");
                int n = int.Parse(head[3]);
                for (int t = 0; t < n; t++)
                {
                    string[] th = r.ReadLine().Split(' ');
                    int nn = int.Parse(th[1]);
                    var tr = new Tree { Feat = new int[nn], Left = new int[nn], Right = new int[nn], Thr = new double[nn] };
                    for (int i = 0; i < nn; i++)
                    {
                        string[] p = r.ReadLine().Split(' ');
                        tr.Feat[i] = int.Parse(p[0]); tr.Thr[i] = double.Parse(p[1], ci);
                        tr.Left[i] = int.Parse(p[2]); tr.Right[i] = int.Parse(p[3]);
                    }
                    string[] lv = r.ReadLine().Split(' ');
                    tr.Leaf = new double[lv.Length];
                    for (int i = 0; i < lv.Length; i++) tr.Leaf[i] = double.Parse(lv[i], ci);
                    trees.Add(tr);
                }
            }
        }

        public int TreeCount { get { return trees.Count; } }

        /// <summary>Malware likelihood 0..1, or -1 if the file can't be read.</summary>
        public double Score(string path)
        {
            byte[] b;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length == 0 || fs.Length > MaxBytes) return -1;
                    b = new byte[fs.Length];
                    int off = 0, n;
                    while (off < b.Length && (n = fs.Read(b, off, b.Length - off)) > 0) off += n;
                }
            }
            catch { return -1; }
            return Predict(Features(b));
        }

        public double Predict(float[] x)
        {
            double sum = 0;
            foreach (var t in trees)
            {
                int i = 0;
                if (t.Feat.Length == 0) { sum += t.Leaf[0]; continue; }
                while (i >= 0) i = x[t.Feat[i]] <= t.Thr[i] ? t.Left[i] : t.Right[i];
                sum += t.Leaf[~i];
            }
            return 1.0 / (1.0 + Math.Exp(-sum));
        }

        public static float[] Features(byte[] b)
        {
            var x = new float[NFeat];
            int n = b.Length;

            // byte histogram
            var hist = new long[256];
            foreach (byte v in b) hist[v]++;
            for (int i = 0; i < 256; i++) x[i] = (float)((double)hist[i] / n);

            // byte-entropy histogram: 2048-byte windows every 1024 bytes
            const int window = 2048, step = 1024;
            var be = new long[256];
            var c = new int[16];
            Action<int, int> block = (start, len) =>
            {
                Array.Clear(c, 0, 16);
                for (int i = start; i < start + len; i++) c[b[i] >> 4]++;
                double h = 0;
                for (int k = 0; k < 16; k++)
                    if (c[k] > 0) { float p = (float)c[k] / window; h -= p * Math.Log(p, 2); }
                int bin = (int)(h * 2 * 2);
                if (bin == 16) bin = 15;
                for (int k = 0; k < 16; k++) be[bin * 16 + k] += c[k];
            };
            if (n < window) block(0, n);
            else for (int s = 0; s + window <= n; s += step) block(s, window);
            long beSum = 0; foreach (long v in be) beSum += v;
            for (int i = 0; i < 256; i++) x[256 + i] = beSum > 0 ? (float)((double)be[i] / beSum) : 0;

            // printable strings
            string text = Encoding.GetEncoding(28591).GetString(b); // one char per byte
            var dist = new long[96];
            long numStr = 0, totalLen = 0;
            foreach (Match m in StrRx.Matches(text))
            {
                numStr++; totalLen += m.Length;
                for (int i = m.Index; i < m.Index + m.Length; i++) dist[text[i] - 0x20]++;
            }
            long printables = totalLen;
            double ent = 0;
            if (printables > 0)
                foreach (long v in dist)
                    if (v > 0) { double p = (double)v / printables; ent -= p * Math.Log(p, 2); }
            int o = 512;
            x[o++] = numStr;
            x[o++] = numStr > 0 ? (float)((double)totalLen / numStr) : 0;
            x[o++] = printables;
            for (int i = 0; i < 96; i++) x[o++] = printables > 0 ? (float)((double)dist[i] / printables) : dist[i];
            x[o++] = (float)ent;
            x[o++] = PathRx.Matches(text).Count;
            x[o++] = UrlRx.Matches(text).Count;
            x[o++] = RegRx.Matches(text).Count;
            x[o++] = MzRx.Matches(text).Count;
            x[o] = (float)(Math.Log(n + 1) / Math.Log(2));
            return x;
        }
    }
}
