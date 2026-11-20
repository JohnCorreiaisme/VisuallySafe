using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

namespace VisuallySafe
{
    /// <summary>Draws Visually Safe's program icon (a green shield with a check on a dark tile) and packs it into a multi-size .ico file.</summary>
    static class IconMaker
    {
        static Bitmap Draw(int size)
        {
            // draw big, then shrink, so the small sizes stay crisp
            int big = size * 4;
            using (var src = new Bitmap(big, big, PixelFormat.Format32bppArgb))
            {
                using (var g = Graphics.FromImage(src))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.Clear(Color.Transparent);
                    float pad = big * 0.02f, w = big - pad * 2, rad = w * 0.22f;

                    // tile
                    var tile = new RectangleF(pad, pad, w, w);
                    using (var path = Theme.Round(tile, rad))
                    {
                        using (var br = new LinearGradientBrush(tile, Color.FromArgb(0x24, 0x33, 0x55), Color.FromArgb(0x08, 0x0D, 0x18), 60f)) g.FillPath(br, path);
                        using (var pen = new Pen(Color.FromArgb(70, 130, 190, 255), big * 0.012f)) g.DrawPath(pen, path);
                        g.SetClip(path);
                        // soft light from the top left
                        using (var gp = new GraphicsPath())
                        {
                            gp.AddEllipse(-big * 0.3f, -big * 0.55f, big * 1.2f, big * 1.0f);
                            using (var pg = new PathGradientBrush(gp) { CenterColor = Color.FromArgb(60, 120, 170, 255), SurroundColors = new[] { Color.FromArgb(0, 120, 170, 255) } }) g.FillPath(pg, gp);
                        }
                        g.ResetClip();
                    }

                    // green glow behind the shield
                    using (var gp = new GraphicsPath())
                    {
                        gp.AddEllipse(big * 0.14f, big * 0.14f, big * 0.72f, big * 0.74f);
                        using (var pg = new PathGradientBrush(gp) { CenterColor = Color.FromArgb(120, 47, 201, 122), SurroundColors = new[] { Color.FromArgb(0, 47, 201, 122) } }) g.FillPath(pg, gp);
                    }

                    // shield
                    var sh = new RectangleF(big * 0.23f, big * 0.17f, big * 0.54f, big * 0.64f);
                    using (var path = new GraphicsPath())
                    {
                        float x = sh.X, y = sh.Y, ww = sh.Width, h = sh.Height;
                        path.AddLine(x + ww * 0.5f, y, x + ww, y + h * 0.16f);
                        path.AddLine(x + ww, y + h * 0.16f, x + ww, y + h * 0.5f);
                        path.AddBezier(x + ww, y + h * 0.5f, x + ww, y + h * 0.78f, x + ww * 0.72f, y + h * 0.93f, x + ww * 0.5f, y + h);
                        path.AddBezier(x + ww * 0.5f, y + h, x + ww * 0.28f, y + h * 0.93f, x, y + h * 0.78f, x, y + h * 0.5f);
                        path.AddLine(x, y + h * 0.5f, x, y + h * 0.16f);
                        path.CloseFigure();
                        using (var br = new LinearGradientBrush(sh, Color.FromArgb(0x5B, 0xE8, 0x9C), Color.FromArgb(0x1F, 0xA8, 0x62), 90f)) g.FillPath(br, path);
                        using (var pen = new Pen(Color.FromArgb(140, 255, 255, 255), big * 0.012f)) g.DrawPath(pen, path);
                        // highlight on the left half
                        g.SetClip(path);
                        using (var br = new LinearGradientBrush(sh, Color.FromArgb(70, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 0f)) g.FillRectangle(br, sh.X, sh.Y, sh.Width * 0.55f, sh.Height);
                        g.ResetClip();
                    }

                    // check mark
                    using (var pen = new Pen(Color.White, big * 0.062f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                        g.DrawLines(pen, new[] { new PointF(sh.X + sh.Width * 0.27f, sh.Y + sh.Height * 0.50f), new PointF(sh.X + sh.Width * 0.44f, sh.Y + sh.Height * 0.66f), new PointF(sh.X + sh.Width * 0.75f, sh.Y + sh.Height * 0.34f) });
                }
                var dst = new Bitmap(size, size, PixelFormat.Format32bppArgb);
                using (var g = Graphics.FromImage(dst))
                {
                    g.InterpolationMode = InterpolationMode.HighQualityBicubic; g.SmoothingMode = SmoothingMode.HighQuality; g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                    g.Clear(Color.Transparent);
                    g.DrawImage(src, 0, 0, size, size);
                }
                return dst;
            }
        }

        public static void Make(string path)
        {
            int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };
            var pngs = new List<byte[]>();
            foreach (int s in sizes)
                using (var bmp = Draw(s)) using (var ms = new MemoryStream()) { bmp.Save(ms, ImageFormat.Png); pngs.Add(ms.ToArray()); }
            using (var fs = new FileStream(path, FileMode.Create))
            using (var bw = new BinaryWriter(fs))
            {
                bw.Write((short)0); bw.Write((short)1); bw.Write((short)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    bw.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i])); bw.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                    bw.Write((byte)0); bw.Write((byte)0); bw.Write((short)1); bw.Write((short)32);
                    bw.Write(pngs[i].Length); bw.Write(offset);
                    offset += pngs[i].Length;
                }
                foreach (var p in pngs) bw.Write(p);
            }
        }
    }
}
