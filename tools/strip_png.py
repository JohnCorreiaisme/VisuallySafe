"""Removes the text/metadata chunks from PNG files (Blender writes the full path of the .blend file into them).
   python tools/strip_png.py art/frames
"""
import os, struct, sys

KEEP = {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS', b'gAMA', b'sRGB', b'cHRM', b'pHYs'}

def strip(path):
    data = open(path, 'rb').read()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return 0
    out = [data[:8]]; pos = 8; dropped = 0
    while pos < len(data):
        (n,) = struct.unpack('>I', data[pos:pos + 4]); typ = data[pos + 4:pos + 8]
        chunk = data[pos:pos + 12 + n]
        if typ in KEEP:
            out.append(chunk)
        else:
            dropped += 1
        pos += 12 + n
    if dropped:
        open(path, 'wb').write(b''.join(out))
    return dropped

total = 0
for root in sys.argv[1:] or ['.']:
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.lower().endswith('.png'):
                total += strip(os.path.join(dirpath, f))
print('removed', total, 'metadata chunks')
