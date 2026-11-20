"""Builds Visually Safe and packs the friendly one-file installer:  python tools/build_setup.py
Output: dist/VisuallySafeSetup-<version>.exe  (+ a .sha256 file). Not signed: a code-signing certificate is what removes Windows' "unknown publisher" box.
"""
import hashlib, os, re, shutil, subprocess, sys, zipfile

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(root)

def run(*cmd):
    print('>', ' '.join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit('failed: ' + ' '.join(cmd))

ver = re.search(r'<Version>([^<]+)</Version>', open('VisuallySafe.csproj', encoding='utf-8').read()).group(1)
run('dotnet', 'build', '-c', 'Release', '-o', 'bin_new')

payload = os.path.join('installer', 'payload.zip')
if os.path.exists(payload):
    os.remove(payload)
with zipfile.ZipFile(payload, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    z.write(os.path.join('bin_new', 'VisuallySafe.exe'), 'VisuallySafe.exe')
    cfg = os.path.join('bin_new', 'VisuallySafe.exe.config')
    if os.path.exists(cfg):
        z.write(cfg, 'VisuallySafe.exe.config')
    z.write(os.path.join('bin', 'visuallysafe.model'), 'visuallysafe.model')
    ydir = os.path.join('bin', 'yara')
    for dirpath, _, files in os.walk(ydir):
        for f in files:
            full = os.path.join(dirpath, f)
            try:
                z.write(full, os.path.relpath(full, 'bin').replace(os.sep, '/'))
            except OSError:      # Defender sometimes blocks the rules file (it holds malware signatures); the app downloads fresh rules itself
                print('skipped (unreadable, likely blocked by Defender):', full)
    z.writestr('version.txt', ver)
print('payload', round(os.path.getsize(payload) / 1048576, 1), 'MB')

out = os.path.join('dist', 'setup')
shutil.rmtree(out, ignore_errors=True)
run('dotnet', 'build', os.path.join('installer', 'VisuallySafeSetup.csproj'), '-c', 'Release', '-o', out)
final = os.path.join('dist', 'VisuallySafeSetup-%s.exe' % ver)
shutil.copyfile(os.path.join(out, 'VisuallySafeSetup.exe'), final)
h = hashlib.sha256(open(final, 'rb').read()).hexdigest()
open(os.path.join('dist', 'VisuallySafeSetup-%s.sha256' % ver), 'w').write('%s  VisuallySafeSetup-%s.exe\n' % (h, ver))
print('done:', final, round(os.path.getsize(final) / 1048576, 1), 'MB')
