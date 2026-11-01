#!/usr/bin/env python3
"""Build with JDK 17+; API dependency is verified and never bundled in the extension."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
API = ROOT / 'lib' / 'burp-extender-api-2.3.jar'
API_URL = 'https://repo.maven.apache.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.3/burp-extender-api-2.3.jar'
API_SHA256 = '0b9b16048e1a3d10bb8f36219bb7dfa637dad2d54e116199d3506b4174518e54'


def run(args):
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    API.parent.mkdir(exist_ok=True)
    if not API.exists():
        with urllib.request.urlopen(API_URL, timeout=30) as response:
            data = response.read(1024 * 1024)
        if hashlib.sha256(data).hexdigest() != API_SHA256:
            raise RuntimeError('API dependency checksum mismatch')
        API.write_bytes(data)
    if hashlib.sha256(API.read_bytes()).hexdigest() != API_SHA256:
        raise RuntimeError('API dependency checksum mismatch')
    out = ROOT / 'build'
    out.mkdir(exist_ok=True)
    sources = sorted((ROOT / 'src/main/java').rglob('*.java'))
    run(['java', 'com.sun.tools.javac.Main', '--release', '8', '-encoding', 'UTF-8',
         '-cp', str(API), '-d', str(out)] + list(map(str, sources)))
    if args.test:
        tests = out / 'tests'
        tests.mkdir(exist_ok=True)
        import os
        cp = os.pathsep.join([str(API), str(out)])
        run(['java', 'com.sun.tools.javac.Main', '-encoding', 'UTF-8', '-cp', cp,
             '-d', str(tests), 'tests/RegressionTest.java'])
        run(['java', '-Djava.awt.headless=true', '-Dsun.net.http.allowRestrictedHeaders=true',
             '-cp', cp + os.pathsep + str(tests), 'RegressionTest'])
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    jar = dist / 'CORS-Hunter-1.0.1.jar'
    with zipfile.ZipFile(jar, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\nImplementation-Title: CORS Hunter\r\nImplementation-Version: 1.0.1\r\n\r\n')
        for package in ('burp', 'hunter'):
            for file in sorted((out / package).rglob('*.class')):
                z.write(file, file.relative_to(out).as_posix())
    print('Built:', jar)
    print('SHA256:', hashlib.sha256(jar.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
