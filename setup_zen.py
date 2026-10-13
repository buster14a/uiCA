#!/usr/bin/env python3
"""Explicit pinned setup. Analysis itself never downloads or builds anything."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import urllib.request

from zen_import import convert

ROOT = Path(__file__).resolve().parent


def run(arguments, cwd=ROOT):
    subprocess.run(arguments, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xml', type=Path, default=ROOT / 'instructions.xml')
    parser.add_argument('--download', action='store_true', help='explicitly download and verify the pinned XML')
    parser.add_argument('--no-intel', action='store_true', help='omit the original Intel table conversion')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'zen-lock.json').read_text())
    try:
        if importlib.metadata.version('setuptools') != lock['setuptools']:
            raise ValueError('install setuptools==' + lock['setuptools'] + ' in this Python environment')
        run(['git', 'submodule', 'update', '--init'])
        for directory, key in (('XED-to-XML', 'xed'), ('mbuild', 'mbuild')):
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT / directory, text=True).strip()
            dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT / directory, text=True)
            if revision != lock[key] or dirty:
                raise ValueError(directory + ' must be clean at its locked revision')
        if args.download:
            args.xml.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=args.xml.parent) as temporary:
                downloaded = Path(temporary) / 'instructions.xml'
                with urllib.request.urlopen(lock['data_url'], timeout=30) as response, downloaded.open('wb') as output:
                    count = 0
                    while chunk := response.read(1024 * 1024):
                        count += len(chunk)
                        if count > lock['data_bytes']:
                            raise ValueError('download exceeds pinned data size')
                        output.write(chunk)
                # Verify before replacing any existing cache.
                convert(downloaded, lock)
                downloaded.replace(args.xml)
        data = convert(args.xml, lock)
        encoded = (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if hashlib.sha256(encoded).hexdigest() != lock['import_sha256']:
            raise ValueError('import output differs from the pinned conversion')
        run([sys.executable, 'mfile.py', '--opt=2', '--no-encoder', 'pymodule'], ROOT / 'XED-to-XML')
        name = 'xed' + sysconfig.get_config_var('EXT_SUFFIX')
        shutil.copyfile(ROOT / 'XED-to-XML' / name, ROOT / name)
        compiler = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
        receipt = {'artifact': name, 'sha256': hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                   'source_revision': lock['xed'], 'mbuild_revision': lock['mbuild'],
                   'python': sys.version, 'compiler': compiler,
                   'build_arguments': ['--opt=2', '--no-encoder', 'pymodule']}
        (ROOT / '.zen-decoder.json').write_text(json.dumps(receipt, indent=2) + '\n')
        (ROOT / 'zen-data.json').write_bytes(encoded)
        if not args.no_intel:
            run([sys.executable, 'convertXML.py', str(args.xml.resolve())])
        print('Pinned AMD setup complete; Intel conversion ' + ('omitted.' if args.no_intel else 'complete.'))
    except (ValueError, OSError, subprocess.SubprocessError, importlib.metadata.PackageNotFoundError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    main()
