#!/usr/bin/env python3
"""Explicit, pinned local download of the upstream browser interface.

The separate site's license is unverified: downloaded source is local only,
excluded from git. This adapter is original AGPL fork source. No CGI backend
is downloaded, and no shortener credential is persisted or used.
"""
import argparse
import hashlib
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / '.uica-web'
LOCK = ROOT / 'uica-web-lock.json'


class ClientHTMLParser(HTMLParser):
    """Preserve the downloaded document while removing selected script nodes."""
    def __init__(self, all_scripts):
        super().__init__(convert_charrefs=False)
        self.all_scripts = all_scripts
        self.dropping_script = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            src = urlsplit(dict(attrs).get('src') or '')
            self.dropping_script = self.all_scripts or (src.hostname in ('uops.info', 'www.uops.info') and src.path == '/m.js')
        if not self.dropping_script:
            if self.all_scripts:
                attributes = ''.join(' ' + name + ('="' + html.escape(value, quote=True) + '"' if value is not None else '')
                                     for name, value in attrs if not name.startswith('on'))
                self.parts.append('<' + tag + attributes + '>')
            else:
                self.parts.append(self.get_starttag_text())

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if not self.dropping_script and not self.parts[-1].endswith('/>'):
            self.parts[-1] = self.parts[-1][:-1] + '/>'
        if tag == 'script':
            self.dropping_script = False

    def handle_endtag(self, tag):
        if not self.dropping_script:
            self.parts.append('</' + tag + '>')
        if tag == 'script':
            self.dropping_script = False

    def handle_data(self, data):
        if not self.dropping_script:
            self.parts.append(data)

    def handle_entityref(self, name):
        self.handle_data('&' + name + ';')

    def handle_charref(self, name):
        self.handle_data('&#' + name + ';')

    def handle_comment(self, data):
        self.handle_data('<!--' + data + '-->')

    def handle_decl(self, decl):
        self.handle_data('<!' + decl + '>')


def filter_client(source, all_scripts):
    parser = ClientHTMLParser(all_scripts)
    parser.feed(source)
    parser.close()
    return ''.join(parser.parts)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sanitize_reference(source):
    # Remove the entire third-party shortening function, including its embedded
    # credential, BEFORE writing any downloaded source to disk.
    source, count = re.subn(r'function createURL\(\)\s*\{.*?(?=function restoreFromURL\()',
                           'function createURL() {\n    copyURLToClipboard(window.location.href.split("?")[0] + "?" + $("#form").serialize())\n}\n\n',
                           source, flags=re.S)
    if count != 1:
        raise ValueError('Pinned frontend layout changed; refusing to save unsanitized source.')
    source = filter_client(source, all_scripts=False)
    if re.search(r'bitly|Bearer\s+|uops\.info/m\.js', source, re.I):
        raise ValueError('Unexpected credential/telemetry reference; refusing to save source.')
    return '<!-- Local reference from https://uica.uops.info/; telemetry and URL shortening removed. Separate frontend license unverified. -->\n' + source


def adapt(source):
    """Patch the actual downloaded DOM/style; never replace it with a mockup."""
    source = filter_client(source, all_scripts=True)
    source = source.replace('https://www.jacklmoore.com/colorbox/example2/colorbox.css', '/vendor/colorbox.css')
    source = source.replace('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css', '/vendor/font-awesome.css')
    source = source.replace('<title>uiCA</title>', '<title>uiCA — local Intel &amp; AMD analyzer</title>')
    source = source.replace('</head>', '<meta name="viewport" content="width=device-width, initial-scale=1">\n<link rel="stylesheet" href="/local.css">\n<script src="/adapter.js" defer></script>\n</head>')
    source = source.replace('<hr>', '<hr><p id="localNotice"><strong>Local fork · Experimental AMD bounds</strong> — Intel uses the original uiCA pipeline model. Zen 4/5 show conditional bounds, not full throughput predictions; hardware qualification is pending.</p>', 1)
    source = source.replace('id="cb_SKL" value="SKL" checked', 'id="cb_SKL" value="SKL"')
    source = source.replace('</select></td>', '<br><label><input type="checkbox" name="uArchs" value="ZEN4" checked>AMD Zen 4</label> <label><input type="checkbox" name="uArchs" value="ZEN5" checked>AMD Zen 5</label></td>', 1)
    source = source.replace('<textarea name="code"', '<textarea aria-label="Assembly or hex code" name="code"')
    source = source.replace('value="Run!"', 'id="runButton" value="Run!" disabled')
    source = source.replace('value="Get URL!"', 'id="urlButton" value="Get URL!"')
    source = source.replace('<div id="outputDiv"></div>', '<div id="outputDiv" role="status" aria-live="polite"></div>')
    source = source.replace('</form>', '<p id="optionNote">Alignment is modeled only for Intel. Local support: uiCA; dependency views for AMD. Pipeline traces and external tools are unavailable in this adapter.</p>\n<label>Example: <select id="example"><option value="">Choose a block…</option></select></label>\n<label class="upload">or upload <select id="fileMode" aria-label="File format"><option value="raw">Raw machine code</option><option value="object">ELF64 object</option></select> <input type="file" id="file" aria-label="Machine code file"></label>\n</form>')
    return source


def download(entry):
    with urllib.request.urlopen(entry['url'], timeout=30) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024 or digest(data) != entry['sha256']:
        raise ValueError('Pinned web asset hash mismatch: ' + entry['path'])
    return data


def install(fetch=download):
    lock = json.loads(LOCK.read_text())
    # Fetch and validate in memory first. In particular raw index.html is never
    # cached because the published page includes a third-party credential.
    source = sanitize_reference(fetch(lock['frontend']).decode('utf-8'))
    files = {'reference.html': source.encode(), 'index.html': adapt(source).encode()}
    for entry in lock['assets']:
        files[entry['path']] = fetch(entry)
    # Only the modern browser font is needed; eliminate unfetched fallbacks.
    css = files['vendor/font-awesome.css'].decode()
    css = re.sub(r'@font-face\{.*?\}', '@font-face{font-family:FontAwesome;src:url(../fonts/fontawesome-webfont.woff2) format("woff2");font-weight:normal;font-style:normal}', css, count=1)
    files['vendor/font-awesome.css'] = css.encode()
    receipt = {'schema_version': 1, 'frontend_url': lock['frontend']['url'],
               'frontend_original_sha256': lock['frontend']['sha256'],
               'frontend_license': 'unverified; local cache only',
               'removed': ['telemetry', 'third-party shortening function and credential'],
               'files': {name: digest(body) for name, body in files.items()}}
    for name, body in files.items():
        path = CACHE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    (CACHE / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def frontend_assets():
    try:
        receipt = json.loads((CACHE / 'receipt.json').read_text())
        lock = json.loads(LOCK.read_text())
        if receipt['frontend_original_sha256'] != lock['frontend']['sha256']:
            raise ValueError('Frontend receipt does not match the pinned source.')
        names = ['index.html', 'reference.html'] + [entry['path'] for entry in lock['assets']]
        files = {}
        for name in names:
            body = (CACHE / name).read_bytes()
            if digest(body) != receipt['files'][name]:
                raise ValueError('Cached frontend asset changed: ' + name)
            files[name] = body
        for name in ('adapter.js', 'local.css', 'favicon.svg'):
            files[name] = (ROOT / 'web' / name).read_bytes()
        files['receipt.json'] = json.dumps(receipt, indent=2).encode()
        return files
    except (OSError, KeyError, ValueError) as error:
        raise ValueError('Web interface setup is missing or invalid. Run setup_uica_web.py --download. ' + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download', action='store_true', help='explicitly download pinned assets into the local ignored cache')
    args = parser.parse_args()
    if not args.download:
        parser.error('--download is required; no downloads occur when launching or analyzing')
    try:
        receipt = install()
    except (OSError, ValueError) as error:
        parser.exit(2, 'Web setup: %s\n' % error)
    print('Pinned upstream interface ready in .uica-web/ (%d local files).' % len(receipt['files']))


if __name__ == '__main__':
    main()
