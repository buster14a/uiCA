#!/usr/bin/env python3
"""Loopback-only GUI for the pinned AMD analyzer; never executes target bytes."""
import argparse
import base64
import binascii
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
import urllib.request
import webbrowser

from zen_cli import (ROOT, MAX_CODE_BYTES, MAX_INSTRUCTIONS, analyze, decode,
                     extract_text, load_data, provenance, sha256)
from zen_model import MODEL_VERSION
from setup_uica_web import frontend_assets
from zen_trace import amd_trace, MAX_TRACE_INSTRUCTIONS, TRACE_VERSION

WEB = ROOT / 'web'
INTEL_TARGETS = ('SNB', 'IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'KBL', 'CFL', 'CLX', 'ICL', 'TGL', 'RKL')
MAX_REQUEST = 23 * 1024 * 1024
MAX_ASSEMBLY = 32768
EXAMPLES = [
    {'id': 'wide', 'name': 'Independent vector additions', 'tag': 'AVX-512',
     'description': 'Four independent 512-bit additions. Compare the conditional resource bounds.',
     'assembly': 'vpaddd zmm0, zmm1, zmm2\nvpaddd zmm3, zmm4, zmm5\nvpaddd zmm6, zmm7, zmm8\nvpaddd zmm9, zmm10, zmm11'},
    {'id': 'chain', 'name': 'A loop-carried scalar chain', 'tag': 'Scalar',
     'description': 'Each addition feeds the next, including across iterations.',
     'assembly': 'add rax, rbx\nadd rbx, rax'},
    {'id': 'dependent', 'name': 'A dependent vector addition', 'tag': 'AVX-512',
     'description': 'One recurrence has different measured latencies on the two targets.',
     'assembly': 'vpaddd zmm0, zmm0, zmm2'},
    {'id': 'shuffle', 'name': 'Two byte shuffles', 'tag': 'AVX2',
     'description': 'Two independent 256-bit shuffles contend for a narrower resource group.',
     'assembly': 'vpshufb ymm0, ymm1, ymm2\nvpshufb ymm3, ymm4, ymm5'},
    {'id': 'mask', 'name': 'Merge-masked vector addition', 'tag': 'Partial model',
     'description': 'The old destination remains a dependency. Masked resource decomposition is still unqualified.',
     'assembly': 'vpaddd zmm0{k1}, zmm1, zmm2'},
    {'id': 'memory', 'name': 'An L1-load hypothesis', 'tag': 'Coverage gaps',
     'description': 'See explicit gaps instead of invented memory and aliasing costs.',
     'assembly': 'mov rax, qword ptr [rdi]\nadd rdi, 8\nadd rbx, rax'},
]


def assembly_source(text, syntax='asIntel'):
    if syntax not in ('asIntel', 'asATT', 'NASM'):
        raise ValueError('Choose GNU as Intel/AT&T or NASM syntax.')
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > MAX_ASSEMBLY:
        raise ValueError('Enter an assembly block of at most 32 KiB.')
    statements = []
    instructions = 0
    for line in text.splitlines():
        # In NASM, semicolon starts a comment; in GNU as it separates instructions.
        line = line.split(';', 1)[0] if syntax == 'NASM' else line.split('#', 1)[0]
        for statement in ([line] if syntax == 'NASM' else line.split(';')):
            statement = statement.strip()
            if not statement:
                continue
            # Only labels and instructions are accepted. In particular .include,
            # .incbin, macros and repetition/file directives cannot read files
            # or expand an unbounded source. A syntax directive is unnecessary.
            label = re.match(r'^([A-Za-z_][A-Za-z0-9_]*|\.L[A-Za-z0-9_]+):\s*(.*)$', statement)
            if label:
                statements.append(label[1] + ':')
                statement = label[2]
                if not statement:
                    continue
            mnemonic = statement.split(None, 1)[0].lower()
            directives = ('bits', 'section', 'segment', 'global', 'extern', 'default', 'absolute', 'org', 'align', 'alignb',
                          'incbin', 'include', 'times', 'equ', 'db', 'dw', 'dd', 'dq', 'dt', 'do', 'dy', 'dz',
                          'resb', 'resw', 'resd', 'resq', 'rest', 'reso', 'resy', 'resz', 'istruc', 'at', 'iend')
            pattern = r'[A-Za-z][A-Za-z0-9]*(?:\s+[A-Za-z0-9_.$%\[\]{}()*+,\-:\s]+)?'
            nasm_directive = syntax == 'NASM' and any(word.lower() in directives for word in re.findall(r'[A-Za-z][A-Za-z0-9]*', statement))
            if mnemonic in directives or nasm_directive or statement.startswith('.') or not re.fullmatch(pattern, statement):
                raise ValueError('Use instructions, labels and comments only; remove assembler directives.')
            instructions += 1
            if instructions > MAX_INSTRUCTIONS:
                raise ValueError('Use at most %d instructions.' % MAX_INSTRUCTIONS)
            statements.append(statement)
    if not instructions:
        raise ValueError('The block has no instructions.')
    prefix = {'asIntel': '.intel_syntax noprefix\n.text\n', 'asATT': '.att_syntax prefix\n.text\n',
              'NASM': 'BITS 64\nSECTION .text\n'}[syntax]
    return prefix + '\n'.join(statements) + '\n'


def assemble(text, syntax='asIntel'):
    source = assembly_source(text, syntax)
    assembler = shutil.which('nasm' if syntax == 'NASM' else 'as')
    if assembler is None:
        raise ValueError('This syntax needs %s. You can still use hex bytes or upload machine code.' % ('NASM' if syntax == 'NASM' else 'GNU as'))
    with tempfile.TemporaryDirectory(prefix='uica-gui-') as directory:
        path = Path(directory)
        (path / 'block.s').write_text(source)
        try:
            flags = ['-f', 'elf64'] if syntax == 'NASM' else ['--64']
            result = subprocess.run([assembler, *flags, '-o', str(path / 'block.o'), str(path / 'block.s')],
                                    cwd=path, capture_output=True, text=True, timeout=5)
        except subprocess.TimeoutExpired as error:
            raise ValueError('Assembly exceeded its 5-second deadline.') from error
        if result.returncode:
            # Keep the useful assembler message, not a temporary host path.
            message = result.stderr.replace(str(path / 'block.s'), 'block')[-2000:]
            raise ValueError(message.strip() or 'The assembly could not be parsed.')
        if (path / 'block.o').stat().st_size > 16 * 1024 * 1024:
            raise ValueError('Assembled object exceeds the size limit.')
        return extract_text((path / 'block.o').read_bytes())


def input_bytes(request):
    mode = request.get('mode')
    text = request.get('input')
    if not isinstance(text, str):
        raise ValueError('Input must be text or a base64-encoded file.')
    if mode == 'assembly':
        code = assemble(text, request.get('syntax', 'asIntel'))
    elif mode == 'hex':
        if len(text) > MAX_CODE_BYTES * 5:
            raise ValueError('Hex input exceeds the size limit.')
        tokens = text.split()
        if any(t.startswith(('0x', '0X')) for t in tokens):
            if not all(re.fullmatch(r'0[xX][0-9a-fA-F]{2}', t) for t in tokens):
                raise ValueError('Use pairs of hex digits, optionally with 0x on every byte.')
            text = ''.join(t[2:] for t in tokens)
        else:
            text = ''.join(tokens)
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', text):
            raise ValueError('Hex code must contain complete pairs of hex digits.')
        code = bytes.fromhex(text)
    elif mode in ('raw', 'object'):
        try:
            raw = base64.b64decode(text, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError('The uploaded file could not be read.') from error
        if len(raw) > (MAX_CODE_BYTES if mode == 'raw' else 16 * 1024 * 1024):
            raise ValueError('The uploaded file exceeds the size limit.')
        code = extract_text(raw) if mode == 'object' else raw
    else:
        raise ValueError('Choose assembly, hex code, a raw binary or an ELF object.')
    if not 1 <= len(code) <= MAX_CODE_BYTES:
        raise ValueError('The code block must contain 1..%d bytes.' % MAX_CODE_BYTES)
    return code


class Analyzer:
    def __init__(self):
        lock, self.data, digest = load_data(ROOT / 'zen-data.json')
        self.identity = provenance(lock, digest)
        self.identity['gui_source_sha256'] = sha256((ROOT / 'zen_gui.py').read_bytes())
        self.identity['gui_assets_sha256'] = {p.name: sha256(p.read_bytes()) for p in WEB.iterdir() if p.is_file()}
        self.identity['intel_gui_sha256'] = sha256((ROOT / 'zen_intel_gui.py').read_bytes())
        self.identity['trace_version'] = TRACE_VERSION
        self.identity['trace_source_sha256'] = sha256((ROOT / 'zen_trace.py').read_bytes())
        self.identity['intel_source_sha256'] = {name: sha256((ROOT / name).read_bytes()) for name in
                                                ('uiCA.py', 'instructions.py', 'microArchConfigs.py', 'facile.py', 'utils.py', 'convertXML.py')}
        self.identity['intel_data_sha256'] = {p.name: sha256(p.read_bytes()) for p in sorted((ROOT / 'instrData').glob('*.py'))}

    def run(self, request):
        started = time.monotonic()
        targets = request.get('targets', ['ZEN4', 'ZEN5'])
        if (not isinstance(targets, list) or not 1 <= len(targets) <= 4 or
                any(target not in (*INTEL_TARGETS, 'ZEN4', 'ZEN5') for target in targets) or
                len(set(targets)) != len(targets)):
            raise ValueError('Choose one to four distinct Intel/AMD targets.')
        alignment = request.get('alignment', 0)
        if type(alignment) is not int or not 0 <= alignment < 64:
            raise ValueError('Alignment offset must be in 0..63.')
        trace = request.get('trace', False)
        if type(trace) is not bool:
            raise ValueError('Trace selection must be true or false.')
        code = input_bytes(request)
        try:
            decoded = decode(code)
        except ValueError as error:
            raise ValueError('The machine code is truncated or could not be decoded completely. Check the bytes and try again.') from error
        if trace and len(decoded) > MAX_TRACE_INSTRUCTIONS:
            raise ValueError('Pipeline views accept at most %d instructions. Disable Trace Table/Graph to analyze a larger block.' % MAX_TRACE_INSTRUCTIONS)
        results = []
        for target in targets:
            if target.startswith('ZEN'):
                result = analyze(decoded, target, self.data)
                if trace:
                    result['trace'] = amd_trace(decoded, target, self.data)
                results.append(result)
            else:
                try:
                    timeout = min(15, 45 - (time.monotonic() - started))
                    if timeout <= 0:
                        raise ValueError('Comparison exceeded its 45-second deadline.')
                    child = subprocess.run([sys.executable, str(ROOT / 'zen_intel_gui.py')],
                                           input=json.dumps({'target': target, 'hex': code.hex(), 'alignment': alignment, 'trace': trace}),
                                           text=True, capture_output=True, timeout=timeout, cwd=ROOT)
                    # XED can print INVALID_FOR_CHIP yet exit 0. Reject any
                    # diagnostic or extra output rather than trusting the TP.
                    if child.returncode or child.stderr.strip():
                        raise ValueError('Input is unsupported by the selected Intel model, or its simulation failed.')
                    result = json.loads(child.stdout)
                    results.append(result)
                except (ValueError, subprocess.TimeoutExpired) as error:
                    results.append({'target': target, 'status': 'unsupported',
                                    'predicted_steady_state_cycles': None, 'error': str(error)})
        return {'schema_version': 1, 'kind': 'local-uica-comparison', 'results': results,
                'input': {'code_hex': code.hex(), 'code_sha256': sha256(code),
                          'bytes': len(code), 'instructions': len(decoded), 'format': request['mode'],
                          'alignment_offset': alignment, 'alignment_modeled': {t: t in INTEL_TARGETS for t in targets},
                          'syntax': request.get('syntax') if request['mode'] == 'assembly' else None,
                          'loop_mode': {r['target']: r.get('loop_mode', 'repeat-exact-block') for r in results},
                          'unroll_factor': {t: None if t in INTEL_TARGETS else 1 for t in targets}},
                'provenance': self.identity, 'analysis_seconds': round(time.monotonic() - started, 3)}


class GuiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, analyzer, assets=None):
        self.analyzer = analyzer
        self.token = secrets.token_urlsafe(32)
        self.analysis_slot = threading.BoundedSemaphore(1)
        self.assets = frontend_assets() if assets is None else assets
        if hasattr(analyzer, 'identity'):
            analyzer.identity['served_assets_sha256'] = {name: sha256(body) for name, body in self.assets.items()}
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = 'uiCA-local'

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Never log uploaded code or the session token.
        pass

    def valid_host(self):
        port = self.server.server_address[1]
        return self.headers.get('Host') in ('127.0.0.1:%d' % port, 'localhost:%d' % port)

    def send(self, status, body, content_type='application/json; charset=utf-8'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, status, value):
        self.send(status, json.dumps(value).encode())

    def do_GET(self):
        if not self.valid_host():
            self.json_response(403, {'error': 'This interface is available only on localhost.'})
            return
        path = urlsplit(self.path).path
        if path == '/api/config':
            self.json_response(200, {'token': self.server.token, 'examples': EXAMPLES,
                                     'model_version': MODEL_VERSION, 'assembly_available': shutil.which('as') is not None,
                                     'nasm_available': shutil.which('nasm') is not None, 'intel_targets': INTEL_TARGETS})
        elif path == '/api/health':
            self.json_response(200, {'status': 'ready', 'app': 'uica-local'})
        else:
            name = 'index.html' if path == '/' else path.removeprefix('/')
            if name not in self.server.assets:
                self.json_response(404, {'error': 'Not found.'})
            else:
                content_type = mimetypes.guess_type(name)[0] or 'application/octet-stream'
                if name.endswith('.js'):
                    content_type = 'text/javascript; charset=utf-8'
                self.send(200, self.server.assets[name], content_type)

    def do_POST(self):
        port = self.server.server_address[1]
        origins = ('http://127.0.0.1:%d' % port, 'http://localhost:%d' % port)
        if not self.valid_host() or self.headers.get('Origin') not in (None, *origins):
            self.json_response(403, {'error': 'Only requests from this local interface are accepted.'})
            return
        if not secrets.compare_digest(self.headers.get('X-uiCA-Token', '').encode(), self.server.token.encode()):
            self.json_response(403, {'error': 'Reload the interface to refresh its session.'})
            return
        if self.path != '/api/analyze':
            self.json_response(404, {'error': 'Not found.'})
            return
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            self.json_response(415, {'error': 'Expected JSON input.'})
            return
        if not self.server.analysis_slot.acquire(blocking=False):
            self.json_response(429, {'error': 'Another block is being analyzed. Try again in a moment.'})
            return
        try:
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= MAX_REQUEST or self.headers.get('Transfer-Encoding'):
                    raise ValueError('The request exceeds the size limit or has an invalid length.')
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('The request ended before its input was complete.')
                request = json.loads(body)
                if not isinstance(request, dict):
                    raise ValueError('Expected an input object.')
                self.json_response(200, self.server.analyzer.run(request))
            except (ValueError, OSError, KeyError, TypeError) as error:
                self.json_response(400, {'error': str(error)})
        finally:
            self.server.analysis_slot.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--open', action='store_true', help='open the interface in the default browser')
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error('port must be in 0..65535')
    if args.open and args.port:
        address = 'http://127.0.0.1:%d' % args.port
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(address + '/api/health', timeout=1) as response:
                health = json.loads(response.read(1024))
            if isinstance(health, dict) and health.get('app') == 'uica-local' and health.get('status') == 'ready':
                webbrowser.open(address)
                return
        except (OSError, ValueError):
            pass
    try:
        server = GuiServer(('127.0.0.1', args.port), Analyzer())
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, 'GUI setup: %s\nRun setup_zen.py and setup_uica_web.py --download with this Python first.\n' % error)
    address = 'http://127.0.0.1:%d' % server.server_address[1]
    print('uiCA local interface: ' + address, flush=True)
    if args.open:
        webbrowser.open(address)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
