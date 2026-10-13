import base64
import http.client
import json
import os
import shutil
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from zen_gui import Analyzer, GuiServer, assemble, assembly_source, input_bytes, main


class InputTests(unittest.TestCase):
    def test_rejects_file_directives_even_after_instruction_or_label(self):
        for source in ('.include "secret"', '.incbin "secret"', '.rept 999999',
                       'nop; .incbin secret', 'loop: .include secret', 'nop\n.macro code',
                       '.intel_syntax noprefix', 'nop\\n.include secret'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                assembly_source(source)

    def test_labels_comments_and_instruction_separators(self):
        source = assembly_source('.Lloop: add rax, rbx; add rbx, rax # recurrence\njnz .Lloop')
        self.assertIn('.Lloop:\nadd rax, rbx\nadd rbx, rax\njnz .Lloop', source)

    def test_source_and_instruction_budgets(self):
        for source in ('# only comments', 'nop\n' * 257, 'nop ' + '1' * 32768):
            with self.assertRaises(ValueError):
                assembly_source(source)

    def test_hex_forms_are_exact_and_incomplete_bytes_fail(self):
        for text in ('4801d8', '48 01 d8', '0x48 0x01 0xd8'):
            self.assertEqual(input_bytes({'mode': 'hex', 'input': text}), bytes.fromhex('4801d8'))
        for text in ('4', '4801d', '0x48 01 d8', 'zz', '', '48;01'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                input_bytes({'mode': 'hex', 'input': text})

    def test_upload_is_bytes_not_a_host_path(self):
        data = base64.b64encode(bytes.fromhex('4801d8')).decode()
        self.assertEqual(input_bytes({'mode': 'raw', 'input': data, 'filename': '/etc/passwd'}), bytes.fromhex('4801d8'))
        for request in ({'mode': 'raw', 'input': '!bad!'}, {'mode': 'raw', 'input': ''},
                        {'mode': 'object', 'input': data}, {'mode': 'path', 'input': '/etc/passwd'},
                        {'mode': 'hex', 'input': None}):
            with self.assertRaises(ValueError):
                input_bytes(request)

    def test_assembler_never_accepts_unresolved_relocations(self):
        self.assertEqual(assemble('add rax,rbx\nadd rbx,rax'), bytes.fromhex('4801d84801c3'))
        with self.assertRaises(ValueError):
            assemble('call external_symbol')

    def test_att_and_nasm_match_intel_bytes(self):
        expected = bytes.fromhex('4801d84801c3')
        self.assertEqual(assemble('add %rbx,%rax\nadd %rax,%rbx', 'asATT'), expected)
        if shutil.which('nasm'):
            self.assertEqual(assemble('add rax,rbx ; comment\nadd rbx,rax', 'NASM'), expected)

    def test_nasm_repetition_and_implicit_label_directives_are_rejected(self):
        for source in ('times 999999 nop', 'label times 999999 nop', 'foo equ 42', '%include x', 'db 0x90', 'foo: incbin x'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                assembly_source(source, 'NASM')


class FakeAnalyzer:
    def __init__(self):
        self.calls = 0

    def run(self, request):
        self.calls += 1
        code = input_bytes(request)
        return {'code': code.hex()}


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = FakeAnalyzer()
        self.server = GuiServer(('127.0.0.1', 0), self.analyzer,
                                assets={'index.html': b'<h1>uiCA local interface</h1>', 'adapter.js': b'"use strict";'})
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.host = '127.0.0.1:%d' % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)

    def request(self, method='POST', path='/api/analyze', value=None, **headers):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=3)
        body = json.dumps(value if value is not None else {'mode': 'hex', 'input': '4801d8'})
        defaults = {'Content-Type': 'application/json', 'X-uiCA-Token': self.server.token}
        defaults.update(headers)
        connection.request(method, path, body if method == 'POST' else None, defaults)
        response = connection.getresponse()
        result = (response.status, response.read(), dict(response.getheaders()))
        connection.close()
        return result

    def test_local_input_and_static_ui(self):
        status, body, _ = self.request()
        self.assertEqual((status, json.loads(body)), (200, {'code': '4801d8'}))
        status, body, headers = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'uiCA local interface', body)
        self.assertIn("default-src 'self'", headers['Content-Security-Policy'])
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')

    def test_foreign_origin_host_and_missing_token_cannot_analyze(self):
        for headers in ({'Origin': 'https://unrelated.example'}, {'Host': 'attacker.example'}, {'X-uiCA-Token': ''}, {'X-uiCA-Token': '\u00e9'}):
            status, _, _ = self.request(**headers)
            self.assertEqual(status, 403)
        self.assertEqual(self.analyzer.calls, 0)
        status, _, _ = self.request(Origin='http://' + self.host)
        self.assertEqual(status, 200)

    def test_static_allowlist_never_exposes_source_or_data(self):
        for path in ('/zen-data.json', '/zen-lock.json', '/.zen-decoder.json', '/../zen_cli.py', '/api/nope'):
            status, _, _ = self.request('GET', path)
            self.assertEqual(status, 404)

    def test_second_gui_launch_reopens_the_running_application(self):
        with patch.object(sys, 'argv', ['zen_gui.py', '--open', '--port', str(self.server.server_address[1])]), patch('zen_gui.webbrowser.open') as open_browser, patch('zen_gui.Analyzer', side_effect=AssertionError('should reuse existing analyzer')):
            main()
        open_browser.assert_called_once_with('http://' + self.host)

    def test_concurrent_analysis_refuses_extra_work(self):
        self.server.analysis_slot.acquire()
        try:
            status, _, _ = self.request()
            self.assertEqual(status, 429)
            self.assertEqual(self.analyzer.calls, 0)
        finally:
            self.server.analysis_slot.release()
        status, _, _ = self.request()
        self.assertEqual(status, 200)

    def test_wrong_content_type_and_bad_requests_remain_errors(self):
        self.assertEqual(self.request(**{'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(self.request(value=[])[0], 400)
        self.assertEqual(self.request(value={'mode': 'hex', 'input': '4'})[0], 400)


class RealGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / 'zen-data.json').exists():
            if os.environ.get('UICA_REQUIRE_SETUP') == '1':
                raise RuntimeError('CI must run pinned setup for real GUI integration')
            raise unittest.SkipTest('run setup_zen.py for real GUI integration')
        cls.analyzer = Analyzer()

    def test_assembly_hex_and_uploaded_bytes_have_identical_real_results(self):
        requests = [{'mode': 'assembly', 'input': 'add rax,rbx\nadd rbx,rax'},
                    {'mode': 'hex', 'input': '4801d84801c3'},
                    {'mode': 'raw', 'input': base64.b64encode(bytes.fromhex('4801d84801c3')).decode()}]
        reports = [self.analyzer.run(request) for request in requests]
        self.assertEqual(len(set(r['input']['code_sha256'] for r in reports)), 1)
        for report in reports:
            self.assertEqual([r['target'] for r in report['results']], ['ZEN4', 'ZEN5'])
            self.assertTrue(all(r['bounds']['register_recurrence'] == 2 for r in report['results']))
            self.assertTrue(all(r['predicted_steady_state_cycles'] is None for r in report['results']))
            self.assertTrue(all(not r['hardware_qualified'] for r in report['results']))

    def test_mask_and_memory_stay_partial_in_gui(self):
        for assembly in ('vpaddd zmm0{k1},zmm1,zmm2', 'mov rax,qword ptr [rdi]'):
            report = self.analyzer.run({'mode': 'assembly', 'input': assembly})
            self.assertTrue(all(r['status'] == 'partial' for r in report['results']))
            self.assertTrue(all(r['bounds']['conditional_execution_resources'] is None for r in report['results']))

    def test_selected_targets_and_alignment_remain_explicit(self):
        report = self.analyzer.run({'mode': 'hex', 'input': '4801d8', 'targets': ['ZEN5'], 'alignment': 17})
        self.assertEqual([r['target'] for r in report['results']], ['ZEN5'])
        self.assertEqual(report['input']['alignment_offset'], 17)
        self.assertEqual(report['input']['alignment_modeled'], {'ZEN5': False})
        for request in ({'targets': []}, {'targets': ['ZEN4', 'ZEN4']}, {'targets': ['unknown']},
                        {'alignment': 64}, {'alignment': True}):
            with self.assertRaises(ValueError):
                self.analyzer.run({'mode': 'hex', 'input': '90', **request})

    def test_original_intel_pipeline_and_invalid_chip_do_not_get_confused(self):
        report = self.analyzer.run({'mode': 'hex', 'input': '4801d84801c3', 'targets': ['SKL', 'ZEN5']})
        intel, amd = report['results']
        self.assertEqual(intel['analysis_mode'], 'upstream-intel-pipeline')
        self.assertAlmostEqual(intel['predicted_steady_state_cycles'], 2, places=2)
        self.assertIsNone(amd['predicted_steady_state_cycles'])
        unsupported = self.analyzer.run({'mode': 'hex', 'input': 'c5f5fec2c5ddfee5', 'targets': ['SNB']})
        self.assertEqual(unsupported['results'][0]['status'], 'unsupported')
        self.assertIsNone(unsupported['results'][0]['predicted_steady_state_cycles'])


if __name__ == '__main__':
    unittest.main()
