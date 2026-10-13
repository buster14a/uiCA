import json
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from setup_uica_web import adapt, digest, frontend_assets, sanitize_reference


class AdapterTests(unittest.TestCase):
    def test_shortener_and_telemetry_removed_before_any_cache_write(self):
        # Synthetic sentinel, never a real key or a downloaded fixture.
        source = '<script src="https://uops.info/m.js"></script><script>function createURL() {\nBearer synthetic\n}\nfunction restoreFromURL() {}</script>'
        clean = sanitize_reference(source)
        self.assertNotIn('synthetic', clean)
        self.assertNotIn('m.js', clean)
        self.assertNotIn('Bearer', clean)
        self.assertIn('copyURLToClipboard', clean)
        with self.assertRaises(ValueError):
            sanitize_reference('<script>unexpected source</script>')

    def test_original_dom_is_adapted_without_executable_inline_handlers(self):
        source = '<head><title>uiCA</title><script>function old() {}</script></head><body><hr><form><textarea name="code"></textarea><table><tr><td></select></td></tr></table><input id="cb_SKL" value="SKL" checked><input onclick="run()" value="Run!"></form><div id="outputDiv"></div></body>'
        page = adapt(source)
        self.assertIn('AMD Zen 4', page)
        self.assertIn('AMD Zen 5', page)
        self.assertIn('aria-label="Assembly or hex code"', page)
        self.assertNotIn('onclick', page)
        self.assertNotIn('function old()', page)
        self.assertIn('src="/adapter.js"', page)
        self.assertIn('<textarea', page)

    def test_mixed_case_scripts_and_all_event_handlers_are_removed(self):
        source = '<HEAD><SCRIPT SRC="https://example.test/code.js"></SCRIPT><ScRiPt>bad()</sCrIpT></HEAD><BODY ONLOAD="bad()"><textarea onfocus=bad>keep &lt; text</textarea></BODY>'
        page = adapt(source)
        self.assertNotIn('bad()', page)
        self.assertNotIn('example.test', page)
        self.assertNotIn('onload', page)
        self.assertNotIn('onfocus', page)
        self.assertIn('keep &lt; text', page)

    def test_source_pin_and_local_cache_exclusion_are_recorded(self):
        lock = json.loads((ROOT / 'uica-web-lock.json').read_text())
        self.assertEqual(len(lock['frontend']['sha256']), 64)
        self.assertIn('unverified', lock['frontend']['license'])
        self.assertIn('.uica-web/', (ROOT / '.gitignore').read_text())
        self.assertEqual(len(set(e['path'] for e in lock['assets'])), len(lock['assets']))

    def test_real_pinned_cache_serves_the_upstream_form_and_original_adapter(self):
        if not (ROOT / '.uica-web/receipt.json').exists():
            if os.environ.get('UICA_REQUIRE_SETUP') == '1':
                self.fail('CI must explicitly fetch the pinned frontend before integration tests.')
            self.skipTest('run setup_uica_web.py --download for web integration')
        files = frontend_assets()
        page = files['index.html'].decode()
        for marker in ('name="uArchs"', 'name="syntax"', 'name="alignment"', 'AMD Zen 4', 'AMD Zen 5', '/adapter.js'):
            self.assertIn(marker, page)
        self.assertNotIn('onclick=', page)
        self.assertNotIn('onchange=', page)
        self.assertNotIn('bitly', files['reference.html'].decode().lower())
        self.assertNotIn('Bearer ', files['reference.html'].decode())
        self.assertEqual(files['adapter.js'], (ROOT / 'web/adapter.js').read_bytes())

    def test_cached_asset_tampering_is_refused(self):
        lock = json.loads((ROOT / 'uica-web-lock.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / 'receipt.json').write_text(json.dumps({'frontend_original_sha256': lock['frontend']['sha256'], 'files': {'index.html': digest(b'expected')}}))
            (cache / 'index.html').write_bytes(b'changed')
            with patch('setup_uica_web.CACHE', cache), self.assertRaisesRegex(ValueError, 'Cached frontend asset changed'):
                frontend_assets()


if __name__ == '__main__':
    unittest.main()
