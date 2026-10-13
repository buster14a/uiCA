import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from zen_cli import analyze, decode, extract_text, load_data, provenance
from zen_import import import_instruction
from zen_model import (CONFIGS, dependency_graph, latency_record, match_form,
                       parse_ports, recurrence_bound, register_parts, resource_bound,
                       resource_jobs, select_target)


class ImportTests(unittest.TestCase):
    def test_retains_unknown_bounds_and_variants_without_intel_defaults(self):
        element = ET.fromstring('''<instruction iform="SYNTHETIC" iclass="ADD" string="synthetic" eosz="3" mask="1" zeroing="0">
          <operand idx="1" name="REG0" type="reg" r="1" w="1" width="64"/>
          <architecture name="ZEN4"><measurement uops="1" TP_loop="0.25">
            <latency start_op="1" target_op="1" cycles="7" cycles_is_upper_bound="1"/>
          </measurement></architecture>
          <architecture name="ZEN5"><measurement ports="1*FP03" uops="2" uops_same_reg="1">
            <latency start_op="1" target_op="1" min_cycles="2" max_cycles="5"/>
          </measurement></architecture>
        </instruction>''')
        result = import_instruction(element)
        self.assertNotIn('ports', result['ZEN4']['measurement'])
        self.assertEqual(result['ZEN5']['measurement']['uops_same_reg'], '1')
        self.assertEqual(result['ZEN4']['attributes']['zeroing'], '0')
        bound = latency_record(result['ZEN4'], '1', '1')
        self.assertIsNone(bound['lower'])
        self.assertEqual(bound['upper'], 7)
        self.assertEqual(latency_record(result['ZEN5'], '1', '1')['upper'], 5)

    def test_missing_measurement_is_not_zero_work(self):
        result = import_instruction(ET.fromstring('''<instruction iform="X" string="X">
          <architecture name="ZEN5"/></instruction>'''))
        self.assertIsNone(result['ZEN5']['measurement'])

    def test_variants_cannot_alias(self):
        a = {'attributes': {'mask': '0', 'zeroing': '0'}}
        b = {'attributes': {'mask': '1', 'zeroing': '1'}}
        self.assertIs(match_form({'mask': '1', 'zeroing': '1'}, [a, b]), b)
        with self.assertRaises(ValueError):
            match_form({'mask': '1', 'zeroing': '0'}, [a, b])
        with self.assertRaises(ValueError):
            match_form({'mask': '0', 'zeroing': '0'}, [a, a])


class ModelTests(unittest.TestCase):
    def test_targets_distinct_and_unknown_never_falls_back(self):
        self.assertEqual(select_target('znver5'), 'ZEN5')
        self.assertNotEqual(CONFIGS['ZEN4'], CONFIGS['ZEN5'])
        with self.assertRaises(ValueError):
            select_target('ZEN6')

    def test_amd_port_names_are_not_intel_characters(self):
        self.assertEqual(parse_ports('2*FP03+1*FP12'), [('FP0', 'FP3')] * 2 + [('FP1', 'FP2')])
        for invalid in ('1*p03', '1*FP00', '0*FP1', '1*FP6', '999*FP1', ''):
            with self.assertRaises(ValueError):
                parse_ports(invalid)

    def test_mixed_resource_subset_binds_more_than_individual_groups(self):
        # Three jobs on {0,1}, three on {1,2}: either group alone gives
        # 1.5 cycles, but their shared union needs 6/3 = 2 cycles.
        jobs = [('FP0', 'FP1')] * 3 + [('FP1', 'FP2')] * 3
        self.assertEqual(resource_bound(jobs)[0], 2)

    def test_partial_register_overlap_and_zero_extension(self):
        ah, _ = register_parts('AH')
        ax, _ = register_parts('AX')
        eax, clear = register_parts('EAX', True)
        rax, _ = register_parts('RAX')
        self.assertEqual(set(ah) & set(ax), set(ah))
        self.assertEqual(set(eax + clear), set(rax))
        self.assertFalse(set(eax) & set(clear))
        low, clear = register_parts('XMM0', True, True)
        full, _ = register_parts('ZMM0')
        self.assertEqual(set(low + clear), set(full))

    def test_recurrence_uses_iteration_distance_and_operand_latency(self):
        graph = {'nodes': [0, 1], 'edges': [
            {'source': 0, 'target': 1, 'iteration_distance': 0, 'latency': {'lower': 2}},
            {'source': 1, 'target': 0, 'iteration_distance': 1, 'latency': {'lower': 3}},
        ]}
        self.assertAlmostEqual(recurrence_bound(graph)[0], 5)
        graph['edges'][1]['iteration_distance'] = 2
        self.assertAlmostEqual(recurrence_bound(graph)[0], 2.5)
        graph['edges'][0]['latency']['lower'] = None
        self.assertIsNone(recurrence_bound(graph)[0])

    def test_no_recurrence_does_not_invent_one_cycle_latency(self):
        graph = {'nodes': [0, 1], 'edges': [
            {'source': 0, 'target': 1, 'iteration_distance': 0, 'latency': {'lower': 10}},
        ]}
        self.assertEqual(recurrence_bound(graph)[0], 0)

    def test_malformed_objects_are_rejected(self):
        for data in (b'', b'\x7fELF', bytes(64), b'\x7fELF\x02\x01\x01' + bytes(57)):
            with self.assertRaises(ValueError):
                extract_text(data)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / 'zen-data.json').exists():
            if os.environ.get('UICA_REQUIRE_SETUP') == '1':
                raise RuntimeError('CI requires pinned setup; cannot skip integration controls')
            raise unittest.SkipTest('run setup_zen.py for pinned data/decoder integration tests')
        cls.lock, cls.data, cls.digest = load_data(ROOT / 'zen-data.json')
        provenance(cls.lock, cls.digest)

    def result(self, code, target='ZEN4'):
        return analyze(decode(bytes.fromhex(code)), target, self.data)

    def test_scalar_recurrence(self):
        result = self.result('4801d84801c3')
        self.assertEqual(result['coverage']['exact_forms'], 2)
        self.assertEqual(result['bounds']['register_recurrence'], 2)
        self.assertEqual(result['bounds']['conditional_execution_resources'], .5)

    def test_dependent_and_independent_vectors_and_target_substitution(self):
        independent = '62f17548fec2'  # vpaddd zmm0,zmm1,zmm2
        dependent = '62f17d48fec2'    # vpaddd zmm0,zmm0,zmm2
        z4 = self.result(independent)
        z5 = self.result(independent, 'ZEN5')
        self.assertEqual(z4['bounds']['conditional_execution_resources'], .5)
        self.assertEqual(z5['bounds']['conditional_execution_resources'], .25)
        self.assertEqual(z4['bounds']['register_recurrence'], 0)
        self.assertEqual(self.result(dependent)['bounds']['register_recurrence'], 1)
        self.assertEqual(self.result(dependent, 'ZEN5')['bounds']['register_recurrence'], 2)
        self.assertFalse(z5['hardware_qualified'])
        self.assertIsNone(z5['predicted_steady_state_cycles'])

    def test_same_register_zeroing_breaks_dependency_but_add_does_not(self):
        self.assertEqual(self.result('4831c0')['bounds']['register_recurrence'], 0)
        self.assertEqual(self.result('4801c0')['bounds']['register_recurrence'], 1)

    def test_mask_merge_keeps_destination_zero_mask_does_not(self):
        merge = self.result('62f17549fec2')
        zero = self.result('62f175c9fec2')
        self.assertEqual(merge['bounds']['register_recurrence'], 1)
        self.assertEqual(zero['bounds']['register_recurrence'], 0)
        self.assertIsNone(merge['bounds']['conditional_execution_resources'])
        self.assertEqual(merge['status'], 'partial')

    def test_memory_unknowns_are_explicit_and_upper_bounds_survive(self):
        result = self.result('488b07488906')
        self.assertEqual(result['status'], 'partial')
        self.assertIsNone(result['bounds']['conditional_execution_resources'])
        self.assertIsNone(result['bounds']['register_recurrence'])
        self.assertTrue(any(l.get('cycles_is_upper_bound') == '1'
                            for row in result['instructions'] for l in row['latency_measurements']))

    def test_address_generation_is_not_a_memory_access(self):
        result = self.result('488d47ff4821c7')  # lea rax,[rdi-1]; and rdi,rax
        self.assertEqual(result['bounds']['register_recurrence'], 2)
        self.assertIsNone(result['bounds']['conditional_execution_resources'])

    def test_reviewed_decoder_alias_preserves_both_identities(self):
        result = self.result('c4e2c0f3cf')  # blsr rdi,rdi
        self.assertEqual(result['bounds']['register_recurrence'], 1)
        row = result['instructions'][0]
        self.assertEqual(row['iform'], 'BLSR_VGPR64q_VGPR64q')
        self.assertEqual(row['data_iform'], 'BLSR_GPR64q_GPR64q')
        self.assertIsNotNone(row['decoder_form_alias'])

    def test_bad_bytes_never_return_a_partial_success(self):
        for code in ('62', '4801d862', '0f', 'c5'):
            with self.assertRaises(ValueError):
                decode(bytes.fromhex(code))

    def test_missing_target_measurement_never_gets_intel_data(self):
        decoded = decode(bytes.fromhex('4801d8'))
        data = copy.deepcopy(self.data)
        del data['targets']['ZEN5'][decoded[0]['iform']]
        result = analyze(decoded, 'ZEN5', data)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['coverage']['exact_forms'], 0)
        self.assertIsNone(result['bounds']['conditional_execution_resources'])

    def test_object_and_raw_have_identical_bounds_and_relocations_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'code.s'
            obj = Path(temporary) / 'code.o'
            source.write_text('.intel_syntax noprefix\nadd rax,rbx\nadd rbx,rax\n')
            subprocess.run(['as', str(source), '-o', str(obj)], check=True)
            code = extract_text(obj.read_bytes())
            self.assertEqual(code.hex(), '4801d84801c3')
            source.write_text('.intel_syntax noprefix\ncall external_symbol\n')
            subprocess.run(['as', str(source), '-o', str(obj)], check=True)
            with self.assertRaises(ValueError):
                extract_text(obj.read_bytes())

    def test_cli_json_graph_alias_and_alignment(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'code.bin'
            result = Path(temporary) / 'report.json'
            graph = Path(temporary) / 'graph.dot'
            source.write_bytes(bytes.fromhex('4801d84801c3'))
            process = subprocess.run([sys.executable, str(ROOT / 'uiCA.py'), str(source),
                                      '-raw', '-arch', 'znver5', '-json', str(result),
                                      '-depGraph', str(graph), '-alignmentOffset', '63'],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            report = json.loads(result.read_text())
            self.assertEqual(report['target'], 'ZEN5')
            self.assertEqual(report['input']['alignment_offset'], 63)
            self.assertFalse(report['input']['alignment_modeled'])
            self.assertIn('distance=1', graph.read_text())
            self.assertIn('decoder', report['provenance'])

    def test_input_budget_and_error_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'too-big.bin'
            report = Path(temporary) / 'error.json'
            source.write_bytes(bytes(8193))
            process = subprocess.run([sys.executable, str(ROOT / 'zen_cli.py'), str(source),
                                      '-raw', '-arch', 'ZEN4', '-json', str(report)],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(json.loads(report.read_text())['status'], 'error')

    def test_import_hash_tampering_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'forged.json'
            path.write_text('{}')
            with self.assertRaises(ValueError):
                load_data(path)

    def test_original_intel_golden_corpus(self):
        baseline = json.loads((ROOT / 'tests/intel-baseline.json').read_text())
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'code.bin'
            for case in baseline['cases']:
                with self.subTest(case=case['case'], target=case['target']):
                    source.write_bytes(bytes.fromhex(case['hex']))
                    process = subprocess.run([sys.executable, str(ROOT / 'uiCA.py'), str(source),
                                              '-raw', '-arch', case['target'], '-TPonly'],
                                             capture_output=True, text=True, timeout=30)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    self.assertEqual(process.stdout, case['stdout'])


if __name__ == '__main__':
    unittest.main()
