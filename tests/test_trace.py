import copy
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from zen_cli import decode, load_data
from zen_gui import Analyzer, assemble
from zen_model import dependency_graph, resolve_form
from zen_trace import amd_trace, assign_resources


class ResourceMatchingTests(unittest.TestCase):
    def test_matching_keeps_the_narrower_resource_available(self):
        self.assertEqual(assign_resources([('A', 'B'), ('A',)], {'A', 'B'}), ['B', 'A'])
        self.assertIsNone(assign_resources([('A',), ('A',)], {'A', 'B'}))


class TraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / 'zen-data.json').exists():
            if os.environ.get('UICA_REQUIRE_SETUP') == '1':
                raise RuntimeError('CI must run pinned analyzer setup')
            raise unittest.SkipTest('run setup_zen.py')
        cls.analyzer = Analyzer()
        cls.data = cls.analyzer.data

    def test_scalar_schedule_obeys_all_loop_carried_operand_dependencies(self):
        decoded = decode(bytes.fromhex('4801d84801c3'))
        graph = dependency_graph([(d, resolve_form(d, self.data['targets']['ZEN4'])[0]) for d in decoded])
        trace = amd_trace(decoded, 'ZEN4', self.data)
        self.assertEqual(trace['status'], 'available')
        self.assertEqual([r['events']['dispatch'] for r in trace['rows'][:4]], [0, 1, 2, 3])
        rows = {(row['iteration'], row['instruction']): row for row in trace['rows']}
        nodes = {node['id']: node for node in graph['nodes']}
        for iteration in range(8):
            for edge in graph['edges']:
                source_iteration = iteration - edge['iteration_distance']
                if source_iteration < 0:
                    continue
                source, target = nodes[edge['source']], nodes[edge['target']]
                completed = rows[(source_iteration, source['instruction'])]['output_ready'][str(source['operand'])]
                dispatched = rows[(iteration, target['instruction'])]['events']['dispatch']
                self.assertLessEqual(completed, dispatched)
        self.assertIn('retirement', trace['unmodeled_stages'])
        self.assertFalse(trace['hardware_qualified'])
        self.assertIsNone(trace['predicted_pipeline_cycles'])

    def test_wide_resource_contention_is_distinct_on_each_target(self):
        code = assemble('vpaddd zmm0,zmm1,zmm2\nvpaddd zmm3,zmm4,zmm5\nvpaddd zmm6,zmm7,zmm8\nvpaddd zmm9,zmm10,zmm11')
        decoded = decode(code)
        zen4, zen5 = [amd_trace(decoded, target, self.data) for target in ('ZEN4', 'ZEN5')]
        self.assertEqual(zen4['status'], 'available')
        self.assertEqual(zen5['status'], 'available')
        self.assertEqual([r['events']['dispatch'] for r in zen4['rows'][:4]], [0, 0, 1, 1])
        self.assertEqual([r['events']['dispatch'] for r in zen5['rows'][:4]], [0, 0, 0, 0])
        for trace in (zen4, zen5):
            for cycle in trace['cycles']:
                used = [unit for row in trace['rows'] if row['events']['dispatch'] == cycle['cycle'] for unit in row['resources']]
                self.assertEqual(len(used), len(set(used)))

    def test_memory_masks_and_censored_latency_cannot_get_invented_traces(self):
        for source in ('mov rax,qword ptr [rdi]', 'vpaddd zmm0{k1},zmm1,zmm2', 'vdivps ymm0,ymm1,ymm2'):
            trace = amd_trace(decode(assemble(source)), 'ZEN5', self.data)
            self.assertEqual(trace['status'], 'unavailable')
            self.assertEqual(trace['rows'], [])
        decoded = decode(bytes.fromhex('4801d8'))
        form, _ = resolve_form(decoded[0], self.data['targets']['ZEN4'])
        modified = copy.deepcopy(form)
        for latency in modified['latencies']:
            if 'cycles' in latency:
                latency['cycles_is_upper_bound'] = '1'
        table = dict(self.data['targets']['ZEN4'])
        table[decoded[0]['iform']] = [modified]
        data = {'targets': {'ZEN4': table}}
        trace = amd_trace(decoded, 'ZEN4', data)
        self.assertEqual(trace['status'], 'unavailable')
        self.assertIn('exact integer operand latency', trace['reason'])

    def test_intel_trace_comes_from_pipeline_events_with_stage_order(self):
        report = self.analyzer.run({'mode': 'hex', 'input': '4801d84801c3', 'targets': ['SKL', 'ZEN4', 'ZEN5'], 'trace': True})
        intel = report['results'][0]
        self.assertAlmostEqual(intel['predicted_steady_state_cycles'], 2)
        trace = intel['trace']
        self.assertEqual(trace['kind'], 'intel-pipeline')
        self.assertTrue(trace['rows'])
        for row in trace['rows']:
            e = row['events']
            self.assertLessEqual(e['issued'], e['dispatch'])
            self.assertLessEqual(e['dispatch'], e['executed'])
            self.assertLessEqual(e['executed'], e['retired'])
        for amd in report['results'][1:]:
            self.assertEqual(amd['trace']['kind'], 'amd-ideal-backend')
            self.assertIsNone(amd['predicted_steady_state_cycles'])

    def test_trace_budget_does_not_change_non_trace_analysis(self):
        with self.assertRaisesRegex(ValueError, 'at most 32'):
            self.analyzer.run({'mode': 'assembly', 'input': 'add rax,rbx\n' * 33, 'trace': True})
        report = self.analyzer.run({'mode': 'assembly', 'input': 'add rax,rbx\n' * 33})
        self.assertEqual(report['input']['instructions'], 33)
        with self.assertRaisesRegex(ValueError, 'true or false'):
            self.analyzer.run({'mode': 'hex', 'input': '90', 'trace': 'true'})


if __name__ == '__main__':
    unittest.main()
