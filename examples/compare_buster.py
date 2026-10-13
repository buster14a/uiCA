#!/usr/bin/env python3
"""Static comparisons only: none of the original code bytes are executed."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from zen_cli import analyze, decode, load_data, provenance, sha256


def compare():
    lock, data, data_hash = load_data(ROOT / 'zen-data.json')
    corpus = json.loads((ROOT / 'examples/buster-blocks.json').read_text())
    rows = []
    for case in corpus['cases']:
        code = bytes.fromhex(case['hex'])
        decoded = decode(code)
        for target in ('ZEN4', 'ZEN5'):
            result = analyze(decoded, target, data)
            rows.append({'name': case['name'], 'group': case['group'], 'target': target,
                         'input_sha256': sha256(code), 'hex': case['hex'],
                         'status': result['status'], 'bounds': result['bounds'],
                         'coverage': result['coverage'], 'unsupported': result['unsupported']})
    return {'schema_version': 1, 'kind': 'static-arithmetic-idiom-comparison',
            'hardware_measurements': [], 'provenance': provenance(lock, data_hash),
            'corpus': corpus, 'results': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    report = compare()
    if args.json:
        args.json.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    for row in report['results']:
        print('%-20s %s resource=%s recurrence=%s (%s)' % (
            row['name'], row['target'], row['bounds']['conditional_execution_resources'],
            row['bounds']['register_recurrence'], row['status']))
    print('Conditional bounds only; full Buster kernels, pipeline predictions and measured speedups remain pending.')


if __name__ == '__main__':
    main()
