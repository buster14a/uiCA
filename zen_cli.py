#!/usr/bin/env python3
"""Opt-in experimental AMD resource/recurrence analysis of machine code."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys

from zen_import import TARGETS
from zen_model import (ALIASES, CONFIGS, MODEL_VERSION, AMD_ARCHITECTURE,
                       dependency_graph, resolve_form, recurrence_bound,
                       resource_bound, resource_jobs, select_target)

ROOT = Path(__file__).resolve().parent
MAX_CODE_BYTES = 8192
MAX_INSTRUCTIONS = 256


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_bounded(path, maximum):
    if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > maximum:
        raise ValueError('input must be a regular file of at most %d bytes' % maximum)
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('input exceeds size limit')
    return data


def extract_text(data):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('AMD object input currently requires ELF64 little-endian x86-64; use -raw otherwise')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    _, kind, machine, _, _, _, section_offset, _, _, _, _, entry_size, count, names_index = header
    if kind != 1 or machine != 62 or entry_size != 64 or count == 0 or names_index >= count:
        raise ValueError('expected a relocatable x86-64 object with ordinary section numbering')
    if section_offset + count * entry_size > len(data):
        raise ValueError('truncated ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, section_offset + i * 64) for i in range(count)]

    def contents(section):
        offset, size = section[4:6]
        if offset + size > len(data):
            raise ValueError('truncated ELF section')
        return data[offset:offset + size]

    names = contents(sections[names_index])
    matches = []
    for index, section in enumerate(sections):
        if section[0] >= len(names):
            raise ValueError('invalid ELF section name')
        end = names.find(b'\0', section[0])
        if end < 0:
            raise ValueError('unterminated ELF section name')
        if names[section[0]:end] == b'.text':
            matches.append((index, section))
    if len(matches) != 1:
        raise ValueError('expected exactly one .text section')
    index, section = matches[0]
    if section[1] != 1 or not section[2] & 4:
        raise ValueError('.text is not executable PROGBITS')
    if any(s[1] in (4, 9) and s[7] == index and s[5] for s in sections):
        raise ValueError('.text contains unresolved relocations')
    return contents(section)


def decode(code):
    # Native decoder runs in a bounded disposable child. The bytes are passed
    # only to XED's disassembler; no generated code is loaded or executed.
    program = """import json,sys
sys.path.insert(0,sys.argv[1])
import xed
code=sys.stdin.read()
decoded=xed.disasHex(code)
if ''.join(d['opcode'] for d in decoded).lower()!=code.lower():
    sys.exit(2)
print(json.dumps(decoded))
"""
    try:
        result = subprocess.run([sys.executable, '-c', program, str(ROOT)],
                                input=code.hex(), text=True, capture_output=True, timeout=15)
    except subprocess.TimeoutExpired as error:
        raise ValueError('decoder exceeded 15-second deadline') from error
    if result.returncode:
        raise ValueError('decoder failed or did not cover every byte: ' + result.stderr[-1000:])
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError('decoder emitted diagnostics or malformed output') from error
    if not decoded or len(decoded) > MAX_INSTRUCTIONS:
        raise ValueError('expected 1..%d instructions' % MAX_INSTRUCTIONS)
    if bytes.fromhex(''.join(d['opcode'] for d in decoded)) != code:
        raise ValueError('decoded bytes differ from input')
    return decoded


def load_data(path):
    lock = json.loads((ROOT / 'zen-lock.json').read_text())
    encoded = read_bounded(path, 100 * 1024 * 1024)
    if sha256(encoded) != lock.get('import_sha256'):
        raise ValueError('imported data hash mismatch; run the pinned importer/setup')
    data = json.loads(encoded)
    if data['schema_version'] != 1 or data['source']['data_sha256'] != lock['data_sha256']:
        raise ValueError('import source/schema does not match zen-lock.json')
    return lock, data, sha256(encoded)


def provenance(lock, data_hash):
    decoder = json.loads((ROOT / '.zen-decoder.json').read_text())
    artifact = ROOT / decoder['artifact']
    if artifact.parent != ROOT or sha256(read_bounded(artifact, 100 * 1024 * 1024)) != decoder['sha256']:
        raise ValueError('decoder artifact does not match setup receipt')
    if decoder['source_revision'] != lock['xed'] or decoder['mbuild_revision'] != lock['mbuild']:
        raise ValueError('decoder source revisions do not match lock')
    try:
        revision = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                                  capture_output=True, text=True, check=True, timeout=5).stdout.strip()
        dirty = bool(subprocess.run(['git', '-C', str(ROOT), 'status', '--porcelain'],
                                    capture_output=True, text=True, check=True, timeout=5).stdout)
    except (OSError, subprocess.SubprocessError):
        revision, dirty = None, None
    sources = {name: sha256((ROOT / name).read_bytes())
               for name in ('zen_cli.py', 'zen_model.py', 'zen_import.py', 'zen-lock.json', 'x64_lib.py')}
    return {'fork_revision': revision, 'working_tree_dirty': dirty,
            'source_sha256': sources, 'upstream_revision': lock['upstream'],
            'decoder': decoder, 'data_xml_sha256': lock['data_sha256'],
            'data_import_sha256': data_hash}


def analyze(decoded, target, data):
    target = select_target(target)
    instructions, rows, jobs, failures = [], [], [], []
    graph_possible = True
    for index, instruction in enumerate(decoded):
        row = {'index': index, 'assembly': instruction['asm'], 'bytes': instruction['opcode'],
               'iform': instruction['iform'], 'resources': None, 'annotations': []}
        try:
            form, alias = resolve_form(instruction, data['targets'][target])
            instructions.append((instruction, form))
            row.update({'form': form['attributes']['string'], 'family': form['family'],
                        'data_iform': form['attributes']['iform'], 'decoder_form_alias': alias,
                        'target_support_evidence': 'exact-form-measurement' if form['measurement'] is not None else 'unconfirmed',
                        'measurement': form['measurement'], 'latency_measurements': form['latencies'],
                        'reference_documentation': form['documentation']})
            try:
                instruction_jobs, notes = resource_jobs(instruction, form, target)
                jobs.extend(instruction_jobs)
                row['resources'] = instruction_jobs
                row['annotations'].extend(notes)
            except ValueError as error:
                failures.append({'instruction': index, 'component': 'resources', 'reason': str(error)})
        except ValueError as error:
            graph_possible = False
            failures.append({'instruction': index, 'component': 'form', 'reason': str(error)})
        rows.append(row)
    graph, dependency, dependency_reason = None, None, None
    if graph_possible:
        try:
            graph = dependency_graph(instructions)
            dependency, dependency_reason = recurrence_bound(graph)
        except ValueError as error:
            dependency_reason = str(error)
        if any(o['type'] == 'mem' for _, form in instructions for o in form['operands']):
            dependency, dependency_reason = None, 'memory aliasing/forwarding is outside this model; graph shows only register/address dependencies'
    else:
        dependency_reason = 'not every instruction has an exact form for this target'
    if dependency_reason:
        failures.append({'instruction': None, 'component': 'dependencies', 'reason': dependency_reason})
    resource, bottlenecks = (None, []) if any(f['component'] in ('form', 'resources') for f in failures) else resource_bound(jobs)
    # No inferred mapping from architectural instructions or AMD's reported
    # "uops" to dispatch macro-ops, retire units or execution slots.
    return {
        'target': target, 'model_version': MODEL_VERSION, 'analysis_mode': 'experimental-conditional-bounds',
        'status': 'partial' if failures else 'experimental', 'hardware_qualified': False,
        'predicted_steady_state_cycles': None,
        'bounds': {'conditional_execution_resources': resource,
                   'register_recurrence': dependency, 'dispatch': None, 'retirement': None},
        'bottleneck_resource_subsets': bottlenecks, 'instructions': rows,
        'dependency_graph': graph, 'unsupported': failures,
        'coverage': {'instructions': len(rows), 'exact_forms': len(instructions),
                     'resource_modeled': sum(r['resources'] is not None for r in rows),
                     'families': sorted(set(r.get('family', 'unknown') for r in rows))},
        'architecture_reference': {'parameters': CONFIGS[target], 'source': AMD_ARCHITECTURE,
                                   'use': 'context and narrowly selected resource bounds; not a full pipeline configuration'},
        'assumptions': [
            'input is one repeated straight-line block; control flow is not followed',
            'register renaming is ideal; mask registers are tracked at whole-register granularity',
            'AMD FP resource mappings come from the pinned exact-form measurements',
            'resource slots are conditional on documented/inferred occupancy annotations',
            'memory execution, aliasing, forwarding and cache misses are unmodeled',
            'fetch/decode/op-cache, alignment penalties, fusion, finite queues, ROB and retirement are unmodeled',
            'no speedup, elapsed time, frequency or branch-prediction claim is made',
        ],
    }


def write_dot(path, report):
    graph = report.get('dependency_graph')
    if graph is None:
        raise ValueError('no complete dependency graph is available')
    if path.suffix != '.dot':
        raise ValueError('AMD dependency graphs currently use .dot; render separately if desired')
    lines = ['digraph dependencies {', '  label="Experimental AMD register dependencies";']
    for node in graph['nodes']:
        label = '%d: %s / %s' % (node['instruction'], report['instructions'][node['instruction']]['assembly'], node['operand'])
        lines.append('  n%d [label=%s];' % (node['id'], json.dumps(label)))
    for edge in graph['edges']:
        latency = edge['latency']
        label = '%s [%s,%s], distance=%d' % (latency['kind'], latency['lower'], latency['upper'], edge['iteration_distance'])
        lines.append('  n%d -> n%d [label=%s];' % (edge['source'], edge['target'], json.dumps(label)))
    path.write_text('\n'.join(lines + ['}']) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename', type=Path, nargs='?')
    parser.add_argument('-arch', required=True, choices=list(ALIASES))
    parser.add_argument('-raw', action='store_true')
    parser.add_argument('-json', type=Path, nargs='?', const=Path('result.json'))
    parser.add_argument('-depGraph', type=Path)
    parser.add_argument('-alignmentOffset', type=int, default=0)
    parser.add_argument('--data', type=Path, default=ROOT / 'zen-data.json')
    parser.add_argument('--coverage-report', type=Path)
    args = parser.parse_args(argv)
    report = {'schema_version': 1, 'status': 'error', 'target': ALIASES[args.arch], 'diagnostics': []}
    exit_code = 2
    try:
        if not 0 <= args.alignmentOffset < 64:
            raise ValueError('alignment offset must be in 0..63')
        lock, data, data_hash = load_data(args.data)
        identity = provenance(lock, data_hash)
        if args.coverage_report:
            # Import inventory is not model coverage. Evaluate each imported
            # form only with real decoded input; do not count all measured forms
            # as supported instructions.
            args.coverage_report.write_text(json.dumps({
                'schema_version': 1, 'kind': 'data-inventory-not-model-coverage',
                'provenance': identity, 'targets': data['inventory'],
            }, indent=2) + '\n')
        if args.filename is None:
            if not args.coverage_report:
                raise ValueError('a machine-code input or --coverage-report is required')
            return 0
        source = read_bounded(args.filename, MAX_CODE_BYTES if args.raw else 16 * 1024 * 1024)
        code = source if args.raw else extract_text(source)
        if not 1 <= len(code) <= MAX_CODE_BYTES:
            raise ValueError('code must contain 1..%d bytes' % MAX_CODE_BYTES)
        decoded = decode(code)
        report.update(analyze(decoded, args.arch, data))
        report.update({'provenance': identity,
                       'input': {'file_sha256': sha256(source), 'code_sha256': sha256(code),
                                 'code_hex': code.hex(), 'format': 'raw' if args.raw else 'ELF64-.text',
                                 'alignment_offset': args.alignmentOffset,
                                 'alignment_modeled': False, 'loop': 'repeat-exact-block', 'unroll_factor': 1}})
        if args.depGraph:
            write_dot(args.depGraph, report)
        exit_code = 3 if report['status'] == 'partial' else 0
    except (ValueError, OSError, KeyError, TypeError, struct.error, json.JSONDecodeError) as error:
        report['status'] = 'error'
        report['diagnostics'].append(str(error))
    if args.json:
        args.json.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print('%s: %s (%s)' % (report['target'], report['status'], MODEL_VERSION))
    if 'bounds' in report:
        for name, value in report['bounds'].items():
            print('  %s: %s' % (name, 'unavailable' if value is None else '%.6f core cycles/block (bound)' % value))
    for diagnostic in report.get('diagnostics', []):
        print('  ' + diagnostic)
    for failure in report.get('unsupported', []):
        print('  unsupported: ' + failure['reason'])
    print('  Experimental model evidence; pipeline prediction and hardware qualification pending.')
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
