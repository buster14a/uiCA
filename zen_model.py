"""AMD-only conditional bounds; never constructs an Intel MicroArchConfig.

Resource subsets use the measured AMD FP names, not character splitting of
Intel port strings. Register dependencies use byte overlap and individual
status flags. The graph is periodic: distance=1 means a loop-carried edge.
There is deliberately no pipeline/accuracy claim in this model version.
"""
from collections import defaultdict
from itertools import combinations
import re

from x64_lib import GPRegs, High8Regs, Low8Regs, getCanonicalReg
from zen_import import ATTRIBUTES

MODEL_VERSION = 'zen-bounds-0.1'
AMD_ARCHITECTURE = 'https://hc2024.hotchips.org/assets/program/conference/day2/24_HC2024.AMD.Cohen.Subramony.final.pdf'
CONFIGS = {
    'ZEN4': {'alu_units': 4, 'dispatch_macroops': 6, 'vector_datapath_bits': 256,
             'rob_entries': 320},
    'ZEN5': {'alu_units': 6, 'dispatch_macroops': 8, 'vector_datapath_bits': 512,
             'rob_entries': 448},
}
ALIASES = {'ZEN4': 'ZEN4', 'ZEN5': 'ZEN5', 'znver4': 'ZEN4', 'znver5': 'ZEN5'}
SIMPLE_ALU = {'ADD', 'SUB', 'AND', 'OR', 'XOR', 'CMP', 'TEST'}
ZERO_IDIOMS = {'XOR', 'PXOR', 'XORPS', 'XORPD', 'VPXOR', 'VPXORD', 'VPXORQ', 'VXORPS', 'VXORPD'}
# Only these specific register arithmetic families receive a documented
# datapath-based, explicitly inferred Zen 4 wide-occupancy assumption.
WIDE_SPLIT = {'VPADDD', 'VADDPS'}
# Reviewed nomenclature changes between the pinned decoder and March 2026
# XML. These register-only encodings retain width/iclass/operand identity.
# No pattern-based rewriting of arbitrary iforms is allowed.
FORM_ALIASES = {
    'BLSR_VGPR32d_VGPR32d': ('BLSR_GPR32d_GPR32d', 'BLSR', '2'),
    'BLSR_VGPR64q_VGPR64q': ('BLSR_GPR64q_GPR64q', 'BLSR', '3'),
}


def select_target(name):
    if name not in ALIASES:
        raise ValueError('unsupported AMD target: ' + name)
    return ALIASES[name]


def match_form(decoded, candidates):
    matches = []
    for form in candidates:
        attrs = form['attributes']
        if all(key not in attrs or
               (decoded.get(key) in attrs[key] if key == 'rm' else decoded.get(key) == attrs[key])
               for key in ATTRIBUTES):
            matches.append(form)
    if len(matches) != 1:
        raise ValueError('no unique exact instruction form (found %d)' % len(matches))
    return matches[0]


def resolve_form(decoded, table):
    name = decoded['iform']
    alias = None
    if name not in table and name in FORM_ALIASES:
        replacement, iclass, width = FORM_ALIASES[name]
        if decoded['iclass'] != iclass or decoded.get('eosz') != width or decoded.get('memOperands'):
            raise ValueError('decoder form alias does not match its reviewed encoding contract')
        name, alias = replacement, {'decoded_iform': name, 'data_iform': replacement,
                                    'reason': 'reviewed register-only XED nomenclature change'}
    return match_form(decoded, table.get(name, [])), alias


def parse_ports(text):
    jobs = []
    for term in text.split('+'):
        match = re.fullmatch(r'([1-9][0-9]*)\*FP([0-5]+)', term)
        if match is None or len(set(match[2])) != len(match[2]):
            raise ValueError('unknown AMD resource expression: ' + text)
        count = int(match[1])
        if count > 64:
            raise ValueError('resource count exceeds model limit')
        jobs.extend([tuple('FP' + p for p in match[2])] * count)
    if len(jobs) > 128:
        raise ValueError('resource count exceeds model limit')
    return jobs


def resource_jobs(decoded, form, target):
    measurement = form['measurement']
    notes = []
    if measurement is None:
        raise ValueError('selected target has no measurement')
    attrs = form['attributes']
    if any(o['type'] == 'mem' for o in form['operands']):
        raise ValueError('memory execution/AGU/aliasing resources not yet modeled')
    if attrs.get('locked') == '1' or attrs.get('rep', '0') != '0':
        raise ValueError('locked/repeated instructions not supported')
    name = attrs.get('iclass')
    data_reads = [r for n, r in decoded['regOperands'].items()
                  if 'R' in decoded['rw'].get(n, '') and r != 'RFLAGS' and not r.startswith('K')]
    same_reg = len(data_reads) > 1 and len(set(data_reads)) == 1
    if name in ZERO_IDIOMS and same_reg and decoded.get('mask') == '0':
        raise ValueError('zero-idiom execution/elimination resources not qualified; dependencies are modeled')
    if name in SIMPLE_ALU and attrs.get('eosz') in ('2', '3'):
        # This narrowly selected class uses AMD's simple ALU capacity. No
        # mapping is reverse-engineered from a repeated-instruction TP number.
        if measurement.get('uops') != '1':
            raise ValueError('simple ALU form does not have one measured AMD operation')
        jobs = [tuple('ALU' + str(p) for p in range(CONFIGS[target]['alu_units']))]
        notes.append('documented simple-ALU capacity; no fusion or elimination credit')
    elif 'ports' in measurement:
        # Indexed/same-register special resources are selected only if present;
        # the caller does not silently import the Intel suffix machinery.
        ports = measurement.get('ports_same_reg', measurement['ports']) if same_reg else measurement['ports']
        jobs = parse_ports(ports)
        if any(r.startswith('ZMM') for r in decoded['regOperands'].values()):
            if name not in WIDE_SPLIT or decoded.get('mask') != '0':
                raise ValueError('exact wide/masked execution decomposition not qualified')
            if target == 'ZEN4':
                jobs *= 2
                notes.append('inferred two 256-bit execution slots for this ZMM arithmetic family; unqualified')
    else:
        raise ValueError('no independently justified execution-resource mapping')
    return jobs, notes


def register_parts(reg, write=False, vector_zero_upper=False):
    canonical = getCanonicalReg(reg)
    cleared = []
    if reg in GPRegs:
        if reg in High8Regs:
            indexes = [1]
        elif reg in Low8Regs:
            indexes = [0]
        elif reg.startswith('E') or reg.endswith('D'):
            indexes = range(4)
            if write:
                cleared = [(canonical, i) for i in range(4, 8)]
        elif reg.endswith('W') or reg in ('AX', 'BX', 'CX', 'DX', 'SI', 'DI', 'SP', 'BP'):
            indexes = range(2)
        else:
            indexes = range(8)
    elif re.fullmatch(r'[XYZ]MM[0-9]+', reg):
        width = {'X': 16, 'Y': 32, 'Z': 64}[reg[0]]
        indexes = range(width)
        if write and vector_zero_upper:
            cleared = [(canonical, i) for i in range(width, 64)]
    elif re.fullmatch(r'K[0-7]', reg):
        # Mask subregister write behavior is not generalized in this version.
        indexes = [0]
    else:
        raise ValueError('unmodeled register: ' + reg)
    return [(canonical, i) for i in indexes], cleared


def latency_record(form, start, target, same_reg=False, kind='cycles'):
    records = [l for l in form['latencies'] if l['start_op'] == start and l['target_op'] == target]
    key = kind + '_same_reg' if same_reg and kind == 'cycles' else kind
    for record in records:
        actual = key if key in record else kind
        if actual in record:
            value = float(record[actual])
            if record.get(actual + '_is_upper_bound') == '1':
                return {'lower': None, 'upper': value, 'kind': 'upper-bound', 'raw': record}
            return {'lower': value, 'upper': value, 'kind': 'exact-measurement', 'raw': record}
        if kind == 'cycles' and 'min_cycles' in record:
            return {'lower': float(record['min_cycles']),
                    'upper': float(record['max_cycles']) if 'max_cycles' in record else None,
                    'kind': 'range', 'raw': record}
    return {'lower': None, 'upper': None, 'kind': 'unknown'}


def operands(decoded, form):
    inputs, outputs, clears = [], [], []
    data_reads = [reg for name, reg in decoded['regOperands'].items()
                  if 'R' in decoded['rw'].get(name, '') and reg != 'RFLAGS'
                  and not reg.startswith('K') and reg not in ('RIP', 'EIP')]
    same_reg = len(data_reads) > 1 and len(set(data_reads)) == 1
    zero = same_reg and decoded['iclass'] in ZERO_IDIOMS and decoded.get('mask') == '0'
    zero_upper = form['attributes'].get('vex') == '1' or form['attributes'].get('evex') == '1'
    for operand in form['operands']:
        name = operand.get('name')
        if not name:
            continue
        idx = operand['idx']
        read = operand.get('r') == '1'
        write = operand.get('w') == '1'
        if operand['type'] == 'flags':
            for flag in ('A', 'C', 'O', 'P', 'S', 'Z'):
                action = operand.get('flag_' + flag + 'F', '')
                keys = [('FLAGS', flag)]
                if 'r' in action and not zero:
                    inputs.append((idx, keys, 'cycles'))
                if 'w' in action:
                    outputs.append((idx, keys))
                if 'u' in action:
                    clears.extend(keys)
        elif operand['type'] == 'reg':
            reg = decoded['regOperands'].get(name)
            if reg is None or reg in ('RIP', 'EIP', 'K0'):
                continue
            if read and not (zero and not reg.startswith('K')):
                keys, _ = register_parts(reg)
                inputs.append((idx, keys, 'cycles'))
            if write:
                keys, cleared = register_parts(reg, True, zero_upper)
                outputs.append((idx, keys))
                clears.extend(cleared)
        elif operand['type'] in ('mem', 'agen'):
            memory = decoded.get('memOperands', {}).get(name, {})
            for component, kind in (('base', 'cycles_addr'), ('index', 'cycles_addr_index')):
                if memory.get(component) and memory[component] != 'RIP':
                    keys, _ = register_parts(memory[component])
                    inputs.append((idx, keys, kind))
            if write:
                outputs.append((idx, []))
    # Flag bits from one architectural flags output share a graph node.
    grouped = defaultdict(list)
    for idx, keys in outputs:
        grouped[idx].extend(keys)
    if not grouped:
        grouped['sink'] = []
    return inputs, list(grouped.items()), clears, same_reg


def dependency_graph(instructions):
    specs = [operands(d, f) for d, f in instructions]
    nodes = [(i, output) for i, spec in enumerate(specs) for output, _ in spec[1]]
    node_ids = {node: n for n, node in enumerate(nodes)}
    state, edges = {}, {}
    # First traversal obtains the previous iteration's last definition of each
    # byte/flag. Second traversal records within- and cross-iteration edges.
    for iteration in (-1, 0):
        for i, ((decoded, form), spec) in enumerate(zip(instructions, specs)):
            inputs, outputs, clears, same_reg = spec
            if iteration == 0:
                for start, keys, kind in inputs:
                    producers = {state[k] for k in keys if state.get(k) is not None}
                    for producer, producer_iteration in sorted(producers):
                        for output, _ in outputs:
                            latency = latency_record(form, start, output, same_reg, kind)
                            target = node_ids[(i, output)]
                            distance = -producer_iteration
                            key = (producer, target, distance, start, output, kind)
                            edges[key] = {'source': producer, 'target': target,
                                          'iteration_distance': distance, 'input_operand': start,
                                          'output_operand': output, 'latency': latency}
            for output, keys in outputs:
                for key in keys:
                    state[key] = (node_ids[(i, output)], iteration)
            for key in clears:
                state[key] = None
    return {'nodes': [{'id': n, 'instruction': i, 'operand': out}
                      for n, (i, out) in enumerate(nodes)], 'edges': list(edges.values())}


def recurrence_bound(graph):
    edges, nodes = graph['edges'], graph['nodes']
    if any(e['latency']['lower'] is None for e in edges):
        return None, 'needed latency is unknown or only upper-bounded'
    if not edges:
        return 0.0, None
    if len(nodes) > 512 or len(edges) > 8192:
        return None, 'dependency graph exceeds analysis budget'
    work = 0

    def positive_cycle(period):
        nonlocal work
        values = [0.0] * len(nodes)
        changed = False
        for _ in nodes:
            changed = False
            for edge in edges:
                work += 1
                if work > 20000000:
                    raise ValueError('dependency analysis work budget exceeded')
                candidate = (values[edge['source']] + edge['latency']['lower']
                             - period * edge['iteration_distance'])
                if candidate > values[edge['target']] + 1e-10:
                    values[edge['target']] = candidate
                    changed = True
            if not changed:
                break
        return changed

    lower, upper = 0.0, sum(e['latency']['lower'] for e in edges) + 1
    try:
        if not positive_cycle(0):
            return 0.0, None
        for _ in range(40):
            middle = (lower + upper) / 2
            if positive_cycle(middle):
                lower = middle
            else:
                upper = middle
    except ValueError as error:
        return None, str(error)
    return round(upper, 6), None


def resource_bound(jobs):
    result, bottlenecks = 0.0, []
    for bank in ('ALU', 'FP'):
        bank_jobs = [set(j) for j in jobs if j[0].startswith(bank)]
        ports = sorted(set().union(*bank_jobs)) if bank_jobs else []
        for size in range(1, len(ports) + 1):
            for subset in combinations(ports, size):
                eligible = set(subset)
                demand = sum(j <= eligible for j in bank_jobs)
                bound = demand / size
                if bound > result:
                    result, bottlenecks = bound, [list(subset)]
                elif bound == result and bound > 0:
                    bottlenecks.append(list(subset))
    return result, bottlenecks
