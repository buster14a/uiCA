"""Cycle traces: original Intel events and conditional AMD execution schedules.

AMD is an ideal-front-end resource scheduler, not a full hardware pipeline.
Unknown stage policies and non-exact latency/resource data are never filled in.
"""
from collections import defaultdict, deque
import math

from zen_model import SIMPLE_ALU, dependency_graph, latency_record, operands, resolve_form, resource_jobs

TRACE_VERSION = 'execution-trace-0.1'
ITERATIONS = 8
MAX_TRACE_INSTRUCTIONS = 32
MAX_CYCLES = 2048
TRACE_ICLASSES = SIMPLE_ALU | {'VPADDD', 'VADDPS', 'VPSHUFB'}
AMD_UNMODELED = ['fetch', 'decode', 'op-cache', 'rename/dispatch bandwidth',
                 'finite scheduler/ROB/queues', 'fusion/elimination', 'retirement',
                 'memory execution/aliasing/forwarding']


def assign_resources(jobs, available):
    """Deterministic bipartite matching, with an iterative augmenting path."""
    units, selected = {}, {}
    for root in range(len(jobs)):
        queue = deque([root])
        seen_jobs, parent = {root}, {}
        free = None
        while queue and free is None:
            job = queue.popleft()
            for unit in sorted(set(jobs[job]) & available):
                if unit in parent:
                    continue
                parent[unit] = job
                if unit not in units:
                    free = unit
                    break
                owner = units[unit]
                if owner not in seen_jobs:
                    seen_jobs.add(owner)
                    queue.append(owner)
        if free is None:
            return None
        while free is not None:
            job = parent[free]
            previous = selected.get(job)
            units[free] = job
            selected[job] = free
            free = previous
    return [selected[job] for job in range(len(jobs))]


def unavailable(reason):
    return {'schema_version': 1, 'version': TRACE_VERSION, 'kind': 'amd-ideal-backend',
            'status': 'unavailable', 'reason': reason, 'rows': [], 'cycles': [],
            'unmodeled_stages': AMD_UNMODELED, 'hardware_qualified': False}


def amd_trace(decoded, target, data):
    try:
        return schedule_amd(decoded, target, data)
    except ValueError as error:
        return unavailable(str(error))


def schedule_amd(decoded, target, data):
    if not 1 <= len(decoded) <= MAX_TRACE_INSTRUCTIONS:
        raise ValueError('Execution traces accept at most %d instructions.' % MAX_TRACE_INSTRUCTIONS)
    forms, jobs, output_latencies = [], [], []
    for index, instruction in enumerate(decoded):
        if instruction['iclass'] not in TRACE_ICLASSES:
            raise ValueError('Instruction %d: execution occupancy is not qualified for the trace scheduler (%s).' % (index, instruction['iclass']))
        form, _ = resolve_form(instruction, data['targets'][target])
        try:
            work, _ = resource_jobs(instruction, form, target)
        except ValueError as error:
            raise ValueError('Instruction %d: %s' % (index, error)) from error
        if not work or len(work) > 8:
            raise ValueError('Instruction %d has no qualified bounded resource decomposition.' % index)
        inputs, outputs, _, same_reg = operands(instruction, form)
        durations = {}
        for output, _ in outputs:
            values = []
            for start, _, kind in inputs:
                latency = latency_record(form, start, output, same_reg, kind)
                if (latency['kind'] != 'exact-measurement' or latency['lower'] is None or
                        not math.isfinite(latency['lower']) or latency['lower'] < 0 or
                        not float(latency['lower']).is_integer()):
                    raise ValueError('Instruction %d needs an exact integer operand latency; unknown, range and censored values cannot drive a trace.' % index)
                values.append(int(latency['lower']))
            if not values:
                raise ValueError('Instruction %d has no qualified input-to-output completion latency.' % index)
            durations[output] = max(values)
        forms.append((instruction, form))
        jobs.append(work)
        output_latencies.append(durations)
    graph = dependency_graph(forms)
    nodes = {node['id']: node for node in graph['nodes']}
    incoming = defaultdict(set)
    output_nodes = defaultdict(list)
    for node in graph['nodes']:
        output_nodes[node['instruction']].append(node)
    for edge in graph['edges']:
        incoming[nodes[edge['target']]['instruction']].add((edge['source'], edge['iteration_distance']))
    all_resources = {unit for work in jobs for choices in work for unit in choices}
    if any(assign_resources(work, all_resources) is None for work in jobs):
        raise ValueError('This operation needs a multi-cycle resource decomposition not qualified by the trace scheduler.')
    pending = [(iteration, i) for iteration in range(ITERATIONS) for i in range(len(decoded))]
    ready_outputs, rows, cycles = {}, [], []
    for cycle in range(MAX_CYCLES):
        free, waiting = set(all_resources), []
        dispatched = {}
        for iteration, index in pending:
            dependencies = [(iteration - distance, source) for source, distance in incoming[index]
                            if iteration - distance >= 0]
            if any(key not in ready_outputs or ready_outputs[key] > cycle for key in dependencies):
                waiting.append((iteration, index))
                continue
            assigned = assign_resources(jobs[index], free)
            if assigned is None:
                waiting.append((iteration, index))
                continue
            free.difference_update(assigned)
            completion = {}
            for node in output_nodes[index]:
                finish = cycle + output_latencies[index][node['operand']]
                ready_outputs[(iteration, node['id'])] = finish
                completion[str(node['operand'])] = finish
            finished = max(completion.values())
            if finished >= MAX_CYCLES:
                raise ValueError('Execution schedule exceeds the %d-cycle trace budget.' % MAX_CYCLES)
            rows.append({'iteration': iteration, 'instruction': index, 'assembly': decoded[index]['asm'],
                         'unit': 'operation resource bundle', 'resources': assigned,
                         'events': {'ready': max((ready_outputs[key] for key in dependencies), default=0),
                                    'dispatch': cycle, 'executed': finished},
                         'output_ready': completion,
                         'predecoded': None, 'issued': None, 'retired': None})
            for unit in assigned:
                dispatched[unit] = {'iteration': iteration, 'instruction': index}
        cycles.append({'cycle': cycle, 'resources': dispatched})
        pending = waiting
        if not pending:
            break
    if pending:
        raise ValueError('Execution schedule did not finish within its cycle budget; no complete trace is returned.')
    last = max(row['events']['executed'] for row in rows)
    by_cycle = {entry['cycle']: entry for entry in cycles}
    for cycle in range(last + 1):
        entry = by_cycle.setdefault(cycle, {'cycle': cycle, 'resources': {}})
        entry['stages'] = {name: sum(row['events'][name] == cycle for row in rows)
                           for name in ('ready', 'dispatch', 'executed')}
    rows.sort(key=lambda row: (row['iteration'], row['instruction']))
    return {'schema_version': 1, 'version': TRACE_VERSION, 'kind': 'amd-ideal-backend',
            'status': 'available', 'rows': rows, 'cycles': [by_cycle[c] for c in range(last + 1)],
            'iterations': ITERATIONS, 'unmodeled_stages': AMD_UNMODELED,
            'hardware_qualified': False, 'predicted_pipeline_cycles': None,
            'assumptions': ['All operations from eight iterations are available to an unlimited scheduler at cycle 0; live-ins are ready at cycle 0.',
                            'Oldest ready operation wins; exact resources are matched deterministically. Each eligible resource admits one slot per cycle.',
                            'All resource slots of an operation start together. Completion uses the maximum exact measured input-to-output latency per output.',
                            'No issue/rename/fetch/decode/queue/ROB/retirement timing, fusion or elimination is inferred.',
                            'Wide-vector slot decomposition retains the experimental model assumptions; this is a conditional feasible schedule, not a hardware trace or full throughput prediction.']}


def intel_trace(raw):
    """Normalize actual events emitted by upstream generateJSONOutput."""
    rows, events = {}, defaultdict(dict)
    instructions = {row['instrID']: row['asm'] for row in raw['instructions']}

    def prefix(item, count):
        return tuple(item.get(key, 0) for key in ('rnd', 'instrID', 'lamUopID', 'fUopID', 'uopID')[:count])

    names = {'addedToIQ': ('predecoded', 2), 'addedToIDQ': ('queued', 3),
             'addedToRB': ('issued', 4), 'readyForDispatch': ('ready', 5),
             'executed': ('executed', 5), 'removedFromRB': ('retired', 4)}
    for entry in raw['cycles']:
        cycle = entry['cycle']
        for field, (name, count) in names.items():
            for item in entry.get(field, []):
                if item['rnd'] < ITERATIONS:
                    key = prefix(item, count)
                    events[key][name] = cycle
                    if count == 5:
                        rows.setdefault(key, {'iteration': key[0], 'instruction': key[1],
                                              'assembly': instructions[key[1]], 'unit': 'uop %d/%d/%d' % key[2:],
                                              'events': {}, 'resources': []})
        for port, item in entry.get('dispatched', {}).items():
            if item['rnd'] < ITERATIONS:
                key = prefix(item, 5)
                events[key]['dispatch'] = cycle
                row = rows.setdefault(key, {'iteration': key[0], 'instruction': key[1],
                                           'assembly': instructions[key[1]], 'unit': 'uop %d/%d/%d' % key[2:],
                                           'events': {}, 'resources': []})
                row['resources'].append(port)
    for key, row in rows.items():
        for count in (2, 3, 4, 5):
            row['events'].update(events[key[:count]])
    normalized = sorted(rows.values(), key=lambda row: (row['iteration'], row['instruction'], row['unit']))
    last = max((max(row['events'].values(), default=0) for row in normalized), default=0)
    cycles = []
    for cycle in range(last + 1):
        stages = {name: sum(row['events'].get(name) == cycle for row in normalized)
                  for name in ('predecoded', 'queued', 'issued', 'ready', 'dispatch', 'executed', 'retired')}
        resources = {port: {'iteration': row['iteration'], 'instruction': row['instruction']}
                     for row in normalized if row['events'].get('dispatch') == cycle for port in row['resources']}
        cycles.append({'cycle': cycle, 'stages': stages, 'resources': resources})
    return {'schema_version': 1, 'version': TRACE_VERSION, 'kind': 'intel-pipeline', 'status': 'available',
            'rows': normalized, 'cycles': cycles, 'iterations': ITERATIONS,
            'parameters': raw['parameters'], 'unmodeled_stages': [],
            'instructions': raw['instructions'],
            'assumptions': ['Events come from the original uiCA pipeline simulator; the view retains the first eight iterations.',
                            'Stage activity counts are normalized per displayed unfused uop; queue/retirement events can repeat for fused or laminated groups.',
                            'Simulation assumes cache hits and original Intel loop/unroll policy. These are simulated events, not measured hardware observations.']}
