#!/usr/bin/env python3
"""Lossless AMD measurement import, separate from the Intel converter.

No inference happens here. Measurement strings, latency bounds, instruction
attributes and operand identities survive conversion. Generated data stays in
the user's cache; it is not distributed with this fork.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
ATTRIBUTES = ('agen', 'bcast', 'eosz', 'high8', 'immzero', 'mask', 'rep',
              'rm', 'sae', 'zeroing')
TARGETS = ('ZEN4', 'ZEN5')


def family(attrs, operands):
    name = attrs.get('iclass', '')
    if 'GATHER' in name or 'SCATTER' in name:
        return 'gather-scatter'
    if 'COMPRESS' in name or 'EXPAND' in name:
        return 'compress-expand'
    if 'SHUF' in name or 'PERM' in name:
        return 'shuffle-permute'
    if name.startswith('K'):
        return 'mask'
    if 'CMP' in name or name.startswith('TEST'):
        return 'compare-flags'
    if attrs.get('category') in ('COND_BR', 'UNCOND_BR', 'CALL', 'RET'):
        return 'control-flow'
    if any(o.get('type') == 'mem' for o in operands):
        return 'memory'
    widths = [int(o.get('width', '0')) for o in operands
              if o.get('width', '0').isdigit()]
    width = max(widths, default=0)
    if width >= 128:
        return 'simd-' + str(width)
    return 'scalar'


def import_instruction(element):
    attrs = dict(element.attrib)
    operands = [dict(o.attrib) for o in element.findall('operand')]
    result = {}
    for arch in element.findall('architecture'):
        target = arch.get('name')
        if target not in TARGETS:
            continue
        measurement = arch.find('measurement')
        result[target] = {
            'attributes': attrs,
            'operands': operands,
            'family': family(attrs, operands),
            'measurement': dict(measurement.attrib) if measurement is not None else None,
            'latencies': [dict(l.attrib) for l in measurement.findall('latency')]
                         if measurement is not None else [],
            'documentation': [dict(d.attrib) for d in arch.findall('doc')],
        }
    return result


def convert(path, lock):
    if path.stat().st_size != lock['data_bytes']:
        raise ValueError('instruction XML size differs from zen-lock.json')
    digest = hashlib.sha256()
    previous = b''
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            scan = previous + chunk
            if b'<!DOCTYPE' in scan.upper() or b'<!ENTITY' in scan.upper():
                raise ValueError('DTD/entities are not accepted')
            previous = chunk[-16:]
    if digest.hexdigest() != lock['data_sha256']:
        raise ValueError('instruction XML hash differs from zen-lock.json; no update was imported')
    forms = {t: defaultdict(list) for t in TARGETS}
    counts = {t: defaultdict(Counter) for t in TARGETS}
    for _, element in ET.iterparse(path, events=('end',)):
        if element.tag != 'instruction':
            continue
        imported = import_instruction(element)
        instruction_family = family(element.attrib, [o.attrib for o in element.findall('operand')])
        for target in TARGETS:
            count = counts[target][instruction_family]
            count['forms'] += 1
            count['target_architecture_present'] += target in imported
            if target not in imported:
                continue
            form = imported[target]
            forms[target][form['attributes']['iform']].append(form)
            measurement = form['measurement']
            count['measured'] += measurement is not None
            count['port_mapping_present'] += measurement is not None and 'ports' in measurement
            count['latency_records_present'] += bool(form['latencies'])
        element.clear()
    return {'schema_version': 1, 'source': {k: v for k, v in lock.items() if k != 'import_sha256'}, 'targets': forms,
            'inventory': counts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('xml', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'zen-data.json')
    args = parser.parse_args()
    try:
        lock = json.loads((ROOT / 'zen-lock.json').read_text())
        data = convert(args.xml, lock)
        encoded = (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode()
        args.output.write_bytes(encoded)
        print(json.dumps({'output': str(args.output), 'sha256': hashlib.sha256(encoded).hexdigest(),
                          'inventory': data['inventory']}, indent=2))
    except (ValueError, OSError, ET.ParseError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    main()
