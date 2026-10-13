#!/usr/bin/env python3
"""Bounded child entry point for original Intel uiCA, without target execution."""
import importlib
import json
from pathlib import Path
import sys
import tempfile

from instructions import UnknownInstr, getInstructions
from microArchConfigs import MicroArchConfigs
from uiCA import runSimulation
import xed
from zen_trace import intel_trace


def main():
    request = json.loads(sys.stdin.read())
    config = MicroArchConfigs[request['target']]
    decoded = xed.disasHex(request['hex'], chip=config.XEDName)
    if not decoded or ''.join(row['opcode'] for row in decoded).lower() != request['hex']:
        raise ValueError('Intel decoder did not cover every byte for this target.')
    data = importlib.import_module('instrData.' + config.name + '_data')
    instructions = getInstructions(decoded, config, data, request['alignment'])
    if any(isinstance(instruction, UnknownInstr) for instruction in instructions):
        raise ValueError('The original Intel model lacks at least one instruction form.')
    with tempfile.TemporaryDirectory(prefix='uica-intel-trace-') as directory:
        path = Path(directory) / 'trace.json'
        cycles = runSimulation(decoded, config, request['alignment'], 'diff', False, False, False, 10, 500,
                               jsonFile=str(path) if request.get('trace') else None)
        trace = None
        if request.get('trace'):
            if path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError('Intel trace exceeds its output budget.')
            trace = intel_trace(json.loads(path.read_text()))
    print(json.dumps({'target': request['target'], 'analysis_mode': 'upstream-intel-pipeline',
                      'predicted_steady_state_cycles': cycles, 'status': 'simulated',
                      'loop_mode': 'repeat-loop' if instructions[-1].isBranchInstr else 'upstream-unrolled-block',
                      'alignment_modeled': True,
                      'trace': trace,
                      'instructions': [{'assembly': row['asm'], 'bytes': row['opcode'], 'iform': row['iform']} for row in decoded]}))


if __name__ == '__main__':
    main()
