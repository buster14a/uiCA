# Experimental AMD analysis

This fork implements a separate AMD resource and register-recurrence analyzer.
It is the first implementation milestone for [Buster #4020](https://github.com/buster14a/buster/issues/4020),
**not completed Zen pipeline support**. It does not predict steady-state
pipeline throughput or claim hardware accuracy. The JSON field
`predicted_steady_state_cycles` is deliberately null and
`hardware_qualified` is false. Intel simulation remains available unchanged.

## Reproducible setup

Linux x86-64 needs Python 3, a C compiler, Python development headers and git;
tests additionally use GNU `as`. No plotting or web service is required. The
host CPU is irrelevant: analyzed bytes are never executed.

```sh
git clone --recurse-submodules https://github.com/buster14a/uiCA.git
cd uiCA
python3 -m venv .venv
.venv/bin/python -m pip install setuptools==80.9.0
.venv/bin/python setup_zen.py --download
.venv/bin/python -m unittest discover -s tests -v
```

The explicit setup download verifies the XML size and SHA256 in
`zen-lock.json`, verifies the deterministic import hash, and builds only the
locked XED-to-XML and mbuild revisions. `--xml /path/to/instructions.xml`
reuses an existing verified file. A changed upstream download fails rather
than silently updating the model. Setup preserves submodules and original
history. The original `setup.sh` is retained for upstream compatibility;
**it does not provide the pinned AMD setup**.

The original Intel conversion also runs unless `--no-intel` is selected.
Python/build-tool/compiler versions and the actual decoder binary hash are
recorded in `.zen-decoder.json`. Analysis verifies that receipt and the
import hash, and records the fork revision, dirty state and model source
hashes. Compiler/ABI differences can change the decoder binary; its receipt
records the actual build rather than claiming byte-identical binaries across
different compilers. CI uses Python 3.12.12 on Ubuntu 24.04; Python 3.14 also
passes the current local corpus. Analysis never downloads data.

## Analyze machine code

### Graphical interface

After the analyzer setup, run `.venv/bin/python setup_uica_web.py --download`
once, then `.venv/bin/python zen_gui.py --open`. The actual downloaded
uiCA.uops.info form opens at `http://127.0.0.1:8765`, with Zen 4/5 choices added.
A second launch reopens an already-running instance. Use `--port 8766` for
another loopback port; stop with Ctrl+C. Restart after updating the fork so
loaded code and provenance match the source.

Paste GNU as Intel/AT&T, NASM or hex input, or upload raw/relocation-free ELF64
machine code. GNU `as` / optional NASM assemble instructions, labels and
comments only; file/macro/repetition directives are rejected. Assembler and
decoder subprocesses have deadlines. Raw code is limited to 8 KiB / 256
instructions. No target code is executed.

Select one to four targets. Intel uses the original pipeline simulation,
including its automatic loop/unroll policy and alignment offset, in a bounded
child process. Unknown Intel forms, decoder diagnostics and invalid-for-chip
encodings cannot produce a successful prediction in the adapter. The original
headless CLI is unchanged. AMD uses the explicit conditional resource and
register-recurrence model; alignment is recorded but unmodeled. The shared
results table keeps pipeline predictions separate from AMD bounds.

AMD **Dependencies** shows instruction-grouped register/address arrows and a
complete operand-edge table; JSON retains the full graph, exact bytes, coverage,
assumptions, code/data/decoder hashes and served-asset hashes. Examples and
instruction details are available. Pipeline **Trace Table** and **Graph** are available for both vendors. Intel
events come directly from upstream `generateJSONOutput`, including predecode,
IDQ, issue, operand readiness, execution-port dispatch, execution and retirement.
The first eight iterations are retained, with the upstream loop/unroll policy.
Per-row cycle letters preserve simultaneous events rather than overwriting them.

AMD traces use `zen_trace.py`: an explicitly experimental, ideal-front-end
execution scheduler driven by exact AMD operand latencies and resource mappings.
It expands eight repeated iterations, respects byte/register/flag and loop-carried
dependencies, matches eligible resource slots without double booking, and uses
oldest-ready priority. All operations are available at cycle zero, live-ins are
ready at zero, and all resource slots of an operation start together. Completion
is the maximum exact measured input-to-output latency for each output.
There is no fetch/decode/op-cache/rename/finite-queue/ROB/retirement timing.
Those stages are explicitly marked unmodeled in the UI and JSON. This is a
conditional feasible execution schedule, **not a full AMD pipeline prediction,
a measured trace, or a speedup comparison against Intel**. Full AMD predictions
remain null and qualification remains pending.

AMD trace occupancy is restricted to simple ADD/SUB/AND/OR/XOR/CMP/TEST and
VPADDD/VADDPS/VPSHUFB register forms with modeled resources and exact integer
operand latencies. Existing narrow wide-vector assumptions remain conditional.
Memory, unqualified masks/widths/classes, unknown/censored/range latencies and
operations needing an unqualified multi-cycle resource decomposition refuse a
trace with an explicit reason. Trace input is limited to 32 instructions, eight
iterations and 2048 AMD cycles. Disable Trace Table/Graph for larger ordinary
analyses. Cycle-window and iteration selectors control the diagram and matrix;
complete recorded data remains in JSON. External IACA/LLVM/OSACA/CQA tools remain
disabled, with visible explanations. A changed or
failed input clears the previous result instead of relabeling it as current.

Frontend provenance: `uica-web-lock.json` pins the retrieved page and dependency
assets. The site's separate frontend license is **unverified**; neither its
HTML/JS/CSS nor its unpublished `/cgi-bin/tp.py` backend is vendored into this
public fork. Explicit setup downloads into ignored `.uica-web/`, verifies hashes,
removes telemetry and the third-party URL-shortening function/credential before
writing, then patches the original DOM/style with this fork's own adapter.
The sanitized browser-side reference is retained as `.uica-web/reference.html`.
Client dependencies retain their upstream notices: jQuery/Colorbox CSS/JS MIT;
Font Awesome CSS MIT and fonts SIL-OFL-1.1. This does not establish a license for
the site's own frontend. The simulator and new adapter/backend remain AGPL-3.0.

The local service needs no browser framework, npm package or plotting library.
It binds only to loopback, restricts Host/Origin and analysis requests to the
current session token, snapshots an explicit asset allowlist, and accepts one
bounded analysis at a time. It sends no code or reports to a remote service.
A web cache is never silently downloaded or refreshed at launch/analysis time.

### Command line

```sh
printf '\110\001\330\110\001\303' > adds.bin
.venv/bin/python uiCA.py adds.bin -raw -arch ZEN4 -json zen4.json -depGraph deps.dot
.venv/bin/python uiCA.py adds.bin -raw -arch znver5 -json zen5.json
.venv/bin/python zen_cli.py -arch ZEN4 --coverage-report data-inventory.json
```

Use `-arch ZEN4`, `ZEN5`, `znver4` or `znver5`. There is no host inference,
Intel substitution or Zen 5 alias to Zen 4. `all` retains its upstream Intel
meaning. AMD options have their own `zen_cli.py --help`. The existing Intel
CLI, graphs and execution traces remain available. AMD currently emits DOT
register-dependency graphs; it has no pipeline execution trace. Unsupported
Intel simulation switches are rejected by the AMD CLI, not silently ignored.

Object input supports a single `.text` section in an ELF64 little-endian
x86-64 relocatable object. Unresolved `.text` relocations are rejected.
For other formats extract a straight-line block to raw bytes explicitly.
All bytes must decode; truncated or malformed code fails, even if an initial
prefix decoded successfully. Limits are 8 KiB of code, 256 instructions,
15 seconds for the isolated native decoder, and a bounded iterative
dependency analysis. Object files are limited to 16 MiB. There is no
input-dependent Python recursion.

Exit codes: 0 = experimental analysis with all requested bounds available;
3 = partial coverage with explicit missing components; 2 = invalid input,
setup/provenance error or unsupported option. Zero is **not a qualification
verdict**. JSON distinguishes a missing bound (`null`) from a known absence
of register recurrences (`0`). Alignment is recorded but is not modeled.

## What the numbers mean

`conditional_execution_resources` is a necessary resource-subset bound
**conditional on the declared resource/occupancy assumptions**. The algorithm
includes overlapping port groups rather than summing independent instruction
throughputs. It uses AMD names such as `FP0123`, never Intel `p0123` parsing.
Resource mappings are not inferred from repeated-instruction throughput.

`register_recurrence` is the maximum latency/iteration-distance cycle ratio
in the periodic byte/flag def-use graph. Operand-specific measurements,
same-register variants, individual flags, GPR partial writes/32-bit zero
extension, overlapping vector widths and VEX/EVEX upper clearing are retained.
Zero idioms remove applicable data dependencies. Mask merge keeps the old
destination; mask zeroing does not. Mask registers currently use whole-register
granularity. Memory graphs show register/address edges, but no total recurrence
bound is published for a memory block because aliasing and forwarding are not
modeled. Unknown and upper-only latencies never become exact zero/one-cycle
latencies. Original latency bounds/ranges are retained in the JSON.

These bounds do not constitute a pipeline prediction. In particular, taking
their maximum does not model fetch/decode/op-cache delivery, alignment,
fusion, queues, rename saturation, ROB/retirement, cache misses or branch
prediction. Control flow is not followed. Treat one input as one repeated
straight-line block. No whole-program elapsed time or speedup is implied.

The pinned decoder predates the XML's BLSR register-form nomenclature. Two
explicit 32/64-bit register-only aliases are checked by iclass, operand width
and absence of memory; reports retain both `iform` and `data_iform` plus the
alias reason. Arbitrary form-name rewriting is not allowed. Intra-vector lane
dependencies and partial mask-register writes are not separately modeled;
the graph must not be used to claim lane-level qualification.

## Buster arithmetic comparisons

Run `.venv/bin/python examples/compare_buster.py --json comparisons.json`.
The original byte sequences in `examples/buster-blocks.json` correspond to
two source operations at Buster commit
`2af78d9b16f9dd88339e74237272da182418083d`. They are arithmetic idioms,
not full kernels emitted by a current Buster compiler:

| Source operation and alternatives | Zen 4 bound | Zen 5 bound | Decision supported |
| --- | --- | --- | --- |
| Metadata `terminators & (terminators-1)`: MOV/SUB/AND versus LEA/AND | Both have a 2-cycle register recurrence | Both have a 2-cycle register recurrence | Fewer architectural instructions alone does not shorten this dependency bound |
| Same data result via BLSR | 1-cycle recurrence | 1-cycle recurrence | A hypothesis for shortening this recurrence; resources remain unavailable and flag side effects must be checked before substitution |
| `c_lex_store_rows`' sixteen u32 offset additions: two independent YMM VPADDD versus one ZMM VPADDD | Both have a conditional 0.5-cycle resource bound | 0.5 versus 0.25 conditional resource bound | The width choice has different resource hypotheses on the two targets |

Loads, widening, broadcasts, output packing, branches, finite rename state and
the rest of each loop are excluded. These comparisons are static model evidence
only. They do not meet the issue's full representative-kernel/hardware delivery
milestone and do not establish an actual Buster speedup.

## Evidence and coverage

| Parameter or behavior | Evidence | Status |
| --- | --- | --- |
| 4 versus 6 simple integer ALUs | AMD's [Zen 5 architecture deck](https://hc2024.hotchips.org/assets/program/conference/day2/24_HC2024.AMD.Cohen.Subramony.final.pdf), comparing Zen 4 and Zen 5 | Documented capacity, used only for selected 32/64-bit register/immediate ADD/SUB/AND/OR/XOR/CMP/TEST forms with one measured AMD operation |
| 6 versus 8 dispatch macro-ops; 320 versus 448 ROB entries | Same AMD deck | Documented context only; not used as a dispatch/ROB simulation |
| Exact-form AMD FP eligibility and operand latencies | [uops.info March 2026 XML](https://uops.info/xml.html), hash in lock | Measured, not independently hardware-qualified by this fork |
| Zen 4 ZMM VPADDD/VADDPS occupancy | AMD's documented 256-bit datapath; exact-form measured/doc throughput is retained alongside the mapping | Inferred two 256-bit execution slots per reported FP slot for these two register-only, unmasked families; conditional and unqualified |
| Zen 5 ZMM VPADDD/VADDPS occupancy | Native 512-bit datapath in AMD deck and separate exact-form measurements | Separate Zen 5 mapping; no Zen 4 scaling |
| Other ZMM/masked decomposition | Exact-form data alone does not establish all occupancy details | Resource bound unavailable; dependencies may still be shown |
| Zero-idiom/move elimination execution capacity | Rename behavior not qualified | No invented resource bound or elimination credit |
| Memory, folded loads, gather/scatter, AGUs, forwarding, aliasing | Incomplete implementation | Resource/memory recurrence bounds unavailable |

This narrow support matrix is intentional, visible and not an accuracy score.
128/256-bit register SIMD can use exact measured FP mappings; unsupported
resource expressions or missing target measurements fail explicitly. The
import inventory includes **every XML instruction form in its denominator**,
even forms with no selected-target architecture/measurement. It reports each
target and family independently, including mask, compare, shuffle/permute,
compress/expand and gather/scatter. This **data inventory is not model
coverage**. Each analyzed block additionally reports exact-form/resource
coverage and every unsupported instruction/component. No subset accuracy
percentage is presented.

The importer preserves form attributes, operand identities, register/memory
distinctions, masking, zeroing, widths, throughput variants, raw AMD operation
counts, operand-specific latencies and documentation conflicts. Reported AMD
`uops`, modeled execution slots, architectural instructions, dispatch
macro-ops and retirement units are not equated. Missing indexed or other
variant resources cannot be silently borrowed from an Intel configuration.

## Qualification and remaining delivery

No target hardware has been commissioned or executed by this change.
Neither model is hardware-qualified. The separate target reports in
[validation/qualification.json](validation/qualification.json) record this
explicitly and predeclare held-out error budgets before evaluation. No
held-out cases have yet been evaluated, and model/calibration tables must
not be relabeled as held-out observations.

Remaining implementation includes a distinct AMD fetch/decode/op-cache and
finite out-of-order pipeline, fusion/rename/retire accounting, memory and wide
SIMD resource validation, execution traces, expanded real Buster comparisons,
and empirical qualification of both targets. Missing genuine Zen 4 hardware
leaves Zen 4 pending; Zen 5 cannot qualify it. Zen 5 uses the existing approved
9700X path. Agents do not run on either measurement host.

Coordinate physical work with [#2340](https://github.com/buster14a/buster/issues/2340)
and the existing measurement owners. Reuse existing raw measurements first;
batch only missing probes through existing tooling. Receipts need exact bytes,
model/data/decoder hashes, CPU/stepping/microcode/OS/tool identity, affinity/SMT,
cache/clock policy, raw repeats/noise and failed attempts. Core cycles and TSC
ticks are separate quantities. Validate dependent/independent/mixed streams,
loop sizes/unrolling/alignment, scalar/vector widths, memory/masks, real
Buster blocks and alternative ranking. Publish excluded coverage and every
outlier as well as median/tail/worst error for each target.

Pinned LLVM comparisons are other model evidence, not hardware truth.
The inspected local `llvm-mca` 23.1.1 build accepted `znver5` but reported
`Zn4*` resources for both targets on the ZMM add probe. That observation is
specific to the inspected binary, not a claim about every LLVM build.
This fork does not use that tool as an AMD backend.

The analyzer stays an opt-in external development tool. Buster does not gain
a linked dependency, Python orchestration, vendored third-party source or a
mandatory PR gate. Under [#4013](https://github.com/buster14a/buster/issues/4013),
its results remain static/model evidence, distinct from native work counts,
native-host measurements and applicable Zen 5 physical acceptance.

## Maintenance and licensing

Upstream base: `6ebeeab0f8705cae4b17a9362f9c65ef91f5cc44`. Keep an `upstream`
remote pointing to andreas-abel/uiCA; fetch and review updates, merge on a
dedicated synchronization branch, then run both the retained Intel golden
corpus and AMD controls before updating this fork. Update data/decoder/model
locks only in separately reviewed changes with fresh import inventories and
qualification disposition. Generic fixes can be proposed upstream; upstream
acceptance is not required to maintain this fork. The inspected upstream
AMD issue [#31](https://github.com/andreas-abel/uiCA/issues/31) had no implementation
or comments. Recent awitten1 and pawan-nirpal forks retained the same upstream
master; the damageboy fork's maximum-cycle-ratio work is separate. This was a
bounded fork review, not an exhaustive claim about all external AMD work.

| Component | Verified license and handling |
| --- | --- |
| uiCA and this derived fork | [Upstream LICENSE](LICENSE), AGPL-3.0; original history, text and attribution retained |
| Locked XED-to-XML (including XED source) | [Apache-2.0](https://github.com/andreas-abel/XED-to-XML/blob/c71679ee893ae91db677056d542f305fcc433cb1/LICENSE); pinned as the original submodule |
| Locked mbuild | [Apache-2.0](https://github.com/intelxed/mbuild/blob/09b6654be0c52bf1df44e88c88b411a67b624cbd/LICENSE); pinned as the original submodule |
| setuptools 80.9.0 build dependency | [MIT](https://github.com/pypa/setuptools/blob/v80.9.0/LICENSE); not vendored |
| uops.info measurement XML and reference tables | Redistribution grant not verified separately; downloaded only by explicit user setup, raw/converted tables excluded from git. A website template's Creative Commons footer is not treated as a data license |
| AMD documentation | Linked for parameter provenance; documentation/tables not redistributed |
| LLVM, when compared externally | [Apache-2.0 WITH LLVM-exception](https://github.com/llvm/llvm-project/blob/main/llvm/LICENSE.TXT); neither source nor executable vendored |
| Buster own code | License selection remains outside this fork and #4020; no relicensing or source vendoring |

Synthetic tests and original machine-code encodings are committed; third-party
measurement tables are not. This license audit does not grant permission to
redistribute the downloaded cache or a data-bearing hosted service.
