# uiCA (uops.info Code Analyzer)

This is Buster's maintained fork of [andreas-abel/uiCA](https://github.com/andreas-abel/uiCA).
The upstream Intel simulator is retained. An opt-in **experimental AMD
resource/recurrence-bound analyzer** supports explicit `ZEN4` / `ZEN5` selection;
it does **not** yet implement or qualify a complete AMD pipeline simulator.
See [AMD setup, supported scope and remaining acceptance](AMD.md).
Work is tracked in [Buster #4020](https://github.com/buster14a/buster/issues/4020).

uiCA is a simulator that can predict the throughput of basic blocks on recent Intel microarchitectures.
In addition to that, it also provides insights into how the code is executed.

uiCA is based on data from [uops.info](https://www.uops.info), combined with a detailed pipeline model.
Like related tools, it assumes that all memory accesses result in cache hits.

Details on uiCA's pipeline model, as well as a comparison with similar tools, can be found in our paper [uiCA: Accurate Throughput Prediction of Basic Blocks on Recent Intel Microarchitectures](https://dl.acm.org/doi/pdf/10.1145/3524059.3532396).

## Web Interface

**This fork adapts the actual [uiCA.uops.info](https://uica.uops.info/) browser
interface for local Intel, Zen 4 and Zen 5 analysis.** After the
[pinned AMD setup](AMD.md#reproducible-setup), explicitly fetch the pinned client
assets and launch:

```sh
.venv/bin/python setup_uica_web.py --download
.venv/bin/python zen_gui.py --open
```

Open [the local interface](http://127.0.0.1:8765): paste GNU as Intel/AT&T,
NASM or hex code; select up to four targets; and press **Run!**. The familiar
upstream form and results table are retained, with AMD comparisons, examples,
raw/ELF uploads, register dependency views, coverage gaps and JSON export.
Intel choices use the original uiCA pipeline model. AMD remains experimental
conditional resource/recurrence analysis, with no full pipeline prediction or
hardware qualification. External analyzers and pipeline traces are disabled in
this local adapter. See [GUI details](AMD.md#graphical-interface).

The separate frontend's license is unverified, and its CGI backend is absent
from the published simulator repository. Downloaded source/assets stay in the
ignored `.uica-web/` local cache, outside public git. The fork contains original
adapter/backend code and pinned download URLs/hashes. Setup removes telemetry
and third-party URL shortening before caching; analysis never downloads assets
or uploads code to the upstream site. The upstream hosted service does not
contain this fork's AMD work.

## Installation
### Ubuntu

* Prerequisites:

      sudo apt-get install gcc python3 python3-pip graphviz
      pip3 install plotly

* Installation:

      git clone https://github.com/andreas-abel/uiCA.git
      cd uiCA
      ./setup.sh

* Update:

      git pull
      ./setup.sh

### Windows

* Prerequisites:
  * [Python 3](https://www.python.org/downloads/)
  * [MSVS compiler](https://visualstudio.microsoft.com/de/vs/features/cplusplus/)
  * `pip3 install plotly pydot`

* Installation:

      git clone https://github.com/andreas-abel/uiCA.git
      cd uiCA
      .\setup.cmd

* Update:

      git pull
      .\setup.cmd

## Example Usage

	echo ".intel_syntax noprefix; l: add rax, rbx; add rbx, rax; dec r15; jnz l" > test.asm
    as test.asm -o test.o
    ./uiCA.py test.o -arch SKL

## Command-Line Options

The following parameters are optional. Parameter names may be abbreviated if the abbreviation is unique (e.g., `-ar` may be used instead of `-arch`).

| Option                       | Description |
|------------------------------|-------------|
| `-arch`                  | The microarchitecture of the simulated CPU. Available microarchitectures: `SNB`, `IVB`, `HSW`, `BDW`, `SKL`, `SKX`, `KBL`, `CFL`, `CLX`, `ICL`, `TGL`, `RKL`. Alternatively, you can use `all` to get an overview of the throughputs for all supported microarchitectures.  `[Default: all]` |
| `-iacaMarkers`           | Analyze only the code that is between the `IACA_START` and `IACA_END` markers of Intel's [IACA](https://software.intel.com/content/www/us/en/develop/articles/intel-architecture-code-analyzer.html) tool. |
| `-raw`                   | Analyze a file that directly contains the machine code of the benchmark, but no headers or other data. |
| `-trace <filename.html>` | Generate an HTML file that contains a table with a cycle-by-cycle view of how the instructions are executed. |
| `-graph <filename.html>` | Generate an HTML file that contains a graph with various performance-related events.  |
| `-depGraph <filename.x>` | Output the dependency graph; the format is determined by the filename extension (e.g., svg, png, dot, etc.)  |
| `-alignmentOffset`       | Alignment offset (relative to a 64-Byte cache line). The option `all` provides an overview of the throughputs for all possible alignment offsets. `[Default: 0]` |
| `-TPonly`                | Output only the throughput prediction. |
| `-minIterations <n>`     | Simulate at least n iterations of the code. `[Default: 10]`. |
| `-minCycles <n>`         | Simulate at least n cycles. `[Default: 500]`. |
| `-simpleFrontEnd`        | Simulate a simple front end that is only limited by the issue width. |
| `-noMicroFusion`         | Simulate a CPU variant that does not support micro-fusion. |
| `-noMacroFusion`         | Simulate a CPU variant that does not support macro-fusion. |
