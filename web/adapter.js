/* Original AGPL fork adapter for the explicitly downloaded uiCA web interface. */
'use strict';
const form = document.getElementById('form');
const output = document.getElementById('outputDiv');
const runButton = document.getElementById('runButton');
let config, uploaded = null, reading = false, generation = 0, fileReadGeneration = 0, reportURL = null;

function element(tag, text, parent, className) {
  const node = document.createElement(tag);
  if (text !== null) node.textContent = text;
  if (className) node.className = className;
  if (parent) parent.append(node);
  return node;
}
function selections(name) {
  return [...form.querySelectorAll(`[name="${name}"]:checked`)].map(n => n.value);
}
function options() {
  const amd = selections('uArchs').some(t => t.startsWith('ZEN'));
  for (const node of form.querySelectorAll('[name="tools"]')) {
    node.disabled = node.value !== 'uiCA';
    if (node.disabled) { node.checked = false; node.parentElement.title = 'Not installed in this local adapter'; }
  }
  for (const node of form.querySelectorAll('[name="uiCAHtmlOptions"]')) {
    node.disabled = node.value !== 'dependencies' || !amd;
    if (node.disabled) node.checked = false;
    node.parentElement.title = node.value === 'dependencies' ? 'AMD register/address dependency view' : 'Pipeline trace output is not implemented in this local adapter';
  }
}
function clearReport(message) {
  output.replaceChildren();
  element('p', message, output);
  if (reportURL) URL.revokeObjectURL(reportURL);
  reportURL = null;
}
function inputChanged() {
  generation++;
  if (output.childNodes.length) clearReport('Input changed. Run again to analyze the current selection.');
  options();
}
function number(value) { return value === null || value === undefined ? 'Unavailable' : Number(value).toFixed(2); }
function table(headers, rows, parent, id) {
  const node = element('table', null, parent);
  if (id) node.id = id;
  const header = element('tr', null, element('thead', null, node));
  headers.forEach(text => element('th', text, header));
  const body = element('tbody', null, node);
  rows.forEach(row => {
    const tr = element('tr', null, body);
    row.forEach(text => element('td', text, tr));
  });
  return node;
}
function dependencies(result, parent) {
  const details = element('details', null, parent);
  element('summary', `${result.target.replace('ZEN', 'AMD Zen ')} dependencies`, details);
  const graph = result.dependency_graph;
  if (!graph) { element('p', 'No complete register dependency graph is available for this block.', details); return; }
  element('p', 'Register and address dependencies only. Dashed arrows cross an iteration; memory aliasing and forwarding are unmodeled.', details);
  const size = result.instructions.length;
  if (size <= 16) {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', `0 0 760 ${80 + size * 76}`);
    svg.setAttribute('aria-label', `${result.target} register dependency diagram`);
    svg.setAttribute('role', 'img');
    svg.classList.add('dependencyGraph');
    details.append(svg);
    const make = (tag, attrs) => {
      const node = document.createElementNS(svgNS, tag);
      Object.entries(attrs).forEach(([k, v]) => node.setAttribute(k, v));
      svg.append(node); return node;
    };
    const defs = document.createElementNS(svgNS, 'defs');
    const marker = document.createElementNS(svgNS, 'marker');
    const markerId = 'arrow-' + result.target;
    Object.entries({id: markerId, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse'}).forEach(([k,v]) => marker.setAttribute(k,v));
    const arrow = document.createElementNS(svgNS, 'path'); arrow.setAttribute('d', 'M 0 0 L 10 5 L 0 10 z'); arrow.setAttribute('fill', '#4472c4');
    marker.append(arrow); defs.append(marker); svg.append(defs);
    const seen = new Set();
    for (const edge of graph.edges) {
      const from = graph.nodes.find(n => n.id === edge.source)?.instruction;
      const to = graph.nodes.find(n => n.id === edge.target)?.instruction;
      const key = `${from}-${to}-${edge.iteration_distance}`;
      if (from === undefined || to === undefined || seen.has(key)) continue;
      seen.add(key);
      const a = 44 + from * 76, b = 44 + to * 76;
      make('path', {d: `M 600 ${a} C 710 ${a - 36}, 710 ${b + 36}, 600 ${b}`, fill: 'none', stroke: '#4472c4', 'stroke-width': 2, 'stroke-dasharray': edge.iteration_distance ? '6 4' : '', 'marker-end': `url(#${markerId})`});
    }
    result.instructions.forEach((instruction, i) => {
      make('rect', {x: 12, y: 20 + i * 76, width: 588, height: 48, rx: 4, fill: '#eef3fb', stroke: '#4472c4'});
      make('text', {x: 26, y: 49 + i * 76, 'font-family': 'monospace', 'font-size': 15}).textContent = `${i}: ${instruction.assembly}`;
    });
  } else element('p', 'Diagram limited to 16 instructions; the table and JSON retain every operand edge.', details);
  table(['From instruction / operand', 'To instruction / operand', 'Iteration distance', 'Latency evidence'], graph.edges.map(e => {
    const a = graph.nodes.find(n => n.id === e.source), b = graph.nodes.find(n => n.id === e.target);
    return [`${a.instruction} / ${a.operand}`, `${b.instruction} / ${b.operand}`, String(e.iteration_distance), `${e.latency.kind}: [${e.latency.lower ?? '?'}, ${e.latency.upper ?? '?'}]`];
  }), details);
}
function render(report, showDependencies) {
  clearReport(`Analyzed ${report.input.instructions} instructions / ${report.input.bytes} bytes in ${report.analysis_seconds}s. Results describe these exact bytes.`);
  table(['Microarchitecture', 'Analysis', 'Pipeline cycles / iteration', 'Conditional resource bound', 'Register recurrence bound', 'Coverage'], report.results.map(r => [
    r.target.replace('ZEN', 'AMD Zen '), r.analysis_mode === 'upstream-intel-pipeline' ? 'Intel pipeline simulation' : r.analysis_mode === 'experimental-conditional-bounds' ? 'Experimental AMD bounds' : r.status,
    number(r.predicted_steady_state_cycles), number(r.bounds?.conditional_execution_resources), number(r.bounds?.register_recurrence),
    r.coverage ? `${r.coverage.exact_forms}/${r.coverage.instructions} exact forms; ${r.coverage.resource_modeled}/${r.coverage.instructions} resources` : (r.error || 'Original Intel model')
  ]), output, 'TPTable');
  const amd = report.results.filter(r => r.target.startsWith('ZEN'));
  if (amd.length) element('p', 'AMD bounds are experimental and conditional. Pipeline cycles remain unavailable; front end, finite queues, retirement and memory execution are unmodeled. These are not measured speedups.', output, 'modelWarning');
  for (const result of report.results) {
    const block = element('div', null, output, 'toolOutput');
    element('h3', result.target.replace('ZEN', 'AMD Zen '), block);
    if (result.error) { element('p', result.error, block); continue; }
    if (result.coverage) {
      const pressure = result.bottleneck_resource_subsets;
      element('p', pressure.length ? 'Limiting eligible resource groups: ' + pressure.map(p => p.join(' / ')).join('; ') : 'Resource ceiling unavailable or no limiting resource group identified.', block);
      if (result.unsupported.length) {
        element('h4', 'Coverage gaps', block);
        const list = element('ul', null, block);
        result.unsupported.forEach(g => element('li', `${g.instruction === null ? 'Block' : 'Instruction ' + g.instruction} · ${g.component}: ${g.reason}`, list));
      }
      if (showDependencies) dependencies(result, block);
    }
    const details = element('details', null, block);
    element('summary', 'Instruction details', details);
    table(['#', 'Assembly', 'Bytes', 'Exact form / evidence'], result.instructions.map((r, i) => [String(i), r.assembly, r.bytes, r.form || r.iform]), details);
  }
  const download = element('a', 'Download JSON report', output, 'download');
  reportURL = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
  download.href = reportURL; download.download = `uica-${report.input.code_sha256.slice(0, 10)}.json`;
  const provenance = element('details', null, output);
  element('summary', 'Exact bytes and provenance', provenance);
  element('pre', JSON.stringify({input: report.input, provenance: report.provenance}, null, 2), provenance);
}
async function run() {
  if (reading || !config) return;
  const current = generation;
  const data = new FormData(form);
  const syntax = data.get('syntax');
  const request = uploaded || {mode: syntax === 'hex' ? 'hex' : 'assembly', input: data.get('code'), syntax};
  const payload = {...request, targets: selections('uArchs'), alignment: Number(data.get('alignment'))};
  const deps = selections('uiCAHtmlOptions').includes('dependencies');
  if (!selections('tools').includes('uiCA')) { clearReport('Select uiCA to analyze the block.'); return; }
  runButton.disabled = true;
  clearReport('Processing…');
  try {
    const response = await fetch('/api/analyze', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-uiCA-Token': config.token}, body: JSON.stringify(payload)});
    const report = await response.json();
    if (current !== generation) return;
    if (!response.ok) throw new Error(report.error || 'Analysis failed.');
    render(report, deps);
  } catch (error) { if (current === generation) clearReport(error.message); }
  finally { runButton.disabled = reading || !config; }
}
function restoreURL() {
  if (!location.search) return;
  const params = new URLSearchParams(location.search);
  for (const name of ['uArchs', 'tools', 'uiCAHtmlOptions']) {
    if (!params.has(name)) continue;
    for (const node of form.querySelectorAll(`[name="${name}"]`)) node.checked = params.getAll(name).includes(node.value);
  }
  const syntax = params.get('syntax');
  for (const node of form.querySelectorAll('[name="syntax"]')) if (syntax) node.checked = node.value === syntax;
  if (params.has('code')) form.elements.code.value = params.get('code');
  if (params.has('alignment')) form.elements.alignment.value = params.get('alignment');
  history.replaceState(null, '', location.pathname);
}
runButton.addEventListener('click', run);
form.addEventListener('submit', e => { e.preventDefault(); run(); });
form.addEventListener('input', e => {
  if (e.target.id === 'file') return;
  if (e.target.name === 'code' || e.target.name === 'syntax' || e.target.id === 'fileMode') {
    uploaded = null; document.getElementById('file').value = '';
  }
  inputChanged();
});
document.getElementById('urlButton').addEventListener('click', async () => {
  if (uploaded) { clearReport('Sharing a file input through a URL is unavailable. Use hex text or export the JSON report.'); return; }
  const url = location.origin + location.pathname + '?' + new URLSearchParams(new FormData(form));
  try { await navigator.clipboard.writeText(url); clearReport('URL copied to clipboard. It opens on this local computer.'); }
  catch { clearReport('Copy this local URL: ' + url); }
});
document.getElementById('file').addEventListener('change', async e => {
  inputChanged(); uploaded = null;
  const readId = ++fileReadGeneration;
  reading = false; runButton.disabled = !config;
  const file = e.target.files[0];
  if (!file) return;
  const current = generation;
  const mode = document.getElementById('fileMode').value;
  if (file.size > (mode === 'raw' ? 8192 : 16 * 1024 * 1024)) { clearReport('File exceeds the input size limit.'); return; }
  reading = true; runButton.disabled = true;
  clearReport('Reading ' + file.name + '…');
  try {
    const input = await new Promise((resolve, reject) => {
      const reader = new FileReader(); reader.onload = () => resolve(reader.result.split(',')[1]); reader.onerror = () => reject(new Error('File could not be read.')); reader.readAsDataURL(file);
    });
    if (generation === current) {
      uploaded = {mode, input};
      clearReport(`${file.name} ready (${file.size} bytes). Run to analyze this file.`);
    }
  } catch (error) { if (generation === current) clearReport(error.message); }
  finally { if (readId === fileReadGeneration) { reading = false; runButton.disabled = !config; } }
});
document.getElementById('example').addEventListener('change', e => {
  const example = config?.examples.find(item => item.id === e.target.value);
  if (!example) return;
  uploaded = null; document.getElementById('file').value = '';
  form.elements.code.value = example.assembly;
  form.querySelector('[name="syntax"][value="asIntel"]').checked = true;
  inputChanged();
});
restoreURL();
options();
fetch('/api/config').then(r => { if (!r.ok) throw new Error('Local service unavailable.'); return r.json(); }).then(value => {
  config = value;
  value.examples.forEach(example => {
    const option = element('option', example.name, document.getElementById('example')); option.value = example.id;
  });
  for (const radio of form.querySelectorAll('[name="syntax"]')) {
    if ((radio.value === 'NASM' && !value.nasm_available) || (radio.value.startsWith('as') && !value.assembly_available)) radio.disabled = true;
  }
  runButton.disabled = false;
}).catch(error => clearReport(error.message + ' Restart the local server and reload.'));
