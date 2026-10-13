'use strict';
const $ = (id) => document.getElementById(id);
const state = { config: null, report: null, mode: 'assembly', view: 'resources', target: 'ZEN4', busy: false,
  text: { assembly: '', hex: '' }, file: null, fileName: '', selectedInstruction: null, readingFile: false, fileReadId: 0 };
const colors = { ZEN4: '#72e5c0', ZEN5: '#baabff' };
const plural = (number, word) => `${number} ${word}${number === 1 ? '' : 's'}`;
const pretty = (value) => value == null ? 'Unavailable' : Number(value).toFixed(2);
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}
function svgEl(tag, attrs = {}, text) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
  if (text != null) node.textContent = text;
  return node;
}
function markEdited() {
  $('error').classList.add('hidden');
  if (state.report && !state.busy) {
    $('run-status').textContent = 'Input changed · analyze to refresh';
    $('run-status').classList.remove('ready');
    $('export').title = 'Export the previous analyzed block';
  }
}
function updateLines() {
  const lines = $('code').value.split('\n').length;
  const bytes = $('code').value.replace(/\s/g, '').replace(/0x/gi, '').length / 2;
  $('line-numbers').textContent = Array.from({length: lines}, (_, i) => i + 1).join('\n');
  $('input-count').textContent = state.mode === 'hex'
    ? `${plural(bytes, 'byte')} entered`
    : `${lines} ${lines === 1 ? 'line' : 'lines'}`;
}
function setMode(mode) {
  if (state.mode !== 'file') state.text[state.mode] = $('code').value;
  state.mode = mode;
  document.querySelectorAll('.input-tab').forEach(button => {
    const selected = button.dataset.mode === mode;
    button.classList.toggle('active', selected); button.setAttribute('aria-selected', String(selected));
  });
  $('editor-wrap').classList.toggle('hidden', mode === 'file');
  $('upload-zone').classList.toggle('hidden', mode !== 'file');
  $('syntax-label').textContent = mode === 'assembly' ? 'Intel syntax' : mode === 'hex' ? 'Raw x86-64 machine code' : 'Machine-code file';
  $('code').setAttribute('aria-label', mode === 'assembly' ? 'Assembly code' : 'Hex code');
  if (mode !== 'file') {
    $('code').value = state.text[mode];
    $('code').placeholder = mode === 'hex' ? '48 01 d8 48 01 c3' : 'add rax, rbx\nadd rbx, rax';
    updateLines();
  } else $('input-count').textContent = state.fileName || 'No file selected';
  markCustomInput(); markEdited();
}
function markCustomInput() {
  $('context-label').textContent = 'YOUR INPUT';
  $('example-name').textContent = state.mode === 'hex' ? 'Your machine-code block' : 'Your assembly block';
  $('example-tag').textContent = state.mode === 'hex' ? 'HEX' : 'AMD64';
  $('example-description').textContent = 'Compare this exact block on both targets. Results refresh when you analyze.';
}
function loadExample(id, run = true) {
  const example = state.config.examples.find(item => item.id === id);
  if (!example) return;
  setMode('assembly');
  $('code').value = example.assembly; state.text.assembly = example.assembly;
  $('context-label').textContent = 'CURRENT EXAMPLE';
  $('example-name').textContent = example.name;
  $('example-description').textContent = example.description;
  $('example-tag').textContent = example.tag;
  updateLines(); markEdited();
  $('examples-dialog').close();
  if (run) analyzeBlock();
}
function setBusy(busy) {
  state.busy = busy;
  $('code').readOnly = busy; $('file').disabled = busy || state.readingFile; $('file-format').disabled = busy || state.readingFile;
  document.querySelectorAll('.input-tab').forEach(button => { button.disabled = busy || state.readingFile; });
  $('analyze').disabled = busy || !state.config || state.readingFile;
  $('analyze-label').textContent = busy ? 'Analyzing both targets…' : 'Analyze block';
  document.querySelector('.results-column').classList.toggle('loading', busy);
  $('analyze').setAttribute('aria-busy', String(busy));
  document.querySelectorAll('[data-example],.example-choice').forEach(button => { button.disabled = busy || state.readingFile; });
}
async function analyzeBlock() {
  if (state.busy || state.readingFile || !state.config) return;
  $('error').classList.add('hidden');
  let mode = state.mode, input = $('code').value;
  if (mode === 'file') {
    if (!state.file) { showError('Choose a raw binary or ELF object first.'); return; }
    mode = $('file-format').value; input = state.file;
  }
  setBusy(true);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 90000);
  try {
    const response = await fetch('/api/analyze', {method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-uiCA-Token': state.config.token},
      body: JSON.stringify({mode, input}), signal: controller.signal});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'The block could not be analyzed.');
    state.report = result; state.selectedInstruction = null;
    renderReport();
  } catch (error) {
    showError(error.name === 'AbortError' ? 'Analysis took too long. Try a smaller code block.' : error.message);
    $('run-status').textContent = state.report ? 'Previous result · new analysis failed' : 'Analysis needs attention';
    $('run-status').classList.remove('ready');
  } finally { clearTimeout(timeout); setBusy(false); }
}
function showError(message) { $('error').textContent = message; $('error').classList.remove('hidden'); }
function currentResult() { return state.report?.results.find(result => result.target === state.target); }
function renderReport() {
  const report = state.report;
  for (const result of report.results) {
    const name = result.target, resource = result.bounds.conditional_execution_resources;
    $('resource-' + name).textContent = pretty(resource);
    $('resource-' + name).classList.toggle('unavailable', resource == null);
    $('recurrence-' + name).textContent = result.bounds.register_recurrence == null ? 'Unavailable' : `${pretty(result.bounds.register_recurrence)} cycles`;
    const coverage = result.coverage;
    $('coverage-' + name).textContent = `${coverage.resource_modeled}/${coverage.instructions} resources`;
    $('coverage-' + name).classList.toggle('partial', result.status === 'partial');
    $('footnote-' + name).textContent = result.bounds.register_recurrence === 0 ? 'No loop-carried register recurrence' :
      result.bounds.register_recurrence == null ? 'Some dependencies are outside the model' : 'Loop-carried register dependency bound';
  }
  $('instruction-badge').textContent = report.input.instructions;
  $('run-status').textContent = `Analyzed in ${report.analysis_seconds.toFixed(2)}s`;
  $('run-status').classList.add('ready');
  $('block-summary').textContent = `${plural(report.input.instructions, 'instruction')} · ${plural(report.input.bytes, 'byte')} · SHA ${report.input.code_sha256.slice(0, 10)}`;
  $('export').disabled = false; $('export').title = 'Export this analyzed block and model provenance';
  renderResources(); renderDetails(); renderGaps();
}
function groupedResources(result) {
  const groups = new Map();
  for (const row of result.instructions) for (const job of row.resources || []) {
    const key = job.join(' / '); groups.set(key, (groups.get(key) || 0) + 1);
  }
  return groups;
}
function renderResources() {
  const chart = $('resource-chart'); chart.replaceChildren();
  const reports = state.report.results;
  const counts = reports.map(groupedResources);
  const names = [...new Set(counts.flatMap(count => [...count.keys()]))];
  if (!names.length) { chart.append(el('div', 'empty-state', 'Resource mappings are not available for this block. The gaps below explain what is missing.')); return; }
  const max = Math.max(1, ...counts.flatMap(count => [...count.values()]));
  for (const name of names) {
    const group = el('div', 'resource-group');
    const title = el('div', 'resource-group-header', name);
    title.append(el('small', '', 'eligible group')); group.append(title);
    reports.forEach((result, index) => {
      const row = el('div', 'bar-row'), track = el('div', 'bar-track'), fill = el('div', 'bar-fill');
      const value = counts[index].get(name) || 0;
      fill.style.width = `${value / max * 100}%`; fill.style.backgroundColor = colors[result.target];
      track.append(fill); row.append(track, el('span', 'bar-value', String(value)));
      row.setAttribute('aria-label', `${result.target}: ${value} modeled slots on ${name}`);
      group.append(row);
    }); chart.append(group);
  }
  if (reports.some(result => result.coverage.resource_modeled < result.coverage.instructions))
    chart.append(el('p', 'resource-caveat', 'Only mapped instructions appear here. The incomplete total is not a resource bound for the whole block.'));
  $('resource-caption').textContent = 'Groups show eligible execution resources, not simulated utilization. Occupancy assumptions remain conditional; Zen 4 wide-vector splitting is applied only to the admitted forms.';
}
function chooseView(view) {
  state.view = view;
  document.querySelectorAll('.detail-tab').forEach(button => {
    const selected = button.dataset.view === view;
    button.classList.toggle('active', selected); button.setAttribute('aria-selected', String(selected));
  });
  ['resources', 'dependencies', 'instructions'].forEach(name => $(name + '-view').classList.toggle('hidden', name !== view));
  $('graph-target').classList.toggle('hidden', view === 'resources');
  renderDetails();
}
function renderDetails() {
  if (!state.report) return;
  if (state.view === 'dependencies') renderGraph();
  if (state.view === 'instructions') renderInstructions();
}
function renderGraph() {
  const root = $('dependency-graph'); root.replaceChildren();
  const result = currentResult(), graph = result.dependency_graph;
  if (!graph) { root.append(el('div', 'empty-state', 'An exact dependency graph is not available for every form in this block. Inspect the coverage gaps below.')); return; }
  const instructions = [...new Set(graph.nodes.map(node => node.instruction))];
  if (instructions.length > 16) {
    root.append(el('div', 'empty-state', `This block has ${instructions.length} instructions. The full operand graph is included in the JSON export; use a smaller block for the diagram.`)); return;
  }
  // Collapse operand nodes only for display. The exported graph retains every
  // operand edge and latency bound; identical visual links share one tooltip.
  const nodeInstruction = new Map(graph.nodes.map(node => [node.id, node.instruction]));
  const edges = new Map();
  graph.edges.forEach(edge => {
    const source = nodeInstruction.get(edge.source), target = nodeInstruction.get(edge.target);
    const key = `${source}/${target}/${edge.iteration_distance}/${edge.latency.lower}/${edge.latency.upper}`;
    if (!edges.has(key)) edges.set(key, {...edge, source, target, count: 0});
    edges.get(key).count++;
  });
  const width = 620, nodeWidth = 240, nodeHeight = 58;
  const rows = Math.ceil(instructions.length / 2), height = rows * 165 + 45;
  const svg = svgEl('svg', {viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': `${state.target} register dependency graph`});
  const defs = svgEl('defs'), marker = svgEl('marker', {id: 'arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 5, markerHeight: 5, orient: 'auto-start-reverse'});
  marker.append(svgEl('path', {d: 'M 0 0 L 10 5 L 0 10 z', fill: '#8fb9bb'})); defs.append(marker); svg.append(defs);
  const positions = new Map();
  instructions.forEach((id, index) => positions.set(id, {x: 25 + index % 2 * 330, y: 48 + Math.floor(index / 2) * 165}));
  [...edges.values()].slice(0, 60).forEach((edge, index) => {
    const from = positions.get(edge.source), to = positions.get(edge.target);
    if (!from || !to) return;
    const sx = from.x + nodeWidth / 2, sy = from.y + nodeHeight, tx = to.x + nodeWidth / 2, ty = to.y;
    let path, labelX, labelY;
    if (edge.source === edge.target) {
      path = `M${sx + 62},${sy} C${sx + 72},${sy + 60} ${sx - 72},${sy + 60} ${sx - 62},${sy}`;
      labelX = sx; labelY = sy + 38;
    } else if (from.y === to.y && !edge.iteration_distance) {
      path = `M${from.x + nodeWidth},${from.y + 29} L${to.x},${to.y + 29}`;
      labelX = (from.x + nodeWidth + to.x) / 2; labelY = from.y + 19;
    } else if (from.y === to.y) {
      path = `M${sx},${from.y} C${sx},${from.y - 48} ${tx},${to.y - 48} ${tx},${to.y}`;
      labelX = (sx + tx) / 2; labelY = from.y - 30;
    } else {
      const bend = Math.max(30, Math.abs(ty - sy) * .45) + (index % 3) * 7;
      path = `M${sx},${sy} C${sx},${sy + bend} ${tx},${ty - bend} ${tx},${ty}`;
      labelX = (sx + tx) / 2 + 14; labelY = (sy + ty) / 2;
    }
    const line = svgEl('path', {d: path, class: `graph-edge ${edge.iteration_distance ? 'carried' : ''}`, 'marker-end': 'url(#arrow)'});
    line.append(svgEl('title', {}, `${edge.count} operand links; iteration distance ${edge.iteration_distance}`)); svg.append(line);
    const latency = edge.latency;
    const label = latency.lower == null ? (latency.upper == null ? '?' : `≤${latency.upper}`) : latency.lower === latency.upper ? String(latency.lower) : `≥${latency.lower}`;
    svg.append(svgEl('text', {x: labelX, y: labelY, class: 'edge-label', 'text-anchor': 'middle'}, `${label} cyc${edge.iteration_distance ? ' · ↻' : ''}`));
  });
  instructions.forEach(id => {
    const p = positions.get(id), group = svgEl('g', {class: 'graph-node'});
    group.append(svgEl('rect', {x: p.x, y: p.y, width: nodeWidth, height: nodeHeight, rx: 7}));
    const instruction = result.instructions[id].assembly;
    group.append(svgEl('text', {x: p.x + 13, y: p.y + 25}, instruction.length > 29 ? instruction.slice(0, 28) + '…' : instruction));
    group.append(svgEl('text', {x: p.x + 13, y: p.y + 43, class: 'operand'}, `INSTRUCTION ${String(id + 1).padStart(2, '0')}`));
    group.append(svgEl('title', {}, instruction)); svg.append(group);
  });
  root.append(svg);
  $('dependency-caption').textContent = `${plural(instructions.length, 'instruction')} · ${plural(graph.edges.length, 'operand link')}, grouped for readability. Latency bounds stay labeled; unknown values are ?. The JSON export retains the full graph.`;
}
function renderInstructions() {
  const tbody = $('instruction-rows'); tbody.replaceChildren();
  currentResult().instructions.forEach((instruction, index) => {
    const row = el('tr', state.selectedInstruction === index ? 'selected' : ''); row.tabIndex = 0;
    row.setAttribute('aria-label', `Inspect instruction ${index + 1}: ${instruction.assembly}`);
    row.append(el('td', '', String(index + 1).padStart(2, '0')), el('td', '', instruction.assembly), el('td', '', instruction.family || 'Unknown form'));
    const status = el('td'); status.append(el('span', instruction.resources == null ? 'status-gap' : 'status-known', instruction.resources == null ? '◈ Missing' : '✓ Mapped')); row.append(status);
    const select = () => { state.selectedInstruction = index; renderInstructions(); renderInstructionDetail(instruction); };
    row.addEventListener('click', select); row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); } });
    tbody.append(row);
  });
  if (state.selectedInstruction == null) $('instruction-detail').classList.add('hidden');
  else renderInstructionDetail(currentResult().instructions[state.selectedInstruction]);
}
function renderInstructionDetail(instruction) {
  const root = $('instruction-detail'); root.replaceChildren(); root.classList.remove('hidden');
  root.append(el('strong', '', instruction.assembly));
  const form = el('p'); form.append(el('span', '', 'Decoded form: '), el('code', '', instruction.iform)); root.append(form);
  if (instruction.decoder_form_alias) root.append(el('p', '', `Reviewed data-form mapping: ${instruction.data_iform}`));
  root.append(el('p', '', `Bytes: ${instruction.bytes.match(/../g).join(' ')}`));
  for (const note of instruction.annotations || []) root.append(el('p', '', note));
  if (instruction.resources != null) root.append(el('p', '', `Eligible resources: ${[...new Set(instruction.resources.map(job => job.join('/')))].join(', ')}`));
  for (const record of instruction.latency_measurements || []) {
    const details = Object.entries(record).filter(([key]) => !['start_op', 'target_op'].includes(key)).map(([key, value]) => `${key}: ${value}`).join(' · ');
    root.append(el('div', 'latency-line', `operand ${record.start_op} → ${record.target_op} · ${details}`));
  }
}
function renderGaps() {
  const list = $('gap-list'); list.replaceChildren();
  const gaps = new Map();
  state.report.results.forEach(result => result.unsupported.forEach(failure => {
    const index = failure.instruction, assembly = index == null ? '' : result.instructions[index]?.assembly || '';
    const key = `${index}/${failure.component}/${failure.reason}`;
    if (!gaps.has(key)) gaps.set(key, {failure, assembly, targets: []});
    gaps.get(key).targets.push(result.target.replace('ZEN', 'Zen '));
  }));
  $('gaps').classList.toggle('hidden', gaps.size === 0);
  $('gap-count').textContent = `${gaps.size} ${gaps.size === 1 ? 'gap' : 'gaps'}`;
  for (const {failure, assembly, targets} of gaps.values()) {
    const item = el('div', 'gap-item');
    item.append(el('strong', '', `${targets.join(' / ')}${assembly ? ' · ' + assembly : ''}: `));
    item.append(document.createTextNode(failure.reason)); list.append(item);
  }
}
function showProvenance() {
  const root = $('provenance-body'); root.replaceChildren();
  if (!state.report) root.append(el('p', '', 'Analyze a block first to inspect its exact input and model identity.'));
  else {
    const report = state.report, identity = report.provenance;
    const fields = [['Input SHA256', report.input.code_sha256], ['Input bytes', report.input.code_hex],
      ['Fork revision', identity.fork_revision || 'Unavailable'], ['Source state', identity.working_tree_dirty ? 'Contains local changes; source hashes are in the export' : 'Clean committed source'],
      ['Instruction data SHA256', identity.data_xml_sha256], ['Imported data SHA256', identity.data_import_sha256],
      ['Decoder revision', identity.decoder.source_revision], ['Decoder binary SHA256', identity.decoder.sha256],
      ['Analysis assumptions', 'Repeat exact block · unroll factor 1 · alignment effects not modeled']];
    for (const [name, value] of fields) { const row = el('div', 'provenance-line'); row.append(el('span', '', name), el('code', '', value)); root.append(row); }
    root.append(el('p', '', 'Export JSON retains both target reports, model annotations, coverage gaps and source hashes. Neither target is hardware-qualified.'));
  }
  $('provenance-dialog').showModal();
}
function toast(message) { $('toast').textContent = message; $('toast').classList.remove('hidden'); setTimeout(() => $('toast').classList.add('hidden'), 3000); }
function exportReport() {
  if (!state.report) return;
  const blob = new Blob([JSON.stringify(state.report, null, 2) + '\n'], {type: 'application/json'});
  const url = URL.createObjectURL(blob), link = el('a'); link.href = url;
  link.download = `uica-zen-${state.report.input.code_sha256.slice(0, 10)}.json`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 3000); toast('Analysis report exported');
}
async function selectFile(file) {
  if (!file || state.busy) return;
  if (file.size > 16 * 1024 * 1024) { showError('Choose a file of at most 16 MiB.'); return; }
  const readId = ++state.fileReadId;
  state.readingFile = true; state.file = null; setBusy(false); markEdited();
  $('file-name').textContent = `Reading ${file.name}…`;
  $('analyze-label').textContent = 'Reading file…';
  const reader = new FileReader();
  reader.onload = () => {
    if (readId !== state.fileReadId) return;
    state.readingFile = false; setBusy(false);
    state.file = String(reader.result).split(',')[1]; state.fileName = file.name;
    $('file-name').textContent = `${file.name} · ${file.size.toLocaleString()} bytes`;
    $('file-format').value = /\.(o|obj)$/i.test(file.name) ? 'object' : 'raw';
    $('context-label').textContent = 'YOUR INPUT'; $('example-name').textContent = 'Your uploaded block'; $('example-description').textContent = 'The file is decoded locally. Its bytes are never executed.';
    $('example-tag').textContent = $('file-format').value === 'object' ? 'ELF64' : 'RAW';
    $('input-count').textContent = `${file.size.toLocaleString()} file bytes`; markEdited(); };
  reader.onerror = () => {
    if (readId !== state.fileReadId) return;
    state.readingFile = false; setBusy(false); showError('The file could not be read.');
  }; reader.readAsDataURL(file);
}
function configureTabs(selector) {
  const buttons = [...document.querySelectorAll(selector)];
  buttons.forEach(button => button.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    const next = buttons[(buttons.indexOf(button) + (event.key === 'ArrowRight' ? 1 : buttons.length - 1)) % buttons.length];
    next.focus(); next.click();
  }));
}
document.querySelectorAll('.input-tab').forEach(button => button.addEventListener('click', () => setMode(button.dataset.mode)));
document.querySelectorAll('.detail-tab').forEach(button => button.addEventListener('click', () => chooseView(button.dataset.view)));
document.querySelectorAll('[data-target]').forEach(button => button.addEventListener('click', () => {
  state.target = button.dataset.target; state.selectedInstruction = null;
  document.querySelectorAll('[data-target]').forEach(item => item.classList.toggle('active', item === button)); renderDetails();
}));
$('code').addEventListener('input', () => { updateLines(); markCustomInput(); markEdited(); });
$('code').addEventListener('scroll', () => { $('line-numbers').scrollTop = $('code').scrollTop; });
new ResizeObserver(() => { $('line-numbers').style.height = `${$('code').clientHeight}px`; }).observe($('code'));
$('code').addEventListener('keydown', event => { if (event.key === 'Tab') {
  event.preventDefault(); const start = $('code').selectionStart, end = $('code').selectionEnd;
  $('code').setRangeText('    ', start, end, 'end'); updateLines(); markEdited();
} });
document.addEventListener('keydown', event => { if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') { event.preventDefault(); analyzeBlock(); } });
$('analyze').addEventListener('click', analyzeBlock); $('export').addEventListener('click', exportReport);
['examples-open', 'examples-nav'].forEach(id => $(id).addEventListener('click', () => { if (state.config) $('examples-dialog').showModal(); }));
['model-notes', 'scope-more', 'about-nav'].forEach(id => $(id).addEventListener('click', () => $('notes-dialog').showModal()));
$('provenance-open').addEventListener('click', showProvenance);
$('workspace-nav').addEventListener('click', () => { window.scrollTo({top: 0, behavior: 'smooth'}); $('code').focus(); });
document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => button.closest('dialog').close()));
document.querySelectorAll('dialog').forEach(dialog => dialog.addEventListener('click', event => { if (event.target === dialog) {
  const rect = dialog.getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close();
} }));
document.querySelectorAll('[data-example]').forEach(button => button.addEventListener('click', () => loadExample(button.dataset.example)));
$('file').addEventListener('change', () => selectFile($('file').files[0]));
$('file-format').addEventListener('change', markEdited);
$('upload-zone').addEventListener('dragover', event => { event.preventDefault(); $('upload-zone').classList.add('dragging'); });
$('upload-zone').addEventListener('dragleave', () => $('upload-zone').classList.remove('dragging'));
$('upload-zone').addEventListener('drop', event => { event.preventDefault(); $('upload-zone').classList.remove('dragging'); selectFile(event.dataTransfer.files[0]); });
configureTabs('.input-tab'); configureTabs('.detail-tab');
async function initialize() {
  setBusy(false); $('analyze').disabled = true;
  try {
    const response = await fetch('/api/config', {credentials: 'same-origin'});
    if (!response.ok) throw new Error('The local analyzer is not ready.');
    state.config = await response.json();
    const list = $('example-list');
    state.config.examples.forEach(example => {
      const button = el('button', 'example-choice'); button.append(el('strong', '', example.name), el('span', '', example.tag), el('p', '', example.description));
      button.addEventListener('click', () => loadExample(example.id)); list.append(button);
    });
    $('connection-status').textContent = 'Local analyzer ready'; $('analyze').disabled = false;
    if (state.config.assembly_available) loadExample('wide');
    else { setMode('hex'); $('code').value = '62 f1 75 48 fe c2'; updateLines(); analyzeBlock(); }
  } catch (error) { showError(`Could not connect to the analyzer. ${error.message}`); $('connection-status').textContent = 'Analyzer unavailable'; }
}
initialize();
