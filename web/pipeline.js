/* Original AGPL renderer. Every colored event comes from the returned trace. */
const stages = [
  ['predecoded', 'P', 'Predecoded', '#9be5f1'], ['queued', 'Q', 'Queued', '#9cc6f5'],
  ['issued', 'I', 'Issued', '#e9a2cf'], ['ready', 'r', 'Operands ready', '#f3ae7c'],
  ['dispatch', 'D', 'Dispatched', '#f5ce70'], ['executed', 'E', 'Executed', '#b7de80'],
  ['retired', 'R', 'Retired', '#64bc9d']
];
function node(tag, text, parent, className) {
  const item = document.createElement(tag);
  if (text !== null) item.textContent = text;
  if (className) item.className = className;
  parent?.append(item);
  return item;
}
export function pipelineView(result, parent, views) {
  const trace = result.trace;
  const amd = result.target.startsWith('ZEN');
  const box = node('section', null, parent, 'pipeline');
  node('h4', amd ? 'Experimental AMD execution timeline' : 'Intel pipeline timeline', box);
  if (!trace || trace.status !== 'available') {
    node('p', trace?.reason || 'No pipeline trace is available for this input.', box, 'modelWarning');
    if (amd) node('p', 'Missing resources or non-exact operand latencies cannot be filled with invented timing.', box);
    return;
  }
  if (amd) node('p', 'Conditional schedule with an ideal, unlimited front end. This is not a full AMD pipeline prediction or a hardware trace.', box, 'modelWarning');
  const flow = node('div', null, box, 'stageFlow');
  const visibleStages = amd ? stages.filter(s => ['ready', 'dispatch', 'executed'].includes(s[0])) : stages;
  if (amd) node('span', 'Fetch / decode / rename: unmodeled', flow, 'unknownStage');
  for (const [key, symbol, label] of visibleStages) node('span', `${symbol} · ${label}`, flow, 'stage-' + key);
  if (amd) node('span', 'Retirement / finite queues: unmodeled', flow, 'unknownStage');
  const controls = node('div', null, box, 'traceControls');
  const firstLabel = node('label', 'Start cycle ', controls);
  const first = node('input', null, firstLabel); first.type = 'number'; first.min = 0; first.max = trace.cycles.length - 1; first.value = 0;
  first.setAttribute('aria-label', result.target + ' start cycle');
  const windowLabel = node('label', 'Cycles shown ', controls);
  const windowSize = node('select', null, windowLabel); windowSize.setAttribute('aria-label', result.target + ' cycles shown');
  for (const value of [16, 32, 64, 128]) { const option = node('option', String(value), windowSize); option.value = value; if (value === 32) option.selected = true; }
  const iterationLabel = node('label', 'Iterations ', controls);
  const iteration = node('select', null, iterationLabel); iteration.setAttribute('aria-label', result.target + ' trace iterations');
  for (const [value, label] of [['first', 'First two'], ['all', 'All eight'], ...Array.from({length: 8}, (_, i) => [String(i), String(i)])]) {
    const option = node('option', label, iteration); option.value = value;
  }
  const previous = node('button', '← Earlier', controls); previous.type = 'button';
  const next = node('button', 'Later →', controls); next.type = 'button';
  const caption = node('p', '', box, 'traceCaption');
  const content = node('div', null, box);
  function redraw() {
    const start = Math.max(0, Math.min(trace.cycles.length - 1, Math.floor(Number(first.value) || 0)));
    first.value = start;
    const end = Math.min(trace.cycles.length - 1, start + Number(windowSize.value) - 1);
    const matching = trace.rows.filter(row => iteration.value === 'all' || (iteration.value === 'first' ? row.iteration < 2 : row.iteration === Number(iteration.value)));
    const rows = matching.slice(0, 256);
    caption.textContent = `Cycles ${start}–${end} · ${rows.length} displayed rows${matching.length > rows.length ? ` of ${matching.length}; full trace in JSON` : ''}. X = executing; W = waiting for operands/resources. Multiple letters mean events share a cycle.`;
    previous.disabled = start === 0; next.disabled = end === trace.cycles.length - 1;
    content.replaceChildren();
    if (views.graph) activityGraph(trace, start, end, visibleStages, content);
    if (views.traceTable) matrix(rows, start, end, content, amd);
  }
  first.addEventListener('change', redraw); windowSize.addEventListener('change', redraw); iteration.addEventListener('change', redraw);
  previous.addEventListener('click', () => { first.value = Math.max(0, Number(first.value) - Number(windowSize.value)); redraw(); });
  next.addEventListener('click', () => { first.value = Math.min(trace.cycles.length - 1, Number(first.value) + Number(windowSize.value)); redraw(); });
  redraw();
  const assumptions = node('details', null, box); node('summary', 'Trace assumptions and limits', assumptions);
  const list = node('ul', null, assumptions); trace.assumptions?.forEach(text => node('li', text, list));
}
function activityGraph(trace, start, end, visibleStages, parent) {
  node('p', 'Stage activity · events per cycle across the recorded eight iterations', parent, 'traceCaption');
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 1000 ${visibleStages.length * 34 + 48}`);
  svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Pipeline stage activity'); svg.classList.add('activityGraph'); parent.append(svg);
  const make = (tag, attrs, text) => {
    const item = document.createElementNS(ns, tag); Object.entries(attrs).forEach(([k, v]) => item.setAttribute(k, v));
    if (text !== undefined) item.textContent = text; svg.append(item); return item;
  };
  const width = 800 / (end - start + 1);
  visibleStages.forEach(([key, , label, color], index) => {
    const y = 12 + index * 34;
    make('text', {x: 4, y: y + 19, 'font-size': 13, 'font-family': 'Arial'}, label);
    for (let cycle = start; cycle <= end; cycle++) {
      const count = trace.cycles[cycle]?.stages?.[key] || 0;
      const rect = make('rect', {x: 155 + (cycle - start) * width, y, width: Math.max(1, width - 1), height: 28, fill: count ? color : '#edf0f4'});
      const title = document.createElementNS(ns, 'title'); title.textContent = `Cycle ${cycle}: ${count} ${label.toLowerCase()} events`; rect.append(title);
      if (count && width >= 15) make('text', {x: 155 + (cycle - start + .5) * width, y: y + 19, 'text-anchor': 'middle', 'font-size': 12, 'font-family': 'Arial'}, count);
    }
  });
  for (let cycle = start; cycle <= end; cycle += Math.max(1, Math.ceil((end - start + 1) / 16))) {
    make('text', {x: 155 + (cycle - start + .5) * width, y: visibleStages.length * 34 + 34, 'text-anchor': 'middle', 'font-size': 12, 'font-family': 'Arial'}, cycle);
  }
}
function matrix(rows, start, end, parent, amd) {
  const scroll = node('div', null, parent, 'traceScroll');
  const table = node('table', null, scroll, 'traceMatrix');
  const heading = node('tr', null, node('thead', null, table));
  ['It.', 'Instruction / operation', 'Resource', ...Array.from({length: end - start + 1}, (_, i) => String(start + i))].forEach(text => node('th', text, heading));
  const body = node('tbody', null, table);
  for (const row of rows) {
    const line = node('tr', null, body);
    node('td', String(row.iteration), line);
    node('td', `${row.instruction}: ${row.assembly} · ${row.unit}`, line, 'traceInstruction');
    node('td', row.resources.join(' + ') || '—', line);
    for (let cycle = start; cycle <= end; cycle++) {
      const hits = stages.filter(([key]) => row.events[key] === cycle);
      let text = hits.map(s => s[1]).join(''), stage = hits.at(-1)?.[0];
      if (!text) {
        const e = row.events;
        if (e.dispatch !== undefined && cycle > e.dispatch && cycle < e.executed) { text = 'X'; stage = 'dispatch'; }
        else if (e.ready !== undefined && cycle >= e.ready && cycle < e.dispatch) { text = 'r'; stage = 'ready'; }
        else if ((amd || (e.issued !== undefined && cycle >= e.issued)) && cycle < e.ready) { text = 'W'; stage = 'waiting'; }
        else if (e.queued !== undefined && cycle > e.queued && cycle < e.issued) { text = 'Q'; stage = 'queued'; }
        else if (e.executed !== undefined && e.retired !== undefined && cycle > e.executed && cycle < e.retired) { text = '·'; stage = 'executed'; }
      }
      const cell = node('td', text, line, stage ? 'stage-' + stage : '');
      cell.title = `Iteration ${row.iteration}, cycle ${cycle}${hits.length ? ': ' + hits.map(s => s[2]).join(', ') : ''}`;
    }
  }
}
