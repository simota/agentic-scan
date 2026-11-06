// DOM-level audit for when no real browser can start: layout, pixels and colour are out of reach, structure and
// keyboard behaviour are not. Development only.
//   NODE_PATH-free usage: node dom_audit.mjs <dashboard.html> <report.html> <node_modules dir>
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const [dashboardPath, reportPath, modules] = process.argv.slice(2);
const require = createRequire(modules + '/');
const { JSDOM, VirtualConsole } = require('jsdom');
const axeSource = readFileSync(modules + '/axe-core/axe.min.js', 'utf8');

function open(path) {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', e => { if (!/Not implemented/.test(e.message)) errors.push(e.message.slice(0, 120)); });
  const dom = new JSDOM(readFileSync(path, 'utf8'), { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://sample.test/d.html', virtualConsole,
    beforeParse(w) { w.Element.prototype.scrollIntoView = function () {}; w.matchMedia = () => ({ matches: false }); } });
  return { dom, w: dom.window, d: dom.window.document, errors };
}
function stops(d, w) {
  return [...d.querySelectorAll('a[href],button,select,input,summary,[tabindex]')].filter(e => {
    if (e.getAttribute('tabindex') === '-1' || e.closest('[hidden]')) return false;
    if (e.closest('details:not([open])') && e.tagName !== 'SUMMARY') return false;
    for (let n = e; n; n = n.parentElement) if (w.getComputedStyle(n).display === 'none') return false;
    return true;
  });
}
async function axe(w) {
  w.eval(axeSource);
  const r = await w.axe.run(w.document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] }, rules: { 'color-contrast': { enabled: false } } });
  return r.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.length,
    overlay: v.nodes.filter(n => /fig-d|figures|bsf|bs-tip/.test(n.html + n.target.join(' '))).length, sample: v.nodes[0].target.join(' ').slice(0, 70) }));
}
const out = {};
{
  const { w, d, errors } = open(dashboardPath);
  await new Promise(r => setTimeout(r, 50));
  const list = stops(d, w);
  out.page_order = [...d.querySelectorAll('#overview,#priority-section,#coverage,#figures,#findings,#lists')].map(e => e.id);
  out.nav_order = [...d.querySelectorAll('.nav-links a')].map(a => a.getAttribute('href').slice(1));
  out.nav_matches_page = out.nav_order.join() === out.page_order.join();
  out.tab_stops_total = list.length;
  out.tab_stops_before_first_record = list.findIndex(e => e.matches('button.finding-toggle'));
  out.figure_tab_stops = list.filter(e => e.closest('.bsf svg')).length;
  const parts = [...d.querySelectorAll('.bsf svg [data-tip]')];
  out.figure_parts = parts.length;
  out.figure_parts_named = parts.filter(e => e.getAttribute('aria-label')).length;
  out.figure_parts_linking_to_a_record = d.querySelectorAll('.bsf svg a[href^="#finding-"]').length;
  out.svg_root_role = [...new Set([...d.querySelectorAll('.bsf svg[viewBox]')].map(s => s.getAttribute('role')))];
  out.table_heads_with_scope = [...d.querySelectorAll('.bsf th')].filter(t => t.getAttribute('scope')).length + '/' + d.querySelectorAll('.bsf th').length;
  out.tip_role = d.getElementById('bs-tip').getAttribute('role');
  out.figure_index_links = d.querySelectorAll('.figindex a').length;
  // T5: keyboard inside a figure
  const first = stops(d, w).find(e => e.closest('#fig-d7 svg'));
  first.focus();
  const key = (el, k) => el.dispatchEvent(new w.KeyboardEvent('keydown', { key: k, bubbles: true }));
  key(first, 'ArrowRight');
  out.T5_arrow_moves = d.activeElement !== first && !!d.activeElement.closest('#fig-d7 svg');
  // T2: from a figure to the record
  const link = d.querySelector('#fig-d7 svg a[href^="#finding-"]');
  if (link) { w.location.hash = link.getAttribute('href').slice(1); await new Promise(r => setTimeout(r, 50)); }
  out.T2_one_activation_opens_record = !!link && d.querySelectorAll('tr.detail:not([hidden])').length > 0;
  d.querySelector('button.finding-toggle').click();
  // A status region repeats at every pointer move before the fix; focus order and names are axe's to judge.
  out.axe_dashboard = await axe(w);
  out.script_errors = errors;
}
{
  const { w, d, errors } = open(reportPath);
  out.report_inert_focus_stops = [...d.querySelectorAll('.bsf svg [tabindex="0"]')].length;
  out.report_links_to_records = [...d.querySelectorAll('.bsf svg a[href^="#finding-"]')].filter(a => d.getElementById(a.getAttribute('href').slice(1))).length;
  out.axe_report = await axe(w);
  out.report_script_errors = errors;
}
console.log(JSON.stringify(out, null, 1));
