// Phase 9 (webinput) unit tests — upload/rate-limit/input-validation parsing. No network/DB.
// Run: node scripts/test-webinput.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildWebInputCommand, parseWebInputReport, extractWebInputFindings, renderWebInput } from '../src/services/webinput/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

// Syntax-check via a temp file (bash -n <file>): reliable for large scripts. Passing a multi-KB script as a
// `bash -nc <arg>` string mangles quoting on Windows spawn, so file-mode is the correct check.
const bashOk = (cmd) => {
  const f = path.join(os.tmpdir(), `wichk_${Math.random().toString(36).slice(2)}.sh`);
  fs.writeFileSync(f, cmd);
  const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' });
  fs.rmSync(f, { force: true });
  return r;
};

console.log('\n[1] bash -n on generated commands');
for (const body of ['https://iamalive.app', 'iamalive.app 15', 'https://x.com/search?q=1', 'curl -X POST x']) {
  const cmd = buildWebInputCommand(body);
  const r = bashOk(cmd);
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty -> null', buildWebInputCommand('') === null);
ok('raw curl passthrough', buildWebInputCommand('curl -I x') === 'curl -I x');
ok('burst clamped to <=40', /N=40/.test(buildWebInputCommand('x.com 999')));
ok('burst clamped to >=5', /N=5/.test(buildWebInputCommand('x.com 1')));
ok('existing query -> uses & separator', /sep=./.test(buildWebInputCommand('https://x.com/a?b=1')) && buildWebInputCommand('https://x.com/a?b=1').includes('*\\?*'));

console.log('\n[2] finding parsing (each type)');
const report = [
  'WEBIN-BEGIN https://acme.tld',
  `WEBINFIND${T}high${T}xss-reflect${T}Reflected input is NOT encoded (reflected-XSS surface)${T}payload echoed with live <svg>${T}https://acme.tld`,
  `WEBINFIND${T}high${T}sqli-error${T}SQL error surfaced from a single quote${T}You have an error in your SQL syntax${T}https://acme.tld`,
  `WEBINFIND${T}critical${T}lfi${T}Path traversal returned /etc/passwd (LFI)${T}root:x:0:0:${T}https://acme.tld`,
  `WEBINFIND${T}medium${T}rate-none${T}No rate limiting observed over 20 rapid requests${T}no 429${T}https://acme.tld`,
  `WEBINFIND${T}medium${T}upload-form${T}File-upload form detected${T}enctype=multipart/form-data${T}https://acme.tld`,
  `WEBINFIND${T}low${T}no-lengthcap${T}6KB parameter value accepted${T}HTTP 200${T}https://acme.tld`,
  `WEBINFIND${T}info${T}rate-ok${T}Rate limiting active (saw 8/20 HTTP 429)${T}429${T}https://acme.tld`,
  'WEBIN-END',
].join('\n');
const f = parseWebInputReport(report);
const bySrc = (s) => f.find((x) => x.source === s);
ok('7 findings parsed', f.length === 7, `got ${f.length}`);
ok('xss -> high + CWE-79', bySrc('webin-xss-reflect')?.severity === 'high' && bySrc('webin-xss-reflect')?.cve === 'CWE-79');
ok('sqli -> high + CWE-89', bySrc('webin-sqli-error')?.cve === 'CWE-89');
ok('lfi -> critical + CWE-22', bySrc('webin-lfi')?.severity === 'critical' && bySrc('webin-lfi')?.cve === 'CWE-22');
ok('rate-none -> medium + CWE-307', bySrc('webin-rate-none')?.cve === 'CWE-307');
ok('upload-form -> CWE-434', bySrc('webin-upload-form')?.cve === 'CWE-434');
ok('no-lengthcap -> low + CWE-20', bySrc('webin-no-lengthcap')?.severity === 'low' && bySrc('webin-no-lengthcap')?.cve === 'CWE-20');
ok('all finding_type input-validation', f.every((x) => x.finding_type === 'input-validation'));

console.log('\n[3] inert + render + authz');
ok('inert on unrelated output', extractWebInputFindings('curl x', 'HTTP 200 OK\nhello').length === 0);
ok('extract returns 7', extractWebInputFindings('c', report).length === 7);
const r = renderWebInput(report);
ok('render shows weaknesses section', /Input-handling weaknesses/.test(r));
ok('render separates good controls (rate-ok)', /Good controls observed/.test(r) && /Rate limiting active/.test(r));
ok('clean -> friendly message', /No input-validation/.test(renderWebInput('WEBIN-BEGIN x\nWEBIN-END')));
const g = classifyAction('webinput', 'https://acme.tld');
ok('webinput <target> gated', g && g.gated === true, JSON.stringify(g));
ok('webinput localhost not gated', classifyAction('webinput', 'http://127.0.0.1').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
