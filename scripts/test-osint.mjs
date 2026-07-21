// OSINT sweep tests — deterministic (no network). Run: node scripts/test-osint.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildOsintSweep, buildOsintCommand, sniffKind, extractOsintFindings, renderOsint } from '../src/services/osint/osint.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const bashOk = (cmd) => { const f = path.join(os.tmpdir(), `osint_${Math.random().toString(36).slice(2)}.sh`); fs.writeFileSync(f, cmd); const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' }); fs.rmSync(f, { force: true }); return r; };

console.log('\n[1] target kind detection');
ok('phone', sniffKind('+91 9540792427') === 'phone');
ok('email', sniffKind('john@doe.com') === 'email');
ok('domain', sniffKind('example.com') === 'domain');
ok('username fallback', sniffKind('john_doe99') === 'username');
ok('osint NOT gated (passive OSINT)', classifyAction('osint', '+91 9540792427').gated === false);

console.log('\n[2] sweep = valid bash + ALWAYS gives leads (never "just a country code")');
for (const [kind, target, minLeads] of [['phone', '+91 9540792427', 8], ['email', 'a@b.com', 4], ['username', 'johndoe', 3]]) {
  const s = buildOsintSweep({ target, type: 'auto' });
  ok(`${kind}: valid bash`, bashOk(s).status === 0, bashOk(s).stderr);
  ok(`${kind}: >=${minLeads} OSINT leads emitted`, (s.match(/OSINTLEAD/g) || []).length >= minLeads);
}
ok('domain sweep valid bash', bashOk(buildOsintSweep({ target: 'example.com', type: 'auto' })).status === 0);

console.log('\n[3] runs the RIGHT tool per kind + correct installs');
const ph = buildOsintSweep({ target: '+919540792427', type: 'phone' });
ok('phone uses phoneinfoga', /phoneinfoga scan -n/.test(ph));
ok('phoneinfoga installed as BINARY, not pip (the old bug)', /sundowndev\/phoneinfoga/.test(ph) && !/pip install phoneinfoga/.test(ph));
ok('phone: Truecaller + WhatsApp + Google dork leads', /truecaller/.test(ph) && /wa\.me/.test(ph) && /google\.com\/search/.test(ph));
const em = buildOsintSweep({ target: 'a@b.com', type: 'email' });
ok('email uses holehe (which sites) + h8mail', /holehe --only-used/.test(em) && /h8mail -t/.test(em));
ok('email: HaveIBeenPwned lead', /haveibeenpwned/.test(em));
const un = buildOsintSweep({ target: 'johndoe', type: 'username' });
ok('username uses maigret (3000+ sites) + sherlock fallback', /maigret/.test(un) && /sherlock/.test(un));

console.log('\n[4] forced single tool still works');
ok('forced phoneinfoga', /phoneinfoga scan -n/.test(buildOsintCommand({ target: '+919540792427', type: 'phone', tool: 'phoneinfoga' })));
ok('forced maigret', /maigret/.test(buildOsintCommand({ target: 'johndoe', type: 'username', tool: 'maigret' })));
ok('unknown tool -> falls back to sweep', /OSINTLEAD/.test(buildOsintCommand({ target: 'johndoe', type: 'username', tool: 'zzz' })));

console.log('\n[5] findings extraction from tool output');
const sample = [
  '[+] github.com',                                   // holehe
  '[+] Twitter: https://twitter.com/johndoe',         // sherlock
  'https://github.com/johndoe',                       // maigret bare url
  'Country: India', 'Carrier: Airtel', 'Line type: Mobile',   // phoneinfoga
  'contact@acme.com',                                  // harvested email
  'OSINTLEAD\tTruecaller\thttps://www.truecaller.com/search/in/919540792427',
].join('\n');
const f = extractOsintFindings('osint', sample);
ok('holehe account finding', f.some((x) => /Account found on github\.com/.test(x.title)));
ok('sherlock profile finding', f.some((x) => /Profile on Twitter/.test(x.title)));
ok('maigret bare-url profile', f.some((x) => /github\.com\/johndoe/.test(x.host || '')));
ok('phone footprint finding', f.some((x) => x.source === 'phoneinfoga' && /Airtel/.test(x.evidence)));
ok('harvested email finding', f.some((x) => /contact@acme\.com/.test(x.title)));
ok('lead becomes a finding', f.some((x) => x.source === 'osint-lead' && /Truecaller/.test(x.title)));
ok('empty output -> no findings', extractOsintFindings('osint', '').length === 0);

console.log('\n[6] render turns leads into clickable bullets');
ok('OSINTLEAD -> bullet', /• Truecaller → https:\/\/www\.truecaller\.com/.test(renderOsint('OSINTLEAD\tTruecaller\thttps://www.truecaller.com/x')));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
