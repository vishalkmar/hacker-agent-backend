// Phase 7 (DIRB) tests — content-discovery parser (dirb/gobuster/feroxbuster/dirsearch). Deterministic.
// Run: node scripts/test-dirb.mjs
import { parseContentDisc, detectContentDisc } from '../src/services/scan/contentdisc.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] detection');
ok('detect dirb', detectContentDisc('dirb http://x /wl'));
ok('detect gobuster', detectContentDisc('gobuster dir -u http://x -w wl'));
ok('detect feroxbuster', detectContentDisc('feroxbuster -u http://x'));
ok('detect dirsearch', detectContentDisc('dirsearch -u http://x'));
ok('non-content -> false', detectContentDisc('nmap -sV x') === false);

console.log('\n[2] dirb output (real v2.22 format) — sensitive paths flagged, regular = info');
const dirb = [
  '+ http://target.com/index.html (CODE:200|SIZE:6974)',
  '==> DIRECTORY: http://target.com/admin/',
  '==> DIRECTORY: http://target.com/images/',
  '+ http://target.com/.git/config (CODE:200|SIZE:92)',
  '+ http://target.com/backup.sql (CODE:200|SIZE:50000)',
  '+ http://target.com/.env (CODE:200|SIZE:120)',
  '+ http://target.com/login (CODE:403|SIZE:290)',
  '+ http://target.com/robots.txt (CODE:200|SIZE:56)',
].join('\n');
const f = parseContentDisc('dirb http://target.com /usr/share/wordlists/dirb/common.txt', dirb);
const byT = (re) => f.find((x) => re.test(x.title));
ok('.git/config -> high exposure', byT(/\.git\/config/)?.severity === 'high' && byT(/\.git\/config/)?.finding_type === 'exposure');
ok('backup.sql -> high', byT(/backup\.sql/)?.severity === 'high');
ok('.env -> high', byT(/\.env/)?.severity === 'high');
ok('admin/ dir -> medium', byT(/\/admin\//)?.severity === 'medium');
ok('login (403) -> low', byT(/\/login/)?.severity === 'low');
ok('index.html -> info', byT(/index\.html/)?.severity === 'info');
ok('robots.txt -> info content-discovery', byT(/robots/)?.severity === 'info' && byT(/robots/)?.finding_type === 'content-discovery');
ok('sensitive findings carry remediation', byT(/\.git/)?.remediation && /deny .git/.test(byT(/\.git/).remediation));
ok('host + evidence captured', byT(/\.env/)?.host === 'target.com' && /200/.test(byT(/\.env/)?.evidence));
ok('all found paths captured (8)', f.length === 8, `got ${f.length}`);

console.log('\n[3] gobuster output (resolves relative path against -u base)');
const gob = [
  '/admin                (Status: 301) [Size: 0]',
  '/.env                 (Status: 200) [Size: 120]',
  '/uploads              (Status: 200) [Size: 512]',
  '/images               (Status: 301) [Size: 0]',
].join('\n');
const fg = parseContentDisc('gobuster dir -u http://acme.com -w big.txt', gob);
ok('gobuster .env -> high + host from -u', fg.find((x) => /\.env/.test(x.title))?.severity === 'high' && fg.find((x) => /\.env/.test(x.title))?.host === 'acme.com');
ok('gobuster admin -> medium', fg.find((x) => /\/admin/.test(x.title))?.severity === 'medium');
ok('gobuster uploads -> high (sensitive)', fg.find((x) => /uploads/.test(x.title))?.severity === 'high');
ok('gobuster images -> info', fg.find((x) => /images/.test(x.title))?.severity === 'info');

console.log('\n[4] feroxbuster + dirsearch formats');
ok('feroxbuster line (admin@200 -> high)', parseContentDisc('feroxbuster -u http://x', '200      GET       10l       20w      512c http://x/admin').some((x) => /\/admin/.test(x.title) && x.severity === 'high'));
ok('dirsearch line', parseContentDisc('dirsearch -u http://x', '[12:00:01] 200 -  512B  - /.git/HEAD').some((x) => /\.git/.test(x.title) && x.severity === 'high'));

console.log('\n[5] hygiene');
ok('non-content command -> []', parseContentDisc('curl http://x', dirb).length === 0);
ok('empty output -> []', parseContentDisc('dirb http://x', '').length === 0);
ok('dedup identical paths', parseContentDisc('dirb http://x', '+ http://x/a (CODE:200|SIZE:1)\n+ http://x/a (CODE:200|SIZE:1)').length === 1);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
