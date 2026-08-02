// Phase 10 (JOHN THE RIPPER) tests — cracked-password parser (run-time + --show). Deterministic.
// Run: node scripts/test-john.mjs
import { parseJohn, detectJohn } from '../src/services/scan/john.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] detection');
ok('detect john', detectJohn('john --wordlist=rockyou.txt hashes.txt'));
ok('detect john --show', detectJohn('john --show sh.txt'));
ok('ignore john.pot path', detectJohn('cat ~/.john/john.pot') === false);
ok('non-john -> false', detectJohn('hashcat -m 0 h.txt') === false);

console.log('\n[2] live crack line: "<password>   (<user>)" -> critical');
const run = 'monkey           (victim)\n1g 0:00:00:03 DONE (2026-07-22) 0.33g/s 4800p/s monkey..secret';
const f = parseJohn('john --wordlist=/usr/share/wordlists/rockyou.txt sh.txt', run);
ok('extracts cracked password', f.some((x) => /Password cracked: victim = monkey/.test(x.title)));
ok('severity critical, source john', f[0]?.severity === 'critical' && f[0]?.source === 'john' && f[0]?.finding_type === 'credential-access');
ok('has remediation', /Rotate this password/.test(f[0]?.remediation || ''));
ok('DONE/status line NOT a finding', !f.some((x) => /DONE|g\/s/.test(x.title)));

console.log('\n[3] raw hash (no user): "hello  (?)" and --show "?:hello"');
ok('run-time no-user -> just the password', parseJohn('john h.txt', 'hello            (?)').some((x) => x.title === 'Password cracked: hello'));
ok('--show ?:pass -> just the password', parseJohn('john --show h.txt', '?:hello\n\n1 password hash cracked, 0 left').some((x) => x.title === 'Password cracked: hello'));

console.log('\n[4] --show with real usernames (shadow/pwdump style)');
const show = 'root:Sup3rP@ss\nadmin:letmein123\nsvc_backup:Winter2024\n\n3 password hashes cracked, 0 left';
const fs = parseJohn('john --show shadow.txt', show);
ok('3 creds extracted', fs.filter((x) => /Password cracked:/.test(x.title)).length === 3, `got ${fs.length}`);
ok('user = password format', fs.some((x) => /root = Sup3rP@ss/.test(x.title)) && fs.some((x) => /svc_backup = Winter2024/.test(x.title)));
ok('summary line itself not a finding', !fs.some((x) => /hashes cracked/.test(x.title)));
ok('dedup identical creds', parseJohn('john --show x', 'root:pass\nroot:pass').filter((x) => /cracked/.test(x.title)).length === 1);

console.log('\n[5] hygiene + fallbacks');
ok('info/banner lines ignored', parseJohn('john h.txt', 'Loaded 1 password hash (md5crypt)\nUsing default input encoding: UTF-8\nPress q to abort').length === 0);
ok('cracked-count fallback when plaintext missing', parseJohn('john --wordlist=rockyou.txt h.txt', 'Something\n5 password hashes cracked, 2 left').some((x) => /5 password hash/.test(x.title) && x.severity === 'critical'));
ok('non-john command -> []', parseJohn('nmap x', run).length === 0);
ok('empty output -> []', parseJohn('john x', '').length === 0);
ok('no false-positive on a URL line', !parseJohn('john x', 'see http://example.com:8080/path').some((x) => /cracked/.test(x.title)));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
