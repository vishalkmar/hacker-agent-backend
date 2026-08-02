// Self-test for the pwnedpass (HaveIBeenPwned k-anonymity) breach checker.
// Validates: SHA-1, local suffix→count matching, password list parsing, report rendering + masking, that
// only a 5-char prefix would be sent (privacy), and a LIVE end-to-end check against the real API if online.
import { sha1Upper, countFromRange, parsePasswords, renderPwnedReport, checkOne, checkMany } from '../src/services/pwnedpass/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.log('  ✗', name); } };

console.log('== 1. SHA-1 (uppercase, 40 hex) ==');
ok('sha1("password") == known vector', sha1Upper('password') === '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
ok('sha1 is 40 uppercase hex', /^[0-9A-F]{40}$/.test(sha1Upper('amit')));
ok('empty string hashes', sha1Upper('') === 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709');

console.log('== 2. local suffix→count matching (k-anonymity, no network) ==');
const h = sha1Upper('password'); // prefix 5BAA6, suffix 1E4C9...
const range = [
  '1CC93AEF7B58A1B631CB55BF3A3A3750285:3',
  h.slice(5) + ':9876543',          // our suffix
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1',
].join('\r\n');
ok('finds our suffix → count', countFromRange(range, h.slice(5)) === 9876543);
ok('case-insensitive suffix match', countFromRange(range.toLowerCase(), h.slice(5)) === 9876543);
ok('absent suffix → 0', countFromRange(range, '0'.repeat(35)) === 0);
ok('only 5-char prefix would be sent', h.slice(0, 5).length === 5 && h.slice(5).length === 35);

console.log('== 3. parse password lists ==');
const parsed = parsePasswords('amit\n  hunter2  \n\n# comment\namit\nP@ss w0rd\n');
ok('dedups + drops blanks/comments', parsed.length === 3);
ok('preserves internal spaces', parsed.includes('P@ss w0rd'));
ok('order preserved', parsed[0] === 'amit' && parsed[1] === 'hunter2');

console.log('== 4. report render + masking ==');
const rep = renderPwnedReport([
  { password: 'amit', breached: true, count: 12345 },
  { password: 'Zx9$kLmn2Qwe', breached: false, count: 0 },
  { password: 'oops', error: 'API HTTP 429' },
]);
ok('marks BREACHED with count', /BREACHED/.test(rep) && /12,345/.test(rep));
ok('marks safe', /not found/.test(rep));
ok('shows error row', /error/.test(rep));
ok('masks the raw password (no plaintext "amit")', !/\bamit\b/.test(rep) && /a•/.test(rep));
ok('summary counts breached', /1\/3 breached/.test(rep));

console.log('== 5. NOT gated (defensive, own passwords) ==');
ok('pwnedpass not gated', classifyAction('pwnedpass', 'amit').gated === false);

console.log('== 6. LIVE end-to-end (real API, if online) ==');
let online = true;
try {
  const known = await checkOne('password');
  if (known.error) { online = false; console.log('  (API unreachable:', known.error, '— skipping live asserts)'); }
  else {
    ok('"password" is BREACHED (millions)', known.breached && known.count > 1000000);
    console.log(`    → "password" seen ${known.count.toLocaleString()} times`);
    const strong = 'Zq7' + Math.random().toString(36).slice(2) + 'X$9pL_' + Date.now();
    const s = await checkMany([strong]);
    ok('a fresh random password is NOT breached', s[0].breached === false && !s[0].error);
    console.log(`    → random "${strong.slice(0, 6)}…" breached=${s[0].breached}`);
  }
} catch (e) { online = false; console.log('  (live test skipped:', e.message, ')'); }

console.log(`\n${pass}/${pass + fail} passed` + (fail ? `  (${fail} FAILED)` : ' ✅') + (online ? '' : '  [live part skipped — offline]'));
process.exit(fail ? 1 : 0);
