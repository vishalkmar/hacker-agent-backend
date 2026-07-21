// Hash identification tests — uses real/standard hashcat example vectors. No network.
// Run: node scripts/test-hashid.mjs
import { identifyHash, identifyHashes, renderHashid } from '../src/services/hashid/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const top = (h) => identifyHash(h).candidates[0];
const modes = (h) => identifyHash(h).candidates.map((c) => c.mode);

console.log('\n[1] structured / prefixed formats -> exact hashcat mode (high confidence)');
const T = [
  ['md5crypt $1$', '$1$28772684$iEwNOgGugqO9.bIz5sk8k/', 500],
  ['sha512crypt $6$', '$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/', 1800],
  ['sha256crypt $5$', '$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD', 7400],
  ['bcrypt $2a$', '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6', 3200],
  ['Kerberoast $krb5tgs$23$', '$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$891ad31d', 13100],
  ['AS-REP $krb5asrep$23$', '$krb5asrep$23$user@domain.local:3e156ada591263b8aab0965f5aebd837$334ad', 18200],
  ['phpass $P$ (WordPress)', '$P$984478476IagS59wHZvyQMArzfx58u.', 400],
  ['Drupal7 $S$', '$S$C33783772bRXEx1aCsvY.dvXpMbTZ99b8n1lFbQ3BClBwzUX3sD.', 7900],
  ['LDAP {SSHA}', '{SSHA}uWQ2FVFT8huRR9Nsljfhi6xBvZDxCJ8 waZ==', 111],
  ['MySQL5 *HEX', '*E56A114692FE0DE073F9A1DD68A00EEB9703F3F1', 300],
  ['Cisco type 8 $8$', '$8$TnGX/fE4KGHOVU$pEhnEvxrEgTAlpGDl.udml9M1Bq6zGaCq/pWYQR8m6Q', 9200],
];
for (const [label, h, mode] of T) {
  const t = top(h);
  ok(`${label} -> -m ${mode}`, t && t.mode === mode && identifyHash(h).confidence === 'high', t ? `got -m ${t.mode}` : 'no match');
}
// Kerberoast AES mode picks 19600/19700 by 17/18
ok('Kerberoast AES $17$ -> -m 19600', top('$krb5tgs$17$*u$r$spn*$deadbeef$cafe')?.mode === 19600);
ok('Kerberoast AES $18$ -> -m 19700', top('$krb5tgs$18$*u$r$spn*$deadbeef$cafe')?.mode === 19700);

console.log('\n[2] structural — JWT / NetNTLM / WPA');
ok('JWT -> -m 16500', top('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF-_123')?.mode === 16500);
ok('NetNTLMv2 -> -m 5600', top('admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c78303100000000000000000b45')?.mode === 5600);
ok('NetNTLMv1 -> -m 5500', top('user::DOMAIN:' + 'a'.repeat(48) + ':' + 'b'.repeat(48) + ':' + 'c'.repeat(16))?.mode === 5500);

console.log('\n[3] ambiguous bare-hex -> ranked candidates');
ok('32-hex MD5 top + NTLM present', top('8743b52063cd84097a65d1633f5c74f5')?.mode === 0 && modes('8743b52063cd84097a65d1633f5c74f5').includes(1000));
ok('32-hex confidence = ambiguous', identifyHash('8743b52063cd84097a65d1633f5c74f5').confidence === 'ambiguous');
ok('40-hex SHA-1 top', top('b89eaac7e61417341b710b727768294d0e6a277b')?.mode === 100);
ok('64-hex SHA-256 top + SHA3 present', top('127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935')?.mode === 1400 && modes('127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935').includes(17400));
ok('128-hex SHA-512 top', top('a'.repeat(128))?.mode === 1700);
ok('16-hex MySQL323 top', top('7196759210defdc0')?.mode === 200);
ok('empty-password NTLM gets a note', identifyHash('31d6cfe0d16ae931b73c59d7e0c089c0').notes.some((n) => /empty password/i.test(n)));

console.log('\n[4] shadow / pwdump preprocessing');
const shadowR = identifyHash('root:$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/:19000:0:99999:7:::');
ok('shadow line -> extracts $6$ + notes user', shadowR.candidates[0]?.mode === 1800 && shadowR.notes.some((n) => /shadow/.test(n)));
const pw = identifyHash('Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::');
ok('pwdump line -> uses NT hash (32-hex ambiguous MD5/NTLM)', pw.candidates.some((c) => c.mode === 1000) && pw.notes.some((n) => /pwdump/.test(n)));
ok('pwdump notes empty LM (aad3b435)', pw.notes.some((n) => /LM was empty/i.test(n)));

console.log('\n[5] crack commands + batch + render + authz');
ok('crack command carries the right -m', /hashcat -m 3200 -a 0 hash\.txt/.test(top('$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6').hashcatCmd));
ok('john command present', /john --format=bcrypt/.test(top('$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6').johnCmd));
ok('batch: identifies multiple lines', identifyHashes('8743b52063cd84097a65d1633f5c74f5\n$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6').length === 2);
const r = renderHashid('$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6');
ok('render shows identified + crack cmd', /bcrypt/.test(r) && /hashcat -m 3200/.test(r));
ok('render ambiguous shows ranked candidates', /Likely \(\d+ candidates/.test(renderHashid('8743b52063cd84097a65d1633f5c74f5')));
ok('render unknown -> fallback tip', /--identify|name-that-hash/.test(renderHashid('not_a_hash_zzz!!')));
ok('hashid NOT gated (local analysis)', classifyAction('hashid', '8743b52063cd84097a65d1633f5c74f5').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
