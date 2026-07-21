// Hash identification & crack-command generation.
//
// Powers the ```hashid agent tag. Give it a hash (or many, one per line, or a shadow/pwdump/Responder line)
// and it identifies the algorithm(s), and for each candidate emits the hashcat mode (-m), the John format,
// and a READY-TO-RUN crack command. Far beyond a simple "what is this hash" — it turns a captured hash into
// the exact next command. Pure local analysis (no target) → NOT authorization-gated.
//
// Design: unambiguous PREFIXED / structured formats are matched first (bcrypt $2a$, sha512crypt $6$,
// Kerberoast $krb5tgs$, JWT, NetNTLMv2, MySQL5 *…), then bare-hex is resolved to a RANKED candidate list
// (e.g. 32-hex could be MD5 or NTLM — both are returned, most-likely first).

import { env } from '../../config/env.js';

// The rockyou path inside the sandbox (backend/rockyou.txt is bind-mounted here read-only). Configurable via
// EXEC_WORDLIST_MOUNT so the generated crack command always matches what's actually available in the sandbox.
const WL = env.exec?.wordlistMount || '/usr/share/wordlists/rockyou.txt';

// hashcat crack command for a mode; john command for a format.
function hcCmd(mode) { return mode == null ? null : `hashcat -m ${mode} -a 0 hash.txt ${WL}`; }
function johnCmd(fmt) { return fmt ? `john --format=${fmt} --wordlist=${WL} hash.txt` : `john --wordlist=${WL} hash.txt`; }

// ---- structured / prefixed formats (high confidence) ----
// Each: { test(h)->bool, name, mode(hashcat -m), john, desc }
const STRUCTURED = [
  { test: (h) => /^\$2[abxy]\$\d{2}\$[./0-9A-Za-z]{53}$/.test(h), name: 'bcrypt', mode: 3200, john: 'bcrypt', desc: 'bcrypt ($2a/$2b/$2y$) — modern web-app password hash (slow, salted).' },
  { test: (h) => /^\$1\$[^$]{0,8}\$[./0-9A-Za-z]{22}$/.test(h), name: 'md5crypt', mode: 500, john: 'md5crypt', desc: 'Unix MD5 crypt ($1$) — older Linux /etc/shadow.' },
  { test: (h) => /^\$5\$(rounds=\d+\$)?[^$]{1,16}\$[./0-9A-Za-z]{43}$/.test(h), name: 'sha256crypt', mode: 7400, john: 'sha256crypt', desc: 'sha256crypt ($5$) — Linux /etc/shadow.' },
  { test: (h) => /^\$6\$(rounds=\d+\$)?[^$]{1,16}\$[./0-9A-Za-z]{86}$/.test(h), name: 'sha512crypt', mode: 1800, john: 'sha512crypt', desc: 'sha512crypt ($6$) — modern Linux /etc/shadow.' },
  { test: (h) => /^\$y\$/.test(h), name: 'yescrypt', mode: null, john: 'crypt', desc: 'yescrypt ($y$) — newest Linux /etc/shadow default. hashcat has no mode; crack with `john --format=crypt` (slow).' },
  { test: (h) => /^\$argon2(id|i|d)\$/.test(h), name: 'argon2', mode: null, john: 'argon2', desc: 'Argon2 ($argon2id$) — strong modern KDF. Use `john --format=argon2` (hashcat unsupported).' },
  { test: (h) => /^\$scrypt\$/i.test(h) || /^SCRYPT:/i.test(h), name: 'scrypt', mode: 8900, john: 'scrypt', desc: 'scrypt — memory-hard KDF.' },
  { test: (h) => /^\$krb5tgs\$23\$/.test(h), name: 'Kerberoast (RC4)', mode: 13100, john: 'krb5tgs', desc: 'Kerberoasting TGS-REP, RC4 ($krb5tgs$23$) — crack to recover the service account password.' },
  { test: (h) => /^\$krb5tgs\$(17|18)\$/.test(h), name: 'Kerberoast (AES)', mode: (h) => (/^\$krb5tgs\$17\$/.test(h) ? 19600 : 19700), john: 'krb5tgs-aes', desc: 'Kerberoasting TGS-REP, AES ($krb5tgs$17/18$) — hashcat -m 19600 (AES128) / 19700 (AES256).' },
  { test: (h) => /^\$krb5asrep\$23\$/.test(h), name: 'AS-REP Roast', mode: 18200, john: 'krb5asrep', desc: 'AS-REP roasting ($krb5asrep$23$) — no-preauth accounts; crack for the user password.' },
  { test: (h) => /^\$krb5pa\$/.test(h), name: 'Kerberos pre-auth', mode: 7500, john: 'krb5pa-md5', desc: 'Kerberos pre-auth (AS-REQ, $krb5pa$) — hashcat -m 7500.' },
  { test: (h) => /^\$DCC2\$/i.test(h) || /^\$DCC\$/i.test(h), name: 'Domain Cached Credentials 2 (mscash2)', mode: 2100, john: 'mscash2', desc: 'MS Domain Cached Creds v2 ($DCC2$) — cached AD logons; slow.' },
  { test: (h) => /^\$(P|H)\$[./0-9A-Za-z]{30,}$/.test(h), name: 'phpass (WordPress/Joomla)', mode: 400, john: 'phpass', desc: 'phpass ($P$/$H$) — WordPress, phpBB3, Joomla.' },
  { test: (h) => /^\$S\$[./0-9A-Za-z]{52}$/.test(h), name: 'Drupal 7', mode: 7900, john: 'drupal7', desc: 'Drupal 7 ($S$) — SHA-512 based.' },
  { test: (h) => /^(sha1|md5|sha256|pbkdf2_sha256|pbkdf2_sha1|argon2)\$[^$]*\$/i.test(h), name: 'Django', mode: (h) => (/^pbkdf2_sha256/i.test(h) ? 10000 : /^sha1\$/i.test(h) ? 124 : 10900), john: 'django', desc: 'Django (algo$salt$hash) — pbkdf2_sha256=hashcat -m 10000, sha1=-m 124.' },
  { test: (h) => /^\{SSHA\}/.test(h), name: 'LDAP SSHA (salted SHA-1)', mode: 111, john: 'ssha', desc: 'LDAP {SSHA} — salted SHA-1, common in OpenLDAP.' },
  { test: (h) => /^\{SHA\}/.test(h), name: 'LDAP SHA-1', mode: 101, john: 'nsldap', desc: 'LDAP {SHA} — unsalted SHA-1 (base64).' },
  { test: (h) => /^\{SSHA512\}/.test(h), name: 'LDAP SSHA-512', mode: 1711, john: 'ssha512', desc: 'LDAP {SSHA512} — salted SHA-512.' },
  { test: (h) => /^\{SMD5\}/.test(h), name: 'LDAP salted MD5', mode: 6300, john: 'salted-sha1', desc: 'LDAP {SMD5} — salted MD5.' },
  { test: (h) => /^\$ml\$/.test(h), name: 'macOS PBKDF2-SHA512', mode: 7100, john: 'pbkdf2-hmac-sha512', desc: 'macOS 10.8+ ($ml$) — PBKDF2-HMAC-SHA512.' },
  { test: (h) => /^\$sha1\$\d+\$/.test(h), name: 'PBKDF2-HMAC-SHA1', mode: 12000, john: 'pbkdf2-hmac-sha1', desc: 'atlassian/PBKDF2-HMAC-SHA1 ($sha1$rounds$).' },
  { test: (h) => /^\$pbkdf2-sha256\$/.test(h), name: 'PBKDF2-HMAC-SHA256', mode: 10900, john: 'pbkdf2-hmac-sha256', desc: 'PBKDF2-HMAC-SHA256 ($pbkdf2-sha256$).' },
  { test: (h) => /^0x0100[0-9A-Fa-f]{88}$/.test(h), name: 'MSSQL 2005', mode: 132, john: 'mssql05', desc: 'MSSQL 2005 (0x0100…, 40-byte).' },
  { test: (h) => /^0x0200[0-9A-Fa-f]{136}$/.test(h), name: 'MSSQL 2012/2014', mode: 1731, john: 'mssql12', desc: 'MSSQL 2012/2014 (0x0200…, SHA-512).' },
  { test: (h) => /^0x0100[0-9A-Fa-f]{40,}$/.test(h), name: 'MSSQL 2000', mode: 131, john: 'mssql', desc: 'MSSQL 2000 (0x0100…).' },
  { test: (h) => /^S:[0-9A-Fa-f]{60}$/.test(h) || /^H:[0-9A-Fa-f]{32}$/.test(h), name: 'Oracle 11g/12c', mode: 112, john: 'oracle11', desc: 'Oracle 11g (S:…) SHA-1, or 12c.' },
  { test: (h) => /^\$8\$[./0-9A-Za-z]+\$[./0-9A-Za-z]{43}$/.test(h), name: 'Cisco IOS PBKDF2 (type 8)', mode: 9200, john: 'cisco8', desc: 'Cisco IOS type 8 ($8$salt$hash) — PBKDF2-SHA256.' },
  // Cisco type 9 has the $9$salt$hash structure (internal $); test it BEFORE the continuous Juniper $9$.
  { test: (h) => /^\$9\$[./0-9A-Za-z]+\$[./0-9A-Za-z]{43}$/.test(h), name: 'Cisco IOS scrypt (type 9)', mode: 9300, john: 'cisco9', desc: 'Cisco IOS type 9 ($9$salt$hash) — scrypt.' },
  { test: (h) => /^\$9\$[./0-9A-Za-z]+$/.test(h), name: 'Juniper ScreenOS $9$ (reversible)', mode: null, john: null, desc: 'Juniper ScreenOS $9$ — NOT a hash; reversible. Decode instantly with a $9$ decoder (no cracking needed).' },
  { test: (h) => /^\*[0-9A-Fa-f]{40}$/.test(h), name: 'MySQL 4.1+ (MySQL5)', mode: 300, john: 'mysql-sha1', desc: 'MySQL 4.1+ (*HEX, 41 chars) — SHA1(SHA1(pass)).' },
];

// ---- JWT / network-capture formats (structural) ----
function structural(h) {
  if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(h))
    return { name: 'JWT (JSON Web Token)', mode: 16500, john: 'jwt', desc: 'JWT — 3 base64url parts. -m 16500 cracks an HS256/384/512 signing secret (only symmetric HMAC).' };
  // NetNTLMv2: user::domain:serverChallenge(16hex):ntproofstr(32hex):blob
  if (/^[^:]+::[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{20,}$/.test(h))
    return { name: 'NetNTLMv2', mode: 5600, john: 'netntlmv2', desc: 'NetNTLMv2 (Responder/SMB capture) — crack for the user password. Highly effective offline.' };
  // NetNTLMv1: user::domain:LMresp(48hex):NTresp(48hex):challenge(16hex)
  if (/^[^:]+::[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}$/.test(h))
    return { name: 'NetNTLMv1', mode: 5500, john: 'netntlm', desc: 'NetNTLMv1 — weak; can be cracked or relayed. Consider crack.sh for DES.' };
  if (/^WPA\*/.test(h) || /^[0-9a-f]{32}:[0-9a-f]{12}:[0-9a-f]{12}:/i.test(h))
    return { name: 'WPA/WPA2 (PMKID/EAPOL)', mode: 22000, john: 'wpapsk', desc: 'WPA/WPA2 handshake or PMKID (hcxtools 22000 format).' };
  return null;
}

// ---- bare-hex candidates, ranked (most likely first) ----
const HEX = {
  16: [{ name: 'MySQL323 (pre-4.1)', mode: 200, john: 'mysql', desc: 'Old MySQL (<4.1), 16 hex.' }, { name: 'DES(Oracle)/crypt', mode: null, john: 'des', desc: '16-hex could also be VNC/DES.' }],
  32: [
    { name: 'MD5', mode: 0, john: 'raw-md5', desc: 'MD5 — 32 hex. The most common bare-hex hash.' },
    { name: 'NTLM', mode: 1000, john: 'nt', desc: 'NTLM (Windows SAM/LSASS) — 32 hex, indistinguishable from MD5 by shape. If from a Windows dump, it is NTLM.' },
    { name: 'MD4', mode: 900, john: 'raw-md4', desc: 'MD4 — 32 hex.' },
    { name: 'LM', mode: 3000, john: 'lm', desc: 'LM (legacy Windows) — usually UPPERCASE; each half cracked separately.' },
    { name: 'NTLMv1 (halves)', mode: null, john: null, desc: 'Also possible: half-LM/NTLM. RIPEMD-128 / double-MD5 with -m 2600 etc.' },
  ],
  40: [
    { name: 'SHA-1', mode: 100, john: 'raw-sha1', desc: 'SHA-1 — 40 hex.' },
    { name: 'RIPEMD-160', mode: 6000, john: 'ripemd-160', desc: 'RIPEMD-160 — 40 hex.' },
    { name: 'MySQL4.1 raw', mode: 300, john: 'mysql-sha1', desc: 'If prefixed with *, it is MySQL5 (-m 300).' },
  ],
  56: [{ name: 'SHA-224', mode: 1300, john: 'raw-sha224', desc: 'SHA-224 — 56 hex.' }, { name: 'SHA3-224 / Keccak-224', mode: 17300, john: null, desc: 'SHA3-224.' }],
  64: [
    { name: 'SHA-256', mode: 1400, john: 'raw-sha256', desc: 'SHA-256 — 64 hex.' },
    { name: 'SHA3-256', mode: 17400, john: 'raw-keccak-256', desc: 'SHA3-256 / Keccak-256 — 64 hex.' },
    { name: 'RIPEMD-256', mode: null, john: null, desc: 'RIPEMD-256 — 64 hex.' },
    { name: 'BLAKE2', mode: 600, john: 'raw-blake2', desc: 'BLAKE2b-256 — 64 hex.' },
  ],
  96: [{ name: 'SHA-384', mode: 10800, john: 'raw-sha384', desc: 'SHA-384 — 96 hex.' }, { name: 'SHA3-384', mode: 17500, john: null, desc: 'SHA3-384.' }],
  128: [
    { name: 'SHA-512', mode: 1700, john: 'raw-sha512', desc: 'SHA-512 — 128 hex.' },
    { name: 'Whirlpool', mode: 6100, john: 'whirlpool', desc: 'Whirlpool — 128 hex.' },
    { name: 'SHA3-512 / Keccak-512', mode: 17600, john: null, desc: 'SHA3-512 — 128 hex.' },
  ],
};

function withCmds(t, hashText) {
  const john = t.mode === null && t.john === null ? null : johnCmd(t.john);
  return { ...t, hashcatCmd: hcCmd(t.mode), johnCmd: john };
}

// Extract the crackable hash from a /etc/shadow or pwdump/secretsdump line, if that's what was pasted.
function preprocess(line) {
  const notes = [];
  let h = line.trim();
  // shadow: user:$6$...:lastchg:... -> take field 2 if it looks like a crypt hash
  const shadow = h.match(/^[^:\s]+:(\$[^:]+|\*|!)/);
  if (shadow && /^\$/.test(shadow[1])) { notes.push(`extracted crypt hash from a shadow line (user "${h.split(':')[0]}")`); h = shadow[1]; }
  else if (shadow && /^[*!]/.test(shadow[1])) { notes.push('shadow account is locked (* or !) — no password set'); }
  // pwdump/secretsdump: user:rid:LMHASH:NTHASH::: -> take the NT hash
  const pw = h.match(/^([^:\s]+):\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::/);
  if (pw) { notes.push(`pwdump line for "${pw[1]}" — using the NT hash (LM was ${/^aad3b435/i.test(pw[2]) ? 'empty' : 'present'})`); h = pw[3]; }
  return { hash: h, notes };
}

// Identify a single hash -> { input, hash, notes, candidates: [{name, mode, hashcatCmd, johnCmd, desc}], confidence }.
export function identifyHash(input) {
  const { hash, notes } = preprocess(String(input || ''));
  if (!hash) return { input, hash, notes, candidates: [], confidence: 'none' };

  // 1) structural (JWT / NetNTLM / WPA)
  const s = structural(hash);
  if (s) return { input, hash, notes, candidates: [withCmds(s, hash)], confidence: 'high' };

  // 2) structured / prefixed
  for (const t of STRUCTURED) {
    if (t.test(hash)) {
      const mode = typeof t.mode === 'function' ? t.mode(hash) : t.mode;
      return { input, hash, notes, candidates: [withCmds({ ...t, mode }, hash)], confidence: 'high' };
    }
  }

  // 3) bare hex -> ranked candidates
  if (/^[0-9a-fA-F]+$/.test(hash) && HEX[hash.length]) {
    const cands = HEX[hash.length].map((t) => withCmds(t, hash));
    if (hash.length === 32 && /^31d6cfe0d16ae931b73c59d7e0c089c0$/i.test(hash)) notes.push('this is the well-known NTLM hash of an EMPTY password.');
    if (hash.length === 32 && hash === hash.toUpperCase()) notes.push('all-uppercase 32-hex often indicates an LM hash.');
    return { input, hash, notes, candidates: cands, confidence: 'ambiguous' };
  }

  // 4) base64-ish (LDAP without prefix, etc.)
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(hash)) {
    return { input, hash, notes: [...notes, 'looks base64-encoded — could be an LDAP {SSHA}/{SHA} digest with the {…} prefix stripped, or a raw digest. Try decoding the base64.'], candidates: [], confidence: 'low' };
  }

  return { input, hash, notes, candidates: [], confidence: 'unknown' };
}

// Identify one or many (newline / comma separated).
export function identifyHashes(body) {
  const items = String(body || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  return items.map(identifyHash);
}

export function renderHashid(body) {
  const results = identifyHashes(body);
  if (!results.length) return 'Usage: ```hashid <hash>``` (or paste several hashes / a shadow line).';
  const blocks = results.map((r) => {
    const head = `**\`${(r.hash || '').slice(0, 70)}${r.hash && r.hash.length > 70 ? '…' : ''}\`**`;
    if (!r.candidates.length) {
      return `${head}\n- _Unrecognised (${r.confidence})._${r.notes.length ? '\n  ↳ ' + r.notes.join('; ') : ''}\n  ↳ Fallback: \`hashcat --identify hash.txt\` or \`nth --text "<hash>"\` (name-that-hash).`;
    }
    const tag = r.confidence === 'high' ? 'Identified' : `Likely (${r.candidates.length} candidates, ranked)`;
    const lines = r.candidates.slice(0, 5).map((c, i) => {
      const modeStr = c.mode == null ? 'no hashcat mode' : `hashcat -m ${c.mode}`;
      const cmd = c.hashcatCmd ? `\n  ↳ crack: \`${c.hashcatCmd}\`` : (c.johnCmd ? `\n  ↳ crack: \`${c.johnCmd}\`` : '');
      return `${i === 0 ? '🎯' : ' •'} **${c.name}** — ${modeStr}${c.john ? ` · john --format=${c.john}` : ''}\n  ↳ ${c.desc}${cmd}`;
    });
    return `${head} — ${tag}${r.notes.length ? `\n  ↳ _${r.notes.join('; ')}_` : ''}\n${lines.join('\n')}`;
  });
  const footer = `\n\n_Tip: save the hash to \`hash.txt\`, then run the crack command. rockyou is ready (uncompressed) at \`${WL}\` in the sandbox. Add rules with \`-r /usr/share/hashcat/rules/best64.rule\`._`;
  return blocks.join('\n\n') + footer;
}
