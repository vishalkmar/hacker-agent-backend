#!/usr/bin/env node
// Phase 0 TEST — verify the vendored cyber-skills corpus is complete and well-formed.
// Exits non-zero (and prints what failed) if any check fails, so it works in CI / as a gate.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEST = path.join(backendRoot, 'data', 'cyber-skills');
const EXPECTED = 817;

let failed = 0;
const fail = (msg) => { console.error('  ❌ ' + msg); failed++; };
const ok = (msg) => console.log('  ✅ ' + msg);

// 1) catalog exists + parses
const catPath = path.join(DEST, 'catalog.json');
if (!fs.existsSync(catPath)) { fail('catalog.json missing — run sync-cyber-skills.mjs first'); process.exit(1); }
const cat = JSON.parse(fs.readFileSync(catPath, 'utf8'));

// 2) count == expected
cat.total === EXPECTED ? ok(`catalog total = ${cat.total}`) : fail(`catalog total = ${cat.total}, expected ${EXPECTED}`);

// 3) SKILL.md files on disk match the count
const skillDirs = fs.existsSync(path.join(DEST, 'skills'))
  ? fs.readdirSync(path.join(DEST, 'skills')).filter((n) => fs.existsSync(path.join(DEST, 'skills', n, 'SKILL.md')))
  : [];
skillDirs.length === EXPECTED ? ok(`SKILL.md files on disk = ${skillDirs.length}`) : fail(`SKILL.md files = ${skillDirs.length}, expected ${EXPECTED}`);

// 4) every catalog entry has name + description + a real body; sample-read the files
let missingDesc = 0, emptyBody = 0, missingFile = 0;
for (const s of cat.skills) {
  if (!s.name || !s.description) missingDesc++;
  const p = path.join(DEST, s.path);
  if (!fs.existsSync(p)) { missingFile++; continue; }
  if (fs.readFileSync(p, 'utf8').trim().length < 300) emptyBody++;
}
missingDesc === 0 ? ok('every entry has name + description') : fail(`${missingDesc} entries missing name/description`);
missingFile === 0 ? ok('every catalog path resolves to a file') : fail(`${missingFile} catalog paths missing on disk`);
emptyBody === 0 ? ok('every SKILL.md has a substantive body') : fail(`${emptyBody} SKILL.md files are suspiciously short`);

// 5) framework mapping coverage (informational)
const withMitre = cat.skills.filter((s) => s.mitre?.length).length;
const withNist = cat.skills.filter((s) => s.nist?.length).length;
console.log(`  ℹ️  MITRE-mapped: ${withMitre} | NIST-mapped: ${withNist} | subdomains: ${new Set(cat.skills.map((s) => s.subdomain)).size}`);

console.log(failed === 0 ? '\n🎉 Phase 0 PASS — corpus is complete and well-formed.' : `\n💥 Phase 0 FAIL — ${failed} check(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
