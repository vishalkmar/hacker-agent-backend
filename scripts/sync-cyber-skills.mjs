#!/usr/bin/env node
// Phase 0 — vendor the Anthropic Cybersecurity Skills corpus into the repo.
//
// Copies every skills/<name>/SKILL.md + index.json from a local clone of
// mukul975/anthropic-cybersecurity-skills into backend/data/cyber-skills/, and builds a normalized
// catalog.json (name, subdomain, description, tags, mitre, nist, path) parsed from each SKILL.md's
// YAML frontmatter — so the ingest step (Phase 1) never has to re-parse 817 files.
//
// Usage:
//   node scripts/sync-cyber-skills.mjs <path-to-clone>
//   (defaults to ../anthropic-cybersecurity-skills relative to the backend dir)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.resolve(process.argv[2] || path.join(backendRoot, '..', 'anthropic-cybersecurity-skills'));
const DEST = path.join(backendRoot, 'data', 'cyber-skills');

// Minimal YAML-frontmatter reader — good enough for these SKILL.md headers (scalars + simple `- ` lists).
function parseFrontmatter(md) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(md);
  if (!m) return { meta: {}, body: md };
  const body = md.slice(m[0].length).trim();
  const meta = {};
  let key = null;
  for (const raw of m[1].split(/\r?\n/)) {
    if (/^\s*-\s+/.test(raw) && key) {
      meta[key] = Array.isArray(meta[key]) ? meta[key] : [];
      meta[key].push(raw.replace(/^\s*-\s+/, '').trim().replace(/^['"]|['"]$/g, ''));
      continue;
    }
    const kv = /^([A-Za-z0-9_]+):\s?(.*)$/.exec(raw);
    if (kv) {
      key = kv[1];
      const val = kv[2].trim();
      if (val === '' ) meta[key] = []; // a list follows on next lines
      else meta[key] = val.replace(/^['"]|['"]$/g, '');
    } else if (key && typeof meta[key] === 'string' && raw.trim()) {
      meta[key] += ' ' + raw.trim(); // folded multi-line scalar (e.g. description)
    }
  }
  return { meta, body };
}

function main() {
  const skillsDir = path.join(SRC, 'skills');
  if (!fs.existsSync(skillsDir)) {
    console.error(`❌ clone not found at ${SRC}\n   Pass the path: node scripts/sync-cyber-skills.mjs <clone-dir>`);
    process.exit(1);
  }
  fs.rmSync(DEST, { recursive: true, force: true });
  fs.mkdirSync(path.join(DEST, 'skills'), { recursive: true });

  const names = fs.readdirSync(skillsDir).filter((n) => fs.existsSync(path.join(skillsDir, n, 'SKILL.md')));
  const catalog = [];
  for (const name of names) {
    const md = fs.readFileSync(path.join(skillsDir, name, 'SKILL.md'), 'utf8');
    const { meta, body } = parseFrontmatter(md);
    const asArr = (v) => (Array.isArray(v) ? v : v ? [v] : []);
    fs.mkdirSync(path.join(DEST, 'skills', name), { recursive: true });
    fs.writeFileSync(path.join(DEST, 'skills', name, 'SKILL.md'), md);
    catalog.push({
      name: meta.name || name,
      subdomain: meta.subdomain || '',
      domain: meta.domain || 'cybersecurity',
      description: (meta.description || '').trim(),
      tags: asArr(meta.tags),
      mitre: asArr(meta.mitre_attack),
      nist: asArr(meta.nist_csf),
      path: `skills/${name}/SKILL.md`,
      bodyChars: body.length,
    });
  }
  // Copy the upstream catalog too (for cross-check).
  const idx = path.join(SRC, 'index.json');
  if (fs.existsSync(idx)) fs.copyFileSync(idx, path.join(DEST, 'index.json'));
  fs.writeFileSync(path.join(DEST, 'catalog.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), total: catalog.length, skills: catalog }, null, 2));

  const subs = catalog.reduce((a, s) => ((a[s.subdomain] = (a[s.subdomain] || 0) + 1), a), {});
  console.log(`✅ vendored ${catalog.length} skills → ${path.relative(backendRoot, DEST)}`);
  console.log(`   subdomains: ${Object.keys(subs).length} | with MITRE: ${catalog.filter((s) => s.mitre.length).length} | with NIST: ${catalog.filter((s) => s.nist.length).length}`);
}

main();
