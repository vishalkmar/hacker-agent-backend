// Feed REAL captured cloud-scan output through the exact agent pipeline and show:
//   (a) the findings that would be stored in the findings table
//   (b) the chat message the user would see (renderCloud)
// Usage: node scripts/verify-cloud-live.mjs /tmp/cloud_raw.txt
import { readFileSync } from 'node:fs';
import { extractCloudFindings, renderCloud, buildCloudCommand } from '../src/services/cloud/index.js';

const path = process.argv[2] || '/tmp/cloud_raw.txt';
const raw = readFileSync(path, 'utf8');
const command = buildCloudCommand('iamalive.app');

const findings = extractCloudFindings(command, raw);
console.log('=== FINDINGS THAT WOULD BE STORED (' + findings.length + ') ===');
for (const f of findings) {
  console.log(`[${f.severity.toUpperCase()}] (${f.source}) ${f.title}`);
  if (f.evidence) console.log(`    evidence: ${f.evidence}`);
  if (f.remediation) console.log(`    fix: ${f.remediation.slice(0, 90)}`);
}
console.log('\n=== CHAT MESSAGE THE USER WOULD SEE (renderCloud) ===\n');
console.log(renderCloud(raw));
