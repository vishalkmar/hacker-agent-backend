// Phase 7 (firewall) unit tests — port classification, segmentation meta, firewall/WAF detection.
// Run: node scripts/test-firewall.mjs
import { spawnSync } from 'node:child_process';
import { buildFirewallCommand, parseFirewallReport, extractFirewallFindings, renderFirewall } from '../src/services/firewall/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] bash -n on generated commands');
for (const body of ['scanme.nmap.org', 'scanme.nmap.org deep', 'https://acme.tld/x', 'nmap -sS host', 'wafw00f https://x']) {
  const cmd = buildFirewallCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty -> null', buildFirewallCommand('') === null);
ok('raw nmap passthrough', buildFirewallCommand('nmap -A host') === 'nmap -A host');
const deepCmd = buildFirewallCommand('myhost deep');
ok('deep flag not used as target', /HOST="myhost"/.test(deepCmd) && /\(deep \/ all-ports\)/.test(deepCmd) && /-p-/.test(deepCmd));

// Realistic captured nmap output: a badly-segmented host (SSH+MySQL+Redis+Docker open, some filtered).
const nmapOut = `== firewall / network segmentation review: acme.tld ==
NETSCAN-BEGIN acme.tld
Starting Nmap
Nmap scan report for acme.tld (203.0.113.7)
PORT      STATE    SERVICE      REASON          VERSION
22/tcp    open     ssh          syn-ack         OpenSSH 8.2p1 Ubuntu
80/tcp    open     http         syn-ack         nginx 1.18.0
443/tcp   open     https        syn-ack         nginx 1.18.0
3306/tcp  open     mysql        syn-ack         MySQL 8.0.32
6379/tcp  open     redis        syn-ack         Redis 6.2.6
2375/tcp  open     docker       syn-ack         Docker 20.10
3389/tcp  filtered ms-wbt-server no-response
445/tcp   filtered microsoft-ds no-response
--- ACK (firewall state) ---
22/tcp    filtered ssh
3306/tcp  filtered mysql
--- WAF detection ---
The site https://acme.tld is behind Cloudflare (Cloudflare Inc.) WAF.
NETSCAN-END`;

console.log('\n[2] port classification');
const f = parseFirewallReport(nmapOut);
const byPort = (p) => f.find((x) => x.port === p);
ok('SSH:22 -> medium remote-access', byPort(22)?.severity === 'medium' && /SSH exposed/.test(byPort(22).title));
ok('MySQL:3306 -> high db', byPort(3306)?.severity === 'high' && /MySQL/.test(byPort(3306).title));
ok('Redis:6379 -> high db', byPort(6379)?.severity === 'high');
ok('Docker:2375 -> critical control-plane', byPort(2375)?.severity === 'critical' && /Docker/.test(byPort(2375).title));
ok('HTTP:80 -> info public web', byPort(80)?.severity === 'info' && /Public HTTP/.test(byPort(80).title));
ok('version captured in evidence', /OpenSSH 8.2p1/.test(byPort(22).evidence));

console.log('\n[3] segmentation + firewall + WAF meta');
const segF = f.find((x) => x.source === 'fw-segmentation');
ok('segmentation finding present', !!segF);
ok('segmentation is CRITICAL (control-plane present)', segF?.severity === 'critical', segF?.severity);
ok('segmentation is CWE-668', segF?.cve === 'CWE-668');
ok('segmentation lists mysql/redis/docker', /MySQL:3306/.test(segF.evidence) && /Redis:6379/.test(segF.evidence) && /Docker API:2375/.test(segF.evidence));
const fwF = f.find((x) => x.source === 'fw-present');
ok('firewall-present detected (filtered ports)', !!fwF && fwF.severity === 'info');
const wafF = f.find((x) => x.source === 'fw-waf');
ok('WAF detected = Cloudflare', !!wafF && /Cloudflare/.test(wafF.title));

console.log('\n[4] clean host + inert');
const clean = `NETSCAN-BEGIN good.tld\nAll 44 scanned ports on good.tld are filtered\n--- WAF detection ---\nis behind Cloudflare WAF\nNETSCAN-END`;
const cf = parseFirewallReport(clean);
ok('all-filtered -> firewall present, no exposure risks', cf.some((x) => x.source === 'fw-present') && !cf.some((x) => /^(high|critical)$/.test(x.severity)));
ok('inert on unrelated output', extractFirewallFindings('curl x', 'HTTP 200 OK\nhello').length === 0);
ok('extract returns findings when sentinel present', extractFirewallFindings('cmd', nmapOut).length >= 7);

console.log('\n[5] render + authz');
const r = renderFirewall(nmapOut);
ok('render shows segmentation risks section', /Segmentation \/ exposure risks/.test(r));
ok('render shows defensive posture (WAF/firewall)', /Defensive posture/.test(r));
ok('render shows attack surface', /Exposed attack surface/.test(r));
const g = classifyAction('firewall', 'acme.tld');
ok('firewall <target> is gated', g && g.gated === true && g.target === 'acme.tld', JSON.stringify(g));
ok('firewall vs localhost not gated', classifyAction('firewall', '127.0.0.1').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
