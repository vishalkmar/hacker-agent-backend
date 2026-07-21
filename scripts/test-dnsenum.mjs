// Phase 8 (DNSENUM) tests — DNS-recon parser: zone-transfer (AXFR) detection + subdomains. Deterministic.
// Run: node scripts/test-dnsenum.mjs
import { parseDnsenum, detectDnsenum } from '../src/services/scan/dnsenum.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] detection');
ok('detect dnsenum', detectDnsenum('dnsenum --enum example.com'));
ok('non-dnsenum -> false', detectDnsenum('dig axfr example.com') === false);

console.log('\n[2] SUCCESSFUL zone transfer (AXFR) -> HIGH (real zonetransfer.me shape)');
const axfrOk = `dnsenum VERSION:1.3.1

-----   zonetransfer.me   -----

Host's addresses:
zonetransfer.me.        7200  IN  A  5.196.105.14

Name Servers:
nsztm1.digi.ninja.      10799 IN  A  81.4.108.41

Trying Zone Transfers and getting Bind Versions:

Trying Zone Transfer for zonetransfer.me on nsztm1.digi.ninja ...
zonetransfer.me.        7200  IN  SOA  (
zonetransfer.me.        7200  IN  MX  0
www.zonetransfer.me.    7200  IN  A  5.196.105.14
internal.zonetransfer.me. 300 IN  A  10.1.1.5
vpn.zonetransfer.me.    7200  IN  CNAME  external.example.com.
mail.zonetransfer.me.   7200  IN  A  5.196.105.20`;
const f = parseDnsenum('dnsenum --noreverse zonetransfer.me', axfrOk);
const axfr = f.find((x) => /zone transfer \(AXFR\) allowed/i.test(x.title));
ok('AXFR success -> high misconfiguration', axfr?.severity === 'high' && axfr?.finding_type === 'misconfiguration');
ok('AXFR names the domain', /zonetransfer\.me/.test(axfr?.title));
ok('AXFR names the NS in evidence', /nsztm1\.digi\.ninja/.test(axfr?.evidence));
ok('AXFR has remediation (allow-transfer)', /allow-transfer/i.test(axfr?.remediation || ''));

console.log('\n[3] subdomains extracted from the zone dump');
const subs = f.filter((x) => x.finding_type === 'subdomain');
ok('extracts www/internal/vpn/mail subdomains', subs.length === 4, `got ${subs.length}: ${subs.map((s) => s.host).join(',')}`);
ok('internal (A 10.x) captured', subs.some((s) => s.host === 'internal.zonetransfer.me'));
ok('vpn (CNAME) captured', subs.some((s) => s.host === 'vpn.zonetransfer.me' && /CNAME/.test(s.evidence)));
ok('apex domain itself NOT listed as a subdomain', !subs.some((s) => s.host === 'zonetransfer.me'));
ok('summary finding lists count', f.some((x) => /4 subdomain\(s\) discovered/.test(x.title)));

console.log('\n[4] REFUSED zone transfer -> info (not a vuln)');
const refused = `-----   example.com   -----

Host's addresses:
example.com.  3600  IN  A  93.184.216.34

Trying Zone Transfers and getting Bind Versions:

Trying Zone Transfer for example.com on a.iana-servers.net ...
AXFR record query failed: REFUSED`;
const fr = parseDnsenum('dnsenum example.com', refused);
ok('refused AXFR -> info (good), NOT high', fr.some((x) => /refused/i.test(x.title) && x.severity === 'info') && !fr.some((x) => x.severity === 'high'));

console.log('\n[5] domain resolution + hygiene');
ok('domain from header', parseDnsenum('dnsenum -f wl.txt acme.io', '-----   acme.io   -----\nTrying Zone Transfer for acme.io on ns1 ...\nacme.io. 7200 IN SOA (').some((x) => /acme\.io/.test(x.title)));
ok('domain from command when no header', parseDnsenum('dnsenum --threads 5 target.org', 'Trying Zone Transfer for target.org on ns1 ...\ntarget.org. 1 IN SOA (').some((x) => /target\.org/.test(x.title)));
ok('non-dnsenum command -> []', parseDnsenum('nmap example.com', axfrOk).length === 0);
ok('empty output -> []', parseDnsenum('dnsenum x.com', '').length === 0);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
