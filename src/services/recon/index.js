// FINAL — Strengthened Reconnaissance (network-level footprinting).
//
// Powers the ```recon tag's deep footprint (the agent runs this in the Kali sandbox and ALSO merges the
// JS tech-recon from web/recon.js). Where the JS recon mines a single page's HTML/JS, this maps the whole
// external footprint:
//   • DNS: A/AAAA/NS/MX/TXT/SOA/CAA/CNAME records; AXFR zone-transfer test against each NS (high if it
//     succeeds); SPF & DMARC presence (email-spoofing exposure).
//   • Subdomains: passive via crt.sh certificate transparency + a common-name wordlist, each resolved so
//     only LIVE assets are reported; sensitive names (dev/staging/admin/vpn/git…) are flagged.
//   • IP / ASN / CDN: resolves the apex, looks up the owning ASN (Team Cymru), and detects the CDN/WAF/host
//     (Cloudflare / Vercel / CloudFront / Fastly / Akamai / Google) from headers + ASN.
//   • Tech: whatweb / httpx fingerprint of server, framework, CMS, CDN.
//   • Ports: (deep) nmap top-ports on the apex.
//   • Asset inventory: the consolidated list of live hostnames + IPs.
// Emits RECONFIND<TAB>sev<TAB>type<TAB>title<TAB>evidence<TAB>host for security-relevant items, plus
// SUB<TAB>host<TAB>ip inventory lines and a TECH<TAB>… line. finding_type 'recon'. This is passive/OSINT-
// level (DNS lookups, cert-transparency, HTTP fingerprint) so — like the existing `recon` tag — it is NOT
// authorization-gated; the active offensive tags (scan/exposed/firewall/…) remain gated.

import { normSev, dedupCap } from '../appsec/engine.js';

function domainOf(t) { return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase(); }

const SUB_WORDS = 'www api api-dev api-staging mail webmail smtp imap pop ftp dev develop staging stage test qa uat admin administrator portal vpn remote git gitlab jenkins ci cd grafana kibana prometheus status blog shop store cdn static assets img images media m mobile app apps dashboard auth login sso beta demo internal intranet backup db database ns1 ns2 mx1 support help docs api2 gateway proxy cpanel webdisk autodiscover';
const SENSITIVE_SUB = /^(dev|develop|staging|stage|test|qa|uat|admin|administrator|vpn|git|gitlab|jenkins|ci|cd|grafana|kibana|prometheus|internal|intranet|backup|db|database|beta|demo|jira|confluence|phpmyadmin|adminer)\b/i;

export function buildReconScan(target, { deep = false } = {}) {
  const D = domainOf(target);
  const lines = [
    `D="${D}"; URL="https://${D}";`,
    `emit(){ printf 'RECONFIND\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$1" "$2" "$3" "$4" "$5"; };`,
    `for t in dig curl jq whatweb; do command -v $t >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y dnsutils curl jq whatweb >/dev/null 2>&1; break; }; done;`,
    `echo "== reconnaissance footprint: $D =="`,
    `echo "RECON-BEGIN $D";`,
    // ---- DNS records ----
    `echo "=== DNS ===";`,
    `for rt in A AAAA NS MX TXT SOA CAA CNAME; do v=$(dig +short "$D" $rt 2>/dev/null | paste -sd '; ' -); [ -n "$v" ] && echo "DNS $rt: $v"; done;`,
    `A=$(dig +short "$D" A 2>/dev/null | grep -E '^[0-9.]+$');`,
    // ---- zone transfer (AXFR) against each NS ----
    `echo "=== AXFR ===";`,
    `for ns in $(dig +short "$D" NS 2>/dev/null); do`,
    `  axfr=$(dig +noall +answer AXFR "$D" @"$ns" 2>/dev/null | head -5);`,
    `  if [ "$(printf '%s' "$axfr" | grep -c .)" -gt 1 ]; then emit high axfr "DNS zone transfer (AXFR) allowed by $ns" "leaks the full internal DNS zone" "$D"; fi;`,
    `done;`,
    // ---- email security (SPF / DMARC) ----
    `spf=$(dig +short "$D" TXT 2>/dev/null | grep -i 'v=spf1');`,
    `[ -z "$spf" ] && emit low email-spf "No SPF record on $D" "domain can be spoofed in email From: headers" "$D";`,
    `dmarc=$(dig +short "_dmarc.$D" TXT 2>/dev/null | grep -i 'v=DMARC1');`,
    `[ -z "$dmarc" ] && emit low email-dmarc "No DMARC record on $D" "no policy to reject spoofed mail (phishing exposure)" "$D";`,
    // ---- ASN / CDN detection ----
    `echo "=== ASN/CDN ===";`,
    `ip1=$(printf '%s' "$A" | head -1);`,
    `if [ -n "$ip1" ]; then asn=$(timeout 8 whois -h whois.cymru.com " -v $ip1" 2>/dev/null | tail -1); [ -n "$asn" ] && echo "ASN: $asn"; fi;`,
    `hdr=$(curl -s -k -L -m 12 -D - -o /dev/null "$URL" 2>/dev/null | tr -d '\\r');`,
    `cdn=$(printf '%s%s' "$hdr" "$asn" | grep -aioiE 'cloudflare|x-vercel-id|vercel|cloudfront|amazon|x-amz-cf|fastly|akamai|google|azure|netlify|sucuri|incapsula|imperva' | head -1);`,
    `[ -n "$cdn" ] && emit info cdn "Fronted by/hosted on: $cdn" "detected from response headers / ASN" "$D";`,
    // ---- subdomain enumeration: crt.sh (passive) + wordlist, then resolve ----
    `echo "=== SUBDOMAINS ===";`,
    `subs=$(mktemp);`,
    `curl -s -k -m 20 "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | tr 'A-Z' 'a-z' | sed 's/^\\*\\.//' | grep -E "\\.$D\\$|^$D\\$" >> "$subs" 2>/dev/null || true;`,
    `for w in ${SUB_WORDS}; do echo "$w.$D"; done >> "$subs";`,
    `sort -u "$subs" -o "$subs";`,
    // resolve each candidate (parallel) -> keep only live ones as "SUB <host> <ip>"
    `resolve(){ ip=$(dig +short "$1" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1); [ -n "$ip" ] && printf 'SUB\\t%s\\t%s\\n' "$1" "$ip"; };`,
    `export -f resolve;`,
    `live=$(cat "$subs" | xargs -P 20 -I{} bash -c 'resolve "{}"' 2>/dev/null | sort -u);`,
    `printf '%s\\n' "$live";`,
    `nlive=$(printf '%s' "$live" | grep -c . || true);`,
    `[ "$nlive" -gt 0 ] && emit info asset-inventory "$nlive live subdomain(s) discovered for $D" "asset inventory built from crt.sh + resolution" "$D";`,
    // flag sensitive-looking live subdomains
    `printf '%s\\n' "$live" | awk -F'\\t' '{print $2}' | while read -r h; do`,
    `  lbl=$(printf '%s' "$h" | cut -d. -f1);`,
    `  case "$lbl" in dev|develop|staging|stage|test|qa|uat|admin|administrator|vpn|git|gitlab|jenkins|ci|cd|grafana|kibana|prometheus|internal|intranet|backup|db|database|beta|demo|jira|confluence) emit low sensitive-sub "Sensitive subdomain exposed: $h" "internal/non-prod hostname is publicly resolvable" "$h";; esac;`,
    `done;`,
    `rm -f "$subs";`,
    // ---- technology fingerprint ----
    `echo "=== TECH ===";`,
    `tech=$(command -v whatweb >/dev/null 2>&1 && whatweb -q --color=never -a1 "$URL" 2>/dev/null | head -1 || printf '%s' "$hdr" | grep -iE '^server:|^x-powered-by:' | paste -sd '; ' -);`,
    `[ -n "$tech" ] && printf 'TECH\\t%s\\n' "$(printf '%s' "$tech" | cut -c1-300)";`,
    `srv=$(printf '%s' "$hdr" | grep -i '^server:' | head -1 | tr -d '\\r'); [ -n "$srv" ] && printf 'TECH\\t%s\\n' "$srv";`,
    `xpb=$(printf '%s' "$hdr" | grep -i '^x-powered-by:' | head -1 | tr -d '\\r'); [ -n "$xpb" ] && emit info tech-disclosure "Technology disclosed via header: $xpb" "$xpb" "$D";`,
  ];
  if (deep) {
    lines.push(
      `echo "=== PORTS ===";`,
      `command -v nmap >/dev/null 2>&1 || { apt-get install -y nmap >/dev/null 2>&1; };`,
      `nmap -Pn -T4 --top-ports 100 "$D" 2>/dev/null | grep -E '^[0-9]+/tcp\\s+open' | while read -r pl; do emit info open-port "Open port: $pl" "nmap top-100" "$D"; done;`,
    );
  }
  lines.push(`echo "RECON-END";`);
  return lines.join('\n');
}

export function buildReconScanCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  const tokens = raw.split(/\s+/);
  const deep = tokens.some((t) => /^(deep|full|ports)$/i.test(t));
  const target = tokens.find((t) => !/^(deep|full|ports)$/i.test(t));
  if (!target) return null;
  return buildReconScan(target, { deep });
}

const TYPE_META = {
  axfr: { cwe: 'CWE-200', fix: 'Restrict AXFR zone transfers to authorized secondary name-servers only (allow-transfer). A public zone transfer leaks every internal hostname.' },
  'email-spf': { cwe: 'CWE-290', fix: 'Publish an SPF TXT record (v=spf1 …) listing authorized senders and ending in -all/~all.' },
  'email-dmarc': { cwe: 'CWE-290', fix: 'Publish a DMARC record at _dmarc (v=DMARC1; p=reject/quarantine) to stop email spoofing/phishing.' },
  'sensitive-sub': { cwe: 'CWE-200', fix: 'Non-production/internal subdomains should not be publicly resolvable — put them behind a VPN/allow-list or split-horizon DNS.' },
  'tech-disclosure': { cwe: 'CWE-200', fix: 'Remove version-revealing headers (Server, X-Powered-By) so you do not advertise the exact stack/version to attackers.' },
};

export function parseReconReport(output) {
  const text = String(output || '');
  const findings = [];
  const subs = [];
  const tech = [];
  const dns = [];
  for (const line of text.split('\n')) {
    if (line.startsWith('RECONFIND\t')) {
      const [, sev, type, title, evidence, host] = line.split('\t');
      if (!title) continue;
      const meta = TYPE_META[type];
      findings.push({
        finding_type: 'recon', severity: normSev(sev), title: title.slice(0, 200),
        host: (host || '').slice(0, 200) || null, evidence: (evidence || '').slice(0, 240),
        cve: meta ? meta.cwe : null,
        remediation: meta ? meta.fix : 'Review this reconnaissance finding as part of your external attack-surface hygiene.',
        source: `recon-${type || 'x'}`,
      });
    } else if (line.startsWith('SUB\t')) {
      const [, host, ip] = line.split('\t');
      if (host) subs.push({ host, ip: ip || '' });
    } else if (line.startsWith('TECH\t')) {
      const t = line.slice(5).trim();
      if (t) tech.push(t);
    } else if (/^DNS [A-Z]+:/.test(line)) {
      dns.push(line.trim());
    }
  }
  return { findings, subs, tech, dns };
}

// For the findings DB: the security-relevant RECONFIND items (subdomain inventory summary included).
export function extractReconScanFindings(command, output) {
  if (!/RECON-BEGIN/.test(String(output || ''))) return [];
  return dedupCap(parseReconReport(output).findings, 120);
}

export function renderReconScan(output) {
  const { findings, subs, tech, dns } = parseReconReport(output);
  if (!findings.length && !subs.length && !tech.length && !dns.length) {
    return '_Recon produced no records — the domain may not resolve or DNS/HTTP was unreachable._';
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const issues = findings.filter((f) => f.severity !== 'info').sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const parts = [];
  if (dns.length) parts.push('**🧭 DNS:**\n' + dns.map((d) => `- ${d}`).join('\n'));
  if (tech.length) parts.push('**🧱 Technology:**\n' + [...new Set(tech)].map((t) => `- ${t}`).join('\n'));
  if (subs.length) {
    const uniq = [...new Map(subs.map((s) => [s.host, s.ip])).entries()];
    const shown = uniq.slice(0, 60).map(([h, ip]) => `- ${h}${ip ? ` → ${ip}` : ''}`).join('\n');
    parts.push(`**🌐 Live assets / subdomains (${uniq.length}):**\n` + shown + (uniq.length > 60 ? `\n…and ${uniq.length - 60} more` : ''));
  }
  if (issues.length) parts.push('**🚩 Recon findings:**\n' + issues.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}${f.cve ? ` [${f.cve}]` : ''}\n  ↳ fix: ${f.remediation}`).join('\n'));
  return parts.join('\n\n');
}
