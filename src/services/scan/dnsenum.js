// dnsenum output parser — turns DNS enumeration results into findings. The crown jewel is detecting a
// successful ZONE TRANSFER (AXFR): dnsenum only dumps the zone (with an `IN SOA` record) when a name server
// wrongly allows a public transfer, which leaks every internal hostname → a real high-severity misconfig.
// Also records discovered subdomains as an asset inventory. Auto-invoked for any dnsenum command.

export function detectDnsenum(command = '') {
  return /\bdnsenum\b/i.test(command);
}

function domainFromCommand(command) {
  // last non-flag token that looks like a domain
  const toks = String(command).trim().split(/\s+/);
  for (let i = toks.length - 1; i >= 0; i--) {
    const t = toks[i];
    if (!t.startsWith('-') && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/i.test(t)) return t.toLowerCase();
  }
  return '';
}

export function parseDnsenum(command, output) {
  if (!detectDnsenum(command) || !output) return [];
  const text = String(output).replace(/\x1b\[[0-9;]*m/g, ''); // strip ANSI colour
  const out = [];
  const domain = (/-----\s+(\S+?)\s+-----/.exec(text)?.[1] || domainFromCommand(command) || '').toLowerCase();

  // ---- Zone transfer (AXFR) ----
  const axfrTried = /Trying Zone Transfer/i.test(text);
  // dnsenum prints an `IN SOA` line ONLY when the transfer actually succeeds; failures show
  // "AXFR record query failed" / "Transfer failed" / "REFUSED" and no SOA.
  const axfrSucceeded = axfrTried && /\bIN\s+SOA\b/i.test(text);
  if (axfrSucceeded) {
    const ns = /Trying Zone Transfer for \S+ on (\S+)/i.exec(text)?.[1]?.replace(/\.$/, '') || 'a name server';
    out.push({
      finding_type: 'misconfiguration', severity: 'high', source: 'dnsenum',
      title: `DNS zone transfer (AXFR) allowed${domain ? ' for ' + domain : ''}`,
      host: domain || null,
      evidence: `zone transfer succeeded on ${ns} — the full DNS zone (every internal hostname/record) was disclosed`,
      remediation: 'Restrict AXFR zone transfers to authorized secondary name servers only (BIND: allow-transfer { ...; }; deny by default). A public zone transfer leaks the entire internal DNS layout.',
    });
  } else if (axfrTried) {
    out.push({
      finding_type: 'recon', severity: 'info', source: 'dnsenum',
      title: `DNS zone transfer refused${domain ? ' for ' + domain : ''} (good)`,
      host: domain || null, evidence: 'name servers correctly refuse AXFR', remediation: null,
    });
  }

  // ---- discovered subdomains (A/AAAA/CNAME records under the domain) ----
  if (domain) {
    const seen = new Set();
    const re = new RegExp(`^\\s*([a-z0-9][a-z0-9._-]*\\.${domain.replace(/[.]/g, '\\.')})\\.?\\s+\\d+\\s+IN\\s+(A|AAAA|CNAME)\\s+(\\S+)`, 'gim');
    let m;
    while ((m = re.exec(text)) !== null) {
      const sub = m[1].toLowerCase();
      if (sub === domain || seen.has(sub)) continue;
      seen.add(sub);
      out.push({
        finding_type: 'subdomain', severity: 'info', source: 'dnsenum',
        title: `Subdomain: ${sub}`, host: sub,
        evidence: `${m[2]} ${m[3]}`.slice(0, 120), remediation: null,
      });
    }
    if (seen.size) {
      out.push({
        finding_type: 'recon', severity: 'info', source: 'dnsenum',
        title: `dnsenum: ${seen.size} subdomain(s) discovered for ${domain}`,
        host: domain, evidence: [...seen].slice(0, 20).join(', ').slice(0, 300), remediation: null,
      });
    }
  }

  // dedup by title, cap
  const seenT = new Set();
  return out.filter((f) => (seenT.has(f.title) ? false : seenT.add(f.title))).slice(0, 80);
}
