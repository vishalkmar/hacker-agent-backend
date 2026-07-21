// OSINT sweep builders + parsers.
//
// Powers the ```osint agent tool — reconnaissance on people/targets by email, username, phone number, or
// domain. Design principle (same as ```dork / ```shodan): the intelligence lives in the TOOL, not in the
// model's memory. So instead of a single fragile command, we build a deterministic SWEEP that
//   (1) runs the RIGHT CLI tools (phoneinfoga, holehe, maigret, sherlock, theHarvester) with correct install
//       paths, AND
//   (2) ALWAYS emits no-install OSINT LEADS — Google dork URLs + reverse-lookup/social links — so the result
//       is genuinely useful even when a tool is missing or the number/email has no automated footprint.
// Note: Maltego is a GUI tool and cannot run headless — these CLI tools are its practical equivalents.

// --- install helper: PATH first (pipx installs to ~/.local/bin), then apt, then pipx/pip. Idempotent. ---
const PATH_FIX = 'export PATH="$PATH:$HOME/.local/bin:/usr/local/bin"; ';
function ensure(bin, { apt, pip, custom } = {}) {
  const steps = [`command -v ${bin} >/dev/null 2>&1 || {`];
  if (apt) steps.push(`apt-get install -y ${apt} >/dev/null 2>&1 ||`);
  if (custom) steps.push(`{ ${custom}; } ||`);
  if (pip) steps.push(`pipx install ${pip} >/dev/null 2>&1 || pip install ${pip} --break-system-packages >/dev/null 2>&1 ||`);
  steps.push('true; }; ');
  return steps.join(' ');
}
// PhoneInfoga is a Go binary — NOT a pip package. Install the official release binary into /usr/local/bin.
const PHONEINFOGA_INSTALL =
  'cd /tmp && curl -fsSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash >/dev/null 2>&1 && install -m755 ./phoneinfoga /usr/local/bin/phoneinfoga >/dev/null 2>&1; cd - >/dev/null';

const looksEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
const looksPhone = (s) => /^\+?[\d][\d\s\-()]{6,}$/.test(String(s).replace(/\s/g, ''));
const looksDomain = (s) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s) && !s.includes('@');

export function sniffKind(target) {
  const t = String(target || '').trim();
  if (looksEmail(t)) return 'email';
  if (looksPhone(t)) return 'phone';
  if (looksDomain(t)) return 'domain';
  return 'username';
}

// ---- phone helpers ----
function normalizePhone(raw) {
  const digits = String(raw || '').replace(/[^\d+]/g, '');
  const e164 = digits.startsWith('+') ? digits : '+' + digits.replace(/^0+/, '');
  const noPlus = e164.replace('+', '');
  // best-effort national vs country code (India-friendly default, but generic)
  let cc = '';
  let national = noPlus;
  const ccGuess = noPlus.match(/^(1|7|20|27|30|31|32|33|34|39|44|49|52|55|61|62|63|65|66|81|82|84|86|90|91|92|93|94|95|98|971|972|880|92)/);
  if (ccGuess) { cc = ccGuess[1]; national = noPlus.slice(cc.length); }
  return { e164, noPlus, cc, national };
}

// Search leads that need NO tool install — always actionable. Returns [{label, url}].
function phoneLeads(p) {
  const { e164, noPlus, national } = p;
  const g = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  const forms = [...new Set([e164, noPlus, national, national.replace(/(\d{5})(\d{5})/, '$1 $2')])].filter(Boolean);
  const leads = [];
  for (const f of forms) leads.push({ label: `Google "${f}"`, url: g(`"${f}"`) });
  leads.push({ label: 'Google — social profiles', url: g(`"${e164}" OR "${national}" (site:facebook.com OR site:linkedin.com OR site:twitter.com OR site:instagram.com)`) });
  leads.push({ label: 'Google — leaks/pastes', url: g(`"${national}" (site:pastebin.com OR site:throwbin.io OR "leaked" OR "breach")`) });
  leads.push({ label: 'Truecaller', url: `https://www.truecaller.com/search/in/${noPlus}` });
  leads.push({ label: 'Sync.me', url: `https://sync.me/search/?number=${encodeURIComponent(e164)}` });
  leads.push({ label: 'WhatsApp (exists?)', url: `https://wa.me/${noPlus}` });
  leads.push({ label: 'Telegram/Viber lookup', url: g(`"${e164}" telegram OR viber`) });
  return leads;
}
function emailLeads(email) {
  const g = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  const [user] = email.split('@');
  return [
    { label: 'Google exact', url: g(`"${email}"`) },
    { label: 'Google — leaks/pastes', url: g(`"${email}" (site:pastebin.com OR "password" OR "leaked" OR "dump")`) },
    { label: 'HaveIBeenPwned', url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}` },
    { label: 'Gravatar', url: `https://gravatar.com/${user}` },
    { label: 'Google — social', url: g(`"${email}" (site:linkedin.com OR site:github.com OR site:twitter.com)`) },
  ];
}
function usernameLeads(user) {
  const g = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  return [
    { label: 'Google exact', url: g(`"${user}"`) },
    { label: 'Namechk-style search', url: g(`"${user}" (site:github.com OR site:reddit.com OR site:instagram.com OR site:twitter.com OR site:tiktok.com)`) },
    { label: 'GitHub', url: `https://github.com/${encodeURIComponent(user)}` },
    { label: 'Reddit', url: `https://www.reddit.com/user/${encodeURIComponent(user)}` },
  ];
}

function leadBlock(title, leads) {
  const lines = [`echo "== ${title} (open these — no tool needed) =="`];
  for (const l of leads) lines.push(`echo "OSINTLEAD	${l.label}	${l.url}"`);
  return lines.join('; ') + '; ';
}

// Build the full OSINT SWEEP shell script for a target. Always prints leads; runs tools when available.
export function buildOsintSweep({ target, type = 'auto' } = {}) {
  const t = String(target || '').trim();
  if (!t) return 'echo "osint: provide an email, username, phone number, or domain"';
  const kind = type === 'auto' ? sniffKind(t) : type;
  const parts = [PATH_FIX, `echo "== OSINT sweep: ${t} (kind=${kind}) =="`];

  if (kind === 'phone') {
    const p = normalizePhone(t);
    parts.push(leadBlock('Phone search leads', phoneLeads(p)));
    parts.push(ensure('phoneinfoga', { custom: PHONEINFOGA_INSTALL }));
    parts.push(`echo "== phoneinfoga scan =="; phoneinfoga scan -n "${p.e164}" 2>/dev/null || echo "(phoneinfoga unavailable — use the leads above)";`);
  } else if (kind === 'email') {
    parts.push(leadBlock('Email search leads', emailLeads(t)));
    parts.push(ensure('holehe', { pip: 'holehe' }));
    parts.push(`echo "== holehe (which sites this email is registered on) =="; holehe --only-used "${t}" 2>/dev/null || echo "(holehe unavailable — use the leads above)";`);
    parts.push(ensure('h8mail', { pip: 'h8mail' }));
    parts.push(`echo "== h8mail (breach lookup) =="; h8mail -t "${t}" 2>/dev/null | head -40 || true;`);
  } else if (kind === 'username') {
    parts.push(leadBlock('Username search leads', usernameLeads(t)));
    // maigret first (3000+ sites, best); fall back to sherlock.
    parts.push(ensure('maigret', { pip: 'maigret' }));
    parts.push(`echo "== maigret (accounts across 3000+ sites) =="; maigret "${t}" --timeout 15 --no-progressbar 2>/dev/null | head -80 || { `);
    parts.push(ensure('sherlock', { apt: 'sherlock', pip: 'sherlock-project' }));
    parts.push(`echo "== sherlock =="; sherlock --timeout 15 --print-found "${t}" 2>/dev/null | head -80 || echo "(no username tool available — use the leads above)"; };`);
  } else {
    // domain
    parts.push(ensure('theHarvester', { apt: 'theharvester' }));
    parts.push(`echo "== theHarvester (emails/hosts/subdomains) =="; theHarvester -d "${t}" -b all -l 200 2>/dev/null | head -120 || true;`);
    parts.push(ensure('whois', { apt: 'whois' }));
    parts.push(`echo "== whois =="; whois "${t}" 2>/dev/null | head -40 || true;`);
  }
  parts.push(`echo "== OSINT sweep complete =="`);
  return parts.join(' ');
}

// Back-compat: single forced tool (still used when the model names a specific tool). Falls through to sweep.
export function buildOsintCommand({ target, type = 'auto', tool } = {}) {
  const t = String(target || '').trim();
  if (tool) {
    const map = {
      holehe: () => ensure('holehe', { pip: 'holehe' }) + `holehe --only-used "${t}"`,
      h8mail: () => ensure('h8mail', { pip: 'h8mail' }) + `h8mail -t "${t}"`,
      sherlock: () => ensure('sherlock', { apt: 'sherlock', pip: 'sherlock-project' }) + `sherlock --timeout 15 --print-found "${t}"`,
      maigret: () => ensure('maigret', { pip: 'maigret' }) + `maigret "${t}" --timeout 15 --no-progressbar`,
      theharvester: () => ensure('theHarvester', { apt: 'theharvester' }) + `theHarvester -d "${t}" -b all -l 200`,
      phoneinfoga: () => PATH_FIX + ensure('phoneinfoga', { custom: PHONEINFOGA_INSTALL }) + `phoneinfoga scan -n "${normalizePhone(t).e164}"`,
      whois: () => ensure('whois', { apt: 'whois' }) + `whois "${t}"`,
    };
    const fn = map[tool.toLowerCase()];
    if (fn) return fn();
  }
  return buildOsintSweep({ target: t, type });
}

// Parse OSINT sweep output into findings (accounts, emails, phone facts, and the always-present leads).
export function extractOsintFindings(command, output) {
  if (!output) return [];
  const out = [];
  const t = String(output);

  // holehe: "[+] site.com" = account exists.
  for (const m of t.matchAll(/^\s*\[\+\]\s*([a-z0-9.-]+\.[a-z]{2,})\s*$/gim))
    out.push({ finding_type: 'osint', severity: 'medium', title: `Account found on ${m[1]}`, evidence: m[0].trim().slice(0, 120), source: 'holehe' });
  // sherlock / maigret: a found profile URL ([^:\n] so the site name can't run across lines)
  for (const m of t.matchAll(/^[ \t]*\[\+\][ \t]*([^:\n]+):[ \t]*(https?:\/\/\S+)/gim))
    out.push({ finding_type: 'osint', severity: 'medium', title: `Profile on ${m[1].trim()}`, host: m[2], evidence: m[0].trim().slice(0, 160), source: 'sherlock/maigret' });
  for (const m of t.matchAll(/https?:\/\/\S+/g)) {
    // maigret prints bare found URLs too; only keep obvious profile hosts to avoid noise
    if (/(github|instagram|twitter|x\.com|reddit|tiktok|facebook|linkedin|telegram|pinterest|vk\.com|medium)\b/i.test(m[0]) && !/google\.com\/search/.test(m[0]))
      out.push({ finding_type: 'osint', severity: 'low', title: `Possible profile: ${m[0].replace(/^https?:\/\//, '').slice(0, 50)}`, host: m[0], evidence: m[0].slice(0, 160), source: 'maigret' });
  }
  // phoneinfoga facts
  const carrier = t.match(/Carrier:\s*(.+)/i);
  const lineType = t.match(/Line type:\s*(.+)/i);
  const country = t.match(/Country:\s*(.+)/i);
  if (carrier || lineType || country) {
    out.push({ finding_type: 'osint', severity: 'info', title: 'Phone footprint', source: 'phoneinfoga',
      evidence: [country && `Country: ${country[1].trim()}`, carrier && `Carrier: ${carrier[1].trim()}`, lineType && `Line: ${lineType[1].trim()}`].filter(Boolean).join(' · ').slice(0, 200) });
  }
  // emails harvested
  for (const m of t.matchAll(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi))
    out.push({ finding_type: 'osint', severity: 'low', title: `Email harvested: ${m[0]}`, evidence: m[0], source: 'theHarvester' });
  // the always-present leads (so the user always gets actionable pivots)
  const leads = [...t.matchAll(/^OSINTLEAD\t([^\t]+)\t(\S+)/gim)];
  for (const m of leads.slice(0, 20))
    out.push({ finding_type: 'osint', severity: 'info', title: `OSINT lead: ${m[1]}`, host: m[2], evidence: m[2].slice(0, 200), source: 'osint-lead' });

  const seen = new Set();
  return out.filter((f) => (seen.has(f.title) ? false : seen.add(f.title))).slice(0, 80);
}

// Pretty-print the sweep output for chat (turn OSINTLEAD lines into clickable bullets).
export function renderOsint(output) {
  const t = String(output || '');
  return t.replace(/^OSINTLEAD\t([^\t]+)\t(\S+)/gim, '  • $1 → $2');
}
