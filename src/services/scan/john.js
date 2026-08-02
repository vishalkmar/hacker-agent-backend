// John the Ripper output parser — captures CRACKED passwords into critical findings. Ties into ```hashid
// (which identifies a hash + suggests `john --format=…`) and the mounted rockyou wordlist. Handles both
// john's live crack lines ("<password>    (<user>)") and `john --show` output ("<user>:<password>").
// Auto-invoked for any john command via runAndCapture.

export function detectJohn(command = '') {
  return /\bjohn\b/i.test(command) && !/john\.(pot|conf|log|rec)\b/i.test(command);
}

export function parseJohn(command, output) {
  if (!detectJohn(command) || !output) return [];
  const text = String(output);
  const out = [];
  const seen = new Set();
  const add = (user, pass) => {
    pass = String(pass || '').trim();
    if (!pass) return;
    const key = `${user}:${pass}`;
    if (seen.has(key)) return;
    seen.add(key);
    const u = user && user !== '?' ? user : null;
    out.push({
      finding_type: 'credential-access', severity: 'critical', source: 'john',
      title: `Password cracked: ${u ? u + ' = ' : ''}${pass}`,
      host: null, evidence: `${user}:${pass}`.slice(0, 160),
      remediation: 'Rotate this password immediately; enforce strong, unique passwords + MFA; investigate reuse of it across the estate.',
    });
  };

  for (const raw of text.split('\n')) {
    const line = raw.replace(/\x1b\[[0-9;]*m/g, '').replace(/\s+$/, '');
    if (!line || /password hash(?:es)? cracked/i.test(line)) continue;
    if (/^(Using|Loaded|Warning|Proceeding|Press|Session|Node|Remaining|No password|Almost|Will run|Cost |Note:|Use the)/i.test(line)) continue;
    // live crack line: "<password>   (<user>)"  — skip the "1g 0:00:00 DONE ... g/s" status lines
    let m = /^(.+?)\s{2,}\((\S+)\)\s*$/.exec(line);
    if (m && !/\bDONE\b|g\/s|guesses:|^\d+g\s/i.test(line)) { add(m[2], m[1].trim()); continue; }
    // `john --show` line: "<user>:<password>" (single colon, user has no spaces)
    m = /^([^:\s]{1,64}):([^:\s].{0,127})$/.exec(line);
    if (m && !/https?:/.test(line)) { add(m[1], m[2]); continue; }
  }

  // If we saw a cracked-count summary but couldn't extract the plaintext (e.g. it was truncated), still flag.
  const cnt = /(\d+)\s+password hash(?:es)?\s+cracked/i.exec(text);
  if (cnt && Number(cnt[1]) > 0 && out.length === 0) {
    out.push({
      finding_type: 'credential-access', severity: 'critical', source: 'john',
      title: `${cnt[1]} password hash(es) cracked by John (run \`john --show\` to reveal)`,
      evidence: cnt[0], remediation: 'Rotate the cracked passwords; enforce a strong password policy + MFA.',
    });
  }
  return out.slice(0, 60);
}
