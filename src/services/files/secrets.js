// Lightweight hardcoded-secret scanner for uploaded code/text.
const RULES = [
  { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'AWS Secret Key', re: /\b(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b(?=.*aws|.*secret)/gi },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: 'GitHub Token', re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g },
  { name: 'OpenAI Key', re: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { name: 'NVIDIA Key', re: /\bnvapi-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: 'Generic password assignment', re: /(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{4,}['"]/gi },
  { name: 'Connection string', re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/gi },
];

export function scanSecrets(text) {
  const found = [];
  for (const rule of RULES) {
    const matches = text.match(rule.re);
    if (matches) {
      for (const m of [...new Set(matches)].slice(0, 5)) {
        const preview = m.length > 60 ? m.slice(0, 40) + '…' : m;
        found.push({ type: rule.name, preview });
      }
    }
  }
  return found;
}
