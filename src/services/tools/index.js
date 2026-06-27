import crypto from 'node:crypto';
import { query, isMemoryReady } from '../../db/index.js';
import { embed, embedOne, toVectorLiteral } from '../memory/embed.js';

const hash = (s) => crypto.createHash('sha1').update(s || '').digest('hex');
const clip = (s, n) => (s || '').toString().slice(0, n);

// Build the compact text we embed for retrieval (name + summary + key flags).
function embedText(t) {
  const flags = (t.help || t.help_text || '')
    .split('\n')
    .filter((l) => /^\s*-/.test(l))
    .slice(0, 20)
    .join('\n');
  return [t.name, t.category, t.summary, flags].filter(Boolean).join('\n').slice(0, 3000);
}

// Upsert a batch of tool docs (embeds in one call). items: {name,package,category,summary,help,man,example?}
export async function upsertToolDocs(items, source = 'extract') {
  if (!isMemoryReady() || !items?.length) return 0;
  const clean = items.filter((t) => t && t.name);
  let vectors;
  try {
    vectors = await embed(clean.map(embedText), 'passage');
  } catch {
    return 0;
  }
  let n = 0;
  for (let i = 0; i < clean.length; i++) {
    const t = clean[i];
    const help = clip(t.help ?? t.help_text, 6000);
    const ch = hash(`${t.summary}|${help}|${t.man}`);
    try {
      await query(
        `INSERT INTO tool_docs (name, package, category, summary, help_text, man_excerpt, example, source, content_hash, embedding, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::vector, now())
         ON CONFLICT (name) DO UPDATE SET
           package=$2, category=$3, summary=$4, help_text=$5, man_excerpt=$6,
           example=COALESCE($7, tool_docs.example), source=$8, content_hash=$9, embedding=$10::vector, updated_at=now()`,
        [t.name, clip(t.package, 120), clip(t.category, 60), clip(t.summary, 1000), help,
         clip(t.man, 6000), t.example || null, source, ch, toVectorLiteral(vectors[i])]
      );
      n++;
    } catch (e) {
      console.warn('upsertToolDoc failed for', t.name, e.message);
    }
  }
  return n;
}

// Ingest NDJSON (one tool object per line). Batches embedding for efficiency.
export async function ingestNdjson(ndjson, { batch = 40 } = {}) {
  const lines = String(ndjson).split('\n').map((l) => l.trim()).filter(Boolean);
  let total = 0;
  for (let i = 0; i < lines.length; i += batch) {
    const items = [];
    for (const l of lines.slice(i, i + batch)) {
      try { items.push(JSON.parse(l)); } catch { /* skip bad line */ }
    }
    total += await upsertToolDocs(items, 'extract');
  }
  return total;
}

// Retrieve top-K tools relevant to a goal. Embedding search + keyword fallback.
export async function retrieveTools(queryText, k = 6) {
  if (!isMemoryReady() || !queryText?.trim()) return [];
  try {
    const qvec = await embedOne(queryText, 'query');
    const rows = await query(
      `SELECT name, category, summary, help_text, example,
              1 - (embedding <=> $1::vector) AS score
       FROM tool_docs
       ORDER BY embedding <=> $1::vector ASC LIMIT $2`,
      [toVectorLiteral(qvec), k]
    );
    if (rows.length) return rows;
  } catch (e) {
    console.warn('retrieveTools vector path failed:', e.message);
  }
  // Keyword fallback (works even when embeddings are in local-hash mode).
  const like = `%${queryText.toLowerCase().slice(0, 60)}%`;
  return query(
    `SELECT name, category, summary, help_text, example, 0 AS score
     FROM tool_docs
     WHERE lower(name) LIKE $1 OR lower(summary) LIKE $1 OR lower(help_text) LIKE $1
     LIMIT $2`,
    [like, k]
  );
}

export async function getTool(name) {
  return (await query(
    `SELECT name, package, category, summary, help_text, man_excerpt, example, source, updated_at
     FROM tool_docs WHERE name = $1`, [name]
  ))[0] || null;
}

export async function toolStats() {
  const [s] = await query(
    `SELECT COUNT(*)::int AS tools,
            COUNT(*) FILTER (WHERE example IS NOT NULL)::int AS with_example
     FROM tool_docs`
  );
  const cats = await query(
    `SELECT COALESCE(NULLIF(category,''),'uncategorized') AS category, COUNT(*)::int AS count
     FROM tool_docs GROUP BY 1 ORDER BY count DESC LIMIT 20`
  );
  return { ...s, categories: cats };
}

// A small built-in corpus so the index + retrieval are testable WITHOUT building the
// 20 GB image. Real docs come from the container extractor (Phase 18).
export const SAMPLE_TOOLS = [
  { name: 'nmap', category: 'recon', summary: 'Network exploration tool and security / port scanner.',
    help: '-sS SYN scan\n-sV service/version detection\n-p ports\n-A aggressive\n-O OS detection\n-oN output',
    example: 'nmap -sV -p- 127.0.0.1' },
  { name: 'masscan', category: 'recon', summary: 'Mass IP port scanner, very fast.',
    help: '-p ports\n--rate packets/sec\n-oG grepable output', example: 'masscan -p1-1000 127.0.0.1 --rate 1000' },
  { name: 'sqlmap', category: 'web', summary: 'Automatic SQL injection and database takeover tool.',
    help: '-u URL\n--dbs enumerate databases\n--batch noninteractive\n--risk\n--level', example: 'sqlmap -u "http://localhost/?id=1" --batch --dbs' },
  { name: 'hydra', category: 'password', summary: 'Parallelized network login cracker (brute force).',
    help: '-l user\n-L userlist\n-p pass\n-P passlist\nservice://host', example: 'hydra -l admin -P rockyou.txt ssh://127.0.0.1' },
  { name: 'gobuster', category: 'web', summary: 'Directory/file, DNS and vhost busting tool.',
    help: 'dir -u URL -w wordlist\ndns -d domain\nvhost', example: 'gobuster dir -u http://localhost -w /usr/share/wordlists/dirb/common.txt' },
  { name: 'nikto', category: 'web', summary: 'Web server scanner for dangerous files and misconfigurations.',
    help: '-h host\n-port\n-ssl\n-Tuning', example: 'nikto -h http://localhost' },
  { name: 'crunch', category: 'password', summary: 'Wordlist generator where you can specify a character set.',
    help: 'min max charset\n-o output', example: 'crunch 6 8 abc123 -o wordlist.txt' },
  { name: 'cewl', category: 'password', summary: 'Custom wordlist generator that spiders a URL.',
    help: '-d depth\n-m min length\n-w write', example: 'cewl -d 2 -w words.txt http://localhost' },
  { name: 'john', category: 'password', summary: 'John the Ripper password hash cracker.',
    help: '--wordlist\n--format\n--show', example: 'john --wordlist=rockyou.txt hashes.txt' },
  { name: 'ffuf', category: 'web', summary: 'Fast web fuzzer for content discovery.',
    help: '-u URL/FUZZ\n-w wordlist\n-mc match codes', example: 'ffuf -u http://localhost/FUZZ -w common.txt' },
  // --- the rest of the installed arsenal (curated for clean retrieval) ---
  { name: 'dnsrecon', category: 'recon', summary: 'DNS enumeration and reconnaissance (records, zone transfer, brute force subdomains).',
    help: '-d domain\n-t std|axfr|brt\n-D wordlist', example: 'dnsrecon -d example.com -t std' },
  { name: 'dnsenum', category: 'recon', summary: 'Enumerate DNS info: hosts, subdomains, MX, zone transfers.',
    help: '--enum\n-f wordlist\n--threads', example: 'dnsenum example.com' },
  { name: 'whatweb', category: 'recon', summary: 'Identify websites: CMS, frameworks, server, JS libraries, versions.',
    help: '-a aggression\n-v verbose\n--log', example: 'whatweb -a 3 http://example.com' },
  { name: 'dirb', category: 'web', summary: 'Web content scanner / directory brute-forcer using a wordlist.',
    help: 'URL wordlist\n-X extensions', example: 'dirb http://localhost /usr/share/wordlists/dirb/common.txt' },
  { name: 'wfuzz', category: 'web', summary: 'Web application fuzzer for brute-forcing params, dirs, forms, auth.',
    help: '-w wordlist\n-u URL with FUZZ\n--hc hide codes', example: 'wfuzz -w common.txt -u http://localhost/FUZZ' },
  { name: 'hashcat', category: 'password', summary: 'World\'s fastest GPU password hash cracker (many hash modes).',
    help: '-m mode\n-a attack\n-w workload', example: 'hashcat -m 0 -a 0 hashes.txt rockyou.txt' },
  { name: 'hash-identifier', category: 'password', summary: 'Identify the type/algorithm of a given password hash.',
    help: '(interactive; paste a hash)', example: 'echo 5f4dcc3b5aa765d61d8327deb882cf99 | hash-identifier' },
  { name: 'metasploit-framework', category: 'exploit', summary: 'The Metasploit exploitation framework: exploits, payloads, post modules.',
    help: 'msfconsole\nuse <module>\nset RHOSTS\nexploit', example: 'msfconsole -q -x "search type:exploit name:smb; exit"' },
  { name: 'msfconsole', category: 'exploit', summary: 'Metasploit console — search/use exploits, set options, run against targets.',
    help: 'search\nuse\nset RHOSTS/LHOST\nexploit/run', example: 'msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS 127.0.0.1; run; exit"' },
  { name: 'msfvenom', category: 'exploit', summary: 'Metasploit payload generator/encoder (reverse shells, meterpreter, etc.).',
    help: '-p payload\nLHOST= LPORT=\n-f format', example: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o sh.elf' },
  { name: 'searchsploit', category: 'exploit', summary: 'Search the Exploit-DB archive for public exploits and shellcode.',
    help: 'term\n-t title\n-x examine\n-m mirror', example: 'searchsploit apache 2.4.49' },
  { name: 'amass', category: 'recon', summary: 'In-depth attack-surface mapping and subdomain/asset enumeration.',
    help: 'enum -d domain\nintel\n-passive', example: 'amass enum -d example.com' },
  { name: 'masscan', category: 'recon', summary: 'Internet-scale TCP port scanner, extremely fast.',
    help: '-p ports\n--rate\n-oG output', example: 'masscan -p1-1000 127.0.0.1 --rate 1000' },
  { name: 'set', category: 'exploit', summary: 'Social-Engineer Toolkit: phishing, payloads, credential harvesting (lab use).',
    help: '(menu-driven)', example: 'setoolkit' },
  { name: 'exploitdb', category: 'exploit', summary: 'Local copy of the Exploit-DB exploit archive (searched via searchsploit).',
    help: 'searchsploit <term>', example: 'searchsploit -w wordpress' },
];

export async function seedSampleTools() {
  return upsertToolDocs(SAMPLE_TOOLS, 'sample');
}
