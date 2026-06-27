import * as cheerio from 'cheerio';

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

const MAX_TEXT = 6000;
const MAX_LINKS = 40;

// Very light technology fingerprinting from headers + meta.
function fingerprint(headers, $) {
  const tech = new Set();
  const server = headers.get('server');
  const xpb = headers.get('x-powered-by');
  if (server) tech.add(server);
  if (xpb) tech.add(xpb);
  const gen = $('meta[name="generator"]').attr('content');
  if (gen) tech.add(gen);
  if ($('script[src*="wp-content"], link[href*="wp-content"]').length) tech.add('WordPress');
  if ($('script[src*="/_next/"]').length || $('#__next').length) tech.add('Next.js');
  if ($('script[src*="react"]').length || $('#root').length) tech.add('React (likely)');
  return [...tech];
}

// Fetch a URL and extract security-relevant structure.
export async function fetchUrl(rawUrl, { timeoutMs = 20000, signal } = {}) {
  let url = String(rawUrl || '').trim();
  if (!url) throw new Error('url is required');
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  // Reddit: use its public JSON API for clean, readable content.
  try {
    const h = new URL(url).hostname;
    if (/(^|\.)reddit\.com$/i.test(h) && !/\.json($|\?)/.test(url)) {
      url = url.replace(/\/?(\?|$)/, '.json$1');
    }
  } catch {
    /* ignore */
  }

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  // Chain the caller's signal if provided.
  signal?.addEventListener?.('abort', () => ac.abort());

  let res;
  try {
    res = await fetch(url, {
      redirect: 'follow',
      signal: ac.signal,
      headers: { 'User-Agent': UA, Accept: '*/*', 'Accept-Language': 'en-US,en;q=0.9' },
    });
  } finally {
    clearTimeout(timer);
  }

  const headers = res.headers;
  const contentType = headers.get('content-type') || '';
  const status = res.status;
  const finalUrl = res.url || url;

  const headerObj = {};
  for (const [k, v] of headers.entries()) headerObj[k] = v;

  // Non-HTML: return a truncated raw body.
  if (!/text\/html|application\/xhtml/i.test(contentType)) {
    const body = (await res.text().catch(() => '')).slice(0, MAX_TEXT);
    return {
      url: finalUrl,
      status,
      contentType,
      title: '',
      text: body,
      technologies: fingerprintFromHeadersOnly(headers),
      links: [],
      forms: [],
      scripts: [],
      headers: headerObj,
    };
  }

  const html = await res.text();
  const $ = cheerio.load(html);

  $('script, style, noscript, svg').remove();
  const title = $('title').first().text().trim();
  const description = $('meta[name="description"]').attr('content') || '';
  const text = $('body').text().replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT);

  const base = new URL(finalUrl);
  const links = [];
  const seen = new Set();
  $('a[href]').each((_, el) => {
    if (links.length >= MAX_LINKS) return;
    try {
      const abs = new URL($(el).attr('href'), base).toString();
      if (!seen.has(abs)) {
        seen.add(abs);
        links.push(abs);
      }
    } catch {
      /* ignore bad hrefs */
    }
  });

  const forms = [];
  $('form').each((_, el) => {
    const inputs = [];
    $(el)
      .find('input, textarea, select')
      .each((__, inp) => {
        const name = $(inp).attr('name');
        if (name) inputs.push({ name, type: $(inp).attr('type') || 'text' });
      });
    forms.push({
      action: $(el).attr('action') || '',
      method: ($(el).attr('method') || 'GET').toUpperCase(),
      inputs,
    });
  });

  const reload$ = cheerio.load(html); // re-parse to read scripts removed above
  const scripts = [];
  reload$('script[src]').each((_, el) => {
    if (scripts.length >= 30) return;
    scripts.push(reload$(el).attr('src'));
  });

  return {
    url: finalUrl,
    status,
    contentType,
    title,
    description,
    text,
    technologies: fingerprint(headers, reload$),
    links,
    forms,
    scripts,
    headers: headerObj,
  };
}

function fingerprintFromHeadersOnly(headers) {
  const tech = [];
  if (headers.get('server')) tech.push(headers.get('server'));
  if (headers.get('x-powered-by')) tech.push(headers.get('x-powered-by'));
  return tech;
}

// Compact text rendering for the LLM.
export function renderPage(p) {
  const lines = [];
  lines.push(`URL: ${p.url}  (HTTP ${p.status}, ${p.contentType})`);
  if (p.title) lines.push(`Title: ${p.title}`);
  if (p.description) lines.push(`Description: ${p.description}`);
  if (p.technologies?.length) lines.push(`Tech: ${p.technologies.join(', ')}`);
  const hdr = ['server', 'x-powered-by', 'content-security-policy', 'set-cookie'].filter(
    (h) => p.headers?.[h]
  );
  if (hdr.length) lines.push(`Headers: ${hdr.map((h) => `${h}: ${p.headers[h]}`).join(' | ')}`);
  if (p.forms?.length) {
    lines.push(
      `Forms (${p.forms.length}): ` +
        p.forms
          .map((f) => `${f.method} ${f.action || '(self)'} [${f.inputs.map((i) => i.name).join(',')}]`)
          .join(' ; ')
    );
  }
  if (p.scripts?.length) lines.push(`Scripts: ${p.scripts.slice(0, 10).join(', ')}`);
  if (p.links?.length) lines.push(`Links (${p.links.length}): ${p.links.slice(0, 15).join(' , ')}`);
  if (p.text) lines.push(`\nContent:\n${p.text}`);
  return lines.join('\n');
}
