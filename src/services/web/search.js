import * as cheerio from 'cheerio';

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// Decode DuckDuckGo redirect links (/l/?uddg=<encoded real url>).
function cleanDdgUrl(href) {
  try {
    if (!href) return '';
    if (href.startsWith('//')) href = 'https:' + href;
    const u = new URL(href, 'https://duckduckgo.com');
    const uddg = u.searchParams.get('uddg');
    return uddg ? decodeURIComponent(uddg) : href;
  } catch {
    return href;
  }
}

// Web search with no API key, via the DuckDuckGo HTML endpoint.
// Returns { query, results: [{ title, url, snippet }] }
export async function webSearch(query, { max = 8, signal } = {}) {
  const q = String(query || '').trim();
  if (!q) return { query: q, results: [] };

  const url = 'https://html.duckduckgo.com/html/?q=' + encodeURIComponent(q);
  const res = await fetch(url, {
    method: 'GET',
    signal,
    headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9' },
  });
  if (!res.ok) throw new Error(`Search failed (${res.status})`);

  const html = await res.text();
  const $ = cheerio.load(html);
  const results = [];

  $('.result').each((_, el) => {
    if (results.length >= max) return;
    const a = $(el).find('.result__a').first();
    const title = a.text().trim();
    const href = cleanDdgUrl(a.attr('href'));
    const snippet = $(el).find('.result__snippet').first().text().trim();
    if (title && href) results.push({ title, url: href, snippet });
  });

  return { query: q, results };
}

// Bing HTML search — a second engine so dork sweeps survive DuckDuckGo rate-limiting. Bing handles the
// site:/filetype:/inurl:/intitle: operators well. Returns the same { query, results:[{title,url,snippet}] }.
export async function bingSearch(query, { max = 8, signal } = {}) {
  const q = String(query || '').trim();
  if (!q) return { query: q, results: [] };
  const url = 'https://www.bing.com/search?count=20&q=' + encodeURIComponent(q);
  const res = await fetch(url, {
    method: 'GET',
    signal,
    headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9', 'Accept': 'text/html' },
  });
  if (!res.ok) throw new Error(`Bing search failed (${res.status})`);
  const html = await res.text();
  const $ = cheerio.load(html);
  const results = [];
  $('li.b_algo').each((_, el) => {
    if (results.length >= max) return;
    const a = $(el).find('h2 a').first();
    const title = a.text().trim();
    const href = (a.attr('href') || '').trim();
    const snippet = $(el).find('.b_caption p, p').first().text().trim();
    if (title && /^https?:\/\//i.test(href)) results.push({ title, url: href, snippet });
  });
  return { query: q, results };
}

// Try multiple engines in order, return the first that yields results (resilient to per-engine blocking).
export async function multiSearch(query, { max = 6, signal, engines = ['bing', 'ddg'] } = {}) {
  let lastErr = null;
  for (const eng of engines) {
    try {
      const fn = eng === 'bing' ? bingSearch : webSearch;
      const r = await fn(query, { max, signal });
      if (r.results.length) return { ...r, engine: eng };
    } catch (e) { lastErr = e; }
  }
  if (lastErr) throw lastErr;
  return { query, results: [], engine: null };
}

// Render results as compact text for the LLM.
export function renderSearchResults({ query, results }) {
  if (!results.length) return `No results for "${query}".`;
  return results
    .map((r, i) => `${i + 1}. ${r.title}\n   ${r.url}\n   ${r.snippet}`)
    .join('\n');
}
