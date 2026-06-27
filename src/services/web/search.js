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

// Render results as compact text for the LLM.
export function renderSearchResults({ query, results }) {
  if (!results.length) return `No results for "${query}".`;
  return results
    .map((r, i) => `${i + 1}. ${r.title}\n   ${r.url}\n   ${r.snippet}`)
    .join('\n');
}
