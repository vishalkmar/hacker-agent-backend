import { fetchUrl } from './fetch.js';

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

const RE = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  url: /https?:\/\/[^\s"'<>)\]}]+/g,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  // route-ish path strings, e.g. "/api/v1/users" found in JS/HTML
  path: /["'`](\/[A-Za-z0-9_\-./]{2,}?)["'`]/g,
};

function uniq(arr, max = 200) {
  return [...new Set(arr)].slice(0, max);
}

function rootDomain(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  return parts.slice(-2).join('.');
}

// Extract recon artifacts from a blob of text/html given a base URL for context.
export function extractRecon(text, baseUrl = '') {
  const emails = uniq((text.match(RE.email) || []).filter((e) => !/\.(png|jpg|gif|svg|webp)$/i.test(e)));
  const ips = uniq(text.match(RE.ipv4) || []);
  const urls = uniq(text.match(RE.url) || []);

  const domains = new Set();
  const subdomains = new Set();
  let baseRoot = '';
  try {
    if (baseUrl) baseRoot = rootDomain(new URL(baseUrl).hostname);
  } catch {
    /* ignore */
  }
  for (const u of urls) {
    try {
      const host = new URL(u).hostname;
      domains.add(rootDomain(host));
      if (host.split('.').length > 2) subdomains.add(host);
    } catch {
      /* ignore */
    }
  }

  const routes = new Set();
  let m;
  RE.path.lastIndex = 0;
  while ((m = RE.path.exec(text)) !== null) {
    const p = m[1];
    if (p.length < 60 && !/\.(png|jpg|jpeg|gif|svg|css|webp|woff2?|ico)$/i.test(p)) routes.add(p);
  }

  return {
    baseRoot,
    emails,
    ips,
    domains: [...domains].slice(0, 100),
    subdomains: [...subdomains].slice(0, 100),
    urls: urls.slice(0, 100),
    routes: [...routes].slice(0, 150),
  };
}

// Recon a URL: fetch the page + up to N same-origin scripts, then aggregate artifacts.
export async function reconUrl(rawUrl, { maxScripts = 6, signal } = {}) {
  const page = await fetchUrl(rawUrl, { signal });
  let blob = [page.text, ...(page.links || []), ...(page.scripts || [])].join('\n');

  // Pull a few JS files to mine endpoints from.
  const scriptUrls = (page.scripts || [])
    .map((s) => {
      try {
        return new URL(s, page.url).toString();
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .slice(0, maxScripts);

  const jsEndpoints = new Set();
  for (const su of scriptUrls) {
    try {
      const res = await fetch(su, { headers: { 'User-Agent': UA }, signal });
      if (!res.ok) continue;
      const js = (await res.text()).slice(0, 200_000);
      const r = extractRecon(js, page.url);
      r.routes.forEach((x) => jsEndpoints.add(x));
      r.urls.forEach((x) => jsEndpoints.add(x));
    } catch {
      /* ignore individual script errors */
    }
  }

  const recon = extractRecon(blob, page.url);
  recon.jsEndpoints = [...jsEndpoints].slice(0, 150);
  recon.scriptsScanned = scriptUrls.length;
  return { url: page.url, status: page.status, title: page.title, technologies: page.technologies, recon };
}

export function renderRecon(r) {
  const x = r.recon;
  const lines = [`Recon for ${r.url} (HTTP ${r.status})`];
  if (r.title) lines.push(`Title: ${r.title}`);
  if (r.technologies?.length) lines.push(`Tech: ${r.technologies.join(', ')}`);
  const block = (label, arr) =>
    arr?.length ? lines.push(`${label} (${arr.length}):\n  ${arr.slice(0, 40).join('\n  ')}`) : null;
  block('Subdomains', x.subdomains);
  block('Domains', x.domains);
  block('Routes/Endpoints', x.routes);
  block('JS endpoints', x.jsEndpoints);
  block('Emails', x.emails);
  block('IPs', x.ips);
  return lines.join('\n');
}
