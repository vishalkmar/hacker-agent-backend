import { chromium } from 'playwright';
import { env } from '../../config/env.js';

// One shared headless browser; one page (tab) per chat session.
let _browser = null;
const _pages = new Map(); // sessionId -> { context, page }

async function getBrowser() {
  if (_browser) return _browser;
  _browser = await chromium.launch({
    headless: env.browser.headless,
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
  });
  return _browser;
}

async function getPage(sessionId = 'default') {
  let entry = _pages.get(sessionId);
  if (entry && !entry.page.isClosed()) return entry.page;
  const browser = await getBrowser();
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: true,
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
  });
  const page = await context.newPage();
  page.setDefaultTimeout(env.browser.timeoutMs);
  entry = { context, page };
  _pages.set(sessionId, entry);
  return page;
}

const isHttp = (u) => /^https?:\/\//i.test(u);

// Capture the page: url, title, a text excerpt, links, forms, and a screenshot (data URL).
async function snapshot(page, { withShot = true } = {}) {
  const url = page.url();
  let title = '';
  let text = '';
  let links = [];
  let forms = [];
  try {
    title = await page.title();
    const data = await page.evaluate(() => {
      const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
      const text = clean(document.body?.innerText || '').slice(0, 3000);
      const links = [...document.querySelectorAll('a[href]')]
        .map((a) => ({ t: clean(a.textContent).slice(0, 50), href: a.href }))
        .filter((l) => l.href && !l.href.startsWith('javascript:'))
        .slice(0, 40);
      const forms = [...document.querySelectorAll('form')].map((f) => ({
        action: f.getAttribute('action') || '',
        method: (f.getAttribute('method') || 'get').toUpperCase(),
        inputs: [...f.querySelectorAll('input,select,textarea')]
          .map((i) => `${i.tagName.toLowerCase()}[${i.type || ''}]${i.name ? '#' + i.name : ''}`)
          .slice(0, 12),
      })).slice(0, 8);
      return { text, links, forms };
    });
    text = data.text; links = data.links; forms = data.forms;
  } catch (e) {
    text = '(could not read page: ' + e.message + ')';
  }
  let screenshot = null;
  if (withShot) {
    try {
      const buf = await page.screenshot({ type: 'jpeg', quality: 60, fullPage: false });
      screenshot = 'data:image/jpeg;base64,' + buf.toString('base64');
    } catch { /* ignore */ }
  }
  return { url, title, text, links, forms, screenshot };
}

// Run one browser action. Returns { ...snapshot, action } or { error }.
//   action lines: goto <url> | reload | back | content | links | forms | screenshot
//                 click <selector> | type <selector> > <text> | press <key> | wait <ms>
export async function runBrowser(sessionId, raw) {
  if (!env.browser.enabled) return { error: 'Browser tool is disabled (BROWSER_ENABLED=false)' };
  const line = String(raw || '').trim();
  const sp = line.indexOf(' ');
  const action = (sp === -1 ? line : line.slice(0, sp)).toLowerCase();
  const arg = sp === -1 ? '' : line.slice(sp + 1).trim();

  let page;
  try {
    page = await getPage(sessionId);
  } catch (e) {
    return { error: 'Browser launch failed: ' + e.message };
  }

  try {
    switch (action) {
      case 'goto':
      case 'open':
      case 'visit': {
        let u = arg;
        if (!isHttp(u)) u = 'http://' + u;
        await page.goto(u, { waitUntil: 'domcontentloaded' });
        await page.waitForTimeout(600);
        return { action: 'goto', ...(await snapshot(page)) };
      }
      case 'reload':
        await page.reload({ waitUntil: 'domcontentloaded' });
        return { action: 'reload', ...(await snapshot(page)) };
      case 'back':
        await page.goBack({ waitUntil: 'domcontentloaded' });
        return { action: 'back', ...(await snapshot(page)) };
      case 'click':
        await page.click(arg, { timeout: 8000 });
        await page.waitForTimeout(600);
        return { action: 'click', ...(await snapshot(page)) };
      case 'type':
      case 'fill': {
        // "type <selector> > <text>"
        const m = arg.split('>');
        const sel = m[0].trim();
        const val = m.slice(1).join('>').trim();
        await page.fill(sel, val, { timeout: 8000 });
        return { action: 'type', ...(await snapshot(page)) };
      }
      case 'press':
        await page.keyboard.press(arg || 'Enter');
        await page.waitForTimeout(600);
        return { action: 'press', ...(await snapshot(page)) };
      case 'wait':
        await page.waitForTimeout(Math.min(Number(arg) || 1000, 10000));
        return { action: 'wait', ...(await snapshot(page)) };
      case 'content':
      case 'links':
      case 'forms':
      case 'screenshot':
      case 'shot':
      default:
        return { action: action || 'snapshot', ...(await snapshot(page)) };
    }
  } catch (e) {
    // Still return a snapshot so the agent sees current state + the error.
    const snap = await snapshot(page).catch(() => ({}));
    return { action, error: e.message.split('\n')[0], ...snap };
  }
}

// Format a browser result into text the LLM can reason over (screenshot stripped out).
export function fmtBrowser(r) {
  if (r.error && !r.url) return 'Browser error: ' + r.error;
  const lines = [`[browser ${r.action}] ${r.url}  (title: ${r.title || '—'})`];
  if (r.error) lines.push('action error: ' + r.error);
  if (r.forms?.length) lines.push('FORMS: ' + r.forms.map((f) => `${f.method} ${f.action} {${f.inputs.join(', ')}}`).join(' | '));
  if (r.links?.length) lines.push('LINKS: ' + r.links.map((l) => `${l.t || '·'} -> ${l.href}`).slice(0, 25).join('\n'));
  if (r.text) lines.push('TEXT:\n' + r.text);
  return lines.join('\n').slice(0, 5000);
}

export async function closeBrowserSession(sessionId) {
  const e = _pages.get(sessionId);
  if (e) { await e.context.close().catch(() => {}); _pages.delete(sessionId); }
}
