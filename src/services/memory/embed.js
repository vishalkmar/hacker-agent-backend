import { env } from '../../config/env.js';

// Deterministic local embedding (no network): hashed bag-of-tokens projected into EMBED_DIM,
// L2-normalized. Weak semantics but keeps the app fully working without an embeddings API.
function localEmbed(text) {
  const dim = env.embed.dim;
  const v = new Float64Array(dim);
  const tokens = String(text).toLowerCase().match(/[a-z0-9]+/g) || [];
  for (const t of tokens) {
    let h = 2166136261;
    for (let i = 0; i < t.length; i++) {
      h ^= t.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    const idx = Math.abs(h) % dim;
    v[idx] += 1;
  }
  let norm = 0;
  for (let i = 0; i < dim; i++) norm += v[i] * v[i];
  norm = Math.sqrt(norm) || 1;
  return Array.from(v, (x) => x / norm);
}

// OpenAI-compatible /embeddings (covers nvidia + openai). NVIDIA needs input_type.
async function apiEmbed(texts, inputType) {
  const { baseUrl, apiKey, model, provider } = env.embed;
  const url = `${baseUrl.replace(/\/$/, '')}/embeddings`;
  const body = {
    model,
    input: texts,
    encoding_format: 'float',
  };
  if (provider === 'nvidia') {
    body.input_type = inputType; // 'query' | 'passage'
    body.truncate = 'END';
  }
  // Retry transient errors (NVIDIA NIM intermittently returns 5xx/429 under load) before
  // the caller falls back to local hash embeddings.
  let lastErr = '';
  for (let attempt = 0; attempt < 4; attempt++) {
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify(body),
      });
    } catch (e) {
      lastErr = e.message;
      await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
      continue;
    }
    if (res.ok) return (await res.json()).data.map((d) => d.embedding);
    if (res.status >= 500 || res.status === 429) {
      lastErr = `${res.status}`;
      await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
      continue; // transient — retry
    }
    const t = await res.text().catch(() => '');
    throw new Error(`Embeddings failed (${res.status}): ${t.slice(0, 200)}`); // permanent
  }
  throw new Error(`Embeddings failed after retries (${lastErr})`);
}

// Embed an array of strings. kind: 'passage' (storing) | 'query' (searching).
export async function embed(texts, kind = 'passage') {
  const arr = Array.isArray(texts) ? texts : [texts];
  const clipped = arr.map((t) => String(t || '').slice(0, 4000));
  if (!env.embed.enabled || env.embed.provider === 'local' || !env.embed.apiKey) {
    return clipped.map(localEmbed);
  }
  try {
    return await apiEmbed(clipped, kind === 'query' ? 'query' : 'passage');
  } catch (e) {
    // Fall back to local so memory never hard-fails the chat.
    console.warn('Embedding API error, using local fallback:', e.message);
    return clipped.map(localEmbed);
  }
}

export async function embedOne(text, kind = 'passage') {
  return (await embed([text], kind))[0];
}

// pgvector literal: '[0.1,0.2,...]'
export function toVectorLiteral(arr) {
  return '[' + arr.map((x) => (Number.isFinite(x) ? x : 0)).join(',') + ']';
}
