// Mock provider: streams a canned reply word-by-word so the whole app can run
// with no API key (useful for UI development and tests).
export async function streamMock({ messages, onDelta }) {
  const lastUser = [...messages].reverse().find((m) => m.role === 'user');
  const q = lastUser?.content?.slice(0, 200) || '(nothing)';

  const reply = `**CypherMind (mock mode)** — no live LLM is configured, so this is a canned reply.

You said: "${q}"

To get real answers, set these in \`backend/.env\`:

\`\`\`
LLM_PROVIDER=nvidia
LLM_BASE_URL=https://integrate.api.nvidia.com/v1
LLM_API_KEY=your-key
LLM_MODEL=meta/llama-3.3-70b-instruct
\`\`\`

Once a key is set, I'll plan, explain, and generate security content for authorized testing.`;

  const tokens = reply.split(/(\s+)/); // keep whitespace as its own chunks
  for (const t of tokens) {
    onDelta?.(t);
    // small delay to simulate streaming
    await new Promise((r) => setTimeout(r, 12));
  }
  return reply;
}
