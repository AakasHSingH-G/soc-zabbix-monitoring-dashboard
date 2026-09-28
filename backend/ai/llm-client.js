async function completeChat({ config, messages, responseSchema, timeoutSeconds, maxTokens, signal }) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, timeoutSeconds * 1000);
  const startedAt = Date.now();
  try {
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (config.apiKey) headers.Authorization = `Bearer ${config.apiKey}`;
    const response = await fetch(new URL('/v1/chat/completions', config.url), {
      method: 'POST',
      headers,
      signal: controller.signal,
      body: JSON.stringify({
        model: config.model,
        messages,
        response_format: {
          type: 'json_schema',
          json_schema: { name: 'attacker_analysis', strict: true, schema: responseSchema },
        },
        temperature: 0.6,
        top_p: 0.95,
        max_tokens: maxTokens,
        stream: false,
      }),
    });
    if (!response.ok) throw new Error(`Local model returned HTTP ${response.status}`);
    const payload = await response.json();
    const content = payload?.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content.trim()) throw new Error('Local model returned an empty response');
    return { content, latencyMs: Date.now() - startedAt };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

module.exports = { completeChat };
