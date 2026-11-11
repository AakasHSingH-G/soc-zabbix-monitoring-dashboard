const { stripReasoningTags } = require('./think-parser');

async function completeChat({ config, messages, responseSchema, timeoutSeconds, maxTokens, signal }) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, timeoutSeconds * 1000);
  const startedAt = Date.now();
  try {
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (config.apiKey) headers.Authorization = `Bearer ${config.apiKey}`;
    const body = {
      model: config.model,
      messages,
      temperature: 0.6,
      top_p: 0.95,
      max_tokens: maxTokens,
      stream: false,
    };
    if (responseSchema) {
      body.response_format = {
        type: 'json_schema',
        json_schema: { name: 'attacker_analysis', strict: true, schema: responseSchema },
      };
    }
    const endpoint = new URL(config.url);
    const basePath = endpoint.pathname.replace(/\/+$/, '');
    endpoint.pathname = `${basePath}${basePath.endsWith('/v1') ? '' : '/v1'}/chat/completions`;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      signal: controller.signal,
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`AI provider returned HTTP ${response.status}`);
    const payload = await response.json();
    const content = payload?.choices?.[0]?.message?.content;
    const cleanedContent = typeof content === 'string' ? stripReasoningTags(content) : '';
    if (typeof content !== 'string' || !cleanedContent.trim()) throw new Error('AI provider returned an empty response');
    return { content: cleanedContent, latencyMs: Date.now() - startedAt };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

module.exports = { completeChat };
