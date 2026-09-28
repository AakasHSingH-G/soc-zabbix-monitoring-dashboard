'use strict';

const { execFileSync } = require('node:child_process');
const os = require('node:os');
const { performance } = require('node:perf_hooks');

const endpoint = new URL(process.env.LOCAL_AI_URL || 'http://127.0.0.1:8090');
if (endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(endpoint.hostname)) {
  throw new Error('Measurement endpoint must use local HTTP loopback.');
}
const model = process.env.LOCAL_AI_MODEL || 'soc-brain';
const maxTokens = Math.max(32, Math.min(192, Number(process.env.P1_MAX_TOKENS) || 96));
const timeoutMs = Math.max(30_000, Math.min(180_000, Number(process.env.P1_TIMEOUT_MS) || 120_000));
const events = Array.from({ length: 25 }, (_, index) => ({
  minute: index,
  source: 'decoy',
  severity: index % 5 === 0 ? 'MED' : 'LOW',
  port: [22, 80, 443, 10050, 3389][index % 5],
  rule: ['port probe', 'login page request', 'authentication failure'][index % 3],
  method: index % 2 ? 'GET' : 'POST',
  path_class: ['admin-login', 'zabbix-web', 'root-path'][index % 3],
  ua_class: 'scanner',
}));
const prompt = `Analyze the 25 synthetic security events. Think briefly, then return compact JSON with stage, observations, uncertainties. Never invent facts. <think>Events: ${JSON.stringify(events)}</think>`;
const started = performance.now();
let firstDeltaMs = null;
let deltas = 0;
let outputChars = 0;
let responseStatus = 0;

function processSnapshot() {
  try {
    const output = execFileSync('ps', ['-p', process.env.P1_MODEL_PID || '', '-o', 'rss=,%cpu='], { encoding: 'utf8' }).trim().split(/\s+/);
    return { rssKb: Number(output[0]) || null, cpuPct: Number(output[1]) || null };
  } catch {
    return { rssKb: null, cpuPct: null };
  }
}

(async () => {
  const before = processSnapshot();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(new URL('/v1/chat/completions', endpoint), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      signal: controller.signal,
      body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], temperature: 0.1, max_tokens: maxTokens, stream: true }),
    });
    responseStatus = response.status;
    if (!response.ok) throw new Error('Model endpoint returned a non-success status.');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line.startsWith('data:')) continue;
        const data = line.slice(5).trim();
        if (!data || data === '[DONE]') continue;
        let chunk;
        try { chunk = JSON.parse(data); } catch { continue; }
        const delta = chunk.choices?.[0]?.delta || {};
        const text = `${delta.reasoning_content || ''}${delta.content || ''}`;
        if (text) {
          if (firstDeltaMs === null) firstDeltaMs = performance.now() - started;
          deltas += 1;
          outputChars += text.length;
        }
      }
    }
    const elapsedMs = performance.now() - started;
    const after = processSnapshot();
    const cpu = os.cpus().length;
    console.log(`http_status=${responseStatus}`);
    console.log(`first_delta_ms=${firstDeltaMs === null ? 'not-observed' : Math.round(firstDeltaMs)}`);
    console.log(`total_latency_ms=${Math.round(elapsedMs)}`);
    console.log(`stream_delta_count=${deltas}`);
    console.log(`output_chars=${outputChars}`);
    console.log(`stream_deltas_per_sec=${(deltas / (elapsedMs / 1000)).toFixed(2)}`);
    console.log(`cpu_count=${cpu}`);
    console.log(`model_rss_before_kb=${before.rssKb ?? 'unavailable'}`);
    console.log(`model_rss_after_kb=${after.rssKb ?? 'unavailable'}`);
    console.log(`model_cpu_percent_after=${after.cpuPct ?? 'unavailable'}`);
    if (firstDeltaMs === null) process.exitCode = 2;
  } finally {
    clearTimeout(timer);
  }
})().catch(error => {
  console.log(`measurement=failed (${error.name === 'AbortError' ? 'timeout' : 'request error'})`);
  if (responseStatus) console.log(`http_status=${responseStatus}`);
  process.exitCode = 2;
});
