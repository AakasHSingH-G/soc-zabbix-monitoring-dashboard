'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const https = require('node:https');
const net = require('node:net');

const MAX_BYTES = 5 * 1024 * 1024;
const MAX_TEXT_LENGTH = 1500;
const TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 2;
const TRUST = Object.freeze({ T1: 0.95, T2: 0.8, T3: 0.6, T4: 0.25 });
const CONTENT_TYPES = new Set(['application/json', 'application/xml', 'text/xml', 'text/plain', 'application/rss+xml', 'application/atom+xml']);
const INSTRUCTION_PATTERN = /ignore (?:all )?(?:previous|prior) instructions|system prompt|reveal (?:the )?(?:secret|system)|jailbreak|execute (?:this|the) (?:command|instruction)|developer message/i;

function dbAll(db, sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row || null)));
}

function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

async function initializeIntelligenceTables(db) {
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_intel_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    exact_domain TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT 'general',
    trust_tier TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'new',
    last_fetched_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_intel_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    content TEXT NOT NULL,
    flagged_instruction INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'new',
    fetched_at TEXT NOT NULL,
    stale_after_days INTEGER NOT NULL,
    UNIQUE(source_id, content_hash)
  )`);
}

function validateSourceUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Source URL is invalid'); }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (url.protocol !== 'https:' || !hostname || net.isIP(hostname) || url.username || url.password || (url.port && url.port !== '443')) {
    throw new Error('Sources must use HTTPS on a public DNS hostname without credentials or a custom port');
  }
  url.hash = '';
  return { url: url.toString(), exactDomain: hostname };
}

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const octets = address.split('.').map(Number);
    const [first, second] = octets;
    return first === 0 || first === 10 || first === 127 || first >= 224 ||
      (first === 169 && second === 254) || (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) || (first === 100 && second >= 64 && second <= 127) ||
      (first === 192 && second === 0) || (first === 198 && (second === 18 || second === 19 || second === 51)) ||
      (first === 203 && second === 0);
  }
  if (family !== 6) return true;
  const normalized = address.toLowerCase().split('%')[0];
  if (normalized === '::' || normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') ||
      /^fe[89ab]/.test(normalized) || normalized.startsWith('ff') || normalized.startsWith('2001:db8:') ||
      normalized.startsWith('2001:0:')) return true;
  const mapped = normalized.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateAddress(mapped[1]);
  const mappedHex = normalized.match(/::ffff:([\da-f]{1,4}):([\da-f]{1,4})$/);
  if (mappedHex) {
    const high = Number.parseInt(mappedHex[1], 16);
    const low = Number.parseInt(mappedHex[2], 16);
    return isPrivateAddress(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  return false;
}

async function resolvePublicAddresses(hostname, lookup = dns.lookup) {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  if (!Array.isArray(addresses) || !addresses.length || addresses.some(item => isPrivateAddress(item.address))) {
    throw new Error('Source hostname resolves to a private, loopback, or reserved address');
  }
  return addresses;
}

function requestHttps(url, addresses, timeoutMs, maximumBytes) {
  return new Promise((resolve, reject) => {
    const address = addresses[0];
    let received = 0;
    const chunks = [];
    const req = https.request(url, {
      method: 'GET',
      headers: { Accept: [...CONTENT_TYPES].join(', '), 'Accept-Encoding': 'identity' },
      servername: url.hostname,
      lookup: (hostname, options, callback) => {
        if (options?.all) callback(null, addresses);
        else callback(null, address.address, address.family);
      },
    }, response => {
      const declaredLength = Number(response.headers['content-length']);
      if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
        req.destroy(new Error('Source response exceeds the 5 MB limit'));
        return;
      }
      response.on('data', chunk => {
        received += chunk.length;
        if (received > maximumBytes) return req.destroy(new Error('Source response exceeds the 5 MB limit'));
        chunks.push(chunk);
      });
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
      response.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('Source request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function safeFetchSource(source, { lookup = dns.lookup, request = requestHttps, now = Date.now } = {}) {
  const startedAt = now();
  let current = new URL(source.url);
  const exactDomain = String(source.exact_domain || current.hostname).toLowerCase().replace(/\.$/, '');
  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    const hostname = current.hostname.toLowerCase().replace(/\.$/, '');
    if (current.protocol !== 'https:' || hostname !== exactDomain || current.username || current.password || (current.port && current.port !== '443')) {
      throw new Error('Redirect does not match the allowlisted HTTPS domain');
    }
    const addresses = await resolvePublicAddresses(hostname, lookup);
    const remaining = TIMEOUT_MS - (now() - startedAt);
    if (remaining <= 0) throw new Error('Source request timed out');
    const response = await request(current, addresses, remaining, MAX_BYTES);
    if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
      if (redirectCount === MAX_REDIRECTS) throw new Error('Source exceeded the redirect limit');
      const location = response.headers.location;
      if (!location) throw new Error('Source redirect omitted its target');
      current = new URL(location, current);
      continue;
    }
    if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`Source returned HTTP ${response.statusCode}`);
    const contentType = String(response.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (!CONTENT_TYPES.has(contentType)) throw new Error('Source content type is not allowed');
    const body = Buffer.isBuffer(response.body) ? response.body : Buffer.from(response.body || '');
    if (body.length > MAX_BYTES) throw new Error('Source response exceeds the 5 MB limit');
    return { content: body.toString('utf8').slice(0, MAX_BYTES), contentType };
  }
  throw new Error('Source redirect processing failed');
}

function trustScore(tier) {
  return TRUST[tier] ?? TRUST.T4;
}

function quarantineReason(content, tier) {
  if (tier === 'T4') return 'trust_tier_t4';
  return INSTRUCTION_PATTERN.test(content) ? 'instruction_like_text' : null;
}

async function addIntelSource(db, { url, trustTier = 'T3', sourceType = 'general' }) {
  await initializeIntelligenceTables(db);
  if (!Object.hasOwn(TRUST, trustTier)) throw new Error('Trust tier must be T1, T2, T3, or T4');
  if (!['general', 'kev'].includes(sourceType)) throw new Error('Unsupported source type');
  const normalized = validateSourceUrl(url);
  const result = await new Promise((resolve, reject) => db.run(
    `INSERT INTO ai_intel_sources (url, exact_domain, source_type, trust_tier, state, created_at)
     VALUES (?, ?, ?, ?, 'new', ?)`,
    [normalized.url, normalized.exactDomain, sourceType, trustTier, new Date().toISOString()],
    function(error) { error ? reject(error) : resolve(this.lastID); }
  ));
  return result;
}

async function readIntelCache(db, now = Date.now()) {
  await initializeIntelligenceTables(db);
  const sources = await dbAll(db, `SELECT id, source_type, state, last_fetched_at, trust_tier
    FROM ai_intel_sources WHERE state NOT IN ('archived', 'new')`);
  for (const source of sources) {
    const staleAfterDays = source.source_type === 'kev' ? 7 : 30;
    const fetchedAt = Date.parse(source.last_fetched_at || '');
    if (Number.isFinite(fetchedAt) && now >= fetchedAt + staleAfterDays * 86400_000 && source.state === 'active') {
      await dbRun(db, "UPDATE ai_intel_sources SET state = 'stale' WHERE id = ? AND state = 'active'", [source.id]);
      await dbRun(db, "UPDATE ai_intel_records SET state = 'stale' WHERE source_id = ? AND state = 'active' AND quarantined = 0", [source.id]);
    }
  }
  return dbAll(db, `SELECT record.id, record.content, record.flagged_instruction, record.state,
      record.fetched_at, source.source_type, source.trust_tier, source.state AS source_state,
      CASE source.trust_tier WHEN 'T1' THEN 0.95 WHEN 'T2' THEN 0.8 WHEN 'T3' THEN 0.6 ELSE 0.25 END AS trust_score
    FROM ai_intel_records AS record JOIN ai_intel_sources AS source ON source.id = record.source_id
    WHERE record.quarantined = 0 AND record.state IN ('active', 'stale') AND source.state IN ('active', 'stale')
    ORDER BY record.id DESC LIMIT 100`);
}

async function validateIntelSource(db, id, options = {}) {
  await initializeIntelligenceTables(db);
  const source = await dbGet(db, 'SELECT * FROM ai_intel_sources WHERE id = ?', [id]);
  if (!source) throw new Error('Intelligence source not found');
  try {
    const fetched = await safeFetchSource(source, options);
    const content = fetched.content.slice(0, MAX_TEXT_LENGTH);
    const flaggedInstruction = INSTRUCTION_PATTERN.test(content);
    const reason = quarantineReason(content, source.trust_tier);
    const state = reason ? 'quarantined' : source.state === 'active' ? 'active' : 'validated';
    const contentHash = crypto.createHash('sha256').update(fetched.content).digest('hex');
    const fetchedAt = new Date(options.now ? options.now() : Date.now()).toISOString();
    const staleAfterDays = source.source_type === 'kev' ? 7 : 30;
    await dbRun(db, `INSERT INTO ai_intel_records
      (source_id, content_hash, content, flagged_instruction, quarantined, state, fetched_at, stale_after_days)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(source_id, content_hash) DO UPDATE SET content = excluded.content,
        flagged_instruction = excluded.flagged_instruction, quarantined = excluded.quarantined,
        state = excluded.state, fetched_at = excluded.fetched_at`,
    [id, contentHash, content, Number(flaggedInstruction), Number(Boolean(reason)), state, fetchedAt, staleAfterDays]);
    await dbRun(db, 'UPDATE ai_intel_sources SET state = ?, last_fetched_at = ?, last_error = NULL WHERE id = ?', [source.state === 'active' ? 'active' : 'validated', fetchedAt, id]);
    return { source_id: id, state: source.state === 'active' ? 'active' : 'validated', record_state: state, quarantined: Boolean(reason), quarantine_reason: reason, offline: false };
  } catch (error) {
    const cached = await readIntelCache(db, options.now ? options.now() : Date.now());
    await dbRun(db, 'UPDATE ai_intel_sources SET last_error = ? WHERE id = ?', [String(error.message).slice(0, 240), id]);
    return { source_id: id, state: source.state, offline: true, cached_records: cached, error: 'Source unavailable; cached intelligence retained' };
  }
}

async function activateIntelSource(db, id) {
  await initializeIntelligenceTables(db);
  const source = await dbGet(db, 'SELECT state, trust_tier FROM ai_intel_sources WHERE id = ?', [id]);
  if (!source || source.state !== 'validated' || source.trust_tier === 'T4') return false;
  await dbRun(db, "UPDATE ai_intel_sources SET state = 'active' WHERE id = ? AND state = 'validated'", [id]);
  await dbRun(db, "UPDATE ai_intel_records SET state = 'active' WHERE source_id = ? AND state = 'validated' AND quarantined = 0", [id]);
  return true;
}

async function archiveIntelSource(db, id) {
  await initializeIntelligenceTables(db);
  const changed = await dbRun(db, "UPDATE ai_intel_sources SET state = 'archived' WHERE id = ? AND state = 'stale'", [id]);
  if (changed) await dbRun(db, "UPDATE ai_intel_records SET state = 'archived' WHERE source_id = ? AND state = 'stale'", [id]);
  return Boolean(changed);
}

module.exports = {
  CONTENT_TYPES,
  INSTRUCTION_PATTERN,
  MAX_BYTES,
  MAX_REDIRECTS,
  MAX_TEXT_LENGTH,
  TIMEOUT_MS,
  TRUST,
  activateIntelSource,
  addIntelSource,
  archiveIntelSource,
  initializeIntelligenceTables,
  isPrivateAddress,
  quarantineReason,
  readIntelCache,
  resolvePublicAddresses,
  safeFetchSource,
  trustScore,
  validateIntelSource,
  validateSourceUrl,
};