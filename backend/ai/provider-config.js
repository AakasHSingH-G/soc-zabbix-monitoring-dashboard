'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

function normalizeBaseUrl(value) {
  if (!value) return '';
  let url;
  try {
    url = new URL(String(value).trim());
  } catch {
    throw new Error('Provider URL must be a valid HTTP or HTTPS URL');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error('Provider URL must use HTTP or HTTPS without credentials, query, or fragment');
  }
  return url.toString().replace(/\/+$/, '');
}

function createProviderConfigStore(db, { keyPath = path.join(__dirname, '..', '.env.ai-provider-key') } = {}) {
  function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row || null)));
  }

  function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => db.run(sql, params, error => error ? reject(error) : resolve()));
  }

  async function loadEncryptionKey(create = false) {
    try {
      const key = await fs.readFile(keyPath);
      if (key.length !== 32) throw new Error('Provider encryption key file is invalid');
      await fs.chmod(keyPath, 0o600);
      return key;
    } catch (error) {
      if (error.code !== 'ENOENT' || !create) throw error;
    }

    const key = crypto.randomBytes(32);
    try {
      await fs.writeFile(keyPath, key, { flag: 'wx', mode: 0o600 });
      return key;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      return loadEncryptionKey(false);
    }
  }

  function encrypt(value, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return JSON.stringify({ iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') });
  }

  async function decrypt(value) {
    if (!value) return '';
    const record = JSON.parse(value);
    const decipher = crypto.createDecipheriv('aes-256-gcm', await loadEncryptionKey(), Buffer.from(record.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, 'base64')), decipher.final()]).toString('utf8');
  }

  async function read() {
    const row = await dbGet('SELECT mode, base_url, model, api_key_encrypted FROM ai_provider_config WHERE id = 1');
    const apiKey = row?.api_key_encrypted ? await decrypt(row.api_key_encrypted) : '';
    return {
      mode: row?.mode || 'local',
      baseUrl: row?.base_url || '',
      model: row?.model || '',
      apiKey,
      apiKeyConfigured: Boolean(apiKey),
    };
  }

  async function save(input = {}) {
    const mode = String(input.mode || 'local');
    if (!['local', 'remote', 'review'].includes(mode)) throw new Error('Mode must be local, remote, or review');
    const baseUrl = normalizeBaseUrl(input.baseUrl);
    const model = String(input.model || '').trim();
    if (model.length > 160) throw new Error('Model name must be 160 characters or fewer');
    if (typeof input.apiKey !== 'undefined' && typeof input.apiKey !== 'string') throw new Error('API key must be text');
    if (input.apiKey?.length > 2048) throw new Error('API key is too long');

    const previous = await read();
    const apiKey = input.clearApiKey === true ? '' : (input.apiKey?.trim() || previous.apiKey);
    if (apiKey && (!baseUrl || !model)) throw new Error('Provider URL and model are required when an API key is configured');
    const encryptedKey = apiKey ? encrypt(apiKey, await loadEncryptionKey(true)) : null;
    await dbRun(`INSERT INTO ai_provider_config (id, mode, base_url, model, api_key_encrypted, updated_at)
      VALUES (1, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET mode = excluded.mode, base_url = excluded.base_url,
        model = excluded.model, api_key_encrypted = excluded.api_key_encrypted, updated_at = excluded.updated_at`,
    [mode, baseUrl, model, encryptedKey, new Date().toISOString()]);
    return { mode, baseUrl, model, apiKeyConfigured: Boolean(apiKey) };
  }

  async function initialize() {
    await dbRun(`CREATE TABLE IF NOT EXISTS ai_provider_config (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      mode TEXT NOT NULL DEFAULT 'local' CHECK(mode IN ('local', 'remote', 'review')),
      base_url TEXT NOT NULL DEFAULT '',
      model TEXT NOT NULL DEFAULT '',
      api_key_encrypted TEXT,
      updated_at TEXT NOT NULL
    )`);
  }

  return { initialize, read, save };
}

module.exports = { createProviderConfigStore, normalizeBaseUrl };