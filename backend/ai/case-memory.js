'use strict';

const crypto = require('node:crypto');

const WEIGHTS = Object.freeze({ stages: 0.25, ports: 0.20, rate_bucket: 0.15, login_bucket: 0.15, admin_bucket: 0.10, decoy_bucket: 0.10, ua_class: 0.05 });
const STAGES = new Set(['impact_exfil', 'lateral_movement', 'persistence', 'execution_post_access', 'initial_access_attempt', 'credential_access', 'enumeration', 'recon']);
const UA_CLASSES = new Set(['empty', 'masscan', 'nmap', 'zgrab', 'nuclei', 'sqlmap', 'curl', 'python', 'go-http', 'browser-like', 'unknown']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'unknown']);

function dbAll(db, sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row || null)));
}

function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

async function initializeCaseMemory(db) {
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_case_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip_hash TEXT NOT NULL,
    event_key TEXT NOT NULL,
    features_json TEXT NOT NULL,
    verdict TEXT NOT NULL,
    outcome TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(source_ip_hash, event_key)
  )`);
}

function bucketRate(rate) {
  if (!Number(rate)) return 'none';
  if (Number(rate) <= 1) return 'low';
  if (Number(rate) <= 10) return 'medium';
  return 'high';
}

function sanitizeFeatures(features = {}, analysis = {}) {
  const ports = [...new Set((Array.isArray(features.ports_ordered) ? features.ports_ordered : [])
    .map(Number).filter(port => Number.isInteger(port) && port > 0 && port <= 65535))].sort((a, b) => a - b).slice(0, 16);
  const stages = [...new Set([features.current_stage, analysis.prediction?.stage?.current]
    .filter(stage => STAGES.has(stage)))].sort();
  const usernames = Array.isArray(features.username_classes) ? features.username_classes : [];
  const success = features.success_on_decoy === true;
  const loginCount = Number(features.auth_attempts) || 0;
  return {
    stages,
    ports,
    rate_bucket: bucketRate(features.auth_attempts_per_minute),
    login_bucket: loginCount === 0 ? 'none' : loginCount < 5 ? 'few' : 'many',
    admin_bucket: usernames.some(value => ['admin', 'root'].includes(value)) ? 'present' : 'absent',
    decoy_bucket: success ? 'success' : Number(features.event_count) > 0 ? 'activity' : 'none',
    ua_class: (Array.isArray(features.ua_classes) ? features.ua_classes : []).find(value => UA_CLASSES.has(value)) || 'unknown',
    severity: SEVERITIES.has(String(analysis.severity || '').toLowerCase()) ? String(analysis.severity).toLowerCase() : 'unknown',
  };
}

function overlap(leftValues = [], rightValues = []) {
  const left = new Set(leftValues);
  const right = new Set(rightValues);
  if (!left.size && !right.size) return 1;
  let shared = 0;
  left.forEach(value => { if (right.has(value)) shared += 1; });
  return shared / (left.size + right.size - shared);
}

function scoreCase(query, candidate) {
  let score = WEIGHTS.stages * overlap(query.stages, candidate.stages)
    + WEIGHTS.ports * overlap(query.ports, candidate.ports);
  for (const field of ['rate_bucket', 'login_bucket', 'admin_bucket', 'decoy_bucket', 'ua_class']) {
    score += WEIGHTS[field] * Number(query[field] === candidate[field]);
  }
  return score;
}

async function saveFeedbackCase(db, analysisId, verdict, createdAt = new Date().toISOString()) {
  await initializeCaseMemory(db);
  const row = await dbGet(db, 'SELECT attacker_ip, result_json FROM ai_analyses WHERE id = ?', [analysisId]);
  if (!row) return false;
  let analysis;
  try { analysis = JSON.parse(row.result_json); } catch { return false; }
  const features = sanitizeFeatures(analysis.prediction?.features, analysis);
  const outcome = features.decoy_bucket === 'success' ? 'confirmed_success'
    : features.login_bucket !== 'none' || features.stages.length ? 'attempt_observed' : 'no_confirmation';
  const sourceIpHash = crypto.createHash('sha256').update(String(row.attacker_ip)).digest('hex');
  const eventKey = crypto.createHash('sha256').update(JSON.stringify({ features, verdict, outcome })).digest('hex');
  await dbRun(db, `INSERT OR IGNORE INTO ai_case_memory
    (source_ip_hash, event_key, features_json, verdict, outcome, approved, created_at)
    VALUES (?, ?, ?, ?, ?, 0, ?)`, [sourceIpHash, eventKey, JSON.stringify(features), verdict, outcome, createdAt]);
  return true;
}

async function findSimilarCases(db, features, { minimumScore = 0.4, limit = 3 } = {}) {
  await initializeCaseMemory(db);
  const query = sanitizeFeatures(features);
  const rows = await dbAll(db, `SELECT id, source_ip_hash, features_json, verdict, outcome, created_at
    FROM ai_case_memory WHERE approved = 1 ORDER BY id DESC LIMIT 1000`);
  const ipCounts = new Map();
  rows.forEach(row => ipCounts.set(row.source_ip_hash, (ipCounts.get(row.source_ip_hash) || 0) + 1));
  const matches = rows.map(row => {
    let candidate;
    try { candidate = JSON.parse(row.features_json); } catch { return null; }
    const score = scoreCase(query, candidate);
    return score < minimumScore ? null : {
      id: row.id,
      score: Number(score.toFixed(3)),
      source_ip_hash: row.source_ip_hash,
      influence_cap: Math.min(Math.log2(1 + ipCounts.get(row.source_ip_hash)), 5),
      features: candidate,
      verdict: row.verdict,
      outcome: row.outcome,
      created_at: row.created_at,
    };
  }).filter(Boolean).sort((left, right) => right.score - left.score || right.id - left.id).slice(0, Math.max(0, Math.min(3, limit)));
  const selectedPerIp = new Map();
  matches.forEach(match => selectedPerIp.set(match.source_ip_hash, (selectedPerIp.get(match.source_ip_hash) || 0) + 1));
  return matches.map(({ source_ip_hash: sourceIpHash, ...match }) => ({
    ...match,
    influence_weight: Number((match.influence_cap / selectedPerIp.get(sourceIpHash)).toFixed(3)),
  }));
}

async function readPendingCases(db) {
  await initializeCaseMemory(db);
  const rows = await dbAll(db, `SELECT id, features_json, verdict, outcome, created_at
    FROM ai_case_memory WHERE approved = 0 ORDER BY id DESC LIMIT 100`);
  return rows.map(row => ({ ...row, features: JSON.parse(row.features_json) }));
}

async function approveCase(db, id) {
  await initializeCaseMemory(db);
  return dbRun(db, 'UPDATE ai_case_memory SET approved = 1 WHERE id = ? AND approved = 0', [id]);
}

module.exports = { WEIGHTS, approveCase, findSimilarCases, initializeCaseMemory, readPendingCases, saveFeedbackCase, sanitizeFeatures, scoreCase };