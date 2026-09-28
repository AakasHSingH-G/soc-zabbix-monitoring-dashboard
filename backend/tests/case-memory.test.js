'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3').verbose();
const {
  approveCase,
  findSimilarCases,
  initializeCaseMemory,
  readPendingCases,
  saveFeedbackCase,
  sanitizeFeatures,
} = require('../ai/case-memory');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));
}

const sourceFeatures = {
  ports_ordered: [22, 80, 22, '443; DROP TABLE users'],
  current_stage: 'credential_access',
  auth_attempts: 3,
  auth_attempts_per_minute: 2,
  username_classes: ['admin', 'raw-attacker-input'],
  success_on_decoy: false,
  event_count: 4,
  ua_classes: ['python', 'Mozilla/5.0 raw string'],
};

test('case memory stores sanitized deduplicated cases and retrieves only approved top matches', async () => {
  const db = openMemoryDatabase();
  try {
    await db.exec(`CREATE TABLE ai_analyses (
      id INTEGER PRIMARY KEY, attacker_ip TEXT NOT NULL, result_json TEXT NOT NULL
    )`);
    await initializeCaseMemory(db);
    await run(db, 'INSERT INTO ai_analyses VALUES (?, ?, ?)', [1, '198.51.100.40', JSON.stringify({
      severity: 'HIGH', prediction: { features: sourceFeatures, stage: { current: 'credential_access' } },
    })]);
    assert.equal(sanitizeFeatures(sourceFeatures).ports.length, 2);
    assert.equal(await saveFeedbackCase(db, 1, 'correct'), true);
    assert.equal(await saveFeedbackCase(db, 1, 'correct'), true);
    assert.equal((await get(db, 'SELECT COUNT(*) AS count FROM ai_case_memory')).count, 1);
    assert.equal((await readPendingCases(db)).length, 1);
    assert.deepEqual(await findSimilarCases(db, sourceFeatures), []);
    assert.equal(await approveCase(db, 1), 1);

    const matches = await findSimilarCases(db, sourceFeatures);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].score, 1);
    assert.equal(matches[0].features.severity, 'high');
    assert.deepEqual(Object.keys(matches[0].features).sort(), [
      'admin_bucket', 'decoy_bucket', 'login_bucket', 'ports', 'rate_bucket', 'severity', 'stages', 'ua_class',
    ]);
    const mismatch = {
      stages: ['recon'], ports: [443], rate_bucket: 'high', login_bucket: 'many',
      admin_bucket: 'absent', decoy_bucket: 'success', ua_class: 'masscan', severity: 'low',
    };
    assert.deepEqual(await findSimilarCases(db, mismatch), []);

    for (let index = 0; index < 40; index += 1) {
      await run(db, `INSERT INTO ai_case_memory
        (source_ip_hash, event_key, features_json, verdict, outcome, approved, created_at)
        VALUES ('same-source', ?, ?, 'correct', 'attempt_observed', 1, '2026-09-28T00:00:00.000Z')`,
      [`duplicate-${index}`, JSON.stringify(matches[0].features)]);
    }
    const cappedMatches = await findSimilarCases(db, sourceFeatures);
    assert.equal(cappedMatches.length, 3);
    assert.equal(cappedMatches[0].influence_cap, 5);
    assert.ok(cappedMatches.reduce((sum, match) => sum + match.influence_weight, 0) <= 5.001);
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});