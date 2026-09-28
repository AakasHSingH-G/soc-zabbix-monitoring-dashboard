'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3').verbose();
const {
  applyLearnedWeights,
  calibratePrediction,
  evaluatePendingPredictions,
  initializeAccuracyTables,
  readPredictionMetrics,
  recordPrediction,
} = require('../ai/accuracy');
const { PRIORS } = require('../ai/predictor');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));
}

test('outcome evaluator is idempotent and records no activity separately', async () => {
  const db = openMemoryDatabase();
  try {
    await initializeAccuracyTables(db);
    await db.exec(`CREATE TABLE ai_ip_timeline (
      id INTEGER PRIMARY KEY, ip TEXT, ts TEXT, action_class TEXT, port INTEGER,
      service TEXT, stage TEXT, weight INTEGER
    )`);
    const madeAt = new Date(Date.now() - 60 * 60_000).toISOString();
    const observedAt = new Date(Date.now() - 50 * 60_000).toISOString();
    const prediction = { engine: 'predictor-v1', playbook_version: 'seed-1', signature: 'S1', predictions: [
      { next_action: 'ssh_bruteforce', probability: 0.55, window: '15m' },
      { next_action: 'broader_port_scan', probability: 0.25, window: '15m' },
      { next_action: 'go_quiet_return_later', probability: 0.20, window: '15m' },
    ] };
    for (let index = 0; index < 10; index += 1) await recordPrediction(db, '198.51.100.10', prediction, madeAt);
    await recordPrediction(db, '198.51.100.20', prediction, madeAt);
    await run(db, 'INSERT INTO ai_ip_timeline (ip, ts, action_class, port, service, stage, weight) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['198.51.100.10', observedAt, 'auth_attempt', 22, 'ssh', 'credential_access', 1]);

    assert.equal(await evaluatePendingPredictions(db, { now: Date.now(), learningEnabled: true }), 11);
    assert.equal(await evaluatePendingPredictions(db, { now: Date.now(), learningEnabled: true }), 0);
    const hit = await get(db, "SELECT COUNT(*) AS total FROM ai_prediction_outcomes WHERE status='hit'");
    const noActivity = await get(db, "SELECT COUNT(*) AS total FROM ai_prediction_outcomes WHERE status='no_activity'");
    assert.equal(hit.total, 10);
    assert.equal(noActivity.total, 1);
    const capped = await get(db, "SELECT effective_count FROM ai_transition_stats WHERE signature='S1' AND next_action='ssh_bruteforce' AND ip='198.51.100.10'");
    assert.equal(capped.effective_count, 5);
    const metrics = await readPredictionMetrics(db);
    assert.equal(metrics.n, 10);
    assert.equal(metrics.status, 'not_enough_data');
    assert.equal(metrics.message, 'Not enough data yet');
    const missedPredictionBucket = await get(db, "SELECT sample_count, observed_sum FROM ai_calibration WHERE signature='S1' AND bucket=3");
    assert.equal(missedPredictionBucket.sample_count, 10);
    assert.equal(missedPredictionBucket.observed_sum, 0);
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});

test('outcome scoring respects each prediction horizon', async () => {
  const db = openMemoryDatabase();
  try {
    await initializeAccuracyTables(db);
    await db.exec(`CREATE TABLE ai_ip_timeline (
      id INTEGER PRIMARY KEY, ip TEXT, ts TEXT, action_class TEXT, port INTEGER,
      service TEXT, stage TEXT, weight INTEGER
    )`);
    const madeAt = new Date(Date.now() - 60 * 60_000).toISOString();
    const prediction = { signature: 'S1', predictions: [
      { next_action: 'ssh_bruteforce', probability: 0.60, window: '15m' },
      { next_action: 'broader_port_scan', probability: 0.25, window: '1h' },
      { next_action: 'go_quiet_return_later', probability: 0.15, window: '24h' },
    ] };
    await recordPrediction(db, '198.51.100.30', prediction, madeAt);
    await run(db, 'INSERT INTO ai_ip_timeline (ip, ts, action_class, port, service, stage, weight) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['198.51.100.30', new Date(Date.parse(madeAt) + 30 * 60_000).toISOString(), 'service_http_probe', 80, 'http', 'recon', 1]);

    assert.equal(await evaluatePendingPredictions(db, { now: Date.parse(madeAt) + 25 * 60 * 60_000 }), 1);
    const outcome = await get(db, 'SELECT hit_top1, hit_top3 FROM ai_prediction_outcomes WHERE prediction_id = 1');
    assert.equal(outcome.hit_top1, 0);
    assert.equal(outcome.hit_top3, 1);
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});

test('calibration uses smoothed observed frequency and learned weight caps at 0.7', async () => {
  const db = openMemoryDatabase();
  try {
    await initializeAccuracyTables(db);
    await run(db, `INSERT INTO ai_calibration (signature,bucket,sample_count,predicted_sum,observed_sum,updated_at)
      VALUES ('S1',6,20,12,8,'2026-09-28T00:00:00.000Z')`);
    const calibrated = await calibratePrediction(db, { signature: 'S1', predictions: [
      { next_action: 'ssh_bruteforce', probability: 0.6 },
      { next_action: 'broader_port_scan', probability: 0.25 },
      { next_action: 'go_quiet_return_later', probability: 0.20 },
    ] });
    assert.ok(Math.abs(calibrated.predictions[0].probability - 0.409) < 0.02);

    for (let index = 0; index < 150; index += 1) {
      await run(db, 'INSERT INTO ai_transition_stats (signature,next_action,ip,effective_count,updated_at) VALUES (?,?,?,?,?)',
        ['S1', 'ssh_bruteforce', `198.51.${Math.floor(index / 250)}.${index + 1}`, 5, '2026-09-28T00:00:00.000Z']);
    }
    const prediction = { signature: 'S1', predictions: PRIORS.S1.map(([next_action, probability, window]) => ({ next_action, probability, window })) };
    const learned = await applyLearnedWeights(db, '198.51.100.10', prediction, true);
    assert.equal(learned.learned_weight, 0.7);
    assert.ok(learned.predictions.reduce((sum, item) => sum + item.probability, 0) <= 1.000001);
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});