'use strict';

const { PRIORS } = require('./predictor');

const WINDOW_MS = { '15m': 15 * 60_000, '1h': 60 * 60_000, '24h': 24 * 60 * 60_000, '7d': 7 * 24 * 60 * 60_000 };
const IP_TRANSITION_CAP = 5;
const LEARNED_WEIGHT_MAX = 0.7;
const FEEDBACK_VERDICTS = new Set(['correct', 'wrong', 'partial', 'false_positive']);

function dbAll(db, sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row || null)));
}

function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

async function initializeAccuracyTables(db) {
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    made_at TEXT NOT NULL,
    signature TEXT NOT NULL,
    predictions_json TEXT NOT NULL,
    engine_ver TEXT NOT NULL,
    playbook_ver TEXT NOT NULL
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_prediction_outcomes (
    prediction_id INTEGER PRIMARY KEY,
    evaluated_at TEXT NOT NULL,
    hit_top1 INTEGER,
    hit_top3 INTEGER,
    matched_action TEXT,
    window_elapsed TEXT NOT NULL,
    observed_actions_json TEXT NOT NULL,
    status TEXT NOT NULL
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_calibration (
    signature TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    predicted_sum REAL NOT NULL DEFAULT 0,
    observed_sum REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(signature, bucket)
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_transition_stats (
    signature TEXT NOT NULL,
    next_action TEXT NOT NULL,
    ip TEXT NOT NULL,
    effective_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(signature, next_action, ip)
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_analysis_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK(verdict IN ('correct', 'wrong', 'partial', 'false_positive')),
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(analysis_id, username)
  )`);
}

async function recordAnalystFeedback(db, { analysisId, username, verdict, note = '', createdAt = new Date().toISOString() }) {
  if (!Number.isInteger(analysisId) || analysisId < 1) throw new Error('A valid analysis ID is required');
  if (!FEEDBACK_VERDICTS.has(verdict)) throw new Error('Unsupported feedback verdict');
  if (typeof note !== 'string' || note.length > 300) throw new Error('Feedback note must be 300 characters or fewer');
  await dbRun(db, `INSERT INTO ai_analysis_feedback (analysis_id, username, verdict, note, created_at)
    VALUES (?, ?, ?, ?, ?)`, [analysisId, username, verdict, note.trim(), createdAt]);
  return readFeedbackMetrics(db);
}

async function readFeedbackMetrics(db) {
  await initializeAccuracyTables(db);
  const rows = await dbAll(db, 'SELECT verdict, COUNT(*) AS count FROM ai_analysis_feedback GROUP BY verdict');
  const counts = Object.fromEntries(rows.map(row => [row.verdict, Number(row.count)]));
  const correct = counts.correct || 0;
  const wrong = counts.wrong || 0;
  const meaningful = correct + wrong;
  const available = meaningful >= 30;
  return {
    meaningful_feedback: meaningful,
    status: available ? 'available' : 'not_enough_data',
    message: available ? null : 'Not enough data yet',
    accuracy: available ? correct / meaningful : null,
    counts: {
      correct,
      wrong,
      partial: counts.partial || 0,
      false_positive: counts.false_positive || 0,
    },
  };
}

function predictionHorizon(predictions = []) {
  return predictions.reduce((maximum, prediction) => Math.max(maximum, WINDOW_MS[prediction.window] || WINDOW_MS['24h']), 0);
}

function actionMatches(prediction, timelineRow) {
  const action = String(prediction.next_action || '');
  const service = String(timelineRow.service || '');
  const actionClass = String(timelineRow.action_class || '');
  if (/ssh|bruteforce|userlist|common_creds/.test(action)) return service === 'ssh' && actionClass === 'auth_attempt';
  if (/rdp/.test(action)) return service === 'rdp' && actionClass === 'auth_attempt';
  if (/iot_default_cred|botnet_payload/.test(action)) return service === 'telnet' && ['auth_attempt', 'exploit_probe'].includes(actionClass);
  if (/zabbix/.test(action)) return service.startsWith('zabbix-') || actionClass === 'web_zabbix-web';
  if (/exploit|cve|command_execution|second_stage|download|dropper/.test(action)) return ['known_cve_probe', 'exploit_probe'].includes(actionClass);
  if (/sensitive|credential_harvest|source_disclosure|cloud_key/.test(action)) return actionClass === 'web_sensitive-file';
  if (/web_login|plugin|sqli|xss/.test(action)) return ['web_login', 'web_wp-admin', 'web_admin-panel', 'web_sqli-like'].includes(actionClass);
  if (/database|db_|data_dump|unauthenticated/.test(action)) return service === 'db' || service === 'redis';
  if (/scan|service_followup|port/.test(action)) return actionClass.startsWith('service_') || actionClass.startsWith('web_');
  if (/sibling|campaign/.test(action)) return false;
  return false;
}

function chooseWindowMatch(prediction, timelineRows, madeAt) {
  const endAt = madeAt + (WINDOW_MS[prediction.window] || WINDOW_MS['24h']);
  return timelineRows.find(row => Date.parse(row.ts) <= endAt && actionMatches(prediction, row)) || null;
}

async function recordPrediction(db, ip, prediction, madeAt = new Date().toISOString()) {
  const result = await new Promise((resolve, reject) => db.run(
    `INSERT INTO ai_predictions (ip, made_at, signature, predictions_json, engine_ver, playbook_ver)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [ip, madeAt, prediction.signature || 'insufficient_pattern', JSON.stringify(prediction.predictions || []), prediction.engine || 'predictor-v1', prediction.playbook_version || 'seed-1'],
    function(error) { error ? reject(error) : resolve(this.lastID); }
  ));
  return result;
}

async function updateLearning(db, predictionRow, predictions, matchedAction, timelineRows, madeAt, enabled) {
  if (!enabled) return;
  const now = new Date().toISOString();
  if (matchedAction) {
    const allowed = new Set((PRIORS[predictionRow.signature] || []).map(prior => prior[0]));
    if (allowed.has(matchedAction)) {
      await dbRun(db, `INSERT INTO ai_transition_stats (signature, next_action, ip, effective_count, updated_at)
        VALUES (?, ?, ?, 1, ?)
        ON CONFLICT(signature, next_action, ip) DO UPDATE SET effective_count = MIN(?, effective_count + 1), updated_at = excluded.updated_at`,
      [predictionRow.signature, matchedAction, predictionRow.ip, now, IP_TRANSITION_CAP]);
    }
  }
  for (const prediction of predictions) {
    const bucket = Math.max(0, Math.min(10, Math.round(Number(prediction.probability || 0) * 10)));
    const observed = Number(Boolean(chooseWindowMatch(prediction, timelineRows, madeAt)));
    for (const calibrationSignature of [predictionRow.signature, 'global']) {
      await dbRun(db, `INSERT INTO ai_calibration (signature, bucket, sample_count, predicted_sum, observed_sum, updated_at)
        VALUES (?, ?, 1, ?, ?, ?)
        ON CONFLICT(signature, bucket) DO UPDATE SET sample_count = sample_count + 1,
          predicted_sum = predicted_sum + excluded.predicted_sum,
          observed_sum = observed_sum + excluded.observed_sum, updated_at = excluded.updated_at`,
      [calibrationSignature, bucket, Number(prediction.probability || 0), observed, now]);
    }
  }
}

async function evaluatePendingPredictions(db, { now = Date.now(), learningEnabled = false } = {}) {
  await initializeAccuracyTables(db);
  const pending = await dbAll(db, `SELECT prediction.* FROM ai_predictions AS prediction
    LEFT JOIN ai_prediction_outcomes AS outcome ON outcome.prediction_id = prediction.id
    WHERE outcome.prediction_id IS NULL ORDER BY prediction.id ASC LIMIT 100`);
  let evaluated = 0;
  for (const row of pending) {
    let predictions;
    try { predictions = JSON.parse(row.predictions_json); } catch { predictions = []; }
    const madeAt = Date.parse(row.made_at);
    const horizon = predictionHorizon(predictions);
    if (!Number.isFinite(madeAt) || now < madeAt + horizon) continue;
    const rows = await dbAll(db, `SELECT action_class, port, service, stage, weight, ts
      FROM ai_ip_timeline WHERE ip = ? AND datetime(ts) > datetime(?) AND datetime(ts) <= datetime(?)
      ORDER BY ts ASC LIMIT 500`, [row.ip, row.made_at, new Date(madeAt + horizon).toISOString()]);
    const match = predictions.map(prediction => ({ prediction, row: chooseWindowMatch(prediction, rows, madeAt) }))
      .find(candidate => candidate.row);
    const status = rows.length ? match ? 'hit' : 'miss' : 'no_activity';
    const hitTop1 = rows.length ? Number(Boolean(predictions[0] && chooseWindowMatch(predictions[0], rows, madeAt))) : null;
    const hitTop3 = rows.length ? Number(Boolean(match)) : null;
    const outcome = {
      prediction_id: row.id,
      evaluated_at: new Date(now).toISOString(),
      hit_top1: hitTop1,
      hit_top3: hitTop3,
      matched_action: match?.action || (rows.length ? rows[0].action_class : 'no_activity'),
      window_elapsed: Object.keys(WINDOW_MS).find(window => WINDOW_MS[window] === horizon) || '24h',
      observed_actions_json: JSON.stringify(rows.map(item => ({ action_class: item.action_class, service: item.service, port: item.port, stage: item.stage }))),
      status,
    };
    await dbRun(db, `INSERT OR IGNORE INTO ai_prediction_outcomes
      (prediction_id, evaluated_at, hit_top1, hit_top3, matched_action, window_elapsed, observed_actions_json, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [outcome.prediction_id, outcome.evaluated_at, outcome.hit_top1, outcome.hit_top3, outcome.matched_action, outcome.window_elapsed, outcome.observed_actions_json, outcome.status]);
    if (rows.length) await updateLearning(db, row, predictions, match?.prediction.next_action || null, rows, madeAt, learningEnabled);
    evaluated += 1;
  }
  return evaluated;
}

async function applyLearnedWeights(db, ip, prediction, enabled) {
  if (!enabled || !prediction?.predictions?.length) return prediction;
  const rows = await dbAll(db, 'SELECT next_action, SUM(effective_count) AS count FROM ai_transition_stats WHERE signature = ? GROUP BY next_action', [prediction.signature]);
  const nEffective = rows.reduce((sum, row) => sum + Number(row.count || 0), 0);
  const learnedWeight = Math.min(nEffective / (nEffective + 30), LEARNED_WEIGHT_MAX);
  if (!nEffective || !learnedWeight) return prediction;
  const learnedTotal = rows.reduce((sum, row) => sum + Number(row.count), 0);
  const priors = PRIORS[prediction.signature] || [];
  const priorMeta = new Map(prediction.predictions.map(item => [item.next_action, item]));
  const actions = new Set([...priors.map(item => item[0]), ...rows.map(row => row.next_action)]);
  const blended = [...actions].map(action => {
    const prior = priors.find(item => item[0] === action);
    const meta = priorMeta.get(action) || prediction.predictions[0];
    const priorProbability = prior ? Number(prior[1]) : 0;
    const learnedProbability = Number(rows.find(row => row.next_action === action)?.count || 0) / learnedTotal;
    return { ...meta, next_action: action, probability: (1 - learnedWeight) * priorProbability + learnedWeight * learnedProbability };
  }).sort((a, b) => b.probability - a.probability).slice(0, 3);
  const sum = blended.reduce((total, item) => total + item.probability, 0);
  if (sum > 1) blended.forEach(item => { item.probability /= sum; });
  return { ...prediction, predictions: blended, learned_weight: learnedWeight };
}

async function calibratePrediction(db, prediction) {
  if (!prediction?.predictions?.length) return prediction;
  const calibrated = [];
  for (const item of prediction.predictions) {
    const bucket = Math.max(0, Math.min(10, Math.round(Number(item.probability || 0) * 10)));
    let row = await dbGet(db, 'SELECT sample_count, observed_sum FROM ai_calibration WHERE signature = ? AND bucket = ?', [prediction.signature, bucket]);
    if (!row || row.sample_count < 20) row = await dbGet(db, 'SELECT SUM(sample_count) AS sample_count, SUM(observed_sum) AS observed_sum FROM ai_calibration WHERE signature = ? AND bucket = ?', ['global', bucket]);
    const useCalibration = row && Number(row.sample_count) >= 20;
    const probability = useCalibration ? (Number(row.observed_sum) + 1) / (Number(row.sample_count) + 2) : item.probability;
    calibrated.push({ ...item, probability });
  }
  const sum = calibrated.reduce((total, item) => total + item.probability, 0);
  if (sum > 1) calibrated.forEach(item => { item.probability /= sum; });
  return { ...prediction, predictions: calibrated, confidence: { ...prediction.confidence, prediction_calibrated: calibrated.some((item, index) => item.probability !== prediction.predictions[index].probability) } };
}

async function readPredictionMetrics(db) {
  await initializeAccuracyTables(db);
  const rows = await dbAll(db, `SELECT prediction.*, outcome.hit_top1, outcome.hit_top3, outcome.status, outcome.observed_actions_json
    FROM ai_predictions AS prediction JOIN ai_prediction_outcomes AS outcome ON outcome.prediction_id = prediction.id
    ORDER BY prediction.id DESC LIMIT 10000`);
  const active = rows.filter(row => row.status !== 'no_activity');
  const n = active.length;
  if (!n) return { n, status: 'not_enough_data', message: 'Not enough data yet' };
  let brier = 0;
  let confidenceTotal = 0;
  let baselineRepeatHits = 0;
  let baselineCommonHits = 0;
  for (const row of active) {
    const predictions = JSON.parse(row.predictions_json || '[]');
    const probability = Number(predictions[0]?.probability || 0);
    const hit = Number(row.hit_top1 || 0);
    brier += (probability - hit) ** 2;
    confidenceTotal += probability;
    const observed = JSON.parse(row.observed_actions_json || '[]');
    const firstObserved = observed[0];
    const lastBefore = await dbGet(db, 'SELECT action_class, service FROM ai_ip_timeline WHERE ip = ? AND datetime(ts) < datetime(?) ORDER BY ts DESC LIMIT 1', [row.ip, row.made_at]);
    if (lastBefore && firstObserved && lastBefore.action_class === firstObserved.action_class) baselineRepeatHits += 1;
    const common = await dbGet(db, `SELECT action_class, service FROM ai_ip_timeline WHERE datetime(ts) < datetime(?) GROUP BY action_class, service ORDER BY COUNT(*) DESC LIMIT 1`, [row.made_at]);
    if (common && firstObserved && common.action_class === firstObserved.action_class) baselineCommonHits += 1;
  }
  const top1 = active.filter(row => Number(row.hit_top1) === 1).length / n;
  const top3 = active.filter(row => Number(row.hit_top3) === 1).length / n;
  const baselineA = baselineRepeatHits / n;
  const baselineB = baselineCommonHits / n;
  return {
    n,
    status: n >= 30 && top3 > baselineA && top3 > baselineB ? 'reliable' : n >= 30 ? 'experimental' : 'not_enough_data',
    message: n < 30 ? 'Not enough data yet' : null,
    top1_hit_rate: top1,
    top3_hit_rate: top3,
    brier_score: brier / n,
    calibration_gap: Math.abs(confidenceTotal / n - top1),
    baseline_repeat_last: baselineA,
    baseline_most_common: baselineB,
  };
}

module.exports = {
  IP_TRANSITION_CAP,
  LEARNED_WEIGHT_MAX,
  FEEDBACK_VERDICTS,
  WINDOW_MS,
  applyLearnedWeights,
  calibratePrediction,
  evaluatePendingPredictions,
  initializeAccuracyTables,
  predictionHorizon,
  readFeedbackMetrics,
  readPredictionMetrics,
  recordAnalystFeedback,
  recordPrediction,
};
