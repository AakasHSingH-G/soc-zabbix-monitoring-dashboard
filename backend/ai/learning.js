'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { initializeAccuracyTables, readFeedbackMetrics, readPredictionMetrics } = require('./accuracy');
const { initializeCaseMemory } = require('./case-memory');

function dbAll(db, sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row || null)));
}

function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

async function initializeLearningTables(db) {
  await initializeAccuracyTables(db);
  await initializeCaseMemory(db);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lesson_key TEXT NOT NULL,
    version INTEGER NOT NULL,
    lesson_text TEXT NOT NULL CHECK(length(lesson_text) <= 1500),
    source_count INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'active', 'rejected', 'retired')),
    created_at TEXT NOT NULL,
    reviewed_by TEXT,
    reviewed_at TEXT,
    UNIQUE(lesson_key, version)
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_tuning_suggestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    suggestion_key TEXT NOT NULL,
    version INTEGER NOT NULL,
    suggestion_text TEXT NOT NULL CHECK(length(suggestion_text) <= 1500),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'retired')),
    created_at TEXT NOT NULL,
    reviewed_by TEXT,
    reviewed_at TEXT,
    UNIQUE(suggestion_key, version)
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_learning_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    period TEXT NOT NULL CHECK(period IN ('daily', 'weekly')),
    report_date TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(period, report_date)
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_learning_jobs (
    job_key TEXT PRIMARY KEY,
    completed_at TEXT NOT NULL
  )`);
}

async function runScheduledLearning(db, now = new Date()) {
  await initializeLearningTables(db);
  if (now.getHours() !== 2) return { ran: false, reason: 'outside_schedule' };
  const date = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const dailyKey = `nightly:${date}`;
  if (!await dbGet(db, 'SELECT job_key FROM ai_learning_jobs WHERE job_key = ?', [dailyKey])) {
    const lessons = await generateNightlyLessons(db, { now });
    const report = await generateReport(db, 'daily', { now });
    await dbRun(db, 'INSERT INTO ai_learning_jobs (job_key, completed_at) VALUES (?, ?)', [dailyKey, now.toISOString()]);
    const result = { ran: true, lessons, daily_report: report };
    if (now.getDay() === 1) {
      const weeklyKey = `weekly:${date}`;
      if (!await dbGet(db, 'SELECT job_key FROM ai_learning_jobs WHERE job_key = ?', [weeklyKey])) {
        result.tuning = await generateTuningSuggestion(db, { now });
        result.weekly_report = await generateReport(db, 'weekly', { now });
        await dbRun(db, 'INSERT INTO ai_learning_jobs (job_key, completed_at) VALUES (?, ?)', [weeklyKey, now.toISOString()]);
      }
    }
    return result;
  }
  return { ran: false, reason: 'already_completed' };
}

async function generateNightlyLessons(db, { now = new Date() } = {}) {
  await initializeLearningTables(db);
  const aggregate = await dbGet(db, `SELECT COUNT(DISTINCT feedback.id) AS feedback_count,
      COUNT(DISTINCT analysis.attacker_ip) AS ip_count,
      SUM(CASE WHEN feedback.verdict = 'correct' THEN 1 ELSE 0 END) AS correct_count,
      SUM(CASE WHEN feedback.verdict = 'wrong' THEN 1 ELSE 0 END) AS wrong_count
    FROM ai_analysis_feedback AS feedback JOIN ai_analyses AS analysis ON analysis.id = feedback.analysis_id`);
  const sourceCount = Math.max(Number(aggregate?.feedback_count || 0), Number(aggregate?.ip_count || 0));
  if (sourceCount < 5) return { created: false, reason: 'not_enough_sources', source_count: sourceCount };
  const versionRow = await dbGet(db, "SELECT COALESCE(MAX(version), 0) AS version FROM ai_lessons WHERE lesson_key = 'feedback-overview'");
  const version = Number(versionRow?.version || 0) + 1;
  const correct = Number(aggregate.correct_count || 0);
  const wrong = Number(aggregate.wrong_count || 0);
  const text = `Analyst feedback from ${sourceCount} distinct feedback records or attacker IPs: ${correct} marked correct and ${wrong} marked wrong. Treat this as a review signal only; do not change prediction thresholds automatically.`.slice(0, 1500);
  await dbRun(db, `INSERT INTO ai_lessons (lesson_key, version, lesson_text, source_count, status, created_at)
    VALUES ('feedback-overview', ?, ?, ?, 'pending', ?)`, [version, text, sourceCount, now.toISOString()]);
  return { created: true, id: (await dbGet(db, 'SELECT last_insert_rowid() AS id')).id, version, source_count: sourceCount, status: 'pending' };
}

async function reviewLesson(db, id, decision, username, now = new Date().toISOString()) {
  await initializeLearningTables(db);
  if (decision === 'approve') {
    const count = await dbGet(db, "SELECT COUNT(*) AS count FROM ai_lessons WHERE status = 'active'");
    if (Number(count?.count || 0) >= 20) throw new Error('Active lesson limit of 20 reached');
    return dbRun(db, "UPDATE ai_lessons SET status = 'active', reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'", [username, now, id]);
  }
  if (decision === 'reject') return dbRun(db, "UPDATE ai_lessons SET status = 'rejected', reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'", [username, now, id]);
  if (decision === 'retire') return dbRun(db, "UPDATE ai_lessons SET status = 'retired', reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'active'", [username, now, id]);
  throw new Error('Unsupported lesson decision');
}

async function generateTuningSuggestion(db, { now = new Date() } = {}) {
  await initializeLearningTables(db);
  const feedback = await readFeedbackMetrics(db);
  const metrics = await readPredictionMetrics(db);
  const suggestionKey = 'weekly-accuracy-review';
  const versionRow = await dbGet(db, 'SELECT COALESCE(MAX(version), 0) AS version FROM ai_tuning_suggestions WHERE suggestion_key = ?', [suggestionKey]);
  const version = Number(versionRow?.version || 0) + 1;
  const text = feedback.meaningful_feedback < 30
    ? `Weekly review: ${feedback.meaningful_feedback} meaningful feedback votes are available. Keep current thresholds unchanged until at least 30 votes; no settings were modified.`
    : `Weekly review: analyst feedback accuracy is ${Math.round(feedback.accuracy * 100)}% across ${feedback.meaningful_feedback} meaningful votes; prediction sample count is ${metrics.n}. Review thresholds manually; no settings were modified.`;
  await dbRun(db, `INSERT INTO ai_tuning_suggestions
    (suggestion_key, version, suggestion_text, status, created_at) VALUES (?, ?, ?, 'pending', ?)`,
  [suggestionKey, version, text.slice(0, 1500), now.toISOString()]);
  return { id: (await dbGet(db, 'SELECT last_insert_rowid() AS id')).id, version, status: 'pending', suggestion_text: text };
}

async function reviewTuningSuggestion(db, id, decision, username, now = new Date().toISOString()) {
  await initializeLearningTables(db);
  if (!['approved', 'rejected', 'retired'].includes(decision)) throw new Error('Unsupported tuning decision');
  return dbRun(db, 'UPDATE ai_tuning_suggestions SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = \'pending\'', [decision, username, now, id]);
}

async function listLearningItems(db) {
  await initializeLearningTables(db);
  const [lessons, suggestions] = await Promise.all([
    dbAll(db, 'SELECT id, lesson_key, version, lesson_text, source_count, status, created_at, reviewed_by, reviewed_at FROM ai_lessons ORDER BY id DESC LIMIT 100'),
    dbAll(db, 'SELECT id, suggestion_key, version, suggestion_text, status, created_at, reviewed_by, reviewed_at FROM ai_tuning_suggestions ORDER BY id DESC LIMIT 100'),
  ]);
  return { lessons, suggestions };
}

async function generateReport(db, period, { now = new Date() } = {}) {
  await initializeLearningTables(db);
  if (!['daily', 'weekly'].includes(period)) throw new Error('Report period must be daily or weekly');
  const days = period === 'daily' ? 1 : 7;
  const start = new Date(now.getTime() - days * 86400_000).toISOString();
  const [alerts, incidents, blocks, captures, feedback, predictions] = await Promise.all([
    dbGet(db, 'SELECT COUNT(*) AS count, COUNT(DISTINCT src_ip) AS distinct_ips FROM security_events WHERE datetime(created_at) >= datetime(?)', [start]),
    dbGet(db, 'SELECT COUNT(*) AS count FROM incidents WHERE datetime(created_at) >= datetime(?)', [start]),
    dbGet(db, 'SELECT COUNT(*) AS count FROM blocks WHERE datetime(created_at) >= datetime(?)', [start]),
    dbGet(db, 'SELECT COUNT(*) AS count FROM honey_captures WHERE datetime(created_at) >= datetime(?)', [start]),
    dbGet(db, 'SELECT COUNT(*) AS count FROM ai_analysis_feedback WHERE datetime(created_at) >= datetime(?)', [start]),
    dbGet(db, 'SELECT COUNT(*) AS count FROM ai_predictions WHERE datetime(made_at) >= datetime(?)', [start]),
  ]);
  const facts = {
    period,
    start,
    end: now.toISOString(),
    alerts: Number(alerts?.count || 0),
    distinct_source_ips: Number(alerts?.distinct_ips || 0),
    incidents: Number(incidents?.count || 0),
    blocks: Number(blocks?.count || 0),
    honeyport_captures: Number(captures?.count || 0),
    analyst_feedback_records: Number(feedback?.count || 0),
    predictions: Number(predictions?.count || 0),
  };
  const report = {
    FACT: facts,
    ANALYSIS: `The ${period} window contains ${facts.alerts} alerts across ${facts.distinct_source_ips} source IPs and ${facts.incidents} incidents.`,
    RECOMMENDATION: 'Review the underlying records before changing thresholds or response policy. No automated policy changes were made.',
  };
  const reportDate = now.toISOString().slice(0, 10);
  await dbRun(db, `INSERT INTO ai_learning_reports (period, report_date, report_json, created_at)
    VALUES (?, ?, ?, ?) ON CONFLICT(period, report_date) DO UPDATE SET report_json = excluded.report_json, created_at = excluded.created_at`,
  [period, reportDate, JSON.stringify(report), now.toISOString()]);
  return report;
}

async function exportLearning(db) {
  await initializeLearningTables(db);
  const [calibration, transitions, cases, feedbackRows, lessons, suggestions] = await Promise.all([
    dbAll(db, 'SELECT signature, bucket, sample_count, predicted_sum, observed_sum, updated_at FROM ai_calibration ORDER BY signature, bucket'),
    dbAll(db, 'SELECT signature, next_action, SUM(effective_count) AS effective_count FROM ai_transition_stats GROUP BY signature, next_action ORDER BY signature, next_action'),
    dbAll(db, 'SELECT features_json, verdict, outcome, approved, created_at FROM ai_case_memory ORDER BY id'),
    dbAll(db, 'SELECT verdict, COUNT(*) AS count FROM ai_analysis_feedback GROUP BY verdict'),
    dbAll(db, 'SELECT lesson_key, version, source_count, status, created_at FROM ai_lessons ORDER BY lesson_key, version'),
    dbAll(db, 'SELECT suggestion_key, version, status, created_at FROM ai_tuning_suggestions ORDER BY suggestion_key, version'),
  ]);
  return {
    exported_at: new Date().toISOString(),
    feedback_counts: feedbackRows,
    calibration,
    transitions,
    cases: cases.map(row => ({ features: JSON.parse(row.features_json), verdict: row.verdict, outcome: row.outcome, approved: Boolean(row.approved), created_at: row.created_at })),
    lessons,
    suggestions,
  };
}

async function resetLearning(db, { backupDir = path.join(os.homedir(), '.soc-ai-learning-backups'), now = new Date() } = {}) {
  await initializeLearningTables(db);
  const backup = await exportLearning(db);
  await fs.mkdir(backupDir, { recursive: true, mode: 0o700 });
  const backupPath = path.join(backupDir, `learning-${now.toISOString().replace(/[:.]/g, '-')}.json`);
  await fs.writeFile(backupPath, JSON.stringify(backup, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  const tables = ['ai_calibration', 'ai_transition_stats', 'ai_case_memory', 'ai_lessons', 'ai_tuning_suggestions'];
  await new Promise((resolve, reject) => db.exec('BEGIN IMMEDIATE', error => error ? reject(error) : resolve()));
  const deleted = {};
  try {
    for (const table of tables) deleted[table] = await dbRun(db, `DELETE FROM ${table}`);
    await new Promise((resolve, reject) => db.exec('COMMIT', error => error ? reject(error) : resolve()));
  } catch (error) {
    await new Promise(resolve => db.exec('ROLLBACK', () => resolve()));
    throw error;
  }
  return { backup_path: backupPath, deleted };
}

module.exports = {
  exportLearning,
  generateNightlyLessons,
  generateReport,
  generateTuningSuggestion,
  initializeLearningTables,
  listLearningItems,
  resetLearning,
  reviewLesson,
  reviewTuningSuggestion,
  runScheduledLearning,
};