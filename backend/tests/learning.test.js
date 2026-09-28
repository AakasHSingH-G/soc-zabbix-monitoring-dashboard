'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const sqlite3 = require('sqlite3').verbose();
const { initializeAccuracyTables } = require('../ai/accuracy');
const {
  exportLearning,
  generateNightlyLessons,
  generateReport,
  generateTuningSuggestion,
  initializeLearningTables,
  listLearningItems,
  resetLearning,
  reviewLesson,
  runScheduledLearning,
} = require('../ai/learning');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));
}

async function setup(db) {
  await initializeAccuracyTables(db);
  await initializeLearningTables(db);
  await db.exec(`
    CREATE TABLE ai_analyses (id INTEGER PRIMARY KEY, attacker_ip TEXT, created_at TEXT);
    CREATE TABLE security_events (id INTEGER, src_ip TEXT, created_at TEXT);
    CREATE TABLE incidents (id TEXT, created_at TEXT);
    CREATE TABLE blocks (id INTEGER, created_at TEXT);
    CREATE TABLE honey_captures (id INTEGER, created_at TEXT);
  `);
}

test('candidate lessons stay pending until five sources and are versioned/admin-reviewed', async () => {
  const db = openMemoryDatabase();
  try {
    await setup(db);
    const now = new Date('2026-09-28T00:00:00.000Z');
    assert.equal((await generateNightlyLessons(db, { now })).reason, 'not_enough_sources');
    for (let index = 1; index <= 5; index += 1) {
      await run(db, 'INSERT INTO ai_analyses VALUES (?, ?, ?)', [index, `198.51.100.${index}`, now.toISOString()]);
      await run(db, 'INSERT INTO ai_analysis_feedback (analysis_id, username, verdict, note, created_at) VALUES (?, ?, ?, ?, ?)', [index, 'analyst', index <= 3 ? 'correct' : 'wrong', 'private analyst note', now.toISOString()]);
    }
    const candidate = await generateNightlyLessons(db, { now });
    assert.equal(candidate.created, true);
    assert.equal(candidate.source_count, 5);
    let items = await listLearningItems(db);
    assert.equal(items.lessons[0].status, 'pending');
    assert.ok(items.lessons[0].lesson_text.length <= 1500);
    assert.equal(await reviewLesson(db, candidate.id, 'approve', 'admin', now.toISOString()), 1);
    assert.equal((await generateNightlyLessons(db, { now: new Date('2026-09-29T00:00:00.000Z') })).version, 2);
    items = await listLearningItems(db);
    assert.deepEqual(items.lessons.map(item => item.status), ['pending', 'active']);
    await assert.rejects(reviewLesson(db, candidate.id, 'delete', 'admin'), /Unsupported/);
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});

test('scheduled nightly and weekly jobs are idempotent', async () => {
  const db = openMemoryDatabase();
  try {
    await setup(db);
    const mondayAtTwo = new Date(2026, 8, 28, 2, 0, 0);
    const first = await runScheduledLearning(db, mondayAtTwo);
    assert.equal(first.ran, true);
    assert.equal(first.daily_report.FACT.period, 'daily');
    assert.equal(first.weekly_report.FACT.period, 'weekly');
    assert.equal(first.tuning.status, 'pending');
    assert.equal((await runScheduledLearning(db, mondayAtTwo)).reason, 'already_completed');
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});

test('reports use SQL facts; export excludes notes; reset backs up before clearing derived learning', async () => {
  const db = openMemoryDatabase();
  const backupDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soc-learning-test-'));
  try {
    await setup(db);
    const now = new Date('2026-09-28T12:00:00.000Z');
    await run(db, 'INSERT INTO security_events VALUES (1, ?, ?)', ['198.51.100.8', now.toISOString()]);
    await run(db, 'INSERT INTO incidents VALUES (?, ?)', ['i1', now.toISOString()]);
    await run(db, 'INSERT INTO blocks VALUES (?, ?)', [1, now.toISOString()]);
    await run(db, 'INSERT INTO honey_captures VALUES (?, ?)', [1, now.toISOString()]);
    await run(db, `INSERT INTO ai_analysis_feedback (analysis_id, username, verdict, note, created_at)
      VALUES (1, 'analyst', 'correct', 'PRIVATE NOTE MUST NOT EXPORT', ?)`, [now.toISOString()]);
    await run(db, `INSERT INTO ai_calibration (signature,bucket,sample_count,predicted_sum,observed_sum,updated_at)
      VALUES ('S1',5,3,1.5,2,?)`, [now.toISOString()]);
    await run(db, `INSERT INTO ai_transition_stats (signature,next_action,ip,effective_count,updated_at)
      VALUES ('S1','ssh_bruteforce','198.51.100.8',2,?)`, [now.toISOString()]);
    const report = await generateReport(db, 'daily', { now });
    assert.equal(report.FACT.alerts, 1);
    assert.equal(report.FACT.incidents, 1);
    assert.equal(report.FACT.blocks, 1);
    assert.equal(report.FACT.honeyport_captures, 1);
    const suggestion = await generateTuningSuggestion(db, { now });
    assert.equal(suggestion.status, 'pending');
    const exported = await exportLearning(db);
    assert.doesNotMatch(JSON.stringify(exported), /PRIVATE NOTE/);
    const result = await resetLearning(db, { backupDir, now });
    const backup = await fs.readFile(result.backup_path, 'utf8');
    assert.doesNotMatch(backup, /PRIVATE NOTE/);
    assert.equal((await get(db, 'SELECT COUNT(*) AS count FROM ai_calibration')).count, 0);
    assert.equal((await get(db, 'SELECT COUNT(*) AS count FROM ai_transition_stats')).count, 0);
    assert.equal((await get(db, 'SELECT COUNT(*) AS count FROM ai_analysis_feedback')).count, 1);
    assert.equal((await get(db, 'SELECT COUNT(*) AS count FROM security_events')).count, 1);
    assert.equal((await fs.stat(result.backup_path)).mode & 0o777, 0o600);
  } finally {
    await new Promise(resolve => db.close(resolve));
    await fs.rm(backupDir, { recursive: true, force: true });
  }
});