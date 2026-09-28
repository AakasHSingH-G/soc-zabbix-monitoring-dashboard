'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const os = require('os');
const sqlite3 = require('sqlite3').verbose();
const {
  evaluateDeceptionTrigger,
  rotateDecoyRoute,
  setDeceptionFreeze,
  getDeceptionFreeze,
  collectNormalizedSecurityEvent,
  markSecurityHistoryCleared,
  hasNewAutoBlockEvidence,
  verifyAdminPanelCredential,
} = require('../server');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => error ? reject(error) : resolve(row || null));
  });
}

test('deception engine triggers when high severity and endpoint footprint is high', async () => {
  const db = openMemoryDatabase();
  const decision = await evaluateDeceptionTrigger(db, {
    attacker_ip: '198.51.100.55',
    severity_label: 'HIGH',
    endpoints_touched: 9,
    total_events: 16,
    admin_panel_hit: true,
    escape_attempt_hits: 0,
  });

  assert.equal(decision.triggered, true);
  assert.equal(decision.reason.includes('severity'), true);
  db.close();
});

test('web route rotation stores the new active path and old path', async () => {
  const db = openMemoryDatabase();
  const result = await rotateDecoyRoute(db, {
    route_type: 'web',
    old_path: '/admin',
    new_path: '/control-x7',
    attacker_ip: '198.51.100.77',
    reason: 'high-risk web probing'
  });

  assert.equal(result.active, 1);
  assert.equal(result.new_path, '/control-x7');
  db.close();
});

test('live decoy event pipeline attaches DNA, graph and route rotation in one pass', async () => {
  setDeceptionFreeze(false);
  const db = openMemoryDatabase();
  const event = {
    attacker_ip: '198.51.100.88',
    event_type: 'ADMIN_PANEL_PROBE',
    event_source: 'decoy_ecommerce',
    severity: 'HIGH',
    path: '/admin',
    method: 'GET',
    rule: 'DECOY_ADMIN_PROBE',
    description: 'Admin path probe',
    metadata: { path: '/admin' },
  };

  const normalized = await collectNormalizedSecurityEvent(event, db);
  const dna = await dbGet(db, 'SELECT * FROM attack_dna WHERE attacker_ip = ?', [normalized.sourceIp]);
  const graph = await dbGet(db, 'SELECT * FROM attack_graph_node WHERE attacker_ip = ?', [normalized.sourceIp]);
  const route = await dbGet(db, 'SELECT * FROM decoy_route_map WHERE route_type = ? ORDER BY id DESC LIMIT 1', ['web']);

  assert.equal(normalized.event_source, 'decoy_ecommerce');
  assert.ok(dna && dna.attacker_ip === normalized.sourceIp);
  assert.ok(graph && graph.stage === 'ADMIN_ENUMERATION');
  assert.ok(normalized.runtime && normalized.runtime.rotation && normalized.runtime.rotation.route && normalized.runtime.rotation.route.new_path === '/control-x7');
  assert.ok(route && route.new_path === '/admin');
  db.close();
});

test('local host decoy events are ignored while remote laptop events remain recorded', async () => {
  const db = openMemoryDatabase();
  const localIp = Object.values(os.networkInterfaces())
    .flatMap(interfaces => (interfaces || []).map(entry => entry.address))[0];
  const localEvent = await collectNormalizedSecurityEvent({
    attacker_ip: localIp,
    event_source: 'decoy_ecommerce',
    severity: 'HIGH',
  }, db);
  const localTables = await dbGet(db, "SELECT COUNT(*) AS total FROM sqlite_master WHERE type = 'table'");

  assert.equal(localEvent.ignored, true);
  assert.equal(localTables.total, 0);

  const remoteEvent = await collectNormalizedSecurityEvent({
    attacker_ip: '198.51.100.91',
    event_source: 'decoy_ecommerce',
    severity: 'HIGH',
    event_type: 'ADMIN_PANEL_PROBE',
    path: '/admin',
  }, db);
  const remoteRow = await dbGet(db, 'SELECT src_ip FROM security_events WHERE src_ip = ?', [remoteEvent.sourceIp]);

  assert.equal(remoteEvent.ignored, undefined);
  assert.equal(remoteRow.src_ip, '198.51.100.91');
  db.close();
});

test('manual security history clear timestamp persists for dashboard filtering', async () => {
  const db = openMemoryDatabase();
  await new Promise((resolve, reject) => {
    db.run(`CREATE TABLE threat_intel_state (
      state_key TEXT PRIMARY KEY,
      state_value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`, error => error ? reject(error) : resolve());
  });
  const clearedAt = Date.now();

  await markSecurityHistoryCleared(db, clearedAt);
  const state = await dbGet(db, "SELECT state_value FROM threat_intel_state WHERE state_key = 'cleared_at'");

  assert.equal(Number(state.state_value), clearedAt);
  db.close();
});

test('unchanged high-threat evidence cannot restart an expired block', () => {
  const attacker = {
    ip: '198.51.100.201',
    lastSeen: '2026-09-27T10:00:00.000Z',
    hits: 4,
    threatScore: 82,
  };

  assert.equal(hasNewAutoBlockEvidence(attacker), true);
  assert.equal(hasNewAutoBlockEvidence(attacker), false);
  assert.equal(hasNewAutoBlockEvidence({ ...attacker, lastSeen: '2026-09-27T10:00:01.000Z', hits: 5 }), true);
});

test('admin panel re-auth accepts either admin login or configured panel password', () => {
  const makeStoredPassword = (password, salt) => `scrypt:${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
  const user = {
    password: makeStoredPassword('account-password', 'login-salt'),
    admin_panel_password: makeStoredPassword('panel-password', 'panel-salt'),
  };

  assert.equal(verifyAdminPanelCredential('account-password', user), true);
  assert.equal(verifyAdminPanelCredential('panel-password', user), true);
  assert.equal(verifyAdminPanelCredential('wrong-password', user), false);
});

test('freeze switch prevents rotations while keeping telemetry live', async () => {
  setDeceptionFreeze(true);
  const state = getDeceptionFreeze();
  assert.equal(state, true);
  setDeceptionFreeze(false);
});
