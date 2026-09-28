'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3').verbose();
const {
  normalizeAttackEvent,
  upsertAttackDna,
  computeSeverityLabel,
  getAttackDna,
  recordDecoyAttackDna
} = require('../server');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

test('normalizeAttackEvent creates a canonical internal format', () => {
  const event = normalizeAttackEvent({
    attacker_ip: '203.0.113.9',
    timestamp: '2026-09-27T00:00:00.000Z',
    source: 'honeyport',
    event_type: 'PORT_PROBE',
    path: '/admin',
    method: 'GET',
    port: 2323,
    user_agent: 'curl/8.0',
    status_code: 403,
    metadata: { probe: 'tcp' }
  });

  assert.equal(event.attacker_ip, '203.0.113.9');
  assert.equal(event.event_type, 'PORT_PROBE');
  assert.equal(event.path, '/admin');
  assert.equal(event.port, 2323);
  assert.equal(event.metadata.probe, 'tcp');
});

test('severity rules escalate by one level per matching trigger', () => {
  assert.equal(computeSeverityLabel({ login_attempts: 6, distinct_endpoints: 3, admin_panel_hit: false, escape_attempt_hits: 0 }), 'MEDIUM');
  assert.equal(computeSeverityLabel({ login_attempts: 1, distinct_endpoints: 12, admin_panel_hit: false, escape_attempt_hits: 0 }), 'MEDIUM');
  assert.equal(computeSeverityLabel({ login_attempts: 0, distinct_endpoints: 3, admin_panel_hit: true, escape_attempt_hits: 0 }), 'MEDIUM');
  assert.equal(computeSeverityLabel({ login_attempts: 0, distinct_endpoints: 2, admin_panel_hit: false, escape_attempt_hits: 1 }), 'MEDIUM');
  assert.equal(computeSeverityLabel({ login_attempts: 6, distinct_endpoints: 12, admin_panel_hit: true, escape_attempt_hits: 1 }), 'CRITICAL');
});

test('attack DNA is upserted and reads back with aggregated counters', async () => {
  const db = openMemoryDatabase();
  const event = normalizeAttackEvent({
    attacker_ip: '198.51.100.10',
    timestamp: '2026-09-27T00:00:00.000Z',
    source: 'decoy_ecommerce',
    event_type: 'LOGIN_ATTEMPT',
    path: '/login',
    method: 'POST',
    port: 3000,
    user_agent: 'curl/8.0',
    status_code: 401,
    metadata: { username: 'admin' }
  });

  await upsertAttackDna(db, event);
  const dna = await getAttackDna(db, '198.51.100.10');

  assert.equal(dna.attacker_ip, '198.51.100.10');
  assert.equal(dna.total_events, 1);
  assert.equal(dna.login_attempts, 1);
  assert.equal(dna.severity_label, 'LOW');

  db.close();
});

test('attack DNA keeps counting distinct ports, endpoints, APIs, and user agents', async () => {
  const db = openMemoryDatabase();
  const baseEvent = {
    attacker_ip: '198.51.100.20',
    source: 'decoy_ecommerce',
    event_type: 'API_ACCESS',
    method: 'GET',
    status_code: 200,
  };

  try {
    for (const [index, path] of ['/api/items', '/api/orders', '/api/users'].entries()) {
      await upsertAttackDna(db, {
        ...baseEvent,
        timestamp: `2026-09-27T00:0${index}:00.000Z`,
        path,
        port: 8080 + index,
        user_agent: `scanner-${index}`,
      });
    }

    const dna = await getAttackDna(db, baseEvent.attacker_ip);
    assert.equal(dna.total_events, 3);
    assert.equal(dna.ports_touched, 3);
    assert.equal(dna.endpoints_touched, 3);
    assert.equal(dna.apis_touched, 3);
    assert.equal(dna.distinct_user_agents, 3);

    await upsertAttackDna(db, {
      ...baseEvent,
      timestamp: '2026-09-27T00:04:00.000Z',
      path: '/api/orders',
      port: 8081,
      user_agent: 'scanner-1',
    });

    const repeatedDna = await getAttackDna(db, baseEvent.attacker_ip);
    assert.equal(repeatedDna.total_events, 4);
    assert.equal(repeatedDna.ports_touched, 3);
    assert.equal(repeatedDna.endpoints_touched, 3);
    assert.equal(repeatedDna.apis_touched, 3);
    assert.equal(repeatedDna.distinct_user_agents, 3);
  } finally {
    db.close();
  }
});

test('only decoy collector events are recorded in attack DNA', async () => {
  const db = openMemoryDatabase();

  try {
    const ignored = await recordDecoyAttackDna(db, {
      attacker_ip: '198.51.100.30',
      event_source: 'security',
      event_type: 'LOGIN_ATTEMPT',
      path: '/login',
    });
    assert.equal(ignored, null);
    const tables = await new Promise((resolve, reject) => {
      db.all("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'attack_dna'", (error, rows) => {
        if (error) reject(error);
        else resolve(rows);
      });
    });
    assert.equal(tables.length, 0);

    const recorded = await recordDecoyAttackDna(db, {
      attacker_ip: '198.51.100.30',
      event_source: 'decoy_ecommerce',
      event_type: 'Fake Login Attempt',
      timestamp: '2026-09-27T00:00:00.000Z',
      path: '/api/decoy/login',
      method: 'POST',
      dest_port: 8081,
      user_agent: 'scanner/1.0',
    });

    assert.equal(recorded.attacker_ip, '198.51.100.30');
    assert.equal(recorded.login_attempts, 1);
    assert.equal(recorded.apis_touched, 1);
    assert.equal(recorded.ports_touched, 1);
  } finally {
    db.close();
  }
});
