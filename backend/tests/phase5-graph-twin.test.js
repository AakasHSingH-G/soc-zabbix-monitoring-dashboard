'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3').verbose();
const {
  mapAttackEventToStage,
  appendAttackGraphEvent,
  getAttackTwinProbabilities,
  registerAttackGraphTransition
} = require('../server');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

test('attack graph stage mapping uses the fixed attack stages', () => {
  assert.equal(mapAttackEventToStage('PORT_PROBE'), 'PORT_PROBE');
  assert.equal(mapAttackEventToStage('ADMIN_ACCESS'), 'ADMIN_ENUMERATION');
  assert.equal(mapAttackEventToStage('API_ENUMERATION'), 'API_ENUMERATION');
  assert.equal(mapAttackEventToStage('DECOY_FINGERPRINTING'), 'DECOY_FINGERPRINTING');
  assert.equal(mapAttackEventToStage('SOC_TARGETING_ATTEMPT'), 'SOC_TARGETING');
});

test('attack graph transition statistics are counted by prior stage', async () => {
  const db = openMemoryDatabase();

  await registerAttackGraphTransition(db, 'RECON', 'PORT_PROBE');
  await registerAttackGraphTransition(db, 'PORT_PROBE', 'HONEYPORT_ACCESS');
  await registerAttackGraphTransition(db, 'PORT_PROBE', 'HONEYPORT_ACCESS');

  const rows = await new Promise((resolve, reject) => {
    db.all('SELECT from_stage, to_stage, count FROM stage_transition_counts ORDER BY from_stage, to_stage', (error, rows) => {
      if (error) reject(error);
      else resolve(rows);
    });
  });

  assert.deepEqual(rows, [
    { from_stage: 'PORT_PROBE', to_stage: 'HONEYPORT_ACCESS', count: 2 },
    { from_stage: 'RECON', to_stage: 'PORT_PROBE', count: 1 },
  ]);

  db.close();
});

test('attack twin reflects historical transition probabilities from current stage', async () => {
  const db = openMemoryDatabase();

  await registerAttackGraphTransition(db, 'API_ENUMERATION', 'LOGIN_ATTEMPT');
  await registerAttackGraphTransition(db, 'API_ENUMERATION', 'LOGIN_ATTEMPT');
  await registerAttackGraphTransition(db, 'API_ENUMERATION', 'DECOY_FINGERPRINTING');

  const twin = await getAttackTwinProbabilities(db, 'API_ENUMERATION');

  assert.equal(twin.current_stage, 'API_ENUMERATION');
  assert.equal(twin.observed_sequences, 3);
  assert.equal(twin.transitions[0].to_stage, 'LOGIN_ATTEMPT');
  assert.equal(Number(twin.transitions[0].probability.toFixed(2)), 0.67);

  db.close();
});
