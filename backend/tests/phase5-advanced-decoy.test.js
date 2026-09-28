'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { createDecoyEcommerceRouter } = require('../decoy-ecommerce');
const {
  rotateApiRoute,
  rotateDecoyRoute,
  adaptApiSchema,
  resolveActiveDecoyRoute,
  getActiveApiSchema,
  computeDecoyFileHashes,
  calculateResponsePolicy,
  checkDecoyIntegrity,
  detectSocTargetingAttempt,
  isAuthorizedDecoyCollectorRequest,
  setDeceptionFreeze,
  getDeceptionFreeze,
  applyDeceptionConfigState,
  getActiveResponsePolicy,
  storeActiveResponsePolicy,
} = require('../server');
const config = require('../config');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => error ? reject(error) : resolve(row || null));
  });
}

function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) return reject(error);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

async function startDecoyRouter(router) {
  const app = express();
  app.use(express.json());
  app.use('/api/decoy', router);
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}/api/decoy` };
}

test('api endpoint rotation records a real decoy route change', async () => {
  const db = openMemoryDatabase();
  const result = await rotateApiRoute(db, {
    old_path: '/api/login',
    new_path: '/service/auth-v4',
    attacker_ip: '198.51.100.15',
    reason: 'api probing'
  });

  assert.equal(result.active, 1);
  assert.equal(result.new_path, '/service/auth-v4');
  const resolved = await resolveActiveDecoyRoute(db, 'api', '/service/auth-v4', '198.51.100.15');
  assert.equal(resolved.path, '/api/login');
  assert.equal(resolved.rotated, true);
  db.close();
});

test('api schema adaptation switches between predefined variants', async () => {
  const db = openMemoryDatabase();
  const result = await adaptApiSchema(db, { current_version: 'V1', attacker_ip: '198.51.100.22' });

  assert.equal(result.active, 1);
  assert.equal(result.schema_version, 'V2');
  const schema = await getActiveApiSchema(db, '198.51.100.22');
  assert.equal(schema.current_version, 'V2');
  db.close();
});

test('active route resolver maps a rotated alias back to its decoy handler', async () => {
  const db = openMemoryDatabase();
  await rotateDecoyRoute(db, {
    route_type: 'web',
    old_path: '/admin',
    new_path: '/control-x7',
    attacker_ip: '198.51.100.23',
  });

  const resolved = await resolveActiveDecoyRoute(db, 'web', '/control-x7', '198.51.100.23');
  assert.equal(resolved.rotated, true);
  assert.equal(resolved.path, '/admin');
  const retired = await resolveActiveDecoyRoute(db, 'web', '/admin', '198.51.100.23');
  assert.equal(retired.invalidated, true);
  db.close();
});

test('response adaptation applies stricter decoy behavior for critical severity', async () => {
  const policy = calculateResponsePolicy('CRITICAL');
  assert.equal(policy.delay_ms, 500);
  assert.equal(policy.manual_review, true);
});

test('getActiveResponsePolicy returns the stored policy for an attacker and the LOW default when expired or unknown', async () => {
  const attackerIp = '198.51.100.71';
  const policy = calculateResponsePolicy('CRITICAL');
  storeActiveResponsePolicy(attackerIp, policy);
  assert.deepEqual(getActiveResponsePolicy(attackerIp), policy);

  storeActiveResponsePolicy(attackerIp, policy, 1);
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.deepEqual(getActiveResponsePolicy(attackerIp), calculateResponsePolicy('LOW'));
  assert.deepEqual(getActiveResponsePolicy('198.51.100.72'), calculateResponsePolicy('LOW'));
});

test('manual review queue row gets written when manual_review is true', async () => {
  const db = openMemoryDatabase();
  const originalFlag = config.deception.applyResponsePolicy;
  config.deception.applyResponsePolicy = true;
  const decoy = createDecoyEcommerceRouter({
    db,
    emitEvent: async () => {},
    getActiveResponsePolicy: () => calculateResponsePolicy('CRITICAL'),
  });
  await decoy.initialize();
  const app = await startDecoyRouter(decoy.router);

  try {
    await fetch(`${app.baseUrl}/products`);
    const row = await dbGet(db, 'SELECT * FROM manual_review_queue ORDER BY id DESC LIMIT 1');
    assert.equal(row.path, '/products');
    assert.equal(row.method, 'GET');
    assert.equal(row.reviewed, 0);
  } finally {
    config.deception.applyResponsePolicy = originalFlag;
    await new Promise(resolve => app.server.close(resolve));
    db.close();
  }
});

test('fake response policy serves PRODUCTS constant instead of DB rows when enabled', async () => {
  const db = openMemoryDatabase();
  const originalFlag = config.deception.applyResponsePolicy;
  config.deception.applyResponsePolicy = true;
  const decoy = createDecoyEcommerceRouter({
    db,
    emitEvent: async () => {},
    getActiveResponsePolicy: () => ({ ...calculateResponsePolicy('HIGH'), fake_response: true, delay_ms: 0 }),
  });
  await decoy.initialize();
  await dbRun(db, "UPDATE decoy_products SET name = 'Database-only product' WHERE product_id = 'decoy-1'");
  const app = await startDecoyRouter(decoy.router);

  try {
    const listResponse = await fetch(`${app.baseUrl}/products`);
    const list = await listResponse.json();
    assert.equal(list.products[0].name, 'Relay Field Kit');

    const detailResponse = await fetch(`${app.baseUrl}/products/decoy-1`);
    const detail = await detailResponse.json();
    assert.equal(detail.product.name, 'Relay Field Kit');
  } finally {
    config.deception.applyResponsePolicy = originalFlag;
    await new Promise(resolve => app.server.close(resolve));
    db.close();
  }
});

test('schema adaptation wraps only isolated decoy API responses when enabled', async () => {
  const db = openMemoryDatabase();
  const originalFlag = config.deception.applyApiSchema;
  config.deception.applyApiSchema = true;
  const decoy = createDecoyEcommerceRouter({
    db,
    emitEvent: async () => {},
    getActiveApiSchema: async () => ({ current_version: 'V2' }),
  });
  await decoy.initialize();
  const app = await startDecoyRouter(decoy.router);

  try {
    const response = await fetch(`${app.baseUrl}/status`);
    const body = await response.json();
    assert.equal(body.schema_version, 'V2');
    assert.equal(body.data.enabled, true);
  } finally {
    config.deception.applyApiSchema = originalFlag;
    await new Promise(resolve => app.server.close(resolve));
    db.close();
  }
});

test('computeDecoyFileHashes detects a changed file in a temporary site', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rtimsz-hashes-'));
  try {
    const sitePath = path.join(tempRoot, 'site');
    fs.mkdirSync(sitePath, { recursive: true });
    fs.writeFileSync(path.join(sitePath, 'index.html'), 'clean');
    const before = await computeDecoyFileHashes(sitePath);
    fs.writeFileSync(path.join(sitePath, 'index.html'), 'tampered');
    const after = await computeDecoyFileHashes(sitePath);

    assert.equal(before.get('index.html') === after.get('index.html'), false);
    assert.equal(after.size, 1);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('failed file integrity check restores files from the configured baseline', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rtimsz-restore-'));
  const originalBaselinePath = config.decoy.baselinePath;
  const originalLiveSitePath = config.decoy.liveSitePath;
  try {
    const baselinePath = path.join(tempRoot, 'baseline');
    const liveSitePath = path.join(tempRoot, 'live');
    fs.mkdirSync(baselinePath, { recursive: true });
    fs.mkdirSync(liveSitePath, { recursive: true });
    fs.writeFileSync(path.join(baselinePath, 'index.html'), '<clean>');
    fs.writeFileSync(path.join(liveSitePath, 'index.html'), '<tampered>');
    config.decoy.baselinePath = baselinePath;
    config.decoy.liveSitePath = liveSitePath;

    const result = await checkDecoyIntegrity(null, {
      container_id: 'decoy-file-restore-test',
      check_type: 'file-hash',
      result: 'failed',
      reason: 'Tampered files detected: index.html',
      restored: true,
    });

    assert.deepEqual(result.restore.file_restore, { attempted: true, success: true, files_restored: 1 });
    assert.equal(fs.readFileSync(path.join(liveSitePath, 'index.html'), 'utf8'), '<clean>');
  } finally {
    config.decoy.baselinePath = originalBaselinePath;
    config.decoy.liveSitePath = originalLiveSitePath;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('self-healing logs integrity restoration when a decoy integrity check fails', async () => {
  const db = openMemoryDatabase();
  const result = await checkDecoyIntegrity(db, {
    container_id: 'decoy-001',
    check_type: 'hash',
    result: 'failed',
    reason: 'hash mismatch',
    restored: true,
    attacker_ip: '198.51.100.33'
  });

  assert.equal(result.restored, true);
  assert.equal(result.check_type, 'hash');
  db.close();
});

test('failed integrity checks automatically restore the decoy baseline', async () => {
  const db = openMemoryDatabase();
  setDeceptionFreeze(true);
  const result = await checkDecoyIntegrity(db, {
    container_id: 'decoy-auto-restore',
    check_type: 'hash',
    result: 'failed',
    reason: 'hash mismatch',
  });

  assert.equal(result.restored, true);
  assert.equal(result.restore.freeze, false);
  assert.equal(getDeceptionFreeze(), false);
  db.close();
});

test('SOC targeting detection classifies unauthorized protected network access as a targeting event', async () => {
  const db = openMemoryDatabase();
  const result = await detectSocTargetingAttempt(db, {
    attacker_ip: '198.51.100.44',
    source: 'decoy_ecommerce',
    destination: '192.168.200.10',
    destination_port: 443,
    event_type: 'SOC_TARGETING_ATTEMPT'
  });

  assert.equal(result.event_type, 'SOC_TARGETING_ATTEMPT');
  assert.equal(result.blocked, true);
  const block = await dbGet(db, 'SELECT ip, action, verify_result FROM blocks WHERE ip = ? ORDER BY id DESC LIMIT 1', ['198.51.100.44']);
  assert.equal(block.action, 'block');
  assert.equal(block.verify_result, 'blocked');
  db.close();
});

test('self-healing restores decoy baseline routes and clears freeze after integrity failure', async () => {
  setDeceptionFreeze(false);
  const db = openMemoryDatabase();
  await rotateDecoyRoute(db, { route_type: 'web', old_path: '/admin', new_path: '/control-x7', attacker_ip: '198.51.100.90', reason: 'test rotation' });
  await rotateApiRoute(db, { old_path: '/api/login', new_path: '/service/auth-v4', attacker_ip: '198.51.100.90', reason: 'test rotation' });
  await adaptApiSchema(db, { current_version: 'V1', attacker_ip: '198.51.100.90', reason: 'test rotation' });
  setDeceptionFreeze(true);

  const result = await checkDecoyIntegrity(db, {
    container_id: 'decoy-restore-test',
    check_type: 'hash',
    result: 'failed',
    reason: 'hash mismatch',
    restored: true,
  });

  const restoredWebRoute = await dbGet(db, 'SELECT * FROM decoy_route_map WHERE route_type = ? ORDER BY id DESC LIMIT 1', ['web']);
  const restoredApiRoute = await dbGet(db, 'SELECT * FROM decoy_api_route_map WHERE route_type = ? ORDER BY id DESC LIMIT 1', ['api']);
  const restoredSchema = await dbGet(db, 'SELECT * FROM decoy_api_schema_map ORDER BY id DESC LIMIT 1');

  assert.equal(result.restored, true);
  assert.equal(getDeceptionFreeze(), false);
  const staleRoute = await dbGet(db, 'SELECT active FROM decoy_api_route_map WHERE new_path = ?', ['/service/auth-v4']);
  const staleSchema = await dbGet(db, 'SELECT active FROM decoy_api_schema_map WHERE current_version = ?', ['V2']);
  assert.equal(restoredWebRoute.new_path, '/admin');
  assert.equal(restoredApiRoute.new_path, '/api/login');
  assert.equal(restoredSchema.current_version, 'V1');
  assert.equal(staleRoute.active, 0);
  assert.equal(staleSchema.active, 0);
  db.close();
});

test('freeze toggle blocks runtime rotation changes', () => {
  setDeceptionFreeze(true);
  assert.equal(getDeceptionFreeze(), true);
  setDeceptionFreeze(false);
});

test('freeze state can be initialized from config and overrides runtime state', () => {
  setDeceptionFreeze(false);
  const applied = applyDeceptionConfigState({ freeze: true, maxRotationsPerHour: 7 });

  assert.equal(applied.freeze, true);
  assert.equal(getDeceptionFreeze(), true);
  setDeceptionFreeze(false);
});

test('freeze boot wiring applies config.deception.freeze before rotation', () => {
  const originalFreeze = config.deception.freeze;
  config.deception.freeze = true;
  setDeceptionFreeze(false);

  const applied = applyDeceptionConfigState({
    freeze: config.deception.freeze,
    maxRotationsPerHour: 7,
  });

  assert.equal(applied.freeze, true);
  assert.equal(getDeceptionFreeze(), true);
  config.deception.freeze = originalFreeze;
  setDeceptionFreeze(false);
});

test('rotation limit throttles repeated route changes for the same attacker', async () => {
  const db = openMemoryDatabase();
  const applied = applyDeceptionConfigState({ freeze: false, maxRotationsPerHour: 1 });
  assert.equal(applied.maxRotationsPerHour, 1);

  const first = await rotateDecoyRoute(db, {
    route_type: 'web',
    old_path: '/admin',
    new_path: '/control-x7',
    attacker_ip: '198.51.100.99',
    reason: 'first rotation'
  });

  const second = await rotateDecoyRoute(db, {
    route_type: 'web',
    old_path: '/login',
    new_path: '/auth-gateway-r4',
    attacker_ip: '198.51.100.99',
    reason: 'second rotation'
  });

  assert.equal(first.active, 1);
  assert.equal(second.throttled, true);
  assert.equal(second.reason.includes('rotation limit'), true);
  db.close();
  setDeceptionFreeze(false);
});

test('decoy collector POST is public only with the configured adapter key', () => {
  const request = (method, originalUrl, apiKey) => ({
    method,
    originalUrl,
    get: header => header === 'x-api-key' ? apiKey : '',
  });

  assert.equal(isAuthorizedDecoyCollectorRequest(request('POST', '/api/decoy/events', config.apiKey)), true);
  assert.equal(isAuthorizedDecoyCollectorRequest(request('POST', '/api/decoy/events?source=test', config.apiKey)), true);
  assert.equal(isAuthorizedDecoyCollectorRequest(request('POST', '/api/decoy/events', 'invalid')), false);
  assert.equal(isAuthorizedDecoyCollectorRequest(request('GET', '/api/decoy/events', config.apiKey)), false);
});
