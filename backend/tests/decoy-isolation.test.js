'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const express = require('express');
const http = require('http');
const sqlite3 = require('sqlite3').verbose();
const { createDecoyEcommerceRouter } = require('../decoy-ecommerce');
const { createDecoyEventAdapter } = require('../decoy-event-adapter');
const { isHoneyAllowlistedIp, isLocalSystemIp } = require('../honey-block-policy');

function openMemoryDatabase() {
  return new sqlite3.Database(':memory:');
}

function query(db, sql) {
  return new Promise((resolve, reject) => db.all(sql, (error, rows) => error ? reject(error) : resolve(rows)));
}

function startApp(router) {
  const app = express();
  app.use(express.json());
  app.use('/api/decoy', router);
  const server = http.createServer(app);
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })));
}

test('only this host is exempt from threat-score blocks', () => {
  assert.equal(isHoneyAllowlistedIp('10.180.115.216'), false);
  assert.equal(isHoneyAllowlistedIp('10.180.115.36'), false);
  assert.equal(isHoneyAllowlistedIp('192.168.200.12'), false);
  assert.equal(isHoneyAllowlistedIp('::ffff:127.0.0.1'), true);
  assert.equal(isLocalSystemIp('198.51.100.91'), false);
  const hostIps = Object.values(os.networkInterfaces()).flatMap(interfaces =>
    (interfaces || []).map(entry => entry.address)
  );
  assert.ok(hostIps.length > 0);
  hostIps.forEach(ip => {
    assert.equal(isHoneyAllowlistedIp(ip), true);
    assert.equal(isLocalSystemIp(ip), true);
  });
});

test('decoy uses isolated tables and one adapter event bridge', async () => {
  const db = openMemoryDatabase();
  const events = [];
  const emitEvent = createDecoyEventAdapter({ collectEvent: async event => { events.push(event); return event; } });
  const decoy = createDecoyEcommerceRouter({ db, emitEvent });
  await decoy.initialize();
  const app = await startApp(decoy.router);

  const loginResponse = await fetch(`http://127.0.0.1:${app.port}/api/decoy/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'synthetic-user', password: 'synthetic-password' }),
  });

  assert.equal(loginResponse.status, 401);
  assert.equal(events.length, 1);
  assert.equal(events[0].event_source, 'decoy_ecommerce');
  assert.equal(events[0].event_type, 'Fake Login Attempt');
  assert.equal(events[0].attacker_ip, '127.0.0.1');

  const tables = await query(db, "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'decoy_%' ORDER BY name");
  assert.deepEqual(tables.map(row => row.name), ['decoy_carts', 'decoy_orders', 'decoy_products']);

  app.server.close();
  db.close();
});
