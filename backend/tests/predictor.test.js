'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3').verbose();
const { buildFeatureVector, findCampaignSiblings, persistTimeline, predictNextAttacks, timelineRows } = require('../ai/predictor');

const fixtures = [
  ['S1', [{ dest_port: 22, rule: 'SSH probe', description: 'SSH service scan' }], {}, 'ssh_bruteforce', '1h'],
  ['S2', [{ dest_port: 22, rule: 'SSH failed login', description: 'authentication failure for root' }], {}, 'continued_bruteforce_wider_userlist', '1h'],
  ['S3', [{ dest_port: 22, rule: 'SSH login', description: 'successful login session opened' }], {}, 'post_access_recon_commands', '15m'],
  ['S4', [{ dest_port: 3389, rule: 'RDP probe', description: 'RDP service scan' }], {}, 'rdp_bruteforce', '1h'],
  ['S5', [{ dest_port: 23, rule: 'Telnet probe', description: 'telnet service hit' }], {}, 'iot_default_cred_bruteforce', '15m'],
  ['S6', [{ dest_port: 443, rule: 'GET /wp-login.php', description: 'web login path probe' }], {}, 'web_login_bruteforce', '1h'],
  ['S7', [{ dest_port: 443, rule: 'GET /.env', description: 'sensitive file request' }], {}, 'credential_harvest_then_reuse', '24h'],
  ['S8', [{ dest_port: 443, rule: 'CVE-2021-44228 probe', description: 'KEV matched request' }], {}, 'exploit_attempt_same_cve', '15m'],
  ['S9', [{ dest_port: 3306, rule: 'database probe', description: 'MySQL service scan' }], {}, 'unauthenticated_access_attempt', '1h'],
  ['S10', [{ dest_port: 10051, rule: 'Zabbix API probe', description: 'api_jsonrpc request' }], {}, 'zabbix_default_credential_login', '1h'],
  ['S11', [41001, 41002, 41003, 41004, 41005].map(dest_port => ({ dest_port, rule: 'generic probe', description: 'service scan' })), {}, 'targeted_service_followup', '24h'],
  ['S12', [{ dest_port: 8080, rule: 'RCE command injection probe', description: 'shell traversal payload attempt' }], {}, 'command_execution_attempt', '15m'],
  ['S13', [{ dest_port: 443, rule: 'campaign probe', description: 'same pattern' }], { siblings: 5 }, 'more_sibling_ips_join', '1h'],
];

test('S1-S13 fixtures select the expected playbook signature and bounded priors', () => {
  for (const [expected, events, campaign, expectedAction, expectedWindow] of fixtures) {
    const result = predictNextAttacks('198.51.100.10', events, [], campaign);
    assert.equal(result.signature, expected);
    assert.equal(result.predictions[0].next_action, expectedAction);
    assert.equal(result.predictions[0].window, expectedWindow);
    assert.ok(result.predictions.length <= 3);
    assert.ok(result.predictions.every(prediction => prediction.probability >= 0 && prediction.probability <= 1));
    const sum = result.predictions.reduce((total, prediction) => total + prediction.probability, 0);
    assert.ok(sum <= 1.000001, `${expected} probability sum was ${sum}`);
  }
});

test('unknown signature reports insufficient pattern without invented precision', () => {
  const result = predictNextAttacks('198.51.100.11', [{ rule: 'generic security event' }]);
  assert.equal(result.signature, 'insufficient_pattern');
  assert.equal(result.predictions[0].next_action, 'insufficient_pattern');
  assert.equal(result.predictions[0].probability, 0);
});

test('feature vector stores enums and counters instead of raw attacker text', () => {
  const vector = buildFeatureVector('203.0.113.4', [{
    dest_port: 10051,
    rule: 'Zabbix password attempt',
    description: 'operator text should not appear in sanitized fields',
    user_agent: 'Nmap/7.0',
  }]);
  const serialized = JSON.stringify(vector);
  assert.equal(vector.signature, 'S10');
  assert.doesNotMatch(serialized, /operator text|password attempt|Nmap/);
  assert.deepEqual(vector.service_classes, ['zabbix-server']);
  assert.deepEqual(vector.ua_classes, ['nmap']);
  assert.equal(Object.hasOwn(vector, 'ip'), false);
  const attributes = predictNextAttacks('203.0.113.4', [{ dest_port: 10051, rule: 'Zabbix API probe', user_agent: 'nmap' }]).mindset;
  for (const attribute of Object.values(attributes)) assert.ok(attribute.reasons.length > 0);
});

test('campaign ids are stable per subnet signature and timeline stores classes only', async () => {
  const first = predictNextAttacks('198.51.100.10', fixtures[12][1], [], fixtures[12][2]);
  const second = predictNextAttacks('198.51.100.20', fixtures[12][1], [], fixtures[12][2]);
  assert.equal(first.campaign.id, second.campaign.id);
  const rows = timelineRows('198.51.100.10', [{
    created_at: '2026-09-28T00:00:00.000Z', dest_port: 10051,
    rule: 'Zabbix login probe', description: 'raw detail must not persist', count: 3,
  }]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].action_class, 'auth_attempt');
  assert.doesNotMatch(JSON.stringify(rows), /raw detail|Zabbix login/);

  const db = new sqlite3.Database(':memory:');
  try {
    assert.equal(await persistTimeline(db, '198.51.100.10', [{
      created_at: '2026-09-28T00:00:00.000Z', dest_port: 10051,
      rule: 'Zabbix login probe', description: 'raw detail must not persist', count: 3,
    }]), 1);
    assert.equal(await persistTimeline(db, '198.51.100.10', [{
      created_at: '2026-09-28T00:00:00.000Z', dest_port: 10051,
      rule: 'Zabbix login probe', description: 'raw detail must not persist', count: 3,
    }]), 0);
    const rowsStored = await new Promise((resolve, reject) => db.all('SELECT action_class, service, weight FROM ai_ip_timeline', (error, rows) => error ? reject(error) : resolve(rows)));
    assert.deepEqual(rowsStored, [{ action_class: 'auth_attempt', service: 'zabbix-server', weight: 3 }]);
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});

test('campaign correlation joins matching sibling IP signatures within the same /24', async () => {
  const db = new sqlite3.Database(':memory:');
  try {
    await new Promise((resolve, reject) => db.exec(`
      CREATE TABLE security_events (
        id INTEGER PRIMARY KEY, src_ip TEXT, created_at TEXT, dest_port INTEGER,
        rule TEXT, description TEXT, user_agent TEXT
      );
    `, error => error ? reject(error) : resolve()));
    const timestamp = new Date().toISOString();
    for (let index = 11; index <= 15; index += 1) {
      await new Promise((resolve, reject) => db.run(
        'INSERT INTO security_events (src_ip, created_at, dest_port, rule, description, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
        [`198.51.100.${index}`, timestamp, 10051, 'Zabbix API probe', 'api_jsonrpc request', 'nmap'],
        error => error ? reject(error) : resolve()
      ));
    }
    const campaign = await findCampaignSiblings(db, '198.51.100.10', [{ dest_port: 10051, rule: 'Zabbix API probe', description: 'api_jsonrpc request', user_agent: 'nmap' }]);
    assert.equal(campaign.siblings, 5);
    assert.ok(campaign.similarity > 0);
    assert.equal(predictNextAttacks('198.51.100.10', [{ dest_port: 10051, rule: 'Zabbix API probe', description: 'api_jsonrpc request', user_agent: 'nmap' }], [], campaign).signature, 'S13');
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
});