'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { isDemoLoginAccepted, isLoginRateLimited, recordLoginFailure, clearLoginFailureState } = require('../server');
const { readAuthConfig } = require('../config');

test('auth configuration requires API_KEY and Zabbix credentials only when configured', () => {
  assert.throws(() => readAuthConfig({}), /API_KEY is required/);
  assert.throws(() => readAuthConfig({ API_KEY: 'CHANGE_ME' }), /API_KEY is required/);
  assert.throws(() => readAuthConfig({ API_KEY: 'fake-key' , ZABBIX_URL: 'http://zabbix.test' }), /ZABBIX_USER and ZABBIX_PASS are required/);
  assert.throws(() => readAuthConfig({ API_KEY: 'fake-key', ZABBIX_URL: 'http://zabbix.test', ZABBIX_USER: 'CHANGE_ME', ZABBIX_PASS: 'fake-pass' }), /ZABBIX_USER and ZABBIX_PASS are required/);

  const optionalZabbix = readAuthConfig({ API_KEY: 'fake-key' });
  assert.equal(optionalZabbix.zabbixUrl, '');
  assert.equal(optionalZabbix.zabbixUser, undefined);
  assert.equal(optionalZabbix.zabbixPass, undefined);

  assert.throws(() => readAuthConfig({ API_KEY: 'fake-key', DEMO_CREDENTIALS: 'true' }), /DEMO_ADMIN_PASSWORD/);
  assert.throws(() => readAuthConfig({ API_KEY: 'fake-key', DEMO_CREDENTIALS: 'true', DEMO_ADMIN_PASSWORD: 'CHANGE_ME', DEMO_ANALYST_PASSWORD: 'fake-analyst', DEMO_VIEWER_PASSWORD: 'fake-viewer' }), /DEMO_ADMIN_PASSWORD/);
  assert.equal(readAuthConfig({ API_KEY: 'fake-key', DEMO_CREDENTIALS: 'false' }).demoCredentials, false);
});

test('demo login passwords are accepted only when DEMO_CREDENTIALS is enabled', () => {
  const authConfig = { demoCredentials: false, demoPasswords: { admin: 'fake-demo-admin' } };
  assert.equal(isDemoLoginAccepted(authConfig, 'admin', 'fake-demo-admin'), false);
  authConfig.demoCredentials = true;
  assert.equal(isDemoLoginAccepted(authConfig, 'admin', 'fake-demo-admin'), true);
  assert.equal(isDemoLoginAccepted(authConfig, 'analyst', 'fake-demo-admin'), false);
});

function buildReq(ip, username) {
  return {
    ip,
    socket: { remoteAddress: ip },
    body: { username },
  };
}

test('failed login attempts are blocked until the cooldown expires', () => {
  const ip = '10.112.171.36';
  const username = 'admin';
  const req = buildReq(ip, username);

  for (let i = 0; i < 4; i++) {
    const record = recordLoginFailure(req);
    assert.equal(record.count, i + 1);
    assert.equal(isLoginRateLimited(req), false);
  }

  const blocked = recordLoginFailure(req);
  assert.equal(blocked.count, 5);
  assert.equal(isLoginRateLimited(req), true);

  const repeatAttempt = recordLoginFailure(req);
  assert.equal(repeatAttempt.count, 5);
  assert.equal(isLoginRateLimited(req), true);

  clearLoginFailureState(req);
  assert.equal(isLoginRateLimited(req), false);
});
