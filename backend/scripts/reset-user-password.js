'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const sqlite3 = require('sqlite3').verbose();
const config = require('../config');

const credentialFile = path.join(os.homedir(), 'soc_new_credentials.txt');
const expectedUsers = ['admin', 'analyst', 'viewer'];

function readCredentials() {
  const lines = fs.readFileSync(credentialFile, 'utf8').trim().split(/\r?\n/);
  const credentials = new Map();
  for (const line of lines) {
    const match = line.match(/^(admin|analyst|viewer)=([A-Za-z0-9_-]{43})$/);
    if (!match || credentials.has(match[1])) throw new Error('Credential file format is invalid.');
    credentials.set(match[1], match[2]);
  }
  if (credentials.size !== expectedUsers.length || expectedUsers.some(username => !credentials.has(username))) {
    throw new Error('Credential file must contain exactly the three expected users.');
  }
  return credentials;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `scrypt:${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

async function resetExistingUsers() {
  const credentials = readCredentials();
  const db = new sqlite3.Database(config.dbPath);
  try {
    const users = await new Promise((resolve, reject) => db.all('SELECT username FROM users ORDER BY username', [], (error, rows) => error ? reject(error) : resolve(rows)));
    if (users.length !== expectedUsers.length || expectedUsers.some(username => !users.some(user => user.username === username))) {
      throw new Error('Expected exactly the existing admin, analyst, and viewer accounts; no rows were changed.');
    }
    for (const username of expectedUsers) {
      const result = await new Promise((resolve, reject) => db.run(
        'UPDATE users SET password = ? WHERE username = ?',
        [hashPassword(credentials.get(username)), username],
        function(error) { error ? reject(error) : resolve(this.changes); }
      ));
      if (result !== 1) throw new Error('A user password update did not affect exactly one existing row.');
    }
    console.log('Updated passwords for three existing users.');
  } finally {
    await new Promise(resolve => db.close(resolve));
  }
}

resetExistingUsers().catch(error => {
  console.error(`Password reset utility stopped: ${error.message}`);
  process.exitCode = 1;
});
