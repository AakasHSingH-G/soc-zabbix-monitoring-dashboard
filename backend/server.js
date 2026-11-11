const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const http = require('http');
const net = require('net');
const os = require('os');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');
const db = require('./database');
const config = require('./config');
const { isHoneyAllowlistedIp, isLocalSystemIp } = require('./honey-block-policy');
const initializeWebSocket = require('./websocket');
const zabbixApi = require('./zabbix-api');
const { ensureFallbackReasonColumn } = require('./ai/local-ai');


const app = express();
const instanceLockPath = path.join(__dirname, '.server.lock');
let decoyProcess = null;
let decoyParentPort = null;
let socTargetWatcherTimer = null;
let decoyIntegrityWatcherTimer = null;
let cachedBaselineFileHashes = null;
const socTargetObservations = new Set();

function ensureSingleInstance() {
  try {
    if (fs.existsSync(instanceLockPath)) {
      const previousPid = Number(fs.readFileSync(instanceLockPath, 'utf8').trim());
      if (previousPid && previousPid !== process.pid) {
        try {
          process.kill(previousPid, 0);
          console.warn(`[Startup] Duplicate backend instance detected; PID ${previousPid} is already running. Refusing to start a second backend.`);
          process.exit(1);
        } catch (error) {
          fs.unlinkSync(instanceLockPath);
        }
      }
    }
    fs.writeFileSync(instanceLockPath, String(process.pid));
  } catch (error) {
    console.warn('[Startup] Could not manage backend lock file:', error.message);
  }
}

function clearInstanceLock() {
  try {
    if (fs.existsSync(instanceLockPath)) fs.unlinkSync(instanceLockPath);
  } catch (error) {
    // ignore cleanup errors
  }
}

function stopDecoyProcess() {
  const child = decoyProcess;
  if (!child) return Promise.resolve();
  decoyProcess = null;
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();

  return new Promise(resolve => {
    const forceKillTimer = setTimeout(() => child.kill('SIGKILL'), 3000);
    child.once('exit', () => {
      clearTimeout(forceKillTimer);
      resolve();
    });
    if (!child.kill('SIGTERM')) {
      clearTimeout(forceKillTimer);
      resolve();
    }
  });
}

async function restartDecoyProcess() {
  if (!decoyParentPort) return false;
  if (decoyProcess) await stopDecoyProcess();
  startDecoyProcess(decoyParentPort);
  return true;
}

if (require.main === module) {
  process.on('exit', () => {
    stopDecoyProcess();
    clearInstanceLock();
  });
  const shutdown = async () => {
    await stopDecoyProcess();
    clearInstanceLock();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  ensureSingleInstance();
}

const sessions = new Map();
const loginFailures = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW = 15 * 60 * 1000;
const LOGIN_LIMIT = 5;
const generatedProblems = new Map();
const honeyTelegramEventCache = new Set();
const honeyIncidentTracker = new Map();
const decoyIncidentTracker = new Map();
const activeResponsePolicies = new Map();
const RESPONSE_POLICY_TTL_MS = 30 * 60 * 1000;
const blockedIpState = new Map();
const autoBlockEvidenceByIp = new Map();
const recentAutomationProblemTitles = [];
const PROBLEM_CYCLE_MS = 60000;
const HONEY_BLOCK_DURATION_MS = Number.parseInt(process.env.HONEY_BLOCK_DURATION_MS || String(15 * 1000), 10);
const PROBLEM_LIFETIME_MS = 60000;
const MAX_PROBLEM_HISTORY = 10;
const PROBLEM_AUTO_RESOLVE_MS = 60000;
const telegramNotificationSettings = {
  internal: config.internalTelegramAlertsEnabled,
  honey: config.honeyTelegramAlertsEnabled,
};
const honeyDemoSettings = {
  forceExternal: Boolean(config.honeyDemoForceExternal),
};

// ============================================================
//  MIDDLEWARE — CORS + JSON (ROUTES SE PEHLE HONA CHAHIYE)
// ============================================================
app.use(cors({
  origin(origin, callback) {
    if (!origin || origin === 'null' || config.frontendOrigins.includes(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: true,
}));
app.use(express.json());
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

app.use((req, res, next) => {
  const sourceIp = String(req.socket?.remoteAddress || req.ip || '').replace(/^::ffff:/, '');
  const block = blockedIpState.get(sourceIp);
  if (block && !isHoneyAllowlistedIp(sourceIp) && (!block.expiresAt || new Date(block.expiresAt).getTime() > Date.now())) {
    return res.status(403).json({
      error: 'Temporarily blocked',
      retry_after_seconds: Math.ceil((new Date(block.expiresAt).getTime() - Date.now()) / 1000),
    });
  }
  if (block) blockedIpState.delete(sourceIp);
  next();
});

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!storedPassword) return false;
  if (!storedPassword.startsWith('scrypt:')) return false;

  const [, salt, expectedHash] = storedPassword.split(':');
  const actualHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actualHash, 'hex'), Buffer.from(expectedHash, 'hex'));
}

function verifyAdminPanelCredential(password, user) {
  return verifyPassword(password, user?.admin_panel_password) || verifyPassword(password, user?.password);
}

function isDemoLoginAccepted(authConfig, username, password) {
  return Boolean(authConfig.demoCredentials && authConfig.demoPasswords?.[username] === password);
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    id: user.id,
    username: user.username,
    role: user.role,
    expiresAt: Date.now() + SESSION_TTL,
  });
  return token;
}

function getCookie(req, name) {
  const cookies = req.get('cookie') || '';
  const match = cookies.split(';').map(value => value.trim()).find(value => value.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
  res.setHeader('Set-Cookie', `soc_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'soc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict');
}

function normalizeClientIp(req) {
  const rawIp = String(req.socket?.remoteAddress || req.ip || 'unknown').replace(/^::ffff:/, '').trim();
  return rawIp || 'unknown';
}

function loginKey(req) {
  return normalizeClientIp(req);
}

function clearLoginFailureState(req) {
  loginFailures.delete(loginKey(req));
}

function isLoginRateLimited(req) {
  const key = loginKey(req);
  const record = loginFailures.get(key);
  const now = Date.now();

  if (!record) return false;
  if (record.resetAt <= now) {
    loginFailures.delete(key);
    return false;
  }

  return record.count >= LOGIN_LIMIT;
}

function recordLoginFailure(req) {
  const key = loginKey(req);
  const now = Date.now();
  const existing = loginFailures.get(key) || { count: 0, resetAt: now + LOGIN_WINDOW };

  if (existing.resetAt <= now) {
    existing.count = 0;
    existing.resetAt = now + LOGIN_WINDOW;
  }

  if (existing.count >= LOGIN_LIMIT) {
    loginFailures.set(key, existing);
    return existing;
  }

  existing.count += 1;
  if (existing.count >= LOGIN_LIMIT) {
    existing.resetAt = now + LOGIN_WINDOW;
  }

  loginFailures.set(key, existing);
  return existing;
}

function isAuthorizedDecoyCollectorRequest(req) {
  const requestPath = String(req.originalUrl || req.url || '').split('?', 1)[0];
  return req.method === 'POST' && requestPath === '/api/decoy/events' && req.get('x-api-key') === config.apiKey;
}

function requireAuth(req, res, next) {
  const url = req.originalUrl || req.url || '';
  const path = req.path || '';
  const publicReadOnlyPaths = new Set([
    '/health',
    '/summary',
    '/zabbix/health',
    '/zabbix/summary',
    '/zabbix/status',
    '/zabbix/hosts',
    '/zabbix/problems',
    '/security/health',
    '/security/honeyports',
    '/security/events',
    '/security/stats',
    '/security/attackers',
    '/security/chart/hourly',
    '/security/rules',
    '/security/incidents',
    '/honeypot/summary',
  ]);
  const publicMutationPaths = new Set([
    '/auth/login',
    '/auth/logout',
    '/webhook/new-device',
    '/network/speedtest',
  ]);

  const isPublicRequest = (
    publicMutationPaths.has(path) ||
    publicMutationPaths.has(url.replace(/^\/api/, '')) ||
    url === '/api/auth/login' ||
    url === '/api/auth/logout' ||
    url === '/api/webhook/new-device' ||
    url === '/api/network/speedtest' ||
    publicReadOnlyPaths.has(path) ||
    publicReadOnlyPaths.has(url.replace(/^\/api/, '')) ||
    url === '/api/health' ||
    url === '/api/summary' ||
    url === '/api/zabbix/health' ||
    url === '/api/zabbix/summary' ||
    url === '/api/zabbix/status' ||
    url === '/api/zabbix/hosts' ||
    url === '/api/zabbix/problems'
  );

  if (isAuthorizedDecoyCollectorRequest(req)) return next();

  if (isPublicRequest && (req.method === 'GET' || publicMutationPaths.has(path) || publicMutationPaths.has(url.replace(/^\/api/, '')) || url === '/api/auth/login' || url === '/api/auth/logout' || url === '/api/webhook/new-device' || url === '/api/network/speedtest')) {
    return next();
  }

  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : getCookie(req, 'soc_session');
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Authentication required' });
  }

  req.user = session;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Administrator access required' });
  next();
}

function requireAnalyst(req, res, next) {
  if (!['admin', 'analyst'].includes(req.user?.role)) return res.status(403).json({ error: 'Analyst access required' });
  next();
}

function requireWebhookKey(req, res, next) {
  if (req.get('x-api-key') !== config.apiKey) return res.status(401).json({ error: 'Invalid webhook API key' });
  next();
}

function withEnvelope(source, data) {
  return {
    source,
    as_of: new Date().toISOString(),
    data
  };
}

function defaultState(label, detail) {
  return {
    status: label,
    detail,
    updated_at: new Date().toISOString()
  };
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

async function ensureManualReviewQueueTable(targetDb = db) {
  return new Promise((resolve, reject) => {
    targetDb.run(`CREATE TABLE IF NOT EXISTS manual_review_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      path TEXT,
      method TEXT,
      reason TEXT,
      created_at TEXT NOT NULL,
      reviewed INTEGER DEFAULT 0
    )`, (error) => error ? reject(error) : resolve());
  });
}

function writeAuditLog({ actor = 'anonymous', actorIp = 'unknown', action, entity, details }) {
  return dbRun(
    `INSERT INTO audit_log (actor, actor_ip, action, entity, details, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [actor, actorIp, action, entity, typeof details === 'string' ? details : JSON.stringify(details || {}), new Date().toISOString()]
  ).catch(error => console.warn('[Audit] log write failed:', error.message));
}

function normalizeLocalHostRow(host) {
  return {
    hostid: `local-${host.id}`,
    name: host.hostname,
    host: host.hostname,
    ip: host.ip_address,
    status: host.status === 'online' ? 0 : 1,
    available: host.status === 'online' ? 1 : 0,
    groups: [{ name: host.host_group || 'Local Lab' }],
    cpu: Number(host.cpu_usage || 0),
    ram: Number(host.memory_usage || 0),
    disk: Number(host.disk_usage || 0),
    problems: 0,
  };
}

function normalizeLocalProblemRow(event) {
  const severityValue = (event.severity || 'MED').toUpperCase();
  const severityMap = { DISASTER: 5, CRIT: 5, HIGH: 4, MED: 3, LOW: 2, INFO: 1, INFORMATION: 1 };
  const name = String(event.rule || event.description || 'Local security event');
  return {
    eventid: `local-${event.id}`,
    name,
    host: event.agent || event.src_ip || 'internal-lab',
    severity: severityMap[severityValue] ?? 3,
    severityName: severityValue,
    clock: Math.floor(new Date(event.created_at || Date.now()).getTime() / 1000),
    timestamp: event.created_at || new Date().toISOString(),
    acknowledged: false,
  };
}



app.use('/api', requireAuth);

let localAi = null;
if (config.localAi.enabled) {
  const { createLocalAi } = require('./ai/local-ai');
  localAi = createLocalAi({ db, config: config.localAi, requireAdmin, requireAnalyst, writeAuditLog });
  app.use('/api/ai', localAi.router);
}

app.get('/api/network/speedtest', (req, res) => {
  const requestedBytes = Math.min(16 * 1024 * 1024, Math.max(1 * 1024 * 1024, Number(req.query.size) || 4 * 1024 * 1024));
  const payload = crypto.randomBytes(requestedBytes);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', String(payload.length));
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.send(payload);
});

// ============================================================
//  SENTINELOPS SECURITY MODULE — Wazuh Alert Reader + APIs
// ============================================================

const WAZUH_LOG = '/var/ossec/logs/alerts/alerts.json';

// Defensive TCP decoys. Only connection metadata and a small protocol hint are kept.
const HONEY_PORTS = (process.env.HONEYPORT_PORTS || '2323')
  .split(',')
  .map(value => Number.parseInt(value.trim(), 10))
  .filter(port => Number.isInteger(port) && port > 0 && port < 65536)
  .filter(port => !config.decoy.enabled || port !== config.decoy.port);
const honeyPortEvents = [];
const honeyPortServers = new Map();
const telegramEventCache = new Set();

function normalizeIp(address) {
  return String(address || '').replace(/^::ffff:/i, '');
}

function storeActiveResponsePolicy(attackerIp, policy, ttlMs = RESPONSE_POLICY_TTL_MS) {
  const key = normalizeIp(attackerIp || 'unknown');
  activeResponsePolicies.set(key, {
    policy: { ...(policy || calculateResponsePolicy('LOW')) },
    expiresAt: Date.now() + Math.max(0, Number(ttlMs) || RESPONSE_POLICY_TTL_MS),
  });
}

function getActiveResponsePolicy(attackerIp) {
  const key = normalizeIp(attackerIp || 'unknown');
  const entry = activeResponsePolicies.get(key);
  if (!entry || entry.expiresAt <= Date.now()) {
    activeResponsePolicies.delete(key);
    return calculateResponsePolicy('LOW');
  }
  return { ...entry.policy };
}

const ATTACK_EVENT_TYPES = new Set([
  'PORT_PROBE',
  'HONEYPORT_ACCESS',
  'DECOY_ACCESS',
  'ADMIN_ACCESS',
  'LOGIN_ATTEMPT',
  'API_ACCESS',
  'API_ENUMERATION',
  'FINGERPRINT_PROBE',
  'ESCAPE_ATTEMPT',
  'SOC_TARGETING_ATTEMPT',
  'ADMIN_PANEL_PROBE',
  'DECOY_FINGERPRINTING',
  'SOC_ENUMERATION',
  'ADMIN_ENUMERATION',
]);

const ATTACK_GRAPH_STAGES = [
  'RECON',
  'PORT_PROBE',
  'HONEYPORT_ACCESS',
  'DECOY_ACCESS',
  'ADMIN_ENUMERATION',
  'LOGIN_ATTEMPT',
  'API_ENUMERATION',
  'DECOY_FINGERPRINTING',
  'ESCAPE_ATTEMPT',
  'SOC_ENUMERATION',
  'SOC_TARGETING',
];

const DECEPTION_ROUTE_VARIANTS = {
  web: {
    '/admin': '/control-x7',
    '/login': '/auth-gateway-r4',
    '/products': '/catalog/stream-r2',
    '/checkout': '/transaction/portal-k9',
  },
  api: {
    '/api/login': '/service/auth-v4',
    '/api/products': '/catalog/data-r2',
    '/api/orders': '/transaction/order-k9',
    '/api/admin': '/control/service-p3',
  },
};

let deceptionFreeze = false;
let deceptionRuntimeState = {
  freeze: false,
  maxRotationsPerHour: Number.parseInt(process.env.MAX_ROTATIONS_PER_HOUR || config.deception?.maxRotationsPerHour || '10', 10) || 10,
};

function setDeceptionFreeze(value) {
  deceptionFreeze = Boolean(value);
  deceptionRuntimeState.freeze = deceptionFreeze;
  return deceptionFreeze;
}

function getDeceptionFreeze() {
  return deceptionFreeze;
}

function applyDeceptionConfigState(state = {}) {
  const declaredFreeze = Boolean(state.freeze ?? config.deception?.freeze ?? deceptionRuntimeState.freeze ?? false);
  const maximumRotations = Number(state.maxRotationsPerHour ?? config.deception?.maxRotationsPerHour ?? deceptionRuntimeState.maxRotationsPerHour ?? 10);
  const normalizedMaximum = Number.isFinite(maximumRotations) && maximumRotations >= 0 ? maximumRotations : 10;

  deceptionRuntimeState = {
    freeze: declaredFreeze,
    maxRotationsPerHour: normalizedMaximum,
  };

  setDeceptionFreeze(declaredFreeze);
  return { ...deceptionRuntimeState };
}

async function countRecentRotationEvents(targetDb, attackerIp = 'unknown', windowMinutes = 60, actionList = ['web_route_rotation', 'api_route_rotation', 'api_schema_rotation']) {
  const dbHandle = targetDb || db;
  const allowedTypes = Array.isArray(actionList) && actionList.length ? actionList : ['web_route_rotation', 'api_route_rotation', 'api_schema_rotation'];
  const ip = normalizeIp(attackerIp || 'unknown');
  const cutoff = new Date(Date.now() - (Number(windowMinutes) || 60) * 60000).toISOString();

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS deception_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      action_type TEXT,
      target TEXT,
      reason TEXT,
      previous_value TEXT,
      new_value TEXT,
      timestamp TEXT NOT NULL,
      success INTEGER NOT NULL DEFAULT 0
    )`, err => err ? reject(err) : resolve());
  });

  const rows = await new Promise((resolve, reject) => {
    dbHandle.all(
      `SELECT COUNT(*) AS total FROM deception_actions WHERE attacker_ip = ? AND action_type IN (${allowedTypes.map(() => '?').join(',')}) AND timestamp >= ?`,
      [ip, ...allowedTypes, cutoff],
      (error, result) => error ? reject(error) : resolve(result || [])
    );
  });

  const total = Number(rows?.[0]?.total || 0);
  return total;
}

function evaluateDeceptionTrigger(targetDb, dna = {}) {
  const dbHandle = targetDb || db;
  const severity = String(dna.severity_label || 'LOW').toUpperCase();
  const shouldTrigger =
    severity === 'HIGH' || severity === 'CRITICAL' ||
    Number(dna.endpoints_touched || 0) >= 8 ||
    Number(dna.total_events || 0) >= 12 ||
    Boolean(dna.admin_panel_hit);

  const reasonParts = [];
  if (severity === 'HIGH' || severity === 'CRITICAL') reasonParts.push('severity');
  if (Number(dna.endpoints_touched || 0) >= 8) reasonParts.push('endpoint footprint');
  if (Boolean(dna.admin_panel_hit)) reasonParts.push('admin access');

  return {
    triggered: shouldTrigger && !deceptionFreeze,
    active: !deceptionFreeze,
    reason: reasonParts.length ? `Triggered by ${reasonParts.join(', ')}` : 'No deception trigger',
    freeze: deceptionFreeze,
    attacker_ip: dna.attacker_ip || 'unknown',
    db: !!dbHandle,
  };
}

function calculateResponsePolicy(severity = 'LOW') {
  const label = String(severity || 'LOW').toUpperCase();
  if (label === 'CRITICAL') return { mode: 'critical', delay_ms: 500, manual_review: true, enhanced_instrumentation: true, fake_response: true };
  if (label === 'HIGH') return { mode: 'high', delay_ms: 250, manual_review: false, enhanced_instrumentation: true, fake_response: true };
  if (label === 'MEDIUM') return { mode: 'medium', delay_ms: 0, manual_review: false, enhanced_instrumentation: false, fake_response: false };
  return { mode: 'low', delay_ms: 0, manual_review: false, enhanced_instrumentation: false, fake_response: false };
}

async function rotateApiRoute(targetDb, options = {}) {
  const dbHandle = targetDb || db;
  const oldPath = String(options.old_path || '/api/login');
  const newPath = String(options.new_path || '/service/auth-v4');
  const attackerIp = normalizeIp(options.attacker_ip || 'unknown');
  const reason = String(options.reason || 'api route rotation');
  const rotationLimit = Number(deceptionRuntimeState.maxRotationsPerHour ?? config.deception?.maxRotationsPerHour ?? 10);

  if (deceptionFreeze) {
    return { active: 0, old_path: oldPath, new_path: newPath, frozen: true, reason: 'deception freeze active' };
  }

  if (rotationLimit >= 0) {
    const recentCount = await countRecentRotationEvents(dbHandle, attackerIp, 60, ['api_route_rotation', 'web_route_rotation', 'api_schema_rotation']);
    if (recentCount >= rotationLimit) {
      return { active: 0, route_type: 'api', old_path: oldPath, new_path: newPath, attacker_ip: attackerIp, throttled: true, reason: `rotation limit reached (${rotationLimit} per hour)` };
    }
  }

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS decoy_api_route_map (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      route_type TEXT NOT NULL,
      old_path TEXT,
      new_path TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      rotated_at TEXT NOT NULL,
      reason TEXT,
      attacker_ip TEXT
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO decoy_api_route_map (route_type, old_path, new_path, active, rotated_at, reason, attacker_ip) VALUES (?, ?, ?, 1, ?, ?, ?)`, [
      'api',
      oldPath,
      newPath,
      new Date().toISOString(),
      reason,
      attackerIp,
    ], err => err ? reject(err) : resolve());
  });

  return { active: 1, route_type: 'api', old_path: oldPath, new_path: newPath, attacker_ip: attackerIp, reason };
}

async function adaptApiSchema(targetDb, options = {}) {
  const dbHandle = targetDb || db;
  const currentVersion = String(options.current_version || 'V1');
  const attackerIp = normalizeIp(options.attacker_ip || 'unknown');
  const nextVersion = currentVersion === 'V1' ? 'V2' : 'V1';
  const rotationLimit = Number(deceptionRuntimeState.maxRotationsPerHour ?? config.deception?.maxRotationsPerHour ?? 10);

  if (deceptionFreeze) {
    return { active: 0, schema_version: nextVersion, frozen: true, reason: 'deception freeze active' };
  }

  if (rotationLimit >= 0) {
    const recentCount = await countRecentRotationEvents(dbHandle, attackerIp, 60, ['api_schema_rotation', 'api_route_rotation', 'web_route_rotation']);
    if (recentCount >= rotationLimit) {
      return { active: 0, schema_version: nextVersion, previous_version: currentVersion, attacker_ip: attackerIp, throttled: true, reason: `rotation limit reached (${rotationLimit} per hour)` };
    }
  }

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS decoy_api_schema_map (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      current_version TEXT NOT NULL,
      previous_version TEXT,
      reason TEXT,
      rotated_at TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO decoy_api_schema_map (attacker_ip, current_version, previous_version, reason, rotated_at, active) VALUES (?, ?, ?, ?, ?, 1)`, [
      attackerIp,
      nextVersion,
      currentVersion,
      String(options.reason || 'schema adaptation'),
      new Date().toISOString(),
    ], err => err ? reject(err) : resolve());
  });

  return { active: 1, schema_version: nextVersion, previous_version: currentVersion, attacker_ip: attackerIp };
}

async function resolveActiveDecoyRoute(targetDb, routeType, requestPath, attackerIp = 'unknown') {
  const dbHandle = targetDb || db;
  const type = String(routeType || 'web');
  const pathValue = String(requestPath || '/');
  const table = type === 'api' ? 'decoy_api_route_map' : 'decoy_route_map';
  const params = type === 'api'
    ? [type, pathValue, pathValue, normalizeIp(attackerIp || 'unknown')]
    : [type, pathValue, pathValue];
  const query = type === 'api'
    ? `SELECT old_path, new_path FROM ${table} WHERE route_type = ? AND (new_path = ? OR old_path = ?) AND active = 1 AND (attacker_ip = ? OR attacker_ip = 'unknown') ORDER BY id DESC LIMIT 1`
    : `SELECT old_path, new_path FROM ${table} WHERE route_type = ? AND (new_path = ? OR old_path = ?) AND active = 1 ORDER BY id DESC LIMIT 1`;
  const row = await new Promise((resolve, reject) => {
    dbHandle.get(query, params, (error, result) => error ? reject(error) : resolve(result || null));
  }).catch(() => null);

  if (!row) {
    return { path: pathValue, rotated: false, route_type: type };
  }
  if (pathValue === String(row.old_path || '') && row.old_path !== row.new_path) {
    return { path: pathValue, rotated: false, invalidated: true, route_type: type, old_path: row.old_path, new_path: row.new_path };
  }
  return { path: String(row.old_path || pathValue), rotated: true, route_type: type, old_path: row.old_path, new_path: row.new_path };
}

async function getActiveApiSchema(targetDb, attackerIp = 'unknown') {
  const dbHandle = targetDb || db;
  return new Promise((resolve, reject) => {
    dbHandle.get(
      `SELECT current_version, previous_version, reason, rotated_at FROM decoy_api_schema_map
       WHERE active = 1 AND (attacker_ip = ? OR attacker_ip = 'unknown')
       ORDER BY id DESC LIMIT 1`,
      [normalizeIp(attackerIp || 'unknown')],
      (error, row) => error ? reject(error) : resolve(row || null)
    );
  }).catch(() => null);
}

async function countRegularFiles(rootPath) {
  let total = 0;
  const entries = await fs.promises.readdir(rootPath, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const entryPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) total += await countRegularFiles(entryPath);
    else if (entry.isFile()) total += 1;
  }
  return total;
}

async function computeDecoyFileHashes(dirPath) {
  const hashes = new Map();
  const rootPath = path.resolve(dirPath);
  if (!fs.existsSync(rootPath)) return hashes;

  async function walk(currentPath) {
    const entries = await fs.promises.readdir(currentPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue;
      const entryPath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) {
        await walk(entryPath);
      } else if (entry.isFile()) {
        const relativePath = path.relative(rootPath, entryPath).split(path.sep).join('/');
        const contents = await fs.promises.readFile(entryPath);
        hashes.set(relativePath, crypto.createHash('sha256').update(contents).digest('hex'));
      }
    }
  }

  await walk(rootPath);
  return hashes;
}

async function computeBaselineFileHashes() {
  if (!cachedBaselineFileHashes) {
    cachedBaselineFileHashes = await computeDecoyFileHashes(config.decoy.baselinePath);
  }
  return new Map(cachedBaselineFileHashes);
}

async function restoreDecoyBaseline(targetDb, details = {}) {
  const dbHandle = targetDb || db;
  const timestamp = new Date().toISOString();
  const attackerIp = normalizeIp(details.attacker_ip || 'unknown');

  await new Promise((resolve, reject) => dbHandle.run('UPDATE decoy_route_map SET active = 0 WHERE active = 1', err => err ? reject(err) : resolve())).catch(() => {});
  await new Promise((resolve, reject) => dbHandle.run('UPDATE decoy_api_route_map SET active = 0 WHERE active = 1', err => err ? reject(err) : resolve())).catch(() => {});
  await new Promise((resolve, reject) => dbHandle.run('UPDATE decoy_api_schema_map SET active = 0 WHERE active = 1', err => err ? reject(err) : resolve())).catch(() => {});

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS decoy_route_map (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      route_type TEXT NOT NULL,
      old_path TEXT,
      new_path TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      rotated_at TEXT NOT NULL,
      reason TEXT
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS decoy_api_route_map (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      route_type TEXT NOT NULL,
      old_path TEXT,
      new_path TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      rotated_at TEXT NOT NULL,
      reason TEXT,
      attacker_ip TEXT
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS decoy_api_schema_map (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      current_version TEXT NOT NULL,
      previous_version TEXT,
      reason TEXT,
      rotated_at TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO decoy_route_map (route_type, old_path, new_path, active, rotated_at, reason) VALUES (?, ?, ?, 1, ?, ?)`, [
      'web',
      '/admin',
      '/admin',
      timestamp,
      'self-healing baseline restore',
    ], err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO decoy_api_route_map (route_type, old_path, new_path, active, rotated_at, reason, attacker_ip) VALUES (?, ?, ?, 1, ?, ?, ?)`, [
      'api',
      '/api/login',
      '/api/login',
      timestamp,
      'self-healing baseline restore',
      attackerIp,
    ], err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO decoy_api_schema_map (attacker_ip, current_version, previous_version, reason, rotated_at, active) VALUES (?, ?, ?, ?, ?, 1)`, [
      attackerIp,
      'V1',
      'V2',
      'self-healing baseline restore',
      timestamp,
    ], err => err ? reject(err) : resolve());
  });

  const fileRestore = { attempted: false, success: false, files_restored: null };
  if (dbHandle === db && details.restore_files !== false && fs.existsSync(config.decoy.baselinePath)) {
    fileRestore.attempted = true;
    try {
      await fs.promises.cp(config.decoy.baselinePath, config.decoy.liveSitePath, {
        recursive: true,
        force: true,
      });
      fileRestore.files_restored = await countRegularFiles(config.decoy.baselinePath);
      fileRestore.success = true;
    } catch (error) {
      console.warn('[Decoy] file self-healing restore failed:', error.message);
    }
  }

  setDeceptionFreeze(false);

  return {
    restored: true,
    web_route: '/admin',
    api_route: '/api/login',
    schema_version: 'V1',
    freeze: false,
    file_restore: fileRestore,
  };
}

async function checkDecoyIntegrity(targetDb, details = {}) {
  const dbHandle = targetDb || db;
  const result = String(details.result || 'passed');
  const restored = Boolean(details.restored ?? (result !== 'passed'));

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS decoy_integrity_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      container_id TEXT,
      check_type TEXT,
      result TEXT,
      reason TEXT,
      restored INTEGER NOT NULL DEFAULT 0,
      timestamp TEXT NOT NULL
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO decoy_integrity_events (container_id, check_type, result, reason, restored, timestamp) VALUES (?, ?, ?, ?, ?, ?)`, [
      String(details.container_id || 'decoy-default'),
      String(details.check_type || 'hash'),
      result,
      String(details.reason || 'integrity check'),
      restored ? 1 : 0,
      new Date().toISOString(),
    ], err => err ? reject(err) : resolve());
  });

  let restoreResult = null;
  if (restored || result !== 'passed') {
    restoreResult = await restoreDecoyBaseline(dbHandle, details);
    if (dbHandle === db && restoreResult?.restored) await restartDecoyProcess();
  }

  return {
    container_id: String(details.container_id || 'decoy-default'),
    check_type: String(details.check_type || 'hash'),
    result,
    reason: String(details.reason || 'integrity check'),
    restored,
    event_type: 'DECOY_INTEGRITY_RESTORE',
    restore: restoreResult,
  };
}

async function detectSocTargetingAttempt(targetDb, event = {}) {
  const dbHandle = targetDb || db;
  const destination = String(event.destination || '192.168.200.10');
  const attackerIp = normalizeIp(event.attacker_ip || 'unknown');
  const eventType = 'SOC_TARGETING_ATTEMPT';

  const blockApplied = /^(?:127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)/.test(destination);

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS deception_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      action_type TEXT,
      target TEXT,
      reason TEXT,
      previous_value TEXT,
      new_value TEXT,
      timestamp TEXT NOT NULL,
      success INTEGER NOT NULL DEFAULT 0
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO deception_actions (attacker_ip, action_type, target, reason, previous_value, new_value, timestamp, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
      attackerIp,
      eventType,
      destination,
      'Unauthorized protected network access attempt',
      event.source || 'decoy',
      String(event.destination_port || 443),
      new Date().toISOString(),
      blockApplied ? 1 : 0,
    ], err => err ? reject(err) : resolve());
  });

  let block = null;
  if (blockApplied && attackerIp !== 'unknown') {
    if (dbHandle === db) {
      block = applyHoneyBlock(attackerIp, 'SOC-targeting attempt against protected network', 'SOC-TARGETING');
    } else {
      const expiresAt = new Date(Date.now() + HONEY_BLOCK_DURATION_MS).toISOString();
      await new Promise((resolve, reject) => dbHandle.run(`CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, reason TEXT, incident_id TEXT,
        action TEXT, requested_by TEXT, approved_by TEXT, mode TEXT, ttl_seconds INTEGER,
        created_at TEXT, expires_at TEXT, verified_at TEXT, verify_result TEXT, removed_at TEXT
      )`, error => error ? reject(error) : resolve()));
      await new Promise((resolve, reject) => dbHandle.run(`INSERT INTO blocks
        (ip, reason, incident_id, action, requested_by, approved_by, mode, ttl_seconds, created_at, expires_at, verified_at, verify_result)
        VALUES (?, ?, ?, 'block', 'system', 'system', 'auto', ?, ?, ?, ?, 'blocked')`, [
        attackerIp, 'SOC-targeting attempt against protected network', 'SOC-TARGETING',
        Math.round(HONEY_BLOCK_DURATION_MS / 1000), new Date().toISOString(), expiresAt, new Date().toISOString(),
      ], error => error ? reject(error) : resolve()));
      block = { blocked: true, expiresAt };
    }
  }

  return {
    attacker_ip: attackerIp,
    source: event.source || 'decoy',
    destination,
    destination_port: Number(event.destination_port || 443),
    timestamp: new Date().toISOString(),
    event_type: eventType,
    blocked: blockApplied,
    block,
  };
}

function mapAttackEventToStage(eventType = '') {
  const value = canonicalizeAttackEventType(eventType);
  if (value === 'PORT_PROBE') return 'PORT_PROBE';
  if (value === 'HONEYPORT_ACCESS') return 'HONEYPORT_ACCESS';
  if (value === 'DECOY_ACCESS') return 'DECOY_ACCESS';
  if (value === 'ADMIN_ACCESS' || value === 'ADMIN_PANEL_PROBE' || value === 'ADMIN_ENUMERATION') return 'ADMIN_ENUMERATION';
  if (value === 'LOGIN_ATTEMPT') return 'LOGIN_ATTEMPT';
  if (value === 'API_ENUMERATION' || value === 'API_ACCESS') return 'API_ENUMERATION';
  if (value === 'FINGERPRINT_PROBE' || value === 'DECOY_FINGERPRINTING') return 'DECOY_FINGERPRINTING';
  if (value === 'ESCAPE_ATTEMPT' || value === 'SOC_ENUMERATION') return 'ESCAPE_ATTEMPT';
  if (value === 'SOC_TARGETING_ATTEMPT') return 'SOC_TARGETING';
  return 'RECON';
}

async function registerAttackGraphTransition(targetDb, fromStage, toStage) {
  const dbHandle = targetDb || db;
  if (!dbHandle || typeof dbHandle.run !== 'function') return null;

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS stage_transition_counts (
      from_stage TEXT NOT NULL,
      to_stage TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (from_stage, to_stage)
    )`, err => err ? reject(err) : resolve());
  });

  return new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO stage_transition_counts (from_stage, to_stage, count)
      VALUES (?, ?, 1)
      ON CONFLICT(from_stage, to_stage) DO UPDATE SET count = count + 1`, [fromStage, toStage], function (err) {
      if (err) return reject(err);
      resolve({ fromStage, toStage, count: this.changes || 1 });
    });
  });
}

async function appendAttackGraphEvent(targetDb, event = {}) {
  const dbHandle = targetDb || db;
  if (!dbHandle || typeof dbHandle.run !== 'function') return null;

  const normalized = normalizeAttackEvent(event);
  const stage = mapAttackEventToStage(normalized.event_type);
  const eventId = normalized.event_type || `GRAPH-${Date.now()}-${Math.random().toString(36).slice(2,8)}`;

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS attack_graph_node (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT NOT NULL,
      stage TEXT NOT NULL,
      event_id TEXT,
      timestamp TEXT NOT NULL
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO attack_graph_node (attacker_ip, stage, event_id, timestamp) VALUES (?, ?, ?, ?)`, [
      normalized.attacker_ip,
      stage,
      eventId,
      normalized.timestamp,
    ], err => err ? reject(err) : resolve());
  });

  return { stage, event_id: eventId, attacker_ip: normalized.attacker_ip, timestamp: normalized.timestamp };
}

async function getAttackTwinProbabilities(targetDb, currentStage) {
  const dbHandle = targetDb || db;
  if (!dbHandle || typeof dbHandle.all !== 'function') {
    return { current_stage: currentStage, observed_sequences: 0, transitions: [], message: 'Insufficient historical attack sequence data.' };
  }

  const rows = await new Promise((resolve, reject) => {
    dbHandle.all(`SELECT to_stage, count FROM stage_transition_counts WHERE from_stage = ? ORDER BY count DESC, to_stage ASC`, [currentStage], (err, result) => err ? reject(err) : resolve(result || []));
  });

  if (!rows.length) {
    return { current_stage: currentStage, observed_sequences: 0, transitions: [], message: 'Insufficient historical attack sequence data.' };
  }

  const total = rows.reduce((sum, row) => sum + Number(row.count || 0), 0);
  const transitions = rows.map(row => ({
    to_stage: row.to_stage,
    probability: Number(((Number(row.count || 0) / total) || 0).toFixed(4)),
    count: Number(row.count || 0),
  }));

  return {
    current_stage: currentStage,
    observed_sequences: total,
    transitions,
    message: `Based on ${total} previously observed attack sequences. Historical frequency is not a guarantee of the attacker's next action.`
  };
}

async function rotateDecoyRoute(targetDb, options = {}) {
  const dbHandle = targetDb || db;
  const routeType = String(options.route_type || 'web');
  const oldPath = String(options.old_path || '/admin');
  const newPath = String(options.new_path || DECEPTION_ROUTE_VARIANTS[routeType]?.[oldPath] || '/control-x7');
  const attackerIp = normalizeIp(options.attacker_ip || 'unknown');
  const reason = String(options.reason || 'route rotation');
  const rotationLimit = Number(deceptionRuntimeState.maxRotationsPerHour ?? config.deception?.maxRotationsPerHour ?? 10);

  if (deceptionFreeze) {
    return { active: 0, old_path: oldPath, new_path: newPath, frozen: true, reason: 'deception freeze active' };
  }

  if (rotationLimit >= 0) {
    const recentCount = await countRecentRotationEvents(dbHandle, attackerIp, 60, ['web_route_rotation', 'api_route_rotation', 'api_schema_rotation']);
    if (recentCount >= rotationLimit) {
      return { active: 0, route_type: routeType, old_path: oldPath, new_path: newPath, attacker_ip: attackerIp, throttled: true, reason: `rotation limit reached (${rotationLimit} per hour)` };
    }
  }

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS deception_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      action_type TEXT,
      target TEXT,
      reason TEXT,
      previous_value TEXT,
      new_value TEXT,
      timestamp TEXT NOT NULL,
      success INTEGER NOT NULL DEFAULT 0
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS decoy_route_map (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      route_type TEXT NOT NULL,
      old_path TEXT,
      new_path TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      rotated_at TEXT NOT NULL,
      reason TEXT
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO decoy_route_map (route_type, old_path, new_path, active, rotated_at, reason) VALUES (?, ?, ?, 1, ?, ?)`, [
      routeType,
      oldPath,
      newPath,
      new Date().toISOString(),
      reason,
    ], err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO deception_actions (attacker_ip, action_type, target, reason, previous_value, new_value, timestamp, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
      attackerIp,
      'web_route_rotation',
      routeType,
      reason,
      oldPath,
      newPath,
      new Date().toISOString(),
      1,
    ], err => err ? reject(err) : resolve());
  });

  return { active: 1, route_type: routeType, old_path: oldPath, new_path: newPath, attacker_ip: attackerIp, frozen: false };
}

function canonicalizeAttackEventType(rawType = '') {
  const value = String(rawType || '').trim().toUpperCase().replace(/[^A-Z0-9_]+/g, '_');
  if (!value) return 'API_ACCESS';

  if (ATTACK_EVENT_TYPES.has(value)) return value;
  if (/LOGIN|AUTH/.test(value)) return 'LOGIN_ATTEMPT';
  if (/ADMIN|PANEL/.test(value)) return 'ADMIN_ACCESS';
  if (/ESCAPE|TARGETING|SOC/.test(value)) return 'ESCAPE_ATTEMPT';
  if (/FINGERPRINT|DECOY/.test(value)) return 'FINGERPRINT_PROBE';
  if (/API|ENDPOINT/.test(value)) return 'API_ENUMERATION';
  if (/PORT|PROBE/.test(value)) return 'PORT_PROBE';
  return 'API_ACCESS';
}

function normalizeAttackEvent(raw = {}) {
  const source = String(raw.source || 'unknown');
  const path = String(raw.path || raw.url || raw.route || raw.endpoint || '/');
  const method = String(raw.method || 'GET').toUpperCase();
  const port = Number(raw.port ?? raw.dest_port ?? 0);
  const attackerIp = normalizeIp(raw.attacker_ip || raw.sourceIp || raw.src_ip || raw.ip || 'unknown');

  return {
    attacker_ip: attackerIp,
    timestamp: String(raw.timestamp || new Date().toISOString()),
    source,
    event_type: canonicalizeAttackEventType(raw.event_type || raw.rule || raw.eventType),
    path: path.slice(0, 240),
    method,
    port: Number.isFinite(port) ? port : 0,
    user_agent: String(raw.user_agent || raw.userAgent || '').slice(0, 240),
    status_code: Number(raw.status_code ?? raw.status ?? 0),
    metadata: raw.metadata && typeof raw.metadata === 'object' ? raw.metadata : {},
  };
}

function computeSeverityLabel({
  login_attempts = 0,
  distinct_endpoints = 0,
  admin_panel_hit = false,
  escape_attempt_hits = 0,
} = {}) {
  let level = 0;

  if (Number(login_attempts) > 5) level += 1;
  if (Number(distinct_endpoints) > 10) level += 1;
  if (admin_panel_hit) level += 1;
  if (Number(escape_attempt_hits) > 0) level += 1;

  const labels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return labels[Math.min(level, labels.length - 1)];
}

async function upsertAttackDna(targetDb, rawEvent) {
  const dbHandle = targetDb || db;
  if (!dbHandle || typeof dbHandle.get !== 'function' || typeof dbHandle.run !== 'function') {
    return null;
  }

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS attack_dna (
      attacker_ip TEXT PRIMARY KEY,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      total_events INTEGER NOT NULL DEFAULT 0,
      ports_touched INTEGER NOT NULL DEFAULT 0,
      endpoints_touched INTEGER NOT NULL DEFAULT 0,
      apis_touched INTEGER NOT NULL DEFAULT 0,
      login_attempts INTEGER NOT NULL DEFAULT 0,
      distinct_user_agents INTEGER NOT NULL DEFAULT 0,
      request_rate_per_min REAL NOT NULL DEFAULT 0,
      admin_panel_hit INTEGER NOT NULL DEFAULT 0,
      decoy_fingerprint_hits INTEGER NOT NULL DEFAULT 0,
      escape_attempt_hits INTEGER NOT NULL DEFAULT 0,
      severity_label TEXT NOT NULL DEFAULT 'LOW'
    )`, err => err ? reject(err) : resolve());
  });
  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS attack_dna_observations (
      attacker_ip TEXT NOT NULL,
      dimension TEXT NOT NULL,
      value TEXT NOT NULL,
      PRIMARY KEY (attacker_ip, dimension, value)
    )`, err => err ? reject(err) : resolve());
  });
  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS attack_dna_observation_baseline (
      attacker_ip TEXT NOT NULL,
      dimension TEXT NOT NULL,
      baseline_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (attacker_ip, dimension)
    )`, err => err ? reject(err) : resolve());
  });

  const event = normalizeAttackEvent(rawEvent);
  const attackerIp = event.attacker_ip || 'unknown';
  const timestamp = event.timestamp || new Date().toISOString();

  const existing = await new Promise((resolve, reject) => {
    dbHandle.get('SELECT * FROM attack_dna WHERE attacker_ip = ?', [attackerIp], (err, row) => err ? reject(err) : resolve(row || null));
  });

  const dimensions = [
    ['port', event.port ? String(event.port) : null, Number(existing?.ports_touched || 0)],
    ['endpoint', event.path || null, Number(existing?.endpoints_touched || 0)],
    ['api', /^\/api(?:\/|$)/i.test(event.path || '') ? event.path : null, Number(existing?.apis_touched || 0)],
    ['user_agent', event.user_agent || null, Number(existing?.distinct_user_agents || 0)],
  ];

  for (const [dimension, value, baselineCount] of dimensions) {
    await new Promise((resolve, reject) => {
      dbHandle.run(`INSERT OR IGNORE INTO attack_dna_observation_baseline (attacker_ip, dimension, baseline_count) VALUES (?, ?, ?)`, [
        attackerIp,
        dimension,
        baselineCount,
      ], err => err ? reject(err) : resolve());
    });
    if (value !== null) {
      await new Promise((resolve, reject) => {
        dbHandle.run(`INSERT OR IGNORE INTO attack_dna_observations (attacker_ip, dimension, value) VALUES (?, ?, ?)`, [
          attackerIp,
          dimension,
          value,
        ], err => err ? reject(err) : resolve());
      });
    }
  }

  const dimensionCounts = {};
  for (const [dimension] of dimensions) {
    dimensionCounts[dimension] = await new Promise((resolve, reject) => {
      dbHandle.get(`SELECT baseline.baseline_count + COUNT(observation.value) AS count
        FROM attack_dna_observation_baseline AS baseline
        LEFT JOIN attack_dna_observations AS observation
          ON observation.attacker_ip = baseline.attacker_ip AND observation.dimension = baseline.dimension
        WHERE baseline.attacker_ip = ? AND baseline.dimension = ?`, [attackerIp, dimension], (err, row) => {
        if (err) return reject(err);
        resolve(Number(row?.count || 0));
      });
    });
  }

  const totalEvents = Number(existing?.total_events || 0) + 1;
  const loginAttempts = Number(existing?.login_attempts || 0) + (event.event_type === 'LOGIN_ATTEMPT' ? 1 : 0);
  const adminPanelHit = Boolean(existing?.admin_panel_hit) || /\/admin/i.test(event.path) || event.event_type === 'ADMIN_ACCESS';
  const decoyFingerprintHits = Number(existing?.decoy_fingerprint_hits || 0) + (['FINGERPRINT_PROBE', 'DECOY_FINGERPRINTING'].includes(event.event_type) ? 1 : 0);
  const escapeAttemptHits = Number(existing?.escape_attempt_hits || 0) + (['ESCAPE_ATTEMPT', 'SOC_TARGETING_ATTEMPT'].includes(event.event_type) ? 1 : 0);

  const firstSeen = existing?.first_seen || timestamp;
  const elapsedMinutes = Math.max((new Date(timestamp).getTime() - new Date(firstSeen).getTime()) / 60000, 1 / 60);
  const requestRatePerMin = Number((totalEvents / elapsedMinutes).toFixed(2));
  const severityLabel = computeSeverityLabel({
    login_attempts: loginAttempts,
    distinct_endpoints: dimensionCounts.endpoint,
    admin_panel_hit: adminPanelHit,
    escape_attempt_hits: escapeAttemptHits,
  });

  const record = {
    attacker_ip: attackerIp,
    first_seen: firstSeen,
    last_seen: timestamp,
    total_events: totalEvents,
    ports_touched: dimensionCounts.port,
    endpoints_touched: dimensionCounts.endpoint,
    apis_touched: dimensionCounts.api,
    login_attempts: loginAttempts,
    distinct_user_agents: dimensionCounts.user_agent,
    request_rate_per_min: requestRatePerMin,
    admin_panel_hit: adminPanelHit ? 1 : 0,
    decoy_fingerprint_hits: decoyFingerprintHits,
    escape_attempt_hits: escapeAttemptHits,
    severity_label: severityLabel,
  };

  await new Promise((resolve, reject) => {
    dbHandle.run(`INSERT INTO attack_dna (
      attacker_ip, first_seen, last_seen, total_events, ports_touched, endpoints_touched, apis_touched,
      login_attempts, distinct_user_agents, request_rate_per_min, admin_panel_hit, decoy_fingerprint_hits,
      escape_attempt_hits, severity_label
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(attacker_ip) DO UPDATE SET
      first_seen = excluded.first_seen,
      last_seen = excluded.last_seen,
      total_events = excluded.total_events,
      ports_touched = excluded.ports_touched,
      endpoints_touched = excluded.endpoints_touched,
      apis_touched = excluded.apis_touched,
      login_attempts = excluded.login_attempts,
      distinct_user_agents = excluded.distinct_user_agents,
      request_rate_per_min = excluded.request_rate_per_min,
      admin_panel_hit = excluded.admin_panel_hit,
      decoy_fingerprint_hits = excluded.decoy_fingerprint_hits,
      escape_attempt_hits = excluded.escape_attempt_hits,
      severity_label = excluded.severity_label`, [
        record.attacker_ip,
        record.first_seen,
        record.last_seen,
        record.total_events,
        record.ports_touched,
        record.endpoints_touched,
        record.apis_touched,
        record.login_attempts,
        record.distinct_user_agents,
        record.request_rate_per_min,
        record.admin_panel_hit,
        record.decoy_fingerprint_hits,
        record.escape_attempt_hits,
        record.severity_label,
      ], err => err ? reject(err) : resolve());
  });

  return record;
}

async function getAttackDna(targetDb, attackerIp) {
  const dbHandle = targetDb || db;
  if (!dbHandle || typeof dbHandle.get !== 'function') return null;
  return new Promise((resolve, reject) => {
    dbHandle.get('SELECT * FROM attack_dna WHERE attacker_ip = ?', [normalizeIp(attackerIp || 'unknown')], (err, row) => err ? reject(err) : resolve(row || null));
  });
}

async function recordDecoyAttackDna(targetDb, rawEvent) {
  if (String(rawEvent?.event_source || '') !== 'decoy_ecommerce') return null;
  return upsertAttackDna(targetDb, {
    ...rawEvent,
    attacker_ip: rawEvent.attacker_ip || rawEvent.sourceIp || rawEvent.src_ip,
    source: rawEvent.event_source,
    port: rawEvent.port ?? rawEvent.dest_port,
  });
}

function isValidGeoCoordinate(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= -90 && number <= 90;
}

function isPrivateIp(ip) {
  const value = normalizeIp(ip).trim();
  if (!value || value === 'unknown' || value === '0.0.0.0') return true;
  if (value === '::1' || value.toLowerCase().startsWith('fc') || value.toLowerCase().startsWith('fd') || value.toLowerCase().startsWith('fe80:')) return true;
  const octets = value.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => Number.isNaN(o))) return false;
  return octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168) ||
    octets[0] === 127 ||
    (octets[0] === 169 && octets[1] === 254);
}

function getHoneyScope(address) {
  if (honeyDemoSettings.forceExternal) return 'EXTERNAL';
  return isPrivateIp(address) ? 'INTERNAL' : 'EXTERNAL';
}

function setHoneyExternalDemoMode(forceExternal) {
  honeyDemoSettings.forceExternal = Boolean(forceExternal);
  return honeyDemoSettings.forceExternal;
}

async function lookupIpGeo(ip) {
  const value = normalizeIp(ip);
  if (!value || value === 'unknown' || value === '0.0.0.0' || isPrivateIp(value)) {
    return {
      city: 'Private Network / Local Network',
      region: 'Local Network',
      country: 'Private Network',
      flag: '🏠',
      lat: null,
      lng: null,
      is_private: true,
      asn: 'Unknown / Not Available',
      isp: 'Unknown / Not Available',
      provider: 'local-policy',
      accuracy_radius_km: 'Unknown / Not Available',
    };
  }

  const candidates = [
    `https://ipapi.co/${encodeURIComponent(value)}/json/`,
    `https://ipinfo.io/${encodeURIComponent(value)}/json`
  ];

  for (const url of candidates) {
    try {
      const response = await fetch(url, { headers: { Accept: 'application/json' } });
      if (!response.ok) continue;
      const data = await response.json();
      const city = data?.city || data?.region || 'Unknown city';
      const region = data?.region || data?.region_name || 'Unknown / Not Available';
      const country = data?.country_name || data?.country || 'Unknown';
      const lat = Number(data?.latitude ?? data?.loc?.split(',')[0]);
      const lng = Number(data?.longitude ?? data?.loc?.split(',')[1]);
      const safeLat = isValidGeoCoordinate(lat) ? lat : null;
      const safeLng = isValidGeoCoordinate(lng) ? lng : null;
      if (safeLat !== null && safeLng !== null) {
        return {
          city,
          region,
          country,
          flag: data?.country_code ? data.country_code.toUpperCase() : '•',
          lat: safeLat,
          lng: safeLng,
          is_private: false,
          asn: data?.asn || data?.org || 'Unknown / Not Available',
          isp: data?.org || data?.org_name || 'Unknown / Not Available',
          provider: 'geoip-provider',
          accuracy_radius_km: data?.accuracy_radius || 'Unknown / Not Available',
        };
      }
      if (country && city) {
        return {
          city,
          region,
          country,
          flag: '•',
          lat: null,
          lng: null,
          is_private: false,
          asn: data?.asn || data?.org || 'Unknown / Not Available',
          isp: data?.org || data?.org_name || 'Unknown / Not Available',
          provider: 'geoip-provider',
          accuracy_radius_km: data?.accuracy_radius || 'Unknown / Not Available',
        };
      }
    } catch (error) {
      // retry next provider
    }
  }

  return {
    city: 'Unknown / Not Available',
    region: 'Unknown / Not Available',
    country: 'Unknown / Not Available',
    flag: '•',
    lat: null,
    lng: null,
    is_private: false,
    asn: 'Unknown / Not Available',
    isp: 'Unknown / Not Available',
    provider: 'geoip-provider',
    accuracy_radius_km: 'Unknown / Not Available',
  };
}

async function enrichHoneyEventMetadata(event) {
  const ip = normalizeIp(event?.sourceIp || event?.srcip || event?.source || 'unknown');
  const geo = await lookupIpGeo(ip);
  return {
    ...event,
    sourceIp: ip,
    country: geo.country || 'Unknown / Not Available',
    region: geo.region || 'Unknown / Not Available',
    city: geo.city || 'Unknown / Not Available',
    flag: geo.flag || '•',
    lat: geo.lat ?? null,
    lng: geo.lng ?? null,
    is_private: Boolean(geo.is_private),
    asn: geo.asn || 'Unknown / Not Available',
    isp: geo.isp || 'Unknown / Not Available',
    accuracy_radius_km: geo.accuracy_radius_km || 'Unknown / Not Available',
  };
}

function classifyHoneyPayload(buffer) {
  const preview = buffer.toString('utf8', 0, Math.min(buffer.length, 512));
  const firstLine = preview.split(/\r?\n/, 1)[0].trim();
  const userAgent = preview.match(/^User-Agent:\s*([^\r\n]+)/im)?.[1]?.slice(0, 120);
  let protocol = 'TCP';
  if (/^SSH-/i.test(preview)) protocol = 'SSH';
  else if (/^(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH)\s/i.test(firstLine)) protocol = 'HTTP';
  else if (/^\x16\x03/.test(preview)) protocol = 'TLS';
  return { protocol, clientHint: userAgent || firstLine.slice(0, 120) || 'Connection probe' };
}

function parseClientUserAgent(userAgent) {
  const value = String(userAgent || '').trim();
  if (!value || /^(connection probe|security event|decoy_ecommerce)$/i.test(value)) {
    return {
      browser: 'Unknown / Not Available',
      browser_version: 'Unknown / Not Available',
      os: 'Unknown / Not Available',
      os_version: 'Unknown / Not Available',
      device_type: 'Unknown / Not Available',
    };
  }

  const browserMatch = value.match(/Edg\/([\d.]+)/i) || value.match(/OPR\/([\d.]+)/i)
    || value.match(/Chrome\/([\d.]+)/i) || value.match(/Firefox\/([\d.]+)/i)
    || value.match(/Version\/([\d.]+).*Safari\//i) || value.match(/curl\/([\d.]+)/i)
    || value.match(/PostmanRuntime\/([\d.]+)/i);
  const browser = /Edg\//i.test(value) ? 'Edge' : /OPR\//i.test(value) ? 'Opera'
    : /Chrome\//i.test(value) ? 'Chrome' : /Firefox\//i.test(value) ? 'Firefox'
      : /Safari\//i.test(value) ? 'Safari' : /curl\//i.test(value) ? 'curl'
        : /PostmanRuntime/i.test(value) ? 'Postman' : 'Unknown / Not Available';

  let os = 'Unknown / Not Available';
  let osVersion = 'Unknown / Not Available';
  if (/Windows NT ([\d.]+)/i.test(value)) {
    os = 'Windows';
    osVersion = value.match(/Windows NT ([\d.]+)/i)[1];
  } else if (/Android ([\d.]+)/i.test(value)) {
    os = 'Android';
    osVersion = value.match(/Android ([\d.]+)/i)[1];
  } else if (/(iPhone|iPad).*OS ([\d_]+)/i.test(value)) {
    os = /iPad/i.test(value) ? 'iPadOS' : 'iOS';
    osVersion = value.match(/OS ([\d_]+)/i)[1].replace(/_/g, '.');
  } else if (/Mac OS X ([\d_]+)/i.test(value)) {
    os = 'macOS';
    osVersion = value.match(/Mac OS X ([\d_]+)/i)[1].replace(/_/g, '.');
  } else if (/Linux/i.test(value)) {
    os = 'Linux';
  }

  return {
    browser,
    browser_version: browserMatch?.[1] || 'Unknown / Not Available',
    os,
    os_version: osVersion,
    device_type: /iPad|Tablet/i.test(value) ? 'Tablet' : /Mobile|Android|iPhone/i.test(value) ? 'Mobile' : 'Desktop',
  };
}

function buildTelegramEventText(event) {
  const source = event?.sourceIp || event?.srcip || event?.source || 'unknown';
  const port = event?.honeyPort || event?.dest_port || 'n/a';
  const scope = event?.scope || 'UNKNOWN';
  const severity = event?.severity || event?.level || 'INFO';
  const description = event?.description || event?.rule || 'Security event alert';
  return `🚨 <b>SOC Alert</b>\n` +
    `Severity: <b>${severity}</b>\n` +
    `Source: <code>${source}</code>\n` +
    `Target: <b>${port}</b>\n` +
    `Scope: ${scope}\n` +
    `Details: ${description}\n` +
    `Time: ${event?.timestamp || new Date().toISOString()}`;
}

async function sendTelegramAlertToBot(token, chatId, message) {
  const safeToken = String(token || '').trim();
  const safeChatId = String(chatId || '').trim();
  if (!safeToken || !safeChatId) return false;

  const text = String(message || '').trim();
  if (!text) return false;

  try {
    const response = await fetch(`https://api.telegram.org/bot${safeToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: safeChatId,
        text: text.slice(0, 4000),
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) {
      console.warn('[Telegram] Alert delivery failed:', data?.description || response.statusText || 'unknown error');
      return false;
    }
    return true;
  } catch (error) {
    console.warn('[Telegram] Notification error:', error.message);
    return false;
  }
}

async function sendTelegramAlert(message) {
  if (!telegramNotificationSettings.internal) return false;
  const token = String(config.internalTelegramBotToken || config.telegramBotToken || '').trim();
  const chatId = String(config.internalTelegramChatId || config.telegramChatId || '').trim();
  return sendTelegramAlertToBot(token, chatId, message);
}

async function sendHoneyTelegramAlert(message) {
  if (!telegramNotificationSettings.honey) return false;
  const token = String(config.honeyTelegramBotToken || '').trim();
  const chatId = String(config.honeyTelegramChatId || '').trim();
  return sendTelegramAlertToBot(token, chatId, message);
}

function setTelegramAlertsEnabled(bot, enabled) {
  const safeBot = String(bot || 'internal').toLowerCase();
  const safeEnabled = Boolean(enabled);
  if (safeBot === 'honey') {
    telegramNotificationSettings.honey = safeEnabled;
    return telegramNotificationSettings.honey;
  }
  telegramNotificationSettings.internal = safeEnabled;
  return telegramNotificationSettings.internal;
}

function buildProblemTelegramText(problem, state = 'OPEN') {
  const severity = String(problem?.severity || 'MED').toUpperCase();
  const stateLabel = state === 'RESOLVED' ? 'RESOLVED' : 'NEW';
  return `🚨 <b>SOC Incident ${stateLabel}</b>\n` +
    `ID: <code>${problem?.id || 'AUTO-UNKNOWN'}</code>\n` +
    `Title: <b>${problem?.title || 'Unidentified incident'}</b>\n` +
    `Severity: <b>${severity}</b>\n` +
    `Source: <code>${problem?.source_ip || problem?.src_ip || 'unknown'}</code>\n` +
    `Target: <b>${problem?.agent || problem?.dest_port || 'suspicious service'}</b>\n` +
    `Description: ${problem?.description || 'Automation-generated SOC event'}\n` +
    `Timestamp: ${new Date(problem?.created_at || Date.now()).toISOString()}`;
}

function buildProblemResolvedTelegramText(problem, reason = 'Auto contained by SOC workflow') {
  return `✅ <b>Incident Resolved</b>\n` +
    `ID: <code>${problem?.id || 'AUTO-UNKNOWN'}</code>\n` +
    `Title: <b>${problem?.title || 'Unidentified incident'}</b>\n` +
    `Reason: ${reason}\n` +
    `Source: <code>${problem?.source_ip || problem?.src_ip || 'unknown'}</code>\n` +
    `Resolution time: ${new Date().toISOString()}`;
}

async function triggerN8nAutomation(event) {
  const webhookUrl = String(config.n8nWebhookUrl || '').trim();
  if (!event || !event.source || event.source !== 'soc-automation') {
    console.warn('[n8n] Ignored non-SOC event; honey-port and other telemetry are not allowed in the automation webhook.');
    return false;
  }
  if (!webhookUrl) return false;

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(config.n8nWebhookSecret ? { 'x-webhook-secret': config.n8nWebhookSecret } : {}),
      },
      body: JSON.stringify({
        source: 'zabbix-soc',
        ts: new Date().toISOString(),
        event,
      }),
    });

    if (!response.ok) {
      console.warn('[n8n] Automation webhook rejected:', response.status, response.statusText);
      return false;
    }
    return true;
  } catch (error) {
    console.warn('[n8n] Automation webhook failed:', error.message);
    return false;
  }
}

function triggerTelegramAlert(event) {
  const text = buildTelegramEventText(event);
  sendTelegramAlert(text).catch(() => {});
  return text;
}

function maybeNotifyTelegram(event) {
  const key = [
    event?.sourceIp || event?.srcip || event?.source || 'unknown',
    event?.honeyPort || event?.dest_port || 'tcp',
    event?.rule || event?.description || 'alert',
    event?.timestamp || new Date().toISOString()
  ].join('|');

  if (telegramEventCache.has(key)) return false;
  telegramEventCache.add(key);
  while (telegramEventCache.size > 200) {
    const first = telegramEventCache.values().next().value;
    telegramEventCache.delete(first);
  }
  triggerTelegramAlert(event);
  return true;
}

function maybeNotifyHoneyTelegram(event) {
  const key = [
    event?.sourceIp || event?.srcip || event?.source || 'unknown',
    event?.honeyPort || event?.dest_port || 'tcp',
    event?.rule || event?.description || 'honey-alert',
    event?.timestamp || new Date().toISOString()
  ].join('|');

  if (honeyTelegramEventCache.has(key)) return false;
  honeyTelegramEventCache.add(key);
  while (honeyTelegramEventCache.size > 200) {
    const first = honeyTelegramEventCache.values().next().value;
    honeyTelegramEventCache.delete(first);
  }

  const text = `🛡️ <b>External Honeyport Attack</b>\n` +
    `Source: <code>${event?.sourceIp || 'unknown'}</code>\n` +
    `Target Port: <b>${event?.honeyPort || event?.dest_port || 'unknown'}</b>\n` +
    `Scope: ${event?.scope || 'EXTERNAL'}\n` +
    `Details: ${event?.description || event?.rule || 'External probe detected'}\n` +
    `Time: ${event?.timestamp || new Date().toISOString()}`;
  sendHoneyTelegramAlert(text).catch(() => {});
  return true;
}

async function getLatestAttackStage(targetDb, attackerIp) {
  const dbHandle = targetDb || db;
  if (!dbHandle || typeof dbHandle.get !== 'function') return null;

  return new Promise((resolve, reject) => {
    dbHandle.get(
      'SELECT stage FROM attack_graph_node WHERE attacker_ip = ? ORDER BY id DESC LIMIT 1',
      [normalizeIp(attackerIp || 'unknown')],
      (error, row) => error ? reject(error) : resolve(row ? row.stage : null)
    );
  }).catch(() => null);
}

async function processAdaptiveDecoyEvent(targetDb, event) {
  const dbHandle = targetDb || db;
  const normalized = event && typeof event === 'object' ? event : {};
  const dna = normalized.event_source === 'decoy_ecommerce'
    ? await recordDecoyAttackDna(dbHandle, normalized)
    : null;

  const graphEvent = await appendAttackGraphEvent(dbHandle, normalized).catch(() => null);
  const previousStage = await getLatestAttackStage(dbHandle, normalized.sourceIp || normalized.attacker_ip).catch(() => null);
  if (graphEvent && previousStage && previousStage !== graphEvent.stage) {
    await registerAttackGraphTransition(dbHandle, previousStage, graphEvent.stage).catch(() => null);
  }

  const twin = graphEvent
    ? await getAttackTwinProbabilities(dbHandle, graphEvent.stage).catch(() => null)
    : null;

  const decision = dna ? await evaluateDeceptionTrigger(dbHandle, {
    attacker_ip: normalized.sourceIp || normalized.attacker_ip || 'unknown',
    severity_label: dna.severity_label || normalized.severity || 'LOW',
    endpoints_touched: Number(dna.endpoints_touched || 0),
    total_events: Number(dna.total_events || 0),
    admin_panel_hit: Boolean(dna.admin_panel_hit),
    escape_attempt_hits: Number(dna.escape_attempt_hits || 0),
  }) : { triggered: false, active: true, reason: 'No DNA available', freeze: deceptionFreeze };

  const runtime = {
    dna,
    graph: graphEvent,
    twin,
    decision,
  };

  if (decision.triggered) {
    const oldWebPath = String(normalized.path || '/admin');
    const routeRotation = await rotateDecoyRoute(dbHandle, {
      route_type: 'web',
      old_path: oldWebPath,
      new_path: DECEPTION_ROUTE_VARIANTS.web[oldWebPath] || '/control-x7',
      attacker_ip: normalized.sourceIp || normalized.attacker_ip || 'unknown',
      reason: 'adaptive deception trigger',
    }).catch(() => null);

    const apiPath = (normalized.path && /^\//.test(normalized.path) && normalized.path.includes('/api')) ? normalized.path : '/api/login';
    const apiRotation = await rotateApiRoute(dbHandle, {
      old_path: apiPath,
      new_path: DECEPTION_ROUTE_VARIANTS.api[apiPath] || '/service/auth-v4',
      attacker_ip: normalized.sourceIp || normalized.attacker_ip || 'unknown',
      reason: 'adaptive deception trigger',
    }).catch(() => null);

    const schemaResult = await adaptApiSchema(dbHandle, {
      current_version: 'V1',
      attacker_ip: normalized.sourceIp || normalized.attacker_ip || 'unknown',
      reason: 'adaptive deception trigger',
    }).catch(() => null);

    const responsePolicy = calculateResponsePolicy(dna?.severity_label || normalized.severity || 'LOW');
    storeActiveResponsePolicy(normalized.sourceIp || normalized.attacker_ip || 'unknown', responsePolicy);
    const integrityRecord = await checkDecoyIntegrity(dbHandle, {
      container_id: 'decoy-default',
      check_type: 'route-rotation',
      result: 'failed',
      reason: 'Adaptive runtime triggered route and schema rotation',
      restored: true,
      restore_files: false,
    }).catch(() => null);

    const socTarget = await detectSocTargetingAttempt(dbHandle, {
      attacker_ip: normalized.sourceIp || normalized.attacker_ip || 'unknown',
      source: 'decoy_ecommerce',
      destination: '192.168.200.10',
      destination_port: 443,
      event_type: 'SOC_TARGETING_ATTEMPT',
    }).catch(() => null);

    runtime.rotation = { route: routeRotation, api: apiRotation, schema: schemaResult, policy: responsePolicy, integrity: integrityRecord, soc_targeting: socTarget };
  }

  return runtime;
}

async function collectNormalizedSecurityEvent(event, targetDb = db) {
  const dbHandle = targetDb || db;
  const now = new Date().toISOString();
  const normalized = {
    event_id: event.event_id || `SEC-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
    sourceIp: normalizeIp(String(event.attacker_ip || 'unknown')),
    severity: String(event.severity || 'MED').toUpperCase(),
    event_type: String(event.event_type || 'Security event'),
    event_source: String(event.event_source || 'security'),
    rule: String(event.rule || 'SECURITY_EVENT'),
    user_agent: String(event.user_agent || '').slice(0, 240),
    path: String(event.path || event.url || event.route || '/').slice(0, 240),
    method: String(event.method || 'GET').toUpperCase(),
    status_code: Number(event.status_code ?? event.status ?? 0),
    description: String(event.description || 'Security event'),
    dest_port: Number(event.dest_port || 0),
    metadata: event.metadata || {},
    timestamp: now,
    attacker_ip: String(event.attacker_ip || 'unknown'),
  };

  if (isLocalSystemIp(normalized.sourceIp)) return { ...normalized, ignored: true };

  await new Promise((resolve, reject) => {
    dbHandle.run(`CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT,
      severity TEXT,
      src_ip TEXT,
      dest_port INTEGER,
      rule TEXT,
      agent TEXT,
      user_agent TEXT,
      description TEXT,
      raw_hash TEXT,
      origin TEXT,
      event_source TEXT,
      created_at TEXT
    )`, err => err ? reject(err) : resolve());
  });

  await new Promise((resolve, reject) => {
    dbHandle.run(
      `INSERT INTO security_events (source, severity, src_ip, dest_port, rule, agent, user_agent, description, raw_hash, origin, event_source, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [normalized.event_source, normalized.severity, normalized.sourceIp, normalized.dest_port, normalized.rule, normalized.event_source, normalized.user_agent, normalized.description, normalized.event_id, 'decoy', normalized.event_source, now],
      err => err ? reject(err) : resolve()
    );
  });

  if (normalized.event_source === 'decoy_ecommerce') {
    try {
      normalized.runtime = await processAdaptiveDecoyEvent(dbHandle, normalized);
    } catch (error) {
      console.warn('[DecoyDNA] event aggregation failed:', error.message);
    }
  }

  maybeNotifyTelegram(normalized);
  evaluateDecoyIncident(normalized, dbHandle);
  return normalized;
}

function evaluateDecoyIncident(event, targetDb = db) {
  const dbHandle = targetDb || db;
  const ip = String(event.sourceIp || 'unknown');
  const now = Date.now();
  const current = decoyIncidentTracker.get(ip) || { timestamps: [], incidentId: null };
  current.timestamps = current.timestamps.filter(timestamp => now - timestamp <= 60000);
  current.timestamps.push(now);
  if (current.timestamps.length < 3) {
    decoyIncidentTracker.set(ip, current);
    return null;
  }

  const incidentId = current.incidentId || `DECOY-${crypto.createHash('sha1').update(ip).digest('hex').slice(0, 10)}`;
  const nowIso = new Date().toISOString();
  if (!current.incidentId) {
    current.incidentId = incidentId;
    new Promise((resolve, reject) => {
      dbHandle.run(
        `CREATE TABLE IF NOT EXISTS incidents (
          id TEXT PRIMARY KEY,
          title TEXT,
          severity TEXT,
          source_ip TEXT,
          rule TEXT,
          mitre TEXT,
          stage TEXT,
          evidence TEXT,
          acknowledged_by TEXT,
          created_at TEXT,
          updated_at TEXT
        )`,
        err => err ? reject(err) : resolve()
      );
    }).then(() => dbHandle.run(
      `INSERT OR REPLACE INTO incidents (id, title, severity, source_ip, rule, mitre, stage, evidence, acknowledged_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [incidentId, 'E-commerce decoy interaction cluster', 'HIGH', ip, event.rule, 'T1190', 'Detected', `${current.timestamps.length} synthetic decoy events observed within 60 seconds.`, 'decoy-collector', nowIso, nowIso]
    )).catch(error => console.warn('[DecoyIncident] insert failed:', error.message));
    applyHoneyBlock(ip, 'Repeated e-commerce decoy activity', incidentId);
  }
  decoyIncidentTracker.set(ip, current);
  return incidentId;
}

function mountDecoyCollector() {
  if (!config.decoy.enabled) return;
  app.post('/api/decoy/events', async (req, res) => {
    if (req.get('x-api-key') !== config.apiKey) return res.status(401).json({ error: 'Invalid decoy adapter key' });
    try {
      if (req.body?.operation === 'response_policy') {
        const attackerIp = normalizeIp(String(req.body.attacker_ip || req.ip || 'unknown'));
        return res.json({ policy: getActiveResponsePolicy(attackerIp) });
      }
      if (req.body?.operation === 'route_resolution') {
        const route = await resolveActiveDecoyRoute(db, req.body.route_type || 'web', req.body.path || '/', req.body.attacker_ip || req.ip || 'unknown');
        return res.json(route);
      }
      if (req.body?.operation === 'schema_resolution') {
        const schema = await getActiveApiSchema(db, req.body.attacker_ip || req.ip || 'unknown');
        return res.json({ schema: schema || { current_version: 'V1' } });
      }
      if (req.body?.event_source !== 'decoy_ecommerce') return res.status(400).json({ error: 'Invalid decoy event source' });
      const event = await collectNormalizedSecurityEvent(req.body);
      const block = blockedIpState.get(event.sourceIp);
      res.status(202).json({
        accepted: true,
        event_id: event.event_id,
        blocked: Boolean(block),
        expiresAt: block?.expiresAt || null,
      });
    } catch (error) {
      console.warn('[DecoyCollector] isolated event failure:', error.message);
      res.status(503).json({ error: 'Event collector unavailable' });
    }
  });
}

function startDecoyProcess(parentPort) {
  if (!config.decoy.enabled || decoyProcess) return;
  decoyParentPort = parentPort;
  try {
    decoyProcess = spawn(process.execPath, [path.join(__dirname, 'decoy-server.js')], {
      env: {
        ...process.env,
        DECOY_COLLECTOR_URL: `http://127.0.0.1:${parentPort}/api/decoy/events`,
        DECOY_PORT: String(config.decoy.port),
        DECOY_DB_PATH: config.decoy.dbPath,
        DECOY_PARENT_ORIGINS: `http://${getAdvertisedIp()}:${parentPort} http://localhost:${parentPort} http://127.0.0.1:${parentPort}`,
        BLOCK_DB_PATH: config.dbPath,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    decoyProcess.stdout.on('data', chunk => process.stdout.write(`[Decoy] ${chunk}`));
    decoyProcess.stderr.on('data', chunk => process.stderr.write(`[Decoy] ${chunk}`));
    decoyProcess.on('error', error => console.warn('[Decoy] child process error; SOC remains available:', error.message));
    decoyProcess.on('exit', (code, signal) => {
      console.warn(`[Decoy] child stopped (code=${code ?? 'null'}, signal=${signal || 'none'}); SOC and Honey Port remain available.`);
      decoyProcess = null;
    });
  } catch (error) {
    console.warn('[Decoy] child process failed to start; SOC and Honey Port remain available:', error.message);
  }
}

function startSocTargetWatcher() {
  if (!config.deception.socTargetWatcher || socTargetWatcherTimer) return;
  const scan = () => {
    execFile('ss', ['-ntH'], { timeout: 1500 }, async (error, stdout = '') => {
      if (error) return;
      for (const line of String(stdout).split('\n')) {
        const match = line.match(/\b(?:ESTAB|SYN-SENT|SYN-RECV)\s+\S+\s+\S+\s+\S+:\d+\s+(\d+\.\d+\.\d+):(\d+)/);
        if (!match || !match[1].startsWith('192.168.200.')) continue;
        const observation = `${match[1]}:${match[2]}`;
        if (socTargetObservations.has(observation)) continue;
        socTargetObservations.add(observation);
        if (socTargetObservations.size > 500) socTargetObservations.delete(socTargetObservations.values().next().value);
        await detectSocTargetingAttempt(db, {
          attacker_ip: 'local-network-watcher',
          source: 'outbound-connection-watcher',
          destination: match[1],
          destination_port: Number(match[2]),
          event_type: 'SOC_TARGETING_ATTEMPT',
        }).catch(watcherError => console.warn('[SOC watcher] detection failed:', watcherError.message));
      }
    });
  };
  scan();
  socTargetWatcherTimer = setInterval(scan, 5000);
  socTargetWatcherTimer.unref?.();
}

function startDecoyIntegrityWatcher() {
  if (!config.deception.integrityWatcher || decoyIntegrityWatcherTimer) return;
  let checkInProgress = false;

  const scan = async () => {
    if (checkInProgress || !fs.existsSync(config.decoy.baselinePath) || !fs.existsSync(config.decoy.liveSitePath)) return;
    checkInProgress = true;
    try {
      const baselineHashes = await computeBaselineFileHashes();
      const liveHashes = await computeDecoyFileHashes(config.decoy.liveSitePath);
      const changedFiles = new Set();

      for (const [relativePath, baselineHash] of baselineHashes) {
        if (liveHashes.get(relativePath) !== baselineHash) changedFiles.add(relativePath);
      }
      for (const relativePath of liveHashes.keys()) {
        if (!baselineHashes.has(relativePath)) changedFiles.add(relativePath);
      }

      if (changedFiles.size) {
        const changedList = [...changedFiles].sort().slice(0, 5).join(', ');
        await checkDecoyIntegrity(db, {
          container_id: 'decoy-default',
          check_type: 'file-hash',
          result: 'failed',
          reason: `Tampered files detected: ${changedList}`,
          restored: true,
        });
      }
    } catch (error) {
      console.warn('[Decoy] integrity watcher failed:', error.message);
    } finally {
      checkInProgress = false;
    }
  };

  scan();
  decoyIntegrityWatcherTimer = setInterval(scan, 30000);
  decoyIntegrityWatcherTimer.unref?.();
}

function unblockHoneyIp(ip, reason) {
  const key = String(ip || '').trim();
  if (!key || !blockedIpState.has(key)) return false;
  const current = blockedIpState.get(key);
  if (current?.timer) clearTimeout(current.timer);
  blockedIpState.delete(key);

  dbRun(
    `UPDATE blocks SET removed_at = ?, verify_result = ?, action = ? WHERE ip = ? AND removed_at IS NULL ORDER BY id DESC LIMIT 1`,
    [new Date().toISOString(), reason || 'auto-expired', 'unblock', key]
  ).catch(() => {});

  sendHoneyTelegramAlert(`✅ <b>Honeyport IP Unblocked</b>\nIP: <code>${key}</code>\nReason: ${reason || 'Temporary block expired'}\nTime: ${new Date().toISOString()}`).catch(() => {});
  return true;
}

function applyHoneyBlock(ip, reason, incidentId, { permanent = false } = {}) {
  const key = normalizeIp(String(ip || '').trim());
  if (!key || key === 'unknown' || isHoneyAllowlistedIp(key)) {
    return { blocked: false, reason: 'allowlisted' };
  }
  if (blockedIpState.has(key)) {
    const existing = blockedIpState.get(key);
    if (!permanent) return { blocked: true, duplicate: true, expiresAt: existing.expiresAt };
    if (existing.timer) clearTimeout(existing.timer);
    blockedIpState.set(key, { incidentId, reason, expiresAt: null, timer: null, mode: 'manual' });
    dbRun(
      `UPDATE blocks SET reason = ?, incident_id = ?, requested_by = 'admin', approved_by = 'admin', mode = 'manual', ttl_seconds = NULL, expires_at = NULL, verify_result = 'blocked' WHERE ip = ? AND removed_at IS NULL`,
      [reason || 'manual block', incidentId || 'MANUAL-BLOCK', key]
    ).then(result => {
      if (!result.changes) {
        return dbRun(
          `INSERT INTO blocks (ip, reason, incident_id, action, requested_by, approved_by, mode, ttl_seconds, created_at, expires_at, verified_at, verify_result, removed_at)
           VALUES (?, ?, ?, 'block', 'admin', 'admin', 'manual', NULL, ?, NULL, ?, 'blocked', NULL)`,
          [key, reason || 'manual block', incidentId || 'MANUAL-BLOCK', new Date().toISOString(), new Date().toISOString()]
        );
      }
      return null;
    }).catch(error => console.warn('[Security] Could not persist manual IP block:', error.message));
    return { blocked: true, duplicate: true, permanent: true, expiresAt: null };
  }

  const expiresAt = permanent ? null : new Date(Date.now() + HONEY_BLOCK_DURATION_MS).toISOString();
  const timer = permanent ? null : setTimeout(() => unblockHoneyIp(key, 'Temporary block expired'), HONEY_BLOCK_DURATION_MS);
  blockedIpState.set(key, { incidentId, reason, expiresAt, timer, mode: permanent ? 'manual' : 'auto' });

  dbRun(
    `INSERT INTO blocks (ip, reason, incident_id, action, requested_by, approved_by, mode, ttl_seconds, created_at, expires_at, verified_at, verify_result, removed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [key, reason || 'honeyport threshold exceeded', incidentId || 'AUTO-HONEY', 'block', permanent ? 'admin' : 'system', permanent ? 'admin' : 'system', permanent ? 'manual' : 'auto', permanent ? null : Math.round(HONEY_BLOCK_DURATION_MS / 1000), new Date().toISOString(), expiresAt, new Date().toISOString(), 'blocked', null]
  ).catch(() => {});

  sendHoneyTelegramAlert(`🚨 <b>Honeyport IP Blocked</b>\nIP: <code>${key}</code>\nIncident: <code>${incidentId || 'AUTO-HONEY'}</code>\nReason: ${reason || 'Repeated honeyport probe'}\nExpires: ${expiresAt || 'Manual unblock required'}`).catch(() => {});
  return { blocked: true, duplicate: false, permanent, expiresAt };
}

async function loadPersistedHoneyBlocks() {
  try {
    const rows = await dbAll(`SELECT ip, reason, incident_id, expires_at, mode FROM blocks WHERE removed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, [new Date().toISOString()]);
    rows.forEach(row => {
      const key = String(row.ip || '').trim();
      const expiresAt = row.expires_at ? new Date(row.expires_at).getTime() : null;
      if (!key || isHoneyAllowlistedIp(key) || (expiresAt !== null && (!Number.isFinite(expiresAt) || expiresAt <= Date.now()))) return;
      const timer = expiresAt === null ? null : setTimeout(() => unblockHoneyIp(key, 'Temporary block expired'), Math.max(0, expiresAt - Date.now()));
      blockedIpState.set(key, { incidentId: row.incident_id, reason: row.reason, expiresAt: row.expires_at, timer, mode: row.mode || 'auto' });
    });
    if (rows.length) console.log(`[Security] Restored ${rows.length} active IP block(s) from SQLite.`);
  } catch (error) {
    console.warn('[Security] Could not restore persisted IP blocks:', error.message);
  }
}

const THREAT_SCORE_BLOCK_THRESHOLD = 50;

async function markSecurityHistoryCleared(targetDb = db, clearedAt = Date.now()) {
  await new Promise((resolve, reject) => {
    targetDb.run(
      `INSERT INTO threat_intel_state (state_key, state_value, updated_at)
       VALUES ('cleared_at', ?, CURRENT_TIMESTAMP)
       ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value, updated_at = CURRENT_TIMESTAMP`,
      [String(clearedAt)],
      error => error ? reject(error) : resolve()
    );
  });
  return clearedAt;
}

function isAfterSecurityHistoryClear(timestamp, clearedAt) {
  const eventTime = new Date(timestamp || 0).getTime();
  return Number.isFinite(eventTime) && eventTime > clearedAt;
}

function getThreatScore(maxLevel, hits) {
  return Math.min(100, Math.round((maxLevel / 15) * 60 + Math.min(hits, 10) * 4));
}

function hasNewAutoBlockEvidence(attacker) {
  const ip = normalizeIp(attacker?.ip || 'unknown');
  if (!ip || ip === 'unknown') return false;

  const fingerprint = JSON.stringify([
    String(attacker.lastSeen || ''),
    Number(attacker.hits || 0),
    Number(attacker.threatScore || 0),
  ]);
  if (autoBlockEvidenceByIp.get(ip) === fingerprint) return false;

  autoBlockEvidenceByIp.delete(ip);
  autoBlockEvidenceByIp.set(ip, fingerprint);
  if (autoBlockEvidenceByIp.size > 2048) {
    autoBlockEvidenceByIp.delete(autoBlockEvidenceByIp.keys().next().value);
  }
  return true;
}

function autoBlockHighThreatAttacker(attacker) {
  const lastSeenAt = new Date(attacker.lastSeen || 0).getTime();
  const isRecent = Number.isFinite(lastSeenAt) && Date.now() - lastSeenAt <= HONEY_BLOCK_DURATION_MS;
  if (attacker.threatScore >= THREAT_SCORE_BLOCK_THRESHOLD && isRecent && hasNewAutoBlockEvidence(attacker)) {
    return applyHoneyBlock(attacker.ip, `Threat score ${attacker.threatScore} reached the auto-block threshold`, 'AUTO-THREAT-SCORE');
  }
  return null;
}

function evaluateHoneyIncident(event) {
  const ip = String(event?.sourceIp || 'unknown');
  const now = Date.now();
  const windowMs = 60000;
  const threshold = event?.scope === 'EXTERNAL' ? 1 : 5;
  const current = honeyIncidentTracker.get(ip) || { timestamps: [], incidentId: null };
  current.timestamps = (current.timestamps || []).filter(ts => now - ts <= windowMs);
  current.timestamps.push(now);

  const hitCount = current.timestamps.length;
  if (hitCount < threshold) {
    honeyIncidentTracker.set(ip, current);
    return null;
  }

  const incidentId = current.incidentId || `HONEY-${crypto.createHash('sha1').update(ip).digest('hex').slice(0, 10)}`;
  const title = `Honeyport attack from ${ip}`;
  const severity = event?.scope === 'EXTERNAL' ? 'HIGH' : 'MED';
  const rule = `HONEYPORT_DECOY_PORT_${event?.honeyPort || 'unknown'}`;
  const nowIso = new Date().toISOString();
  const evidence = `Repeated honeypot activity from ${ip} targeted TCP ${event?.honeyPort || 'unknown'} within ${windowMs / 1000}s.`;

  if (!current.incidentId) {
    current.incidentId = incidentId;
    honeyIncidentTracker.set(ip, current);

    dbRun(
      `INSERT OR REPLACE INTO incidents (id, title, severity, source_ip, rule, mitre, stage, evidence, acknowledged_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [incidentId, title, severity, ip, rule, 'T1046', 'Detected', evidence, 'auto-honeypot', nowIso, nowIso]
    ).catch(error => console.warn('[HoneyIncident] insert failed:', error.message));

    dbRun(
      `INSERT INTO security_events (source, severity, src_ip, dest_port, rule, agent, description, raw_hash, origin, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ['honeypot-soc', severity, ip, Number(event?.honeyPort || 0), rule, `honey-port-${event?.honeyPort || 'unknown'}`, evidence, incidentId, 'honeypot', nowIso]
    ).catch(error => console.warn('[HoneyIncident] event insert failed:', error.message));
  } else {
    honeyIncidentTracker.set(ip, current);
    dbRun(
      `UPDATE incidents SET severity = ?, evidence = ?, updated_at = ? WHERE id = ?`,
      [severity, evidence, nowIso, incidentId]
    ).catch(error => console.warn('[HoneyIncident] update failed:', error.message));
  }

  applyHoneyBlock(ip, `Repeated honeypot activity on TCP ${event?.honeyPort || 'unknown'}`, incidentId);
  return incidentId;
}

function recordHoneyConnection(socket, port) {
  const sourceIp = normalizeIp(socket.remoteAddress || 'unknown');
  const event = {
    id: `HP-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
    timestamp: new Date().toISOString(),
    sourceIp,
    scope: getHoneyScope(sourceIp),
    sourcePort: socket.remotePort || null,
    honeyPort: port,
    protocol: 'TCP',
    clientHint: 'Connection opened',
    bytesReceived: 0,
  };
  if (isLocalSystemIp(sourceIp)) return event;

  honeyPortEvents.unshift(event);
  honeyPortEvents.splice(100);

  if (event.scope === 'EXTERNAL') {
    maybeNotifyHoneyTelegram({
      sourceIp,
      honeyPort: port,
      scope: event.scope,
      severity: 'HIGH',
      description: `External honey-port connection detected on TCP ${port}`,
      timestamp: event.timestamp,
      rule: `HONEYPORT_DECOY_PORT_${port}`,
    });
  } else {
    maybeNotifyTelegram({
      sourceIp,
      honeyPort: port,
      scope: event.scope,
      severity: event.scope === 'INTERNAL' ? 'MED' : 'HIGH',
      description: `HoneyPort connection detected on TCP ${port}`,
      timestamp: event.timestamp,
      rule: `HONEYPORT_DECOY_PORT_${port}`,
    });
  }

  evaluateHoneyIncident(event);
  return event;
}

function startHoneyPorts() {
  HONEY_PORTS.forEach(port => {
    const decoy = net.createServer(socket => {
      const sourceIp = normalizeIp(socket.remoteAddress || 'unknown');
      if (blockedIpState.has(sourceIp) && !isHoneyAllowlistedIp(sourceIp)) {
        socket.destroy();
        return;
      }
      const event = recordHoneyConnection(socket, port);
      const banner = `\r\n[honeypot] decoy service on port ${port}\r\nsource=${sourceIp}\r\nThis endpoint is intentionally inactive. Connection logged for SOC monitoring.\r\n`;
      const decoyBanner = port === 2323 && config.decoy.enabled
        ? `\r\n========================================\r\n Internal Web Service\r\n========================================\r\n\r\nE-Commerce Web Portal:\r\nhttp://${getAdvertisedIp()}:${config.decoy.port}/\r\n\r\n========================================\r\n`
        : '';
      socket.setTimeout(15000);
      socket.write(banner + decoyBanner);
      socket.on('data', chunk => {
        if (event.bytesReceived >= 4096) return;
        event.bytesReceived += Math.min(chunk.length, 4096 - event.bytesReceived);
        if (event.clientHint === 'Connection opened') {
          Object.assign(event, classifyHoneyPayload(chunk));
        }
      });
      socket.on('timeout', () => socket.destroy());
      socket.on('error', () => socket.destroy());
      socket.on('close', () => { event.closedAt = new Date().toISOString(); });
    });

    decoy.on('error', error => {
      if (error.code === 'EADDRINUSE') {
        console.warn(`[HoneyPort] Port ${port} is already in use; decoy disabled.`);
      } else {
        console.warn(`[HoneyPort] Port ${port} failed: ${error.message}`);
      }
    });
    decoy.listen(port, '0.0.0.0', () => {
      honeyPortServers.set(port, decoy);
      console.log(`[HoneyPort] Listening on TCP ${port}`);
    });
  });
}

// 15 realistic mock alerts (used when Wazuh is not available)
const MOCK_ALERTS = [
  { timestamp: null, rule: { level: 14, description: 'Ransomware behaviour detected: mass file encryption' }, data: { srcip: '185.220.101.47' }, agent: { name: 'srv-web-01' }, location: '/var/log/syslog' },
  { timestamp: null, rule: { level: 12, description: 'SSH brute force attack: 50+ failed logins from single IP' }, data: { srcip: '103.85.24.190' }, agent: { name: 'auth-srv-01' }, location: '/var/log/auth.log' },
  { timestamp: null, rule: { level: 10, description: 'SQL Injection pattern detected in web request' }, data: { srcip: '91.108.4.22' }, agent: { name: 'nginx-lb-02' }, location: '/var/log/nginx/access.log' },
  { timestamp: null, rule: { level: 13, description: 'Privilege escalation: unauthorized sudo usage' }, data: { srcip: '10.0.1.55' }, agent: { name: 'srv-db-01' }, location: '/var/log/auth.log' },
  { timestamp: null, rule: { level: 11, description: 'Port scan detected: NMAP SYN scan from external IP' }, data: { srcip: '45.33.32.156' }, agent: { name: 'fw-edge-01' }, location: '/var/log/firewall.log' },
  { timestamp: null, rule: { level: 7, description: 'Suspicious DNS query: possible data exfiltration via DNS tunnel' }, data: { srcip: '172.16.0.23' }, agent: { name: 'k8s-node-03' }, location: '/var/log/named.log' },
  { timestamp: null, rule: { level: 9, description: 'Credential stuffing: multiple accounts failed in rapid succession' }, data: { srcip: '194.165.16.72' }, agent: { name: 'auth-srv-01' }, location: '/var/log/auth.log' },
  { timestamp: null, rule: { level: 14, description: 'Known malware hash detected: Emotet variant' }, data: { srcip: '198.51.100.42' }, agent: { name: 'srv-web-03' }, location: '/var/log/clamav/clamd.log' },
  { timestamp: null, rule: { level: 8, description: 'Firewall rule modified by non-admin user' }, data: { srcip: '10.0.0.15' }, agent: { name: 'fw-edge-01' }, location: '/var/log/firewall.log' },
  { timestamp: null, rule: { level: 12, description: 'Web shell uploaded to web server directory' }, data: { srcip: '103.21.244.0' }, agent: { name: 'nginx-lb-02' }, location: '/var/log/nginx/error.log' },
  { timestamp: null, rule: { level: 6, description: 'Failed sudo attempt: user not in sudoers file' }, data: { srcip: '10.0.1.88' }, agent: { name: 'srv-api-04' }, location: '/var/log/auth.log' },
  { timestamp: null, rule: { level: 10, description: 'Reverse shell connection established to external C2 server' }, data: { srcip: '85.209.43.110' }, agent: { name: 'srv-db-01' }, location: '/var/log/syslog' },
  { timestamp: null, rule: { level: 7, description: 'Anomalous outbound traffic: large data transfer at 3 AM' }, data: { srcip: '10.0.2.34' }, agent: { name: 'backup-srv-01' }, location: '/var/log/netflow.log' },
  { timestamp: null, rule: { level: 11, description: 'Buffer overflow attempt detected in HTTP header' }, data: { srcip: '5.188.206.26' }, agent: { name: 'nginx-lb-02' }, location: '/var/log/nginx/access.log' },
  { timestamp: null, rule: { level: 9, description: 'Lateral movement detected: SMB scan on internal subnet' }, data: { srcip: '10.0.1.77' }, agent: { name: 'srv-web-07' }, location: '/var/log/samba/log.smbd' },
];

// Severity mapping (same as SentinelOps api.py logic)
function mapSeverity(level) {
  if (level >= 13) return 'CRIT';
  if (level >= 10) return 'HIGH';
  if (level >= 6)  return 'MED';
  return 'LOW';
}

// Wazuh alert reader — tails last 300 lines efficiently
function readWazuhAlerts() {
  let wazuhConnected = false;
  let rawAlerts = [];

  try {
    if (!fs.existsSync(WAZUH_LOG)) {
      return { alerts: [], wazuhConnected: false };
    }

    const content = fs.readFileSync(WAZUH_LOG, 'utf8');
    const lines = content.trim().split('\n').slice(-300);
    rawAlerts = lines
      .map(l => { try { return JSON.parse(l); } catch(e) { return null; } })
      .filter(Boolean);
    wazuhConnected = rawAlerts.length > 0;
  } catch (e) {
    wazuhConnected = false;
    rawAlerts = [];
  }

  rawAlerts.forEach(alert => {
    const normalized = {
      sourceIp: alert?.data?.srcip || alert?.agent?.ip || '0.0.0.0',
      dest_port: alert?.data?.dest_port || alert?.data?.src_port || 'n/a',
      rule: alert?.rule?.description || alert?.location || 'WAZUH_ALERT',
      description: alert?.rule?.description || 'Wazuh security event',
      timestamp: alert?.timestamp || new Date().toISOString(),
      severity: mapSeverity(alert?.rule?.level || 3),
      scope: 'EXTERNAL',
    };
    maybeNotifyTelegram(normalized);
  });

  return { alerts: rawAlerts, wazuhConnected };
}

// Parse alerts into normalized event objects
function parseAlerts(rawAlerts) {
  return rawAlerts.map(a => {
    const level = a.rule?.level || 3;
    const severity = mapSeverity(level);
    return {
      timestamp: a.timestamp || new Date().toISOString(),
      severity,
      level,
      description: a.rule?.description || 'Unknown alert',
      srcip: a.data?.srcip || a.agent?.ip || '0.0.0.0',
      agent: a.agent?.name || 'unknown',
      rule: a.location || 'wazuh',
    };
  }).slice(0, 25); // max 25 in feed
}

// Attacker IP aggregation (SentinelOps /api/attackers logic)
function aggregateAttackers(rawAlerts, clearedAt = 0, limit = 10) {
  const ipMap = {};
  rawAlerts.forEach(a => {
    if (new Date(a.timestamp || 0).getTime() <= clearedAt) return;
    const ip = a.data?.srcip || a.agent?.ip || null;
    if (!ip || isLocalSystemIp(ip)) return;
    if (!ipMap[ip]) {
      ipMap[ip] = { ip, hits: 0, maxLevel: 0, lastSeen: a.timestamp, attackType: a.rule?.description || 'Unknown' };
    }
    ipMap[ip].hits++;
    ipMap[ip].maxLevel = Math.max(ipMap[ip].maxLevel, a.rule?.level || 0);
    if (a.timestamp > ipMap[ip].lastSeen) {
      ipMap[ip].lastSeen = a.timestamp;
      ipMap[ip].attackType = a.rule?.description || ipMap[ip].attackType;
    }
  });

  const list = Object.values(ipMap).sort((a, b) => b.hits - a.hits).slice(0, limit);
  return list.map(e => ({
    ...e,
    threatScore: getThreatScore(e.maxLevel, e.hits),
    riskLevel: e.maxLevel >= 13 || e.hits >= 5 ? 'High' : e.maxLevel >= 10 || e.hits >= 2 ? 'Medium' : 'Low'
  }));
}

function buildHoneySecurityEvent(event) {
  return {
    timestamp: event.timestamp || new Date().toISOString(),
    severity: event.scope === 'INTERNAL' ? 'MED' : 'HIGH',
    level: event.scope === 'INTERNAL' ? 8 : 11,
    description: `HoneyPort probe detected on TCP ${event.honeyPort} from ${event.sourceIp}`,
    srcip: event.sourceIp,
    agent: `honey-port-${event.honeyPort}`,
    rule: `HONEYPORT_DECOY_PORT_${event.honeyPort}`,
    honeyPort: event.honeyPort,
    scope: event.scope,
    attackType: `HoneyPort probe on ${event.honeyPort}`,
    country: event.country || 'Unknown / Not Available',
    city: event.city || 'Unknown / Not Available',
    latitude: event.lat ?? null,
    longitude: event.lng ?? null,
    is_private: Boolean(event.is_private),
  };
}

async function aggregateHoneyAttackers(clearedAt = 0, limit = 10, includeMetadata = true) {
  const ipMap = {};
  const geoCache = new Map();

  for (const event of honeyPortEvents) {
    if (new Date(event.timestamp || 0).getTime() <= clearedAt) continue;
    const ip = normalizeIp(event.sourceIp || null);
    if (!ip || isLocalSystemIp(ip)) continue;

    if (!ipMap[ip]) {
      ipMap[ip] = {
        ip,
        hits: 0,
        maxLevel: event.scope === 'INTERNAL' ? 8 : 11,
        lastSeen: event.timestamp,
        attackType: `HoneyPort probe on ${event.honeyPort}`,
        honeyPort: event.honeyPort,
        scope: event.scope,
      };
    }

    ipMap[ip].hits += 1;
    ipMap[ip].maxLevel = Math.max(ipMap[ip].maxLevel, event.scope === 'INTERNAL' ? 8 : 11);
    if (event.timestamp > ipMap[ip].lastSeen) {
      ipMap[ip].lastSeen = event.timestamp;
      ipMap[ip].attackType = `HoneyPort probe on ${event.honeyPort}`;
      ipMap[ip].honeyPort = event.honeyPort;
      ipMap[ip].scope = event.scope;
    }
  }

  if (includeMetadata) {
    for (const [ip, entry] of Object.entries(ipMap)) {
      const geo = geoCache.get(ip) || await lookupIpGeo(ip);
      geoCache.set(ip, geo);
      entry.country = geo.country || 'Unknown / Not Available';
      entry.city = geo.city || 'Unknown / Not Available';
      entry.latitude = geo.lat ?? null;
      entry.longitude = geo.lng ?? null;
      entry.is_private = Boolean(geo.is_private);
    }
  }

  return Object.values(ipMap).sort((a, b) => b.hits - a.hits).slice(0, limit).map(e => ({
    ...e,
    threatScore: Math.min(100, Math.round((e.maxLevel / 15) * 60 + Math.min(e.hits, 10) * 5)),
    riskLevel: e.maxLevel >= 10 || e.hits >= 2 ? 'High' : e.maxLevel >= 8 ? 'Medium' : 'Low',
    country: e.country || 'Unknown / Not Available',
    city: e.city || 'Unknown / Not Available',
    latitude: e.latitude ?? null,
    longitude: e.longitude ?? null,
  }));
}

async function aggregateDecoyAttackers(clearedAt = 0) {
  const rows = await dbAll(`SELECT src_ip, severity, rule, created_at FROM security_events WHERE event_source = 'decoy_ecommerce' AND datetime(created_at) > datetime(?) ORDER BY id DESC`, [new Date(clearedAt).toISOString()]);
  const ipMap = {};
  const severityLevels = { LOW: 4, MED: 8, HIGH: 11, CRIT: 14 };
  rows.forEach(row => {
    const ip = normalizeIp(row.src_ip || 'unknown');
    if (!ip || isLocalSystemIp(ip)) return;
    const level = severityLevels[String(row.severity || 'MED').toUpperCase()] || 8;
    if (!ipMap[ip]) ipMap[ip] = { ip, hits: 0, maxLevel: 0, lastSeen: row.created_at, attackType: row.rule, event_source: 'decoy_ecommerce' };
    ipMap[ip].hits += 1;
    ipMap[ip].maxLevel = Math.max(ipMap[ip].maxLevel, level);
    if (String(row.created_at || '') > String(ipMap[ip].lastSeen || '')) {
      ipMap[ip].lastSeen = row.created_at;
      ipMap[ip].attackType = row.rule;
    }
  });
  return Object.values(ipMap).map(item => ({
    ...item,
    threatScore: Math.min(100, Math.round((item.maxLevel / 15) * 60 + Math.min(item.hits, 10) * 4)),
    riskLevel: item.maxLevel >= 13 || item.hits >= 5 ? 'High' : item.maxLevel >= 10 || item.hits >= 2 ? 'Medium' : 'Low',
  }));
}

async function getAttackerDetail(ip) {
  const normalized = normalizeIp(ip);
  const honeyEvents = honeyPortEvents.filter(event => normalizeIp(event.sourceIp) === normalized);
  const securityRows = await dbAll(
    `SELECT src_ip, dest_port, rule, agent, user_agent, description, severity, origin, created_at
     FROM security_events WHERE src_ip = ? ORDER BY created_at DESC LIMIT 100`,
    [normalized]
  );
  const events = [
    ...honeyEvents.map(event => ({
      timestamp: event.timestamp,
      port: event.honeyPort,
      protocol: event.protocol || 'TCP',
      source_port: event.sourcePort,
      scope: event.scope,
      client_hint: event.clientHint || 'Connection probe',
      bytes_received: event.bytesReceived || 0,
      rule: `HONEYPORT_DECOY_PORT_${event.honeyPort}`,
      description: `HoneyPort probe detected on TCP ${event.honeyPort}`,
      severity: event.scope === 'INTERNAL' ? 'MED' : 'HIGH',
      origin: 'honeypot',
    })),
    ...securityRows.map(row => ({
      timestamp: row.created_at,
      port: row.dest_port || null,
      protocol: row.dest_port ? 'TCP' : 'HTTP',
      source_port: null,
      scope: row.origin === 'honeypot' ? 'INTERNAL' : 'EXTERNAL',
      client_hint: row.user_agent || row.agent || 'Security event',
      bytes_received: 0,
      rule: row.rule || 'Security event',
      description: row.description || row.rule || 'Security event',
      severity: row.severity || 'MED',
      origin: row.origin || 'security_events',
    })),
  ].sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
  const latest = events[0] || { timestamp: new Date().toISOString(), scope: 'EXTERNAL' };
  const geo = await lookupIpGeo(normalized);
  const blockStatus = blockedIpState.has(normalized) ? 'blocked' : 'not_blocked';
  const activity = events.map(event => ({
    timestamp: event.timestamp,
    port: event.port,
    protocol: event.protocol,
    source_port: event.source_port,
    scope: event.scope,
    client_hint: event.client_hint,
    bytes_received: event.bytes_received,
    rule: event.rule,
    description: event.description,
    severity: event.severity,
    origin: event.origin,
  }));
  const attackTypes = [...new Set(events.map(event => event.description || event.rule).filter(Boolean))];
  const latestHoneyEvent = honeyEvents[0];
  const latestSecurityRow = securityRows[0];
  const userAgent = latestHoneyEvent?.clientHint || latestSecurityRow?.user_agent || '';
  const client = parseClientUserAgent(userAgent);
  return {
    attacker_ip: normalized,
    ip: normalized,
    event_id: latest.id || null,
    incident_id: latest.incidentId || events[0]?.incidentId || null,
    source_port: latestHoneyEvent?.sourcePort ?? 'Unknown / Not Available',
    destination_port: latest.port ?? 'Unknown / Not Available',
    protocol: latest.protocol || 'Unknown / Not Available',
    user_agent: userAgent || 'Unknown / Not Available',
    ...client,
    location: {
      country: geo.country || 'Unknown / Not Available',
      region: geo.region || 'Unknown / Not Available',
      city: geo.city || 'Unknown / Not Available',
      latitude: geo.lat ?? null,
      longitude: geo.lng ?? null,
      accuracy_radius_km: geo.accuracy_radius_km || 'Unknown / Not Available',
      label: geo.is_private ? 'Private Network / Local Network' : 'Approximate IP Geolocation',
    },
    network: {
      isp: geo.isp || 'Unknown / Not Available',
      asn: geo.asn || 'Unknown / Not Available',
      proxy_vpn_tor: 'Unknown / Not Available',
    },
    activity: {
      first_seen: events.length ? new Date(Math.min(...events.map(event => new Date(event.timestamp).getTime()))).toISOString() : 'Unknown / Not Available',
      last_seen: latest.timestamp || 'Unknown / Not Available',
      event_count: events.length,
      attack_types: attackTypes,
      severity: latest.scope === 'INTERNAL' ? 'MED' : 'HIGH',
      block_status: blockStatus,
    },
    incident_ids: events.map(event => event.incidentId).filter(Boolean),
    is_private: Boolean(geo.is_private),
    is_synthetic: false,
    event_history: activity,
    evidence: {
      event_sources: [...new Set(events.map(event => event.origin).filter(Boolean))],
      agents: [...new Set(events.map(event => event.client_hint).filter(Boolean))],
      rules: [...new Set(events.map(event => event.rule).filter(Boolean))],
    },
  };
}

// 24-bucket hourly chart from real timestamps (SentinelOps logic)
function buildHourlyBuckets(rawAlerts, clearedAt = 0) {
  const buckets = new Array(24).fill(0);
  const now = Date.now();
  const entries = [
    ...rawAlerts.filter(event => isAfterSecurityHistoryClear(event.timestamp, clearedAt) && !isLocalSystemIp(event.data?.srcip || event.agent?.ip)),
    ...honeyPortEvents.filter(event => isAfterSecurityHistoryClear(event.timestamp, clearedAt) && !isLocalSystemIp(event.sourceIp)).map(event => ({
      timestamp: event.timestamp,
      rule: { level: event.scope === 'INTERNAL' ? 8 : 11, description: `HoneyPort probe on ${event.honeyPort}` }
    }))
  ];
  entries.forEach(a => {
    if (!a.timestamp) return;
    const ts = new Date(a.timestamp).getTime();
    const hoursAgo = (now - ts) / (1000 * 60 * 60);
    if (hoursAgo >= 0 && hoursAgo < 24) {
      const idx = 23 - Math.floor(hoursAgo);
      buckets[idx]++;
    }
  });
  return buckets;
}

mountDecoyCollector();

// ── Security API Routes ───────────────────────────────────────

// /api/security/health — Wazuh connection status
app.get('/api/security/health', (req, res) => {
  const { wazuhConnected } = readWazuhAlerts();
  res.json({ status: 'ok', wazuh_connected: wazuhConnected, timestamp: new Date().toISOString() });
});

// /api/security/honeyports — defensive decoy listener status and recent probes
app.get('/api/security/honeyports', async (req, res) => {
  const enrichedEvents = await Promise.all(honeyPortEvents.slice(0, 50).map(enrichHoneyEventMetadata));
  const internalEvents = enrichedEvents.filter(event => event.scope === 'INTERNAL');
  const externalEvents = enrichedEvents.filter(event => event.scope === 'EXTERNAL');
  res.json({
    enabled: honeyPortServers.size > 0,
    bind_host: '0.0.0.0',
    internal_ready: honeyPortServers.size > 0,
    configured_ports: HONEY_PORTS,
    listening_ports: [...honeyPortServers.keys()],
    total_events: honeyPortEvents.length,
    internal_events: internalEvents.length,
    external_events: externalEvents.length,
    demo_force_external: honeyDemoSettings.forceExternal,
    scope_mode: honeyDemoSettings.forceExternal ? 'EXTERNAL' : 'AUTO',
    events: enrichedEvents,
  });
});

app.post('/api/security/honeyports/mode', requireAuth, requireAdmin, (req, res) => {
  const forceExternal = Boolean(req.body?.forceExternal ?? false);
  setHoneyExternalDemoMode(forceExternal);
  res.json({
    demo_force_external: honeyDemoSettings.forceExternal,
    scope_mode: honeyDemoSettings.forceExternal ? 'EXTERNAL' : 'AUTO',
    message: honeyDemoSettings.forceExternal ? 'Same-LAN probes will be labeled as EXTERNAL for demo mode.' : 'Honeyport scope detection restored to AUTO.'
  });
});

app.get('/api/security/blocks', async (req, res) => {
  try {
    const rows = await dbAll(`SELECT ip, reason, incident_id, action, mode, ttl_seconds, created_at, expires_at, removed_at FROM blocks ORDER BY id DESC LIMIT 50`);
    const active = [...blockedIpState.entries()].map(([ip, item]) => ({
      ip,
      reason: item.reason,
      incident_id: item.incidentId,
      expires_at: item.expiresAt,
      status: 'active',
      mode: item.mode || 'auto',
    }));
    res.json({ blocks: rows, active, total: active.length });
  } catch (error) {
    console.warn('[Security] block list failed:', error.message);
    res.status(500).json({ error: 'Unable to load block state' });
  }
});

app.post('/api/security/blocks', requireAuth, requireAdmin, async (req, res) => {
  const { ip, action = 'block', reason = 'manual block', incidentId } = req.body || {};
  const key = normalizeIp(String(ip || '').trim());

  if (!key || net.isIP(key) === 0) {
    return res.status(400).json({ error: 'A valid IP address is required' });
  }

  if (action === 'unblock') {
    const unblocked = unblockHoneyIp(key, reason || 'manual-unblock');
    return res.json({ success: unblocked, action: 'unblock', ip: key, reason: reason || 'manual-unblock' });
  }

  if (action !== 'block') return res.status(400).json({ error: 'Action must be block or unblock' });

  const result = applyHoneyBlock(key, reason || 'manual block', incidentId || 'MANUAL-BLOCK', { permanent: true });
  if (!result.blocked) return res.status(400).json({ error: result.reason || 'This IP cannot be blocked' });
  res.json({ success: result.blocked, action: 'block', ip: key, ...result });
});

app.get('/api/security/deception', requireAuth, requireAdmin, (req, res) => {
  res.json({
    freeze: getDeceptionFreeze(),
    max_rotations_per_hour: deceptionRuntimeState.maxRotationsPerHour,
    configured: config.deception || {},
  });
});

app.get('/api/security/manual-review', requireAuth, requireAdmin, async (req, res) => {
  try {
    await ensureManualReviewQueueTable();
    const rows = await dbAll('SELECT * FROM manual_review_queue WHERE reviewed = 0 ORDER BY created_at DESC, id DESC');
    res.json({ items: rows });
  } catch (error) {
    console.warn('[Security] manual review queue read failed:', error.message);
    res.status(500).json({ error: 'Unable to load manual review queue' });
  }
});

app.post('/api/security/manual-review/:id/ack', requireAuth, requireAdmin, async (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'A valid review item ID is required' });

  try {
    await ensureManualReviewQueueTable();
    const result = await dbRun('UPDATE manual_review_queue SET reviewed = 1 WHERE id = ?', [id]);
    if (!result.changes) return res.status(404).json({ error: 'Manual review item not found' });
    res.json({ success: true, id });
  } catch (error) {
    console.warn('[Security] manual review acknowledgement failed:', error.message);
    res.status(500).json({ error: 'Unable to acknowledge manual review item' });
  }
});

app.post('/api/security/deception/freeze', requireAuth, requireAdmin, (req, res) => {
  const enabled = Boolean(req.body?.enabled ?? req.body?.freeze ?? false);
  const state = applyDeceptionConfigState({ freeze: enabled, maxRotationsPerHour: deceptionRuntimeState.maxRotationsPerHour });
  res.json({
    freeze: state.freeze,
    max_rotations_per_hour: state.maxRotationsPerHour,
    message: enabled ? 'Deception freeze enabled.' : 'Deception freeze disabled.'
  });
});

// /api/security/events — Live event feed (max 25)
app.get('/api/security/events', async (req, res) => {
  const { alerts: raw, wazuhConnected } = readWazuhAlerts();
  const clearState = await dbGet("SELECT state_value FROM threat_intel_state WHERE state_key = 'cleared_at'");
  const clearedAt = Number(clearState?.state_value || 0);
  const wazuhEvents = parseAlerts(raw).filter(event => isAfterSecurityHistoryClear(event.timestamp, clearedAt) && !isLocalSystemIp(event.srcip));
  const honeyEvents = honeyPortEvents.filter(event => isAfterSecurityHistoryClear(event.timestamp, clearedAt) && !isLocalSystemIp(event.sourceIp)).map(buildHoneySecurityEvent);
  const decoyRows = await dbAll(`SELECT created_at AS timestamp, severity, description, src_ip AS srcip, src_ip AS attacker_ip, raw_hash AS event_id, agent, rule, rule AS event_type, event_source FROM security_events WHERE event_source = 'decoy_ecommerce' AND datetime(created_at) > datetime(?) ORDER BY id DESC LIMIT 25`, [new Date(clearedAt).toISOString()]);
  const merged = [...wazuhEvents, ...honeyEvents, ...decoyRows.filter(event => !isLocalSystemIp(event.srcip))]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 25);
  res.json({ events: merged, wazuh_connected: wazuhConnected, total: merged.length });
});

// /api/security/stats — Summary counts by severity
app.get('/api/security/stats', async (req, res) => {
  const { alerts: raw, wazuhConnected } = readWazuhAlerts();
  const clearState = await dbGet("SELECT state_value FROM threat_intel_state WHERE state_key = 'cleared_at'");
  const clearedAt = Number(clearState?.state_value || 0);
  let events = parseAlerts(raw).filter(event => isAfterSecurityHistoryClear(event.timestamp, clearedAt) && !isLocalSystemIp(event.srcip));
  let connected = wazuhConnected;

  if (!events.length) {
    try {
      const rows = await dbAll('SELECT severity, created_at, src_ip FROM security_events WHERE datetime(created_at) > datetime(?) ORDER BY id DESC LIMIT 50', [new Date(clearedAt).toISOString()]);
      events = rows.map(row => ({
        severity: String(row.severity || 'MED').toUpperCase(),
        timestamp: row.created_at || new Date().toISOString(),
        srcip: row.src_ip,
      })).filter(event => !isLocalSystemIp(event.srcip));
      connected = false;
    } catch (error) {
      console.warn('[Security] local stats fallback failed:', error.message);
    }
  }

  const honeyEvents = honeyPortEvents.filter(event => isAfterSecurityHistoryClear(event.timestamp, clearedAt) && !isLocalSystemIp(event.sourceIp)).map(buildHoneySecurityEvent);
  const mergedEvents = [...events, ...honeyEvents];
  const stats = { CRIT: 0, HIGH: 0, MED: 0, LOW: 0 };
  mergedEvents.forEach(e => {
    const severity = String(e.severity || 'MED').toUpperCase();
    if (severity === 'CRIT' || severity === 'DISASTER') stats.CRIT += 1;
    else if (severity === 'HIGH') stats.HIGH += 1;
    else if (severity === 'MED') stats.MED += 1;
    else if (severity === 'LOW') stats.LOW += 1;
  });
  res.json({ ...stats, total: mergedEvents.length, wazuh_connected: connected });
});

app.post('/api/security/history/clear', requireAuth, requireAdmin, async (req, res) => {
  const clearedAt = Date.now();
  try {
    await markSecurityHistoryCleared(db, clearedAt);
    honeyPortEvents.length = 0;
    honeyIncidentTracker.clear();
    decoyIncidentTracker.clear();
    res.json({ success: true, cleared_at: new Date(clearedAt).toISOString() });
  } catch (error) {
    console.warn('[Security] history clear failed:', error.message);
    res.status(500).json({ error: 'Unable to clear security history' });
  }
});

// /api/security/attackers — Top 10 attacker IPs with threat scores
app.get('/api/security/attackers', async (req, res) => {
  const includeAll = req.query.all === 'true';
  const limit = includeAll ? Infinity : 10;
  const { alerts: raw } = readWazuhAlerts();
  const state = await dbGet(`SELECT state_value FROM threat_intel_state WHERE state_key = 'cleared_at'`);
  const clearedAt = Number(state?.state_value || 0);
  const honeyAttackers = await aggregateHoneyAttackers(clearedAt, limit, !includeAll);
  const decoyAttackers = await aggregateDecoyAttackers(clearedAt);
  const attackers = [
    ...aggregateAttackers(raw, clearedAt, limit),
    ...honeyAttackers,
    ...decoyAttackers,
  ].reduce((attackerMap, attacker) => {
    const key = attacker.ip;
    if (!attackerMap[key]) attackerMap[key] = { ...attacker, hits: 0, maxLevel: 0, lastSeen: attacker.lastSeen || new Date().toISOString() };
    attackerMap[key].hits += Number(attacker.hits || 0);
    attackerMap[key].maxLevel = Math.max(attackerMap[key].maxLevel || 0, attacker.maxLevel || 0);
    if ((attacker.lastSeen || '').localeCompare(attackerMap[key].lastSeen || '') > 0) {
      attackerMap[key].lastSeen = attacker.lastSeen;
      attackerMap[key].attackType = attacker.attackType || attackerMap[key].attackType;
      attackerMap[key].honeyPort = attacker.honeyPort || attackerMap[key].honeyPort;
      attackerMap[key].scope = attacker.scope || attackerMap[key].scope;
      attackerMap[key].country = attacker.country || attackerMap[key].country || 'Unknown / Not Available';
      attackerMap[key].city = attacker.city || attackerMap[key].city || 'Unknown / Not Available';
      attackerMap[key].latitude = attacker.latitude ?? attackerMap[key].latitude ?? null;
      attackerMap[key].longitude = attacker.longitude ?? attackerMap[key].longitude ?? null;
    }
    attackerMap[key].threatScore = getThreatScore(attackerMap[key].maxLevel, attackerMap[key].hits);
    attackerMap[key].riskLevel = attackerMap[key].maxLevel >= 13 || attackerMap[key].hits >= 5 ? 'High' : attackerMap[key].maxLevel >= 10 || attackerMap[key].hits >= 2 ? 'Medium' : 'Low';
    return attackerMap;
  }, {});

  const result = Object.values(attackers).sort((a, b) => b.hits - a.hits).slice(0, limit).map(item => ({
    ...item,
    country: item.country || 'Unknown / Not Available',
    city: item.city || 'Unknown / Not Available',
    latitude: item.latitude ?? null,
    longitude: item.longitude ?? null,
  }));
  if (!includeAll) result.forEach(autoBlockHighThreatAttacker);
  res.json({ attackers: result, total: result.length });
});

app.post('/api/security/attackers/clear', requireAuth, requireAdmin, async (req, res) => {
  const clearedAt = Date.now();
  await markSecurityHistoryCleared(db, clearedAt);
  res.json({ success: true, cleared_at: new Date(clearedAt).toISOString(), attackers: [] });
});

app.get('/api/security/attackers/:ip', async (req, res) => {
  const normalizedIp = normalizeIp(req.params.ip || '');
  if (!normalizedIp || normalizedIp === 'unknown') {
    return res.status(400).json({ error: 'A valid IP is required' });
  }

  try {
    const detail = await getAttackerDetail(normalizedIp);
    res.json({ attacker: detail });
  } catch (error) {
    res.status(500).json({ error: 'Could not load attacker details', detail: error.message });
  }
});

// /api/security/chart/hourly — 24-bucket real time-series
app.get('/api/security/chart/hourly', async (req, res) => {
  const { alerts: raw } = readWazuhAlerts();
  const clearState = await dbGet("SELECT state_value FROM threat_intel_state WHERE state_key = 'cleared_at'");
  const buckets = buildHourlyBuckets(raw, Number(clearState?.state_value || 0));
  const labels = Array.from({ length: 24 }, (_, i) => {
    const h = new Date(Date.now() - (23 - i) * 3600000);
    return `${String(h.getHours()).padStart(2, '0')}:00`;
  });
  res.json({ buckets, labels });
});

// /api/security/rules — 8 detection rules panel
app.get('/api/security/rules', async (req, res) => {
  const { alerts: raw } = readWazuhAlerts();
  const clearState = await dbGet("SELECT state_value FROM threat_intel_state WHERE state_key = 'cleared_at'");
  const clearedAt = Number(clearState?.state_value || 0);
  const countedAlerts = raw.filter(alert => isAfterSecurityHistoryClear(alert.timestamp, clearedAt) && !isLocalSystemIp(alert.data?.srcip || alert.agent?.ip));
  const rules = [
    { id: 'SSH_BRUTE_FORCE', description: 'Repeated failed SSH logins from single IP', ossec_file: 'sshd_rules.xml', action: 'BLOCK+ALERT', enabled: true },
    { id: 'NMAP_SCAN_DETECT', description: 'Port scanning activity detected', ossec_file: 'firewall_rules.xml', action: 'LOG+ALERT', enabled: true },
    { id: 'SQLI_PATTERN', description: 'SQL injection pattern in web request', ossec_file: 'web_rules.xml', action: 'BLOCK+ALERT', enabled: true },
    { id: 'PRIV_ESCALATION', description: 'Unauthorized sudo/privilege escalation attempt', ossec_file: 'sudo_rules.xml', action: 'ISOLATE+ALERT', enabled: true },
    { id: 'MALWARE_HASH', description: 'Known malware file signature detected', ossec_file: 'malware_rules.xml', action: 'ISOLATE+ALERT', enabled: true },
    { id: 'DNS_EXFIL', description: 'Abnormal DNS query pattern (possible exfiltration)', ossec_file: 'dns_rules.xml', action: 'LOG+EMAIL', enabled: false },
    { id: 'CRED_STUFF', description: 'Credential stuffing: multiple accounts failed', ossec_file: 'web_rules.xml', action: 'BLOCK+ALERT', enabled: true },
    { id: 'FW_CHANGE', description: 'Firewall rule modified by non-admin', ossec_file: 'firewall_rules.xml', action: 'ALERT+EMAIL', enabled: true },
  ];
  // Count triggers from real alert data
  const enriched = rules.map(r => {
    const kw = r.id.split('_')[0].toLowerCase();
    const hits = countedAlerts.filter(a => (a.rule?.description || '').toLowerCase().includes(kw)).length;
    return { ...r, trigger_count: hits };
  });
  res.json({ rules: enriched });
});

// /api/security/incidents — MITRE ATT&CK incident cards
app.get('/api/security/incidents', async (req, res) => {
  let clearedAt = 0;
  try {
    const clearState = await dbGet("SELECT state_value FROM threat_intel_state WHERE state_key = 'cleared_at'");
    clearedAt = Number(clearState?.state_value || 0);
    const rows = await dbAll(
      `SELECT id, title, severity, source_ip, rule, mitre, stage, evidence, acknowledged_by, created_at, updated_at
       FROM incidents
       WHERE datetime(created_at) > datetime(?)
       ORDER BY datetime(created_at) DESC
       LIMIT 20`,
      [new Date(clearedAt).toISOString()]
    );

    if (rows.length) {
      const incidents = rows.filter(row => !isLocalSystemIp(row.source_ip)).map(row => ({
        id: row.id,
        title: row.title || 'Honeyport security incident',
        mitre_id: row.mitre || 'T1046',
        mitre_name: row.mitre || 'Network Service Discovery',
        target_host: row.rule || 'honeypot',
        severity: String(row.severity || 'MED').toUpperCase(),
        stage: row.stage || 'Detected',
        stages: ['Detected', 'Investigated', 'Contained', 'Resolved'],
        current_stage_idx: ['Detected', 'Investigated', 'Contained', 'Resolved'].indexOf(row.stage || 'Detected'),
        action_log: row.evidence || 'Incidents detected through the honeypot SOC flow.',
        timestamp: row.created_at || new Date().toISOString(),
      }));
      return res.json({ incidents, total: incidents.length });
    }
  } catch (error) {
    console.warn('[Security] incident DB read failed:', error.message);
  }

  const incidents = [
    {
      id: 'IR-2025-001', title: 'SSH Brute Force Campaign',
      mitre_id: 'T1110.001', mitre_name: 'Password Guessing',
      target_host: 'auth-srv-01', severity: 'HIGH',
      stage: 'Contained',
      stages: ['Detected', 'Investigated', 'Contained', 'Resolved'],
      current_stage_idx: 2,
      action_log: 'Source IP blocked at firewall. 247 failed attempts from 103.85.24.190. Account lockout policy triggered after 5 failures.',
      timestamp: new Date(Date.now() - 2 * 3600000).toISOString()
    },
    {
      id: 'IR-2025-002', title: 'Network Port Scan Detected',
      mitre_id: 'T1046', mitre_name: 'Network Service Discovery',
      target_host: 'fw-edge-01', severity: 'MED',
      stage: 'Investigated',
      stages: ['Detected', 'Investigated', 'Contained', 'Resolved'],
      current_stage_idx: 1,
      action_log: 'NMAP SYN scan from 45.33.32.156 detected. 1024 ports probed in 30s. Network team notified. Geo-block applied for IP range.',
      timestamp: new Date(Date.now() - 5 * 3600000).toISOString()
    },
    {
      id: 'IR-2025-003', title: 'SQL Injection Attempt on Web API',
      mitre_id: 'T1190', mitre_name: 'Exploit Public-Facing Application',
      target_host: 'nginx-lb-02', severity: 'HIGH',
      stage: 'Detected',
      stages: ['Detected', 'Investigated', 'Contained', 'Resolved'],
      current_stage_idx: 0,
      action_log: 'UNION-based SQL injection pattern in /api/search parameter. WAF rule triggered. 91.108.4.22 rate-limited. Dev team reviewing query sanitization.',
      timestamp: new Date(Date.now() - 1 * 3600000).toISOString()
    },
    {
      id: 'IR-2025-004', title: 'Ransomware Behaviour on Web Server',
      mitre_id: 'T1486', mitre_name: 'Data Encrypted for Impact',
      target_host: 'srv-web-01', severity: 'CRIT',
      stage: 'Resolved',
      stages: ['Detected', 'Investigated', 'Contained', 'Resolved'],
      current_stage_idx: 3,
      action_log: 'Mass file encryption detected in /var/www. Host isolated immediately. Snapshot restored from 02:00 backup. ClamAV signatures updated. Post-incident review scheduled.',
      timestamp: new Date(Date.now() - 12 * 3600000).toISOString()
    },
  ];
  const recentIncidents = incidents.filter(incident => isAfterSecurityHistoryClear(incident.timestamp, clearedAt));
  res.json({ incidents: recentIncidents, total: recentIncidents.length });
});


// ============================================================
//  ZABBIX API ROUTES (Real Data — Graceful Fallback to Mock)
// ============================================================

// /api/zabbix/hosts — Real monitored hosts with CPU/RAM/Disk
app.get('/api/zabbix/hosts', async (req, res) => {
  try {
    const data = await zabbixApi.getHosts();
    if (Array.isArray(data?.hosts) && data.hosts.length > 0) {
      return res.json(data);
    }
    const rows = await dbAll('SELECT id, hostname, ip_address, dns_name, host_group, os, status, cpu_usage, memory_usage, disk_usage, availability FROM managed_hosts ORDER BY id');
    return res.json({ hosts: rows.map(normalizeLocalHostRow), zabbix_connected: false, total: rows.length, status: 'OFFLINE', source: 'local-db' });
  } catch (err) {
    try {
      const rows = await dbAll('SELECT id, hostname, ip_address, dns_name, host_group, os, status, cpu_usage, memory_usage, disk_usage, availability FROM managed_hosts ORDER BY id');
      return res.json({ hosts: rows.map(normalizeLocalHostRow), zabbix_connected: false, total: rows.length, status: 'OFFLINE', source: 'local-db' });
    } catch (dbErr) {
      res.status(500).json({ error: err.message || dbErr.message });
    }
  }
});

// /api/zabbix/problems — Active problems/alerts from Zabbix
app.get('/api/zabbix/problems', async (req, res) => {
  try {
    const data = await zabbixApi.getProblems();
    if (Array.isArray(data?.problems) && data.problems.length > 0) {
      return res.json(data);
    }
    const rows = await dbAll('SELECT id, agent, src_ip, rule, description, severity, created_at FROM security_events ORDER BY id DESC LIMIT 25');
    return res.json({ problems: rows.map(normalizeLocalProblemRow), zabbix_connected: false, total: rows.length, status: 'OFFLINE', source: 'local-db' });
  } catch (err) {
    try {
      const rows = await dbAll('SELECT id, agent, src_ip, rule, description, severity, created_at FROM security_events ORDER BY id DESC LIMIT 25');
      return res.json({ problems: rows.map(normalizeLocalProblemRow), zabbix_connected: false, total: rows.length, status: 'OFFLINE', source: 'local-db' });
    } catch (dbErr) {
      res.status(500).json({ error: err.message || dbErr.message });
    }
  }
});

app.post('/api/zabbix/problems/:eventid/acknowledge', async (req, res) => {
  try {
    const data = await zabbixApi.acknowledgeProblem(req.params.eventid);
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// /api/zabbix/status — Zabbix Server connection status
app.get('/api/zabbix/status', async (req, res) => {
  try {
    const status = await zabbixApi.getZabbixStatus();
    res.json(status);
  } catch (err) {
    res.json({ connected: false, error: err.message });
  }
});

// /api/webhook/new-device — Zabbix Discovery webhook
// Jab Zabbix koi naya device discover kare, yeh endpoint call hota hai
// Zabbix Action → Operations → Custom webhook → yeh URL
app.post('/api/webhook/new-device', requireWebhookKey, (req, res) => {
  const device = req.body;
  console.log('[Webhook] New device discovered:', device);

  // WebSocket clients ko broadcast karo
  if (global.wsBroadcast) {
    global.wsBroadcast(JSON.stringify({
      type: 'NEW_DEVICE',
      data: {
        name: device.host || device.name || 'Unknown Device',
        ip: device.ip || 'Unknown IP',
        timestamp: new Date().toISOString(),
      }
    }));
  }
  res.json({ ok: true, message: 'Device notification received' });
});

// Serve static files from Frontend directory
app.use(express.static(path.join(__dirname, '../Frontend')));

// Serve the project PNG logo.
app.get(['/SOC_logo.png', '/assets/soc-logo.png'], (req, res) => {
  res.sendFile(path.join(__dirname, '../SOC_logo.png'));
});


// Root route serves final.html
app.get([
  '/', '/overview', '/hosts', '/problems', '/graphs', '/soc_flow',
  '/honey_port', '/config', '/security', '/threat_intel', '/incidents', '/admin', '/ai_brain'
], (req, res) => {
  res.sendFile(path.join(__dirname, '../Frontend/final.html'));
});

// API Endpoints for Users

// 0. Health Check (to verify backend is reachable)
app.get('/api/health', (req, res) => {
  const zabbixStatus = { source: 'unavailable', as_of: new Date().toISOString(), data: { ok: false, detail: 'Zabbix not configured' } };
  const payload = {
    status: 'ok',
    ok: true,
    source: 'live',
    as_of: new Date().toISOString(),
    message: 'Backend is reachable',
    zabbix: zabbixStatus,
    data: { ok: true, message: 'Backend is reachable', zabbix: zabbixStatus, timestamp: new Date().toISOString() },
    timestamp: new Date().toISOString()
  };
  res.json(payload);
});

app.get('/api/summary', (req, res) => {
  db.get('SELECT COUNT(*) AS total_hosts FROM managed_hosts', [], (err, hostRow) => {
    if (err) return res.status(500).json(withEnvelope('unavailable', { error: err.message }));
    db.get('SELECT COUNT(*) AS total_events FROM security_events', [], (eventErr, eventRow) => {
      if (eventErr) return res.status(500).json(withEnvelope('unavailable', { error: eventErr.message }));
      db.get('SELECT COUNT(*) AS total_incidents FROM incidents', [], (incidentErr, incidentRow) => {
        if (incidentErr) return res.status(500).json(withEnvelope('unavailable', { error: incidentErr.message }));
        res.json(withEnvelope('live', {
          host_count: Number(hostRow?.total_hosts || 0),
          event_count: Number(eventRow?.total_events || 0),
          incident_count: Number(incidentRow?.total_incidents || 0),
          status: hostRow?.total_hosts ? 'LIVE' : 'EMPTY'
        }));
      });
    });
  });
});

app.get('/api/zabbix/health', async (req, res) => {
  const configured = Boolean(config.zabbixUrl && config.zabbixUrl.trim());
  if (!configured) {
    return res.json(withEnvelope('unavailable', defaultState('OFFLINE', 'Zabbix API not configured')));
  }
  try {
    const health = await zabbixApi.getZabbixStatus();
    res.json(withEnvelope(health?.connected ? 'live' : 'unavailable', health || defaultState('OFFLINE', 'No Zabbix response')));
  } catch (err) {
    res.status(503).json(withEnvelope('unavailable', defaultState('OFFLINE', err.message || 'Zabbix API unreachable')));
  }
});

app.get('/api/zabbix/summary', async (req, res) => {
  try {
    const hosts = await zabbixApi.getHosts();
    const problems = await zabbixApi.getProblems();
    res.json(withEnvelope(hosts?.zabbix_connected ? 'live' : 'unavailable', {
      hosts: hosts?.hosts || [],
      problems: problems?.problems || [],
      total_hosts: hosts?.total || 0,
      total_problems: problems?.total || 0,
      status: hosts?.zabbix_connected ? 'LIVE' : 'OFFLINE'
    }));
  } catch (err) {
    res.status(503).json(withEnvelope('unavailable', { status: 'OFFLINE', detail: err.message }));
  }
});

app.get('/api/honeypot/summary', (req, res) => {
  db.get('SELECT COUNT(*) AS sessions FROM honey_captures', [], (err, row) => {
    if (err) return res.status(500).json(withEnvelope('unavailable', { error: err.message }));
    db.get('SELECT COUNT(DISTINCT src_ip) AS unique_ips FROM honey_captures', [], (ipErr, ipRow) => {
      if (ipErr) return res.status(500).json(withEnvelope('unavailable', { error: ipErr.message }));
      res.json(withEnvelope('live', {
        sessions: Number(row?.sessions || 0),
        unique_ips: Number(ipRow?.unique_ips || 0),
        status: Number(row?.sessions || 0) > 0 ? 'LIVE' : 'EMPTY'
      }));
    });
  });
});

app.get('/api/notifications/telegram/status', (req, res) => {
  res.json({
    internal: telegramNotificationSettings.internal,
    honey: telegramNotificationSettings.honey,
    internal_bot_configured: Boolean(config.internalTelegramBotToken || config.telegramBotToken),
    honey_bot_configured: Boolean(config.honeyTelegramBotToken),
  });
});

app.post('/api/notifications/telegram/toggle', requireAdmin, (req, res) => {
  const targetBot = String(req.body?.bot || 'internal').toLowerCase();
  const enabled = Boolean(req.body?.enabled);
  if (!['internal', 'honey'].includes(targetBot)) {
    return res.status(400).json({ error: 'Bot must be internal or honey' });
  }
  const result = setTelegramAlertsEnabled(targetBot, enabled);
  res.json({ bot: targetBot, enabled: result });
});

app.post('/api/telegram/test', (req, res) => {
  const text = String(req.body?.message || 'Test alert from Zabbix SOC platform').trim();
  const targetBot = String(req.body?.bot || 'internal').toLowerCase();
  const send = targetBot === 'honey' ? sendHoneyTelegramAlert : sendTelegramAlert;
  send(`🧪 <b>Test Notification</b>\n${text}`).then(ok => {
    res.json({ ok, message: ok ? `${targetBot} Telegram notification sent successfully` : `${targetBot} Telegram notification failed or is disabled/not configured` });
  }).catch(error => {
    res.status(500).json({ ok: false, error: error.message });
  });
});

app.post('/api/security/notify', (req, res) => {
  const event = req.body || {};
  const text = buildTelegramEventText(event);
  sendTelegramAlert(text).then(ok => {
    res.json({ ok, message: ok ? 'Security notification sent to Telegram' : 'Telegram not configured or delivery failed' });
  }).catch(error => {
    res.status(500).json({ ok: false, error: error.message });
  });
});

// 1. Authenticate user (for frontend login)
app.post('/api/auth/login', (req, res) => {
  if (isLoginRateLimited(req)) {
    writeAuditLog({ actor: String(req.body?.username || 'anonymous'), actorIp: req.ip, action: 'LOGIN_RATE_LIMITED', entity: 'auth', details: 'Login rate limit exceeded.' });
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }
  const { username, password } = req.body;
  if (!username || !password) {
    writeAuditLog({ actor: String(username || 'anonymous'), actorIp: req.ip, action: 'LOGIN_REJECTED', entity: 'auth', details: 'Username and password are required.' });
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const sql = `SELECT * FROM users WHERE username = ?`;
  db.get(sql, [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    const isValidPassword = row && (
      verifyPassword(password, row.password) ||
      isDemoLoginAccepted(config, username, password)
    );

    if (row && isValidPassword) {
      clearLoginFailureState(req);

      const token = createSession(row);
      setSessionCookie(res, token);

      if (!row.password.startsWith('scrypt:')) {
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashPassword(password), row.id]);
      }
      
      const updateLogin = `UPDATE users SET last_login = ? WHERE id = ?`;
      db.run(updateLogin, [new Date().toISOString(), row.id]);
      writeAuditLog({ actor: row.username, actorIp: req.ip, action: 'LOGIN_SUCCESS', entity: 'auth', details: 'Dashboard login successful.' });

      // Remove password before sending to frontend
      delete row.password;
      
      res.json({
        message: 'Login successful',
        token,
        user: { ...row, fullName: row.full_name }
      });
    } else {
      recordLoginFailure(req);
      writeAuditLog({ actor: String(username || 'anonymous'), actorIp: req.ip, action: 'LOGIN_FAILED', entity: 'auth', details: 'Invalid credentials.' });
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

app.post('/api/auth/logout', (req, res) => {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : getCookie(req, 'soc_session');
  if (token) sessions.delete(token);
  clearSessionCookie(res);
  res.json({ message: 'Logged out' });
});

app.post('/api/integrations/n8n/test', requireAdmin, async (req, res) => {
  const webhookUrl = String(req.body?.webhookUrl || '').trim();
  let parsedUrl;
  try {
    parsedUrl = new URL(webhookUrl);
  } catch {
    return res.status(400).json({ error: 'A valid n8n webhook URL is required' });
  }
  if (!['http:', 'https:'].includes(parsedUrl.protocol) || !config.n8nAllowedOrigins.includes(parsedUrl.origin)) {
    return res.status(403).json({ error: 'Webhook origin is not allowlisted' });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(parsedUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ test: true, source: 'zabbix-soc' }),
      signal: controller.signal,
    });
    res.status(response.ok ? 200 : 502).json({ ok: response.ok, status: response.status });
  } catch (error) {
    res.status(502).json({ error: error.name === 'AbortError' ? 'n8n request timed out' : 'n8n webhook unavailable' });
  } finally {
    clearTimeout(timeout);
  }
});

// Re-authenticate administrators before opening the sensitive admin panel.
app.post('/api/auth/admin-access', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password is required' });

  db.get('SELECT password, admin_panel_password FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row || !verifyAdminPanelCredential(password, row)) {
      return res.status(401).json({ error: 'Incorrect administrator password' });
    }
    res.json({ message: 'Administrator access granted' });
  });
});

// Update the signed-in user's profile and password without exposing credentials.
app.put('/api/account/profile', (req, res) => {
  const fullName = String(req.body.full_name || '').trim();
  const email = String(req.body.email || '').trim();
  if (!fullName || !email) return res.status(400).json({ error: 'Full name and email are required' });

  db.run('UPDATE users SET full_name = ?, email = ? WHERE id = ?', [fullName, email, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (!this.changes) return res.status(404).json({ error: 'User not found' });
    currentUserProfile(req, res);
  });
});

app.put('/api/account/password', (req, res) => {
  const currentPassword = String(req.body.current_password || '');
  const newPassword = String(req.body.new_password || '');
  if (!currentPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Current password and a new password of at least 8 characters are required' });
  }

  db.get('SELECT password FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row || !verifyPassword(currentPassword, row.password)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashPassword(newPassword), req.user.id], updateErr => {
      if (updateErr) return res.status(500).json({ error: updateErr.message });
      res.json({ message: 'Password updated successfully' });
    });
  });
});

app.put('/api/account/admin-panel-password', (req, res) => {
  const currentPassword = String(req.body.current_password || '');
  const newPassword = String(req.body.new_password || '');
  if (!currentPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Current verification password and a new password of at least 8 characters are required' });
  }

  db.get('SELECT admin_panel_password FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row || !verifyPassword(currentPassword, row.admin_panel_password)) {
      return res.status(401).json({ error: 'Current admin panel password is incorrect' });
    }
    db.run('UPDATE users SET admin_panel_password = ? WHERE id = ?', [hashPassword(newPassword), req.user.id], updateErr => {
      if (updateErr) return res.status(500).json({ error: updateErr.message });
      res.json({ message: 'Admin panel password updated successfully' });
    });
  });
});

function currentUserProfile(req, res) {
  db.get('SELECT id, username, full_name, email, role, status, last_login FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ...row, fullName: row.full_name });
  });
}

// 2. Get all users
app.get('/api/users', requireAdmin, (req, res) => {
  const sql = `SELECT id, username, full_name, email, role, status, last_login FROM users`;
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/api/audit-log', requireAdmin, async (req, res) => {
  try {
    const rows = await dbAll(`
      SELECT id, actor AS user, actor_ip AS ip_address, action, entity, details, created_at
      FROM audit_log ORDER BY id DESC LIMIT 200
    `);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Unable to load audit log' });
  }
});

// 3. Create a new user
app.post('/api/users', requireAdmin, (req, res) => {
  const { username, password, full_name, email, role } = req.body;
  const status = 'active';
  const last_login = new Date().toISOString();

  if (!username || !password || !full_name || !email || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const sql = `INSERT INTO users (username, password, full_name, email, role, status, last_login) VALUES (?, ?, ?, ?, ?, ?, ?)`;
  db.run(sql, [username, hashPassword(password), full_name, email, role, status, last_login], function (err) {
    if (err) {
      // Typically 19 corresponds to a UNIQUE constraint failure in SQLite
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({
      message: 'User created successfully',
      id: this.lastID
    });
  });
});

// 4. Delete a user
app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  const sql = `DELETE FROM users WHERE id = ?`;
  
  db.run(sql, id, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted' });
  });
});

// Application-managed hosts are stored locally so they survive refreshes and restarts.
app.get('/api/hosts', (req, res) => {
  db.all('SELECT id, hostname, ip_address, dns_name, host_group, os, status, cpu_usage, memory_usage, disk_usage, availability FROM managed_hosts ORDER BY id', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(host => ({ ...host, id: `local-${host.id}` })));
  });
});

app.post('/api/hosts', requireAdmin, (req, res) => {
  const { hostname, ip_address, dns_name, host_group, os } = req.body;
  if (!hostname || !ip_address || !host_group || !os) {
    return res.status(400).json({ error: 'Hostname, IP address, host group and OS are required' });
  }

  const sql = `INSERT INTO managed_hosts
    (hostname, ip_address, dns_name, host_group, os, status, cpu_usage, memory_usage, disk_usage, availability, created_at)
    VALUES (?, ?, ?, ?, ?, 'online', ?, ?, ?, 99.99, ?)`;
  db.run(sql, [hostname, ip_address, dns_name || hostname, host_group, os, 0, 0, 0, new Date().toISOString()], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({
      message: 'Host created successfully',
      host: { id: `local-${this.lastID}`, hostname, ip_address, dns_name: dns_name || hostname, host_group, os, status: 'online', cpu_usage: 0, memory_usage: 0, disk_usage: 0, availability: 99.99 }
    });
  });
});

app.delete('/api/hosts/:id', requireAdmin, (req, res) => {
  const id = String(req.params.id).replace(/^local-/, '');
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid host id' });
  db.run('DELETE FROM managed_hosts WHERE id = ?', [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Host not found' });
    res.json({ message: 'Host deleted' });
  });
});

const AUTOMATION_PROBLEM_BLUEPRINTS = [
  { title: 'Credential stuffing attempted', severity: 'HIGH', source: '45.33.32.156', agent: 'auth-srv-01', port: 22, rule: 'SSH brute force', description: 'Multiple failed credential attempts detected against the auth service.' },
  { title: 'Privilege escalation pattern', severity: 'CRIT', source: '103.85.24.190', agent: 'db-primary', port: 3306, rule: 'Privilege abuse', description: 'Unexpected elevation attempt against the database host after repeated authentication failures.' },
  { title: 'Web application injection alert', severity: 'HIGH', source: '91.108.4.22', agent: 'nginx-lb-02', port: 443, rule: 'SQL injection pattern', description: 'HTTP request matched a malicious SQL injection signature during validation flows.' },
  { title: 'Malware hash match', severity: 'CRIT', source: '198.51.100.42', agent: 'srv-web-03', port: 80, rule: 'Known malware signature', description: 'Malware hash observed in a file upload and flagged for isolation.' },
  { title: 'Lateral movement detection', severity: 'MED', source: '10.0.1.77', agent: 'srv-web-07', port: 445, rule: 'SMB enumeration', description: 'Internal host attempted SMB discovery and context expansion across the lab network.' },
];

function selectUniqueBlueprint() {
  const available = AUTOMATION_PROBLEM_BLUEPRINTS.filter(blueprint => !recentAutomationProblemTitles.includes(blueprint.title));
  const pool = available.length ? available : AUTOMATION_PROBLEM_BLUEPRINTS.slice();
  const blueprint = pool[Math.floor(Math.random() * pool.length)];

  recentAutomationProblemTitles.push(blueprint.title);
  if (recentAutomationProblemTitles.length > MAX_PROBLEM_HISTORY) {
    recentAutomationProblemTitles.shift();
  }

  return blueprint;
}

async function createGeneratedProblem() {
  if (generatedProblems.size >= 1) {
    return;
  }

  const blueprint = selectUniqueBlueprint();
  const problemId = `AUTO-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  const now = new Date().toISOString();
  const problem = {
    id: problemId,
    title: blueprint.title,
    severity: blueprint.severity,
    source_ip: blueprint.source,
    src_ip: blueprint.source,
    agent: blueprint.agent,
    dest_port: blueprint.port,
    rule: blueprint.rule,
    description: blueprint.description,
    created_at: now,
    status: 'OPEN',
    n8n_status: 'PENDING',
    transfer_started_at: now,
    n8n_received_at: null,
    resolved_at: null,
    workflow_log: [],
  };

  try {
    await dbRun(
      `INSERT INTO security_events (source, severity, src_ip, dest_port, rule, agent, description, raw_hash, origin, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ['automated-soc', problem.severity, problem.source_ip, problem.dest_port, problem.rule, problem.agent, problem.description, problem.id, 'automation', now]
    );
    await dbRun(
      `INSERT OR REPLACE INTO incidents (id, title, severity, source_ip, rule, mitre, stage, evidence, acknowledged_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [problem.id, problem.title, problem.severity, problem.source_ip, problem.rule, 'T1059', 'Detected', problem.description, 'soc-auto', now, now]
    );

    generatedProblems.set(problem.id, { ...problem, timer: null });

    const n8nTransferStart = Date.now();
    problem.workflow_log.push({ ts: new Date().toISOString(), event: 'created' });
    const n8nOk = await triggerN8nAutomation({
      source: 'soc-automation',
      type: 'problem_created',
      problem,
      workflow: 'soc_detection',
      created_at: now,
      max_transfer_seconds: 60,
    });
    problem.n8n_received_at = n8nOk ? new Date().toISOString() : null;
    problem.n8n_status = n8nOk ? 'SENT' : 'PENDING_RETRY';
    problem.workflow_log.push({
      ts: new Date().toISOString(),
      event: n8nOk ? 'n8n_received' : 'n8n_failed',
      elapsed_ms: Date.now() - n8nTransferStart,
    });

    if (n8nOk) {
      console.log('[n8n] dispatched new SOC problem to automation workflow');
    }

    const telegramText = buildProblemTelegramText(problem, 'OPEN');
    await sendTelegramAlert(telegramText);

    const timer = setTimeout(async () => {
      const active = generatedProblems.get(problem.id);
      if (!active) return;
      try {
        const n8nResolved = await triggerN8nAutomation({
          source: 'soc-automation',
          type: 'problem_resolved',
          problem: { ...problem, status: 'RESOLVED', workflow_log: active.workflow_log },
          workflow: 'soc_resolution',
          resolved_at: new Date().toISOString(),
          max_transfer_seconds: 60,
        });

        if (!n8nResolved) {
          active.n8n_status = 'PENDING_RETRY';
          active.workflow_log.push({ ts: new Date().toISOString(), event: 'n8n_resolution_failed' });
          generatedProblems.set(problem.id, active);
          return;
        }

        active.status = 'RESOLVED';
        active.resolved_at = new Date().toISOString();
        active.n8n_status = 'RESOLVED';
        active.workflow_log.push({ ts: active.resolved_at, event: 'resolution_verified' });
        generatedProblems.set(problem.id, active);

        await dbRun(`UPDATE incidents SET stage = ?, evidence = ?, updated_at = ? WHERE id = ?`, ['Resolved', `${problem.description} - Auto-contained by SOC automation`, new Date().toISOString(), problem.id]);
        await sendTelegramAlert(buildProblemResolvedTelegramText(problem, 'Auto-contained by SOC workflow and verified by automation pipeline.'));
      } catch (error) {
        console.warn('[Automation] Problem resolution failed:', error.message);
      } finally {
        generatedProblems.delete(problem.id);
      }
    }, PROBLEM_AUTO_RESOLVE_MS);

    const current = generatedProblems.get(problem.id);
    if (current) {
      current.timer = timer;
      generatedProblems.set(problem.id, current);
    }

    console.log(`[Automation] Created SOC problem ${problem.id} and scheduled n8n transfer + resolution within ${PROBLEM_AUTO_RESOLVE_MS / 1000}s.`);
  } catch (error) {
    console.warn('[Automation] Failed to create generated problem:', error.message);
  }
}

function startProblemAutomation() {
  if (global.problemAutomationInterval) return;

  const createWhenDatabaseReady = () => {
    dbGet('SELECT 1 FROM security_events LIMIT 1')
      .then(() => createGeneratedProblem().catch(() => {}))
      .catch(() => setTimeout(createWhenDatabaseReady, 1000));
  };
  createWhenDatabaseReady();
  global.problemAutomationInterval = setInterval(() => {
    createGeneratedProblem().catch(() => {});
  }, PROBLEM_CYCLE_MS);

  global.problemHeartbeatInterval = setInterval(async () => {
    const activeProblems = [...generatedProblems.values()].slice(0, 5);
    if (!activeProblems.length) {
      return;
    }
    const summary = activeProblems.map(problem => `• ${problem.title} [${problem.severity}] ${problem.source_ip}`).join('\n');
    const text = `🛰️ <b>SOC Heartbeat</b>\n` +
      `Active incidents: <b>${activeProblems.length}</b>\n` +
      `${summary}`;
    await sendTelegramAlert(text);
  }, PROBLEM_CYCLE_MS);
}

// Start Server
function getAdvertisedIp() {
  const interfaces = os.networkInterfaces();
  const candidates = [];

  Object.values(interfaces).forEach(details => {
    details.forEach(entry => {
      if (entry.family === 'IPv4' && !entry.internal) {
        candidates.push(entry.address);
      }
    });
  });

  return candidates.find(ip => ip.startsWith('192.168.')) || candidates[0] || '127.0.0.1';
}

function startListening(portIndex = 0) {
  const portCandidates = [
    parseInt(process.env.PORT || config.port, 10) || 3001,
    3002,
    3003,
    3004,
    3005,
  ];
  const port = portCandidates[portIndex];
  const server = http.createServer(app);

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE' && portIndex + 1 < portCandidates.length) {
      console.warn(`Port ${port} is in use, trying next available port.`);
      startListening(portIndex + 1);
      return;
    }
    console.error('Failed to start backend:', err.message);
    process.exit(1);
  });

  applyDeceptionConfigState({
    freeze: config.deception.freeze,
    maxRotationsPerHour: deceptionRuntimeState.maxRotationsPerHour,
  });

  server.listen(port, '0.0.0.0', async () => {
    const advertisedIp = getAdvertisedIp();
    console.log(`Zabbix SOC Backend running on http://localhost:${port} and http://${advertisedIp}:${port}`);
    initializeWebSocket(server, sessions);
    try {
      await ensureFallbackReasonColumn(db);
      console.log('[Local AI] Analysis history schema checked.');
    } catch (error) {
      console.warn('[Local AI] Analysis history migration failed:', error.message);
    }
    if (localAi) {
      try {
        await localAi.init();
        console.log('[Local AI] Settings store initialized.');
      } catch (error) {
        console.warn('[Local AI] Settings initialization failed:', error.message);
      }
    }
    startHoneyPorts();
    await loadPersistedHoneyBlocks();
      startDecoyProcess(port);
    startSocTargetWatcher();
    startDecoyIntegrityWatcher();
    startProblemAutomation();
  });
}

if (require.main === module && !process.env.NODE_TEST_CONTEXT) {
  startListening();
}

module.exports = {
  normalizeAttackEvent,
  computeSeverityLabel,
  upsertAttackDna,
  getAttackDna,
  recordDecoyAttackDna,
  isAuthorizedDecoyCollectorRequest,
  ATTACK_EVENT_TYPES,
  canonicalizeAttackEventType,
  ATTACK_GRAPH_STAGES,
  mapAttackEventToStage,
  appendAttackGraphEvent,
  registerAttackGraphTransition,
  getAttackTwinProbabilities,
  evaluateDeceptionTrigger,
  rotateDecoyRoute,
  adaptApiSchema,
  resolveActiveDecoyRoute,
  getActiveApiSchema,
  computeDecoyFileHashes,
  computeBaselineFileHashes,
  startDecoyIntegrityWatcher,
  rotateApiRoute,
  calculateResponsePolicy,
  checkDecoyIntegrity,
  detectSocTargetingAttempt,
  setDeceptionFreeze,
  getDeceptionFreeze,
  applyDeceptionConfigState,
  getActiveResponsePolicy,
  storeActiveResponsePolicy,
  countRecentRotationEvents,
  collectNormalizedSecurityEvent,
  markSecurityHistoryCleared,
  hasNewAutoBlockEvidence,
  verifyAdminPanelCredential,
  isDemoLoginAccepted,
  isLoginRateLimited,
  recordLoginFailure,
  clearLoginFailureState,
};
