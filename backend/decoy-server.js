'use strict';

const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const config = require('./config');
const { createDecoyEventAdapter } = require('./decoy-event-adapter');
const { createDecoyEcommerceRouter } = require('./decoy-ecommerce');

const app = express();
const siteRoot = path.join(__dirname, '../honeypot-site');
const collectorUrl = process.env.DECOY_COLLECTOR_URL || '';
const decoyDb = new sqlite3.Database(config.decoy.dbPath);
const blockDb = new sqlite3.Database(process.env.BLOCK_DB_PATH || config.dbPath);
const blockedIpState = new Map();
const pagePaths = new Set([
  '/', '/products', '/search', '/categories', '/cart', '/checkout', '/login', '/register', '/profile', '/orders',
  '/admin', '/admin/login', '/admin/dashboard', '/admin/products', '/admin/orders', '/admin/users',
  '/admin/categories', '/admin/coupons', '/admin/settings', '/admin/reports', '/admin/logs',
]);

async function sendToCollector(event) {
  if (!collectorUrl) return false;
  try {
    const response = await fetch(collectorUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': config.apiKey },
      body: JSON.stringify(event),
    });
    if (!response.ok) return null;
    return response.json();
  } catch (error) {
    console.warn(`collector unavailable: ${error.message}`);
    return false;
  }
}

const emitDecoyEvent = createDecoyEventAdapter({ collectEvent: sendToCollector });

async function getActiveResponsePolicy(attackerIp) {
  if (!collectorUrl) return null;
  try {
    const response = await fetch(collectorUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': config.apiKey },
      body: JSON.stringify({ operation: 'response_policy', attacker_ip: attackerIp }),
    });
    if (!response.ok) return null;
    const body = await response.json();
    return body?.policy || null;
  } catch (error) {
    console.warn(`response policy lookup failed: ${error.message}`);
    return null;
  }
}

async function getActiveApiSchema(attackerIp) {
  if (!collectorUrl) return null;
  try {
    const response = await fetch(collectorUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': config.apiKey },
      body: JSON.stringify({ operation: 'schema_resolution', attacker_ip: attackerIp }),
    });
    if (!response.ok) return null;
    const body = await response.json();
    return body?.schema || null;
  } catch (error) {
    console.warn(`schema resolution failed: ${error.message}`);
    return null;
  }
}

async function resolveRotatedPath(requestPath, attackerIp, routeType = 'web') {
  if (!collectorUrl) return { path: requestPath };
  try {
    const response = await fetch(collectorUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': config.apiKey },
      body: JSON.stringify({ operation: 'route_resolution', route_type: routeType, path: requestPath, attacker_ip: attackerIp }),
    });
    if (!response.ok) return requestPath;
    const body = await response.json();
    return body || { path: requestPath };
  } catch (error) {
    console.warn(`route resolution failed: ${error.message}`);
    return { path: requestPath };
  }
}

function getPersistedBlock(ip) {
  return new Promise(resolve => {
    blockDb.get(
      `SELECT expires_at FROM blocks WHERE ip = ? AND removed_at IS NULL AND expires_at > ? ORDER BY id DESC LIMIT 1`,
      [ip, new Date().toISOString()],
      (error, row) => resolve(error ? null : row)
    );
  });
}

app.use(express.json({ limit: '32kb' }));
app.disable('x-powered-by');
app.use(async (req, res, next) => {
  const attackerIp = String(req.socket?.remoteAddress || req.ip || 'unknown').replace(/^::ffff:/, '');
  const currentBlock = blockedIpState.get(attackerIp) || await getPersistedBlock(attackerIp);
  const expiresAt = currentBlock ? (typeof currentBlock.expiresAt === 'number' ? currentBlock.expiresAt : new Date(currentBlock.expires_at).getTime()) : 0;
  if (expiresAt > Date.now()) {
    res.status(403).json({ error: 'Temporarily blocked', retry_after_seconds: Math.ceil((expiresAt - Date.now()) / 1000) });
    return;
  }
  if (currentBlock) blockedIpState.delete(attackerIp);

  const webResolution = await resolveRotatedPath(req.path, attackerIp, 'web');
  if (webResolution.invalidated) {
    res.status(404).json({ error: 'Decoy route retired' });
    return;
  }
  if (webResolution.path !== req.path) req.url = `${webResolution.path}${req.url.slice(req.path.length)}`;

  if (config.deception.applyApiRotation) {
    const apiPath = req.path.startsWith('/api/decoy/') ? `/api${req.path.slice('/api/decoy'.length)}` : req.path;
    const apiResolution = await resolveRotatedPath(apiPath, attackerIp, 'api');
    if (apiResolution.invalidated) {
      res.status(404).json({ error: 'Decoy API route retired' });
      return;
    }
    if (apiResolution.rotated) {
      const targetPath = String(apiResolution.path || apiPath).startsWith('/api/')
        ? `/api/decoy${String(apiResolution.path).slice(4)}`
        : String(apiResolution.path);
      req.url = `${targetPath}${req.url.slice(req.path.length)}`;
    }
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (process.env.DECOY_PARENT_ORIGINS) res.setHeader('Content-Security-Policy', `frame-ancestors ${process.env.DECOY_PARENT_ORIGINS}`);
  const isProductDetail = /^\/product\/[^/]+$/.test(req.path);
  const isPage = pagePaths.has(req.path) || isProductDetail;
  const isAsset = /\.(?:css|js|png|jpg|jpeg|svg|ico|woff2?)$/i.test(req.path);
  const scannerAgent = /nmap|nikto|sqlmap|masscan|burp|gobuster|ffuf/i.test(req.get('user-agent') || '');
  const suspiciousParameter = /(?:union(?:\+|\s)+select|<script|\.\.%2f|drop(?:\+|\s)+table|\bpasswd\b)/i.test(req.originalUrl || '');
  if (req.method === 'GET' && !isAsset && (isPage || scannerAgent || suspiciousParameter || !req.path.startsWith('/api/'))) {
    const eventType = suspiciousParameter ? 'Suspicious Parameter' : scannerAgent ? 'Scanner Behaviour' : !isPage ? 'Directory Probe' : req.path === '/' ? 'Decoy Homepage Access' : req.path.startsWith('/admin') ? 'Admin Panel Probe' : req.path === '/products' ? 'Product Enumeration' : isProductDetail ? 'Product Detail Access' : 'Decoy Page Access';
    const collectorResult = await emitDecoyEvent(req, {
      event_type: eventType,
      severity: suspiciousParameter || scannerAgent || req.path.startsWith('/admin') ? 'HIGH' : 'LOW',
      rule: `DECOY_PAGE_${req.path === '/' ? 'HOME' : req.path.slice(1).replace(/[^a-z0-9]+/gi, '_').toUpperCase()}`,
      description: `Synthetic e-commerce page accessed: ${req.path}.`,
    }).catch(() => null);
    if (collectorResult?.blocked && collectorResult.expiresAt) {
      blockedIpState.set(attackerIp, { expiresAt: new Date(collectorResult.expiresAt).getTime() });
      res.status(403).json({ error: 'Temporarily blocked', retry_after_seconds: Math.ceil((new Date(collectorResult.expiresAt).getTime() - Date.now()) / 1000) });
      return;
    }
  }
  next();
});

const decoy = createDecoyEcommerceRouter({ db: decoyDb, reviewDb: blockDb, emitEvent: emitDecoyEvent, getActiveResponsePolicy, getActiveApiSchema });
app.use('/api/decoy', decoy.router);
app.use(express.static(siteRoot, { index: 'index.html' }));
app.get([...pagePaths].filter(page => page !== '/'), (req, res) => res.sendFile(path.join(siteRoot, 'index.html')));
app.get('/product/:id', (req, res) => res.sendFile(path.join(siteRoot, 'product.html')));
app.get('/', (req, res) => res.sendFile(path.join(siteRoot, 'index.html')));

async function start() {
  try {
    await decoy.initialize();
    app.listen(config.decoy.port, '0.0.0.0', () => {
      console.log(`listening on http://0.0.0.0:${config.decoy.port}`);
    });
  } catch (error) {
    console.error(`initialization failed: ${error.message}`);
    process.exitCode = 1;
  }
}

start();
