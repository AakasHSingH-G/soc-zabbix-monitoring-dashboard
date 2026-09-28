'use strict';

const express = require('express');
const crypto = require('crypto');
const config = require('./config');

const PRODUCTS = [
  { id: 'decoy-1', name: 'Relay Field Kit', category: 'field', price_cents: 12800, description: 'Synthetic demo equipment for decoy interactions.' },
  { id: 'decoy-2', name: 'Signal Desk Lamp', category: 'desk', price_cents: 8600, description: 'Synthetic demo product with no real inventory.' },
  { id: 'decoy-3', name: 'Northstar Cable Roll', category: 'carry', price_cents: 4200, description: 'Synthetic demo accessory for monitoring tests.' },
];

function createDecoyEcommerceRouter({ db, emitEvent, getActiveResponsePolicy, getActiveApiSchema, reviewDb = db }) {
  const router = express.Router();
  const requestCounts = new Map();

  function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => db.run(sql, params, function onRun(error) {
      if (error) return reject(error);
      resolve({ lastID: this.lastID, changes: this.changes });
    }));
  }

  function reviewDbRun(sql, params = []) {
    return new Promise((resolve, reject) => reviewDb.run(sql, params, function onRun(error) {
      if (error) return reject(error);
      resolve({ lastID: this.lastID, changes: this.changes });
    }));
  }

  function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => {
      if (error) return reject(error);
      resolve(rows || []);
    }));
  }

  function text(value, max = 160) {
    return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max);
  }

  function rateLimit(req, res, next) {
    const key = `${req.ip}:${Math.floor(Date.now() / 60000)}`;
    const count = (requestCounts.get(key) || 0) + 1;
    requestCounts.set(key, count);
    if (requestCounts.size > 500) requestCounts.clear();
    if (count > 60) return res.status(429).json({ error: 'Decoy request limit reached' });
    next();
  }

  async function adaptResponsePolicy(req, res, next) {
    if (!config.deception.applyResponsePolicy) return next();

    let policy = { mode: 'low', delay_ms: 0, manual_review: false, enhanced_instrumentation: false, fake_response: false };
    try {
      if (typeof getActiveResponsePolicy === 'function') {
        const resolved = await getActiveResponsePolicy(req.ip);
        if (resolved && typeof resolved === 'object') {
          policy = { ...policy, ...resolved };
        }
      }
    } catch (error) {
      console.warn('[Decoy] response policy lookup failed:', error.message);
    }

    if (policy.fake_response === true) {
      req.__useFakeDecoyData = true;
    }

    if (policy.manual_review === true) {
      try {
        await reviewDbRun(
          'INSERT INTO manual_review_queue (attacker_ip, path, method, reason, created_at, reviewed) VALUES (?, ?, ?, ?, ?, 0)',
          [req.ip, req.path, req.method, `Response policy ${policy.mode || 'unknown'} requires review`, new Date().toISOString()]
        );
      } catch (error) {
        console.warn('[Decoy] manual review queue insert failed:', error.message);
      }
    }

    const delayMs = Math.max(0, Number(policy.delay_ms) || 0);
    if (delayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
    next();
  }

  async function adaptApiSchema(req, res, next) {
    if (!config.deception.applyApiSchema || typeof getActiveApiSchema !== 'function') return next();
    const schema = await getActiveApiSchema(req.ip).catch(() => null);
    if (!schema || schema.current_version === 'V1') return next();
    const originalJson = res.json.bind(res);
    res.json = payload => originalJson({ schema_version: schema.current_version, data: payload });
    req.__activeApiSchema = schema.current_version;
    next();
  }

  router.use(rateLimit);
  router.use(adaptResponsePolicy);
  router.use(adaptApiSchema);

  router.get('/status', (req, res) => {
    res.json({ enabled: true, event_source: 'decoy_ecommerce', synthetic_data: true });
  });

  router.get('/products', async (req, res) => {
    try {
      if (req.__useFakeDecoyData) {
        return res.json({ products: PRODUCTS });
      }
      const products = await dbAll('SELECT product_id AS id, name, category, price_cents, description FROM decoy_products ORDER BY product_id');
      res.json({ products });
    } catch (error) {
      console.warn('[Decoy] product read failed:', error.message);
      res.status(503).json({ error: 'Decoy catalog unavailable' });
    }
  });

  router.get('/products/:id', async (req, res) => {
    try {
      if (req.__useFakeDecoyData) {
        const product = PRODUCTS.find(item => item.id === text(req.params.id, 40));
        if (!product) return res.status(404).json({ error: 'Product not found' });
        return res.json({ product });
      }
      const rows = await dbAll('SELECT product_id AS id, name, category, price_cents, description FROM decoy_products WHERE product_id = ?', [text(req.params.id, 40)]);
      if (!rows.length) return res.status(404).json({ error: 'Product not found' });
      res.json({ product: rows[0] });
    } catch (error) {
      console.warn('[Decoy] product detail failed:', error.message);
      res.status(503).json({ error: 'Decoy catalog unavailable' });
    }
  });

  router.post('/login', async (req, res) => {
    try {
      const username = text(req.body?.username, 80);
      await emitEvent(req, {
        event_type: 'Fake Login Attempt',
        severity: 'HIGH',
        rule: 'DECOY_FAKE_LOGIN',
        description: `Synthetic decoy login attempt for username ${username || 'blank'}.`,
        metadata: { username, password_supplied: Boolean(req.body?.password) },
      });
      res.status(401).json({ error: 'Invalid credentials' });
    } catch (error) {
      console.warn('[Decoy] login event failed:', error.message);
      res.status(503).json({ error: 'Decoy login unavailable' });
    }
  });

  router.post('/cart', async (req, res) => {
    try {
      const productId = text(req.body?.product_id, 40);
      const quantity = Math.min(20, Math.max(1, Number.parseInt(req.body?.quantity, 10) || 1));
      await dbRun('INSERT INTO decoy_carts (attacker_ip, product_id, quantity, created_at) VALUES (?, ?, ?, ?)', [req.ip, productId, quantity, new Date().toISOString()]);
      await emitEvent(req, {
        event_type: 'Cart Manipulation',
        severity: 'MED',
        rule: 'DECOY_CART_MUTATION',
        description: `Synthetic cart mutation for product ${productId || 'unknown'}.`,
        metadata: { product_id: productId, quantity },
      });
      res.status(202).json({ accepted: true, cart_id: `decoy-cart-${crypto.randomUUID().slice(0, 8)}` });
    } catch (error) {
      console.warn('[Decoy] cart event failed:', error.message);
      res.status(503).json({ error: 'Decoy cart unavailable' });
    }
  });

  router.post('/checkout', async (req, res) => {
    try {
      const totalCents = Math.min(1000000, Math.max(0, Number.parseInt(req.body?.total_cents, 10) || 0));
      await dbRun('INSERT INTO decoy_orders (attacker_ip, total_cents, status, created_at) VALUES (?, ?, ?, ?)', [req.ip, totalCents, 'simulated', new Date().toISOString()]);
      await emitEvent(req, {
        event_type: 'Checkout Probe',
        severity: 'HIGH',
        rule: 'DECOY_CHECKOUT_ATTEMPT',
        description: 'Synthetic checkout submitted; no payment provider or email service was contacted.',
        metadata: { total_cents: totalCents, payment_processed: false },
      });
      res.status(202).json({ accepted: true, status: 'simulated', payment_processed: false });
    } catch (error) {
      console.warn('[Decoy] checkout event failed:', error.message);
      res.status(503).json({ error: 'Decoy checkout unavailable' });
    }
  });

  router.all('/admin/*', async (req, res) => {
    try {
      await emitEvent(req, {
        event_type: 'Admin Panel Probe',
        severity: 'HIGH',
        rule: 'DECOY_ADMIN_PROBE',
        description: `Synthetic admin route probe: ${text(req.originalUrl, 180)}.`,
        metadata: { method: req.method, path: text(req.path, 120) },
      });
      res.status(403).json({ error: 'Administrative access denied' });
    } catch (error) {
      console.warn('[Decoy] admin event failed:', error.message);
      res.status(503).json({ error: 'Decoy admin unavailable' });
    }
  });

  router.use((error, req, res, next) => {
    console.warn('[Decoy] isolated route error:', error.message);
    if (res.headersSent) return next(error);
    res.status(503).json({ error: 'Decoy module unavailable' });
  });

  return { router, initialize: async () => {
    await dbRun(`CREATE TABLE IF NOT EXISTS decoy_products (
      product_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      price_cents INTEGER NOT NULL DEFAULT 0,
      description TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    await dbRun(`CREATE TABLE IF NOT EXISTS decoy_carts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      product_id TEXT,
      quantity INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    )`);
    await dbRun(`CREATE TABLE IF NOT EXISTS decoy_orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      total_cents INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    await reviewDbRun(`CREATE TABLE IF NOT EXISTS manual_review_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attacker_ip TEXT,
      path TEXT,
      method TEXT,
      reason TEXT,
      created_at TEXT NOT NULL,
      reviewed INTEGER DEFAULT 0
    )`);
    for (const product of PRODUCTS) {
      await dbRun('INSERT OR IGNORE INTO decoy_products (product_id, name, category, price_cents, description, created_at) VALUES (?, ?, ?, ?, ?, ?)', [product.id, product.name, product.category, product.price_cents, product.description, new Date().toISOString()]);
    }
  }};
}

module.exports = { createDecoyEcommerceRouter };
