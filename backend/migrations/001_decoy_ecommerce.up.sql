-- Additive migration. Run after taking a database checkpoint.
ALTER TABLE security_events ADD COLUMN event_source TEXT DEFAULT 'security';

CREATE TABLE IF NOT EXISTS decoy_products (
  product_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price_cents INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decoy_carts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attacker_ip TEXT,
  product_id TEXT,
  quantity INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decoy_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attacker_ip TEXT,
  total_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
