-- Reversible only for decoy-owned tables. Take a backup before running against production.
DROP TABLE IF EXISTS decoy_orders;
DROP TABLE IF EXISTS decoy_carts;
DROP TABLE IF EXISTS decoy_products;

-- SQLite removes a column by copying all existing rows into the previous shape.
BEGIN TRANSACTION;
CREATE TABLE security_events_without_event_source (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	source TEXT,
	severity TEXT,
	src_ip TEXT,
	dest_port INTEGER,
	rule TEXT,
	agent TEXT,
	description TEXT,
	raw_hash TEXT,
	origin TEXT DEFAULT 'live',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO security_events_without_event_source (id, source, severity, src_ip, dest_port, rule, agent, description, raw_hash, origin, created_at)
	SELECT id, source, severity, src_ip, dest_port, rule, agent, description, raw_hash, origin, created_at
	FROM security_events;
DROP TABLE security_events;
ALTER TABLE security_events_without_event_source RENAME TO security_events;
COMMIT;
