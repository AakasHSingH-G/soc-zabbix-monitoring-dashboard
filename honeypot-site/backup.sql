-- Northstar Relay - synthetic export, staging snapshot
-- This is a decoy file. No real customer, payment, or credential data is contained below.
CREATE TABLE accounts (id INT, username VARCHAR(64), role VARCHAR(32), email VARCHAR(128));
INSERT INTO accounts VALUES (1, 'admin', 'admin', 'a.mercer@northstar.local');
INSERT INTO accounts VALUES (2, 'j.park', 'operator', 'j.park@northstar.local');
CREATE TABLE orders (id VARCHAR(16), customer VARCHAR(128), total DECIMAL(10,2), status VARCHAR(32));
INSERT INTO orders VALUES ('NR-88213', 'field-ops-3@client-example.com', 214.00, 'Fulfilled');
-- end of synthetic snapshot
