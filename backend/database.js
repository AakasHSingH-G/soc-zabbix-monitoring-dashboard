const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const config = require('./config');

const IS_TEST_MODE = String(process.env.TEST_MODE || '').toLowerCase() === '1' || process.env.NODE_ENV === 'test' || Boolean(process.env.NODE_TEST_CONTEXT);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function seedInternalSecurityData() {
  const now = new Date().toISOString();
  const hosts = [
    { hostname: 'gateway-router', ip_address: '192.168.200.1', dns_name: 'gateway.local', host_group: 'Core Network', os: 'Linux', status: 'online', cpu_usage: 28, memory_usage: 41, disk_usage: 54, availability: 99.5 },
    { hostname: 'lab-controller', ip_address: '192.168.200.12', dns_name: 'lab.local', host_group: 'Lab Servers', os: 'Ubuntu', status: 'online', cpu_usage: 36, memory_usage: 52, disk_usage: 61, availability: 98.8 },
    { hostname: 'honeypot-2222', ip_address: '192.168.200.77', dns_name: 'honeypot.local', host_group: 'Deception', os: 'Linux', status: 'online', cpu_usage: 18, memory_usage: 24, disk_usage: 29, availability: 99.1 },
    { hostname: 'ops-windows', ip_address: '192.168.200.24', dns_name: 'ops.local', host_group: 'Endpoints', os: 'Windows', status: 'online', cpu_usage: 46, memory_usage: 63, disk_usage: 70, availability: 97.4 },
    { hostname: 'db-primary', ip_address: '192.168.200.30', dns_name: 'db.local', host_group: 'Databases', os: 'Linux', status: 'online', cpu_usage: 53, memory_usage: 68, disk_usage: 77, availability: 98.2 },
    { hostname: 'mail-gateway', ip_address: '192.168.200.18', dns_name: 'mail.local', host_group: 'Messaging', os: 'Linux', status: 'online', cpu_usage: 44, memory_usage: 58, disk_usage: 62, availability: 99.0 },
    { hostname: 'vpn-edge', ip_address: '192.168.200.40', dns_name: 'vpn.local', host_group: 'Remote Access', os: 'Linux', status: 'online', cpu_usage: 31, memory_usage: 49, disk_usage: 52, availability: 98.7 },
    { hostname: 'identity-svc', ip_address: '192.168.200.50', dns_name: 'id.local', host_group: 'Identity', os: 'Linux', status: 'online', cpu_usage: 58, memory_usage: 72, disk_usage: 76, availability: 97.9 }
  ];

  const events = [
    { source: 'internal-test', severity: 'HIGH', src_ip: '192.168.200.10', dest_port: 22, rule: 'SSH brute-force test', agent: 'local-lab-host', description: 'Repeated failed SSH login attempts from an internal test host.', raw_hash: 'LOCAL-SSH-01', origin: 'internal' },
    { source: 'internal-test', severity: 'MED', src_ip: '192.168.200.42', dest_port: 443, rule: 'Web scan', agent: 'gateway-proxy', description: 'Internal HTTP probe on the local network gateway.', raw_hash: 'LOCAL-WEB-02', origin: 'internal' },
    { source: 'honey-port', severity: 'LOW', src_ip: '192.168.200.77', dest_port: 2222, rule: 'Decoy service probe', agent: 'honey-port-2222', description: 'Connection attempt to a honey listener on the internal network.', raw_hash: 'LOCAL-HONEY-03', origin: 'internal' },
    { source: 'internal-test', severity: 'HIGH', src_ip: '192.168.200.24', dest_port: 3389, rule: 'RDP reconnaissance', agent: 'ops-windows', description: 'Repeated RDP port checks from an internal workstation.', raw_hash: 'LOCAL-RDP-04', origin: 'internal' },
    { source: 'internal-test', severity: 'MED', src_ip: '192.168.200.30', dest_port: 3306, rule: 'Database port scan', agent: 'db-primary', description: 'Database service probe against the local primary database node.', raw_hash: 'LOCAL-DB-05', origin: 'internal' },
    { source: 'internal-test', severity: 'LOW', src_ip: '192.168.200.12', dest_port: 8080, rule: 'Local app probe', agent: 'lab-controller', description: 'Application endpoint probe against the lab controller host.', raw_hash: 'LOCAL-APP-06', origin: 'internal' },
    { source: 'internal-test', severity: 'HIGH', src_ip: '192.168.200.50', dest_port: 22, rule: 'Privilege escalation pattern', agent: 'identity-svc', description: 'Internal host attempted repeated credential abuse against the identity service.', raw_hash: 'LOCAL-ID-07', origin: 'internal' },
    { source: 'internal-test', severity: 'MED', src_ip: '192.168.200.18', dest_port: 25, rule: 'Mail relay validation', agent: 'mail-gateway', description: 'Mail gateway observed internal SMTP relay misuse from a trusted lab subnet.', raw_hash: 'LOCAL-MAIL-08', origin: 'internal' },
    { source: 'internal-test', severity: 'LOW', src_ip: '192.168.200.40', dest_port: 443, rule: 'VPN endpoint checking', agent: 'vpn-edge', description: 'Remote access gateway was scanned for exposed services by an internal validator.', raw_hash: 'LOCAL-VPN-09', origin: 'internal' }
  ];

  const incidents = [
    { id: 'INT-LOCAL-001', title: 'Internal SSH patrol alert', severity: 'HIGH', source_ip: '192.168.200.10', rule: 'SSH brute-force test', mitre: 'T1110.001', stage: 'Detected', evidence: 'Local test environment generated repeated SSH failures on internal subnet.', acknowledged_by: 'local-admin', created_at: now, updated_at: now },
    { id: 'INT-LOCAL-002', title: 'Internal web probe', severity: 'MED', source_ip: '192.168.200.42', rule: 'Web scan', mitre: 'T1595.002', stage: 'Investigated', evidence: 'Port 443 probe observed from a local test host.', acknowledged_by: 'local-admin', created_at: now, updated_at: now },
    { id: 'INT-LOCAL-003', title: 'Identity service brute-force attempt', severity: 'HIGH', source_ip: '192.168.200.50', rule: 'Privilege escalation pattern', mitre: 'T1110.001', stage: 'Contained', evidence: 'Repeated SSH and API credential attempts against the identity service were blocked.', acknowledged_by: 'local-admin', created_at: now, updated_at: now },
    { id: 'INT-LOCAL-004', title: 'Mail relay validation anomaly', severity: 'MED', source_ip: '192.168.200.18', rule: 'Mail relay validation', mitre: 'T1114', stage: 'Detected', evidence: 'Internal SMTP relay checks triggered a suspicious mail-path validation event.', acknowledged_by: 'local-admin', created_at: now, updated_at: now }
  ];

  const captures = [
    { src_ip: '192.168.200.77', dest_port: 2222, protocol: 'TCP', source: 'internal-test', country: 'Local', city: 'Lab', lat: 0, lng: 0, scope: 'INTERNAL', description: 'Internal decoy service probe', origin: 'internal' },
    { src_ip: '192.168.200.42', dest_port: 443, protocol: 'TCP', source: 'internal-test', country: 'Local', city: 'Lab', lat: 0, lng: 0, scope: 'INTERNAL', description: 'Local HTTPS probe', origin: 'internal' },
    { src_ip: '192.168.200.24', dest_port: 3389, protocol: 'TCP', source: 'internal-test', country: 'Local', city: 'Lab', lat: 0, lng: 0, scope: 'INTERNAL', description: 'RDP traversal probe', origin: 'internal' },
    { src_ip: '192.168.200.50', dest_port: 22, protocol: 'TCP', source: 'internal-test', country: 'Local', city: 'Lab', lat: 0, lng: 0, scope: 'INTERNAL', description: 'Identity service brute-force probe', origin: 'internal' },
    { src_ip: '192.168.200.18', dest_port: 25, protocol: 'TCP', source: 'internal-test', country: 'Local', city: 'Lab', lat: 0, lng: 0, scope: 'INTERNAL', description: 'SMTP relay validation test', origin: 'internal' }
  ];

  const needsReset = () => new Promise((resolve) => {
    db.all('SELECT hostname, cpu_usage, memory_usage, disk_usage FROM managed_hosts', [], (err, rows) => {
      if (err) return resolve(true);
      const stale = !rows.length || rows.every(row => {
        const hostName = String(row.hostname || '').toLowerCase();
        const zeroed = Number(row.cpu_usage || 0) === 0 && Number(row.memory_usage || 0) === 0 && Number(row.disk_usage || 0) === 0;
        return hostName === 'gurudev' || zeroed;
      });
      resolve(stale);
    });
  });

  needsReset().then((resetData) => {
    if (resetData) {
      db.run('DELETE FROM managed_hosts', () => {
        hosts.forEach(host => {
          db.run(`INSERT INTO managed_hosts (hostname, ip_address, dns_name, host_group, os, status, cpu_usage, memory_usage, disk_usage, availability, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [host.hostname, host.ip_address, host.dns_name, host.host_group, host.os, host.status, host.cpu_usage, host.memory_usage, host.disk_usage, host.availability, now], () => {});
        });
      });
    }
  });

  db.get('SELECT COUNT(*) AS total FROM security_events', [], (err, eventRow) => {
    if (!err && Number(eventRow?.total || 0) < 6) {
      db.run('DELETE FROM security_events', () => {
        events.forEach(event => {
          db.run(`INSERT INTO security_events (source, severity, src_ip, dest_port, rule, agent, description, raw_hash, origin, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [event.source, event.severity, event.src_ip, event.dest_port, event.rule, event.agent, event.description, event.raw_hash, event.origin, now], () => {});
        });
      });
    }
  });

  db.get('SELECT COUNT(*) AS total FROM incidents', [], (err, incidentRow) => {
    if (!err && Number(incidentRow?.total || 0) < 2) {
      db.run('DELETE FROM incidents', () => {
        incidents.forEach(item => {
          db.run(`INSERT INTO incidents (id, title, severity, source_ip, rule, mitre, stage, evidence, acknowledged_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [item.id, item.title, item.severity, item.source_ip, item.rule, item.mitre, item.stage, item.evidence, item.acknowledged_by, item.created_at, item.updated_at], () => {});
        });
      });
    }
  });

  db.get('SELECT COUNT(*) AS total FROM honey_captures', [], (err, captureRow) => {
    if (!err && Number(captureRow?.total || 0) < 3) {
      db.run('DELETE FROM honey_captures', () => {
        captures.forEach(item => {
          db.run(`INSERT INTO honey_captures (src_ip, dest_port, protocol, source, country, city, lat, lng, scope, description, origin, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [item.src_ip, item.dest_port, item.protocol, item.source, item.country, item.city, item.lat, item.lng, item.scope, item.description, item.origin, now], () => {});
        });
      });
    }
  });
}

const db = new sqlite3.Database(IS_TEST_MODE ? ':memory:' : config.dbPath, (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      admin_panel_password TEXT,
      full_name TEXT,
      email TEXT,
      role TEXT,
      status TEXT,
      last_login TEXT
    )`, (err) => {
      if (err) {
        console.error('Error creating users table', err.message);
      } else {
        db.run('ALTER TABLE users ADD COLUMN admin_panel_password TEXT', () => {
        // Ensure the documented demo users exist without overwriting custom users.
        const defaultUsers = [
          ['admin', process.env.INITIAL_ADMIN_PASSWORD && process.env.INITIAL_ADMIN_PASSWORD !== 'CHANGE_ME' ? process.env.INITIAL_ADMIN_PASSWORD : (IS_TEST_MODE ? crypto.randomBytes(32).toString('hex') : null), 'System Administrator', 'admin@company.com', 'admin', 'INITIAL_ADMIN_PASSWORD'],
          ['viewer', process.env.INITIAL_VIEWER_PASSWORD && process.env.INITIAL_VIEWER_PASSWORD !== 'CHANGE_ME' ? process.env.INITIAL_VIEWER_PASSWORD : (IS_TEST_MODE ? crypto.randomBytes(32).toString('hex') : null), 'Read-Only User', 'viewer@company.com', 'viewer', 'INITIAL_VIEWER_PASSWORD'],
          ['analyst', process.env.INITIAL_ANALYST_PASSWORD && process.env.INITIAL_ANALYST_PASSWORD !== 'CHANGE_ME' ? process.env.INITIAL_ANALYST_PASSWORD : (IS_TEST_MODE ? crypto.randomBytes(32).toString('hex') : null), 'SOC Analyst', 'analyst@company.com', 'analyst', 'INITIAL_ANALYST_PASSWORD'],
        ];
        const insert = 'INSERT OR IGNORE INTO users (username, password, full_name, email, role, status, last_login) VALUES (?,?,?,?,?,?,?)';
        const now = new Date().toISOString();
        const adminPanelPassword = process.env.ADMIN_PANEL_PASSWORD && process.env.ADMIN_PANEL_PASSWORD !== 'CHANGE_ME' ? process.env.ADMIN_PANEL_PASSWORD : (IS_TEST_MODE ? crypto.randomBytes(32).toString('hex') : null);
        db.all('SELECT username, role, admin_panel_password FROM users', [], (seedCheckErr, existingUsers) => {
          if (seedCheckErr) throw new Error(`Unable to check initial users: ${seedCheckErr.message}`);
          const usersToInsert = existingUsers.length === 0 ? defaultUsers : [];
          const adminsNeedingPanelPassword = existingUsers.some(user => user.role === 'admin' && !user.admin_panel_password);
          const missingInitialPasswords = usersToInsert.filter(user => !user[1]).map(user => user[5]);
          const needsPanelPassword = adminsNeedingPanelPassword || usersToInsert.some(user => user[4] === 'admin');

          if (missingInitialPasswords.length || (needsPanelPassword && !adminPanelPassword)) {
            const required = [...missingInitialPasswords, ...(needsPanelPassword && !adminPanelPassword ? ['ADMIN_PANEL_PASSWORD'] : [])];
            throw new Error(`Set ${required.join(', ')} before initializing the missing SOC user credentials.`);
          }

          usersToInsert.forEach(user => {
            db.run(insert, [user[0], hashPassword(user[1]), user[2], user[3], user[4], 'active', now]);
          });

          // Migrate legacy plaintext passwords once, without changing user-selected passwords.
          db.all('SELECT id, password FROM users', [], (migrationQueryErr, rows) => {
            if (migrationQueryErr) {
              console.error('Error checking password hashes', migrationQueryErr.message);
              return;
            }
            rows.forEach(user => {
              if (user.password && !user.password.startsWith('scrypt:')) {
                db.run('UPDATE users SET password = ? WHERE id = ?', [hashPassword(user.password), user.id]);
              }
            });
          });

          // Keep the panel verification credential separate from the login credential.
          if (needsPanelPassword) {
            db.run('UPDATE users SET admin_panel_password = ? WHERE role = ? AND (admin_panel_password IS NULL OR admin_panel_password = ?)', [hashPassword(adminPanelPassword), 'admin', ''], migrationErr => {
              if (migrationErr) console.error('Error initializing admin panel password', migrationErr.message);
            });
          }
        });
        });
      }
    });

    db.run(`CREATE TABLE IF NOT EXISTS managed_hosts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hostname TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      dns_name TEXT,
      host_group TEXT NOT NULL,
      os TEXT,
      status TEXT NOT NULL DEFAULT 'online',
      cpu_usage INTEGER NOT NULL DEFAULT 0,
      memory_usage INTEGER NOT NULL DEFAULT 0,
      disk_usage INTEGER NOT NULL DEFAULT 0,
      availability REAL NOT NULL DEFAULT 99.99,
      created_at TEXT NOT NULL
    )`, (err) => {
      if (err) console.error('Error creating managed_hosts table', err.message);
    });

    const schemaSql = [
      `CREATE TABLE IF NOT EXISTS security_events (
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
        origin TEXT DEFAULT 'live',
        event_source TEXT DEFAULT 'security',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS threat_intel (
        ip TEXT PRIMARY KEY,
        geo_country TEXT,
        geo_city TEXT,
        lat REAL,
        lng REAL,
        asn TEXT,
        abuse_score INTEGER,
        abuse_reports INTEGER,
        greynoise_class TEXT,
        local_score INTEGER,
        score_breakdown TEXT,
        fetched_at TEXT,
        expires_at TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS threat_intel_state (
        state_key TEXT PRIMARY KEY,
        state_value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        reason TEXT,
        incident_id TEXT,
        action TEXT,
        requested_by TEXT,
        approved_by TEXT,
        mode TEXT,
        ttl_seconds INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT,
        verified_at TEXT,
        verify_result TEXT,
        removed_at TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT,
        actor_ip TEXT,
        action TEXT,
        entity TEXT,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS integrations (
        name TEXT PRIMARY KEY,
        status TEXT,
        last_test_at TEXT,
        last_test_result TEXT,
        detail TEXT
      )`,
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
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS honey_captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        dest_port INTEGER,
        protocol TEXT,
        source TEXT,
        country TEXT,
        city TEXT,
        lat REAL,
        lng REAL,
        scope TEXT,
        description TEXT,
        origin TEXT DEFAULT 'live',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS automation_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        source TEXT,
        payload TEXT,
        result TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS attack_dna (
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
      )`,
      `CREATE TABLE IF NOT EXISTS attack_dna_observations (
        attacker_ip TEXT NOT NULL,
        dimension TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (attacker_ip, dimension, value)
      )`,
      `CREATE TABLE IF NOT EXISTS attack_dna_observation_baseline (
        attacker_ip TEXT NOT NULL,
        dimension TEXT NOT NULL,
        baseline_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (attacker_ip, dimension)
      )`,
      `CREATE TABLE IF NOT EXISTS attack_graph_node (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attacker_ip TEXT NOT NULL,
        stage TEXT NOT NULL,
        event_id TEXT,
        timestamp TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS stage_transition_counts (
        from_stage TEXT NOT NULL,
        to_stage TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (from_stage, to_stage)
      )`,
      `CREATE TABLE IF NOT EXISTS deception_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attacker_ip TEXT,
        action_type TEXT,
        target TEXT,
        reason TEXT,
        previous_value TEXT,
        new_value TEXT,
        timestamp TEXT NOT NULL,
        success INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS decoy_route_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        route_type TEXT NOT NULL,
        old_path TEXT,
        new_path TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        rotated_at TEXT NOT NULL,
        reason TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS decoy_api_route_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        route_type TEXT NOT NULL,
        old_path TEXT,
        new_path TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        rotated_at TEXT NOT NULL,
        reason TEXT,
        attacker_ip TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS decoy_api_schema_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attacker_ip TEXT,
        current_version TEXT NOT NULL,
        previous_version TEXT,
        reason TEXT,
        rotated_at TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1
      )`,
      `CREATE TABLE IF NOT EXISTS decoy_integrity_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        container_id TEXT,
        check_type TEXT,
        result TEXT,
        reason TEXT,
        restored INTEGER NOT NULL DEFAULT 0,
        timestamp TEXT NOT NULL
      )`
    ];

    schemaSql.forEach(statement => {
      db.run(statement, (err) => {
        if (err) console.error('Error creating schema table', err.message);
      });
    });

    // Additive, backward-compatible migration for normalized decoy events.
    db.run(`ALTER TABLE security_events ADD COLUMN event_source TEXT DEFAULT 'security'`, () => {});
    db.run(`ALTER TABLE security_events ADD COLUMN user_agent TEXT`, () => {});

    setTimeout(() => {
      seedInternalSecurityData();
    }, 200);
  }
});

module.exports = db;
