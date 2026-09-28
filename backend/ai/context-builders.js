const { cleanText } = require('./validator');

function dbAll(db, sql, params) {
  return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));
}

function classifyUserAgent(value) {
  const userAgent = String(value || '').toLowerCase();
  if (!userAgent) return 'unknown';
  if (/scanner|masscan|nmap|zgrab|sqlmap|nikto/.test(userAgent)) return 'scanner';
  if (/curl|wget|python-requests|go-http-client/.test(userAgent)) return 'script';
  if (/mozilla|chrome|safari|firefox|edg\//.test(userAgent)) return 'browser';
  return 'unknown';
}

async function buildAttackerContext(db, ip) {
  const events = await dbAll(db,
    `SELECT created_at, severity, dest_port, rule, source, event_source, user_agent, description
     FROM security_events WHERE src_ip = ? ORDER BY id DESC LIMIT 40`,
    [ip]
  );
  const incidents = await dbAll(db,
    `SELECT id, title, severity, rule, mitre, stage, evidence, created_at
     FROM incidents WHERE source_ip = ? ORDER BY created_at DESC LIMIT 10`,
    [ip]
  );
  const blocks = await dbAll(db,
    `SELECT reason, action, mode, ttl_seconds, created_at, expires_at, removed_at
     FROM blocks WHERE ip = ? AND removed_at IS NULL AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
     ORDER BY id DESC LIMIT 3`,
    [ip]
  );

  const eventGroups = new Map();
  events.forEach(event => {
    const source = cleanText(event.event_source || event.source, 50);
    const severity = cleanText(event.severity, 16).toUpperCase();
    const rule = cleanText(event.rule, 90);
    const description = cleanText(event.description, 140);
    const userAgentClass = classifyUserAgent(event.user_agent);
    const key = JSON.stringify([source, severity, rule, description, userAgentClass]);
    const group = eventGroups.get(key) || {
      source,
      severity,
      rule,
      description,
      user_agent_class: userAgentClass,
      count: 0,
      ports: [],
    };
    group.count += 1;
    const port = Number(event.dest_port);
    if (Number.isInteger(port) && port > 0 && !group.ports.includes(port)) group.ports.push(port);
    eventGroups.set(key, group);
  });

  return {
    attacker_ip: ip,
    events: [...eventGroups.values()].slice(0, 12),
    incidents: incidents.slice(0, 5).map(incident => ({
      severity: cleanText(incident.severity, 16),
      rule: cleanText(incident.rule, 90),
      stage: cleanText(incident.stage, 40),
      evidence: cleanText(incident.evidence, 180),
    })),
    block_history: blocks.map(block => ({
      reason: cleanText(block.reason, 180),
      action: cleanText(block.action, 24),
      mode: cleanText(block.mode, 24),
      ttl_seconds: Number.isFinite(Number(block.ttl_seconds)) ? Number(block.ttl_seconds) : null,
      created_at: cleanText(block.created_at, 40),
      expires_at: cleanText(block.expires_at, 40),
      removed: Boolean(block.removed_at),
    })),
  };
}

module.exports = { buildAttackerContext };
