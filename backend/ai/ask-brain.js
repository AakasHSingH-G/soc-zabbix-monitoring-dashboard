'use strict';

const MAX_QUESTION_LENGTH = 500;

const INTENTS = [
  ['top_attackers', /\b(top|most|noisiest|highest)\b.{0,40}\b(attacker|attackers|source ip|source ips)\b|\btop attackers\b/i],
  ['recent_incidents', /\b(recent|latest|new)\b.{0,30}\bincidents?\b|\bincidents?\b/i],
  ['block_history', /\b(block history|blocked ips|recent blocks|block list)\b/i],
  ['alert_volume', /\b(alert volume|event volume|how many alerts|alert count|security alerts)\b/i],
  ['honeyport_activity', /\b(honey.?port|honeypot)\b.{0,40}\b(activity|events|captures|traffic)\b|\b(honey.?port|honeypot) activity\b/i],
  ['zabbix_problems', /\bzabbix\b.{0,40}\bproblems?\b|\bproblems?\b.{0,40}\bzabbix\b/i],
  ['todays_changes', /\b(today'?s changes|changes today|what changed today|audit changes today)\b/i],
];

function dbAll(db, sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));
}

function classifyIntent(question) {
  if (typeof question !== 'string' || question.length > MAX_QUESTION_LENGTH) return null;
  const normalized = question.trim();
  if (!normalized) return null;
  return INTENTS.find(([, pattern]) => pattern.test(normalized))?.[0] || null;
}

async function answerFixedIntent(db, question, zabbixApi) {
  if (typeof question !== 'string' || question.length > MAX_QUESTION_LENGTH) {
    return { error: 'Question must be 500 characters or fewer' };
  }
  const intent = classifyIntent(question);
  if (!intent) return { intent: null, answer: 'unsupported question', items: [] };

  const queryLimit = [20];
  const queries = {
    top_attackers: () => dbAll(db, `SELECT src_ip AS attacker_ip, COUNT(*) AS alert_count,
        MAX(created_at) AS last_seen
      FROM security_events
      WHERE src_ip IS NOT NULL AND datetime(created_at) >= datetime('now', '-24 hours')
      GROUP BY src_ip ORDER BY alert_count DESC, last_seen DESC LIMIT ?`, [10]),
    recent_incidents: () => dbAll(db, `SELECT id, title, severity, source_ip, stage, created_at
      FROM incidents ORDER BY datetime(created_at) DESC LIMIT ?`, queryLimit),
    block_history: () => dbAll(db, `SELECT ip, reason, action, mode, created_at, expires_at, removed_at
      FROM blocks ORDER BY datetime(created_at) DESC LIMIT ?`, queryLimit),
    alert_volume: () => dbAll(db, `SELECT strftime('%Y-%m-%d %H:00', created_at) AS hour,
        COUNT(*) AS alert_count
      FROM security_events WHERE datetime(created_at) >= datetime('now', '-24 hours')
      GROUP BY hour ORDER BY hour DESC LIMIT ?`, [24]),
    honeyport_activity: () => dbAll(db, `SELECT src_ip, dest_port, protocol, source, scope, created_at
      FROM honey_captures ORDER BY datetime(created_at) DESC LIMIT ?`, queryLimit),
    todays_changes: () => dbAll(db, `SELECT actor, action, entity, created_at
      FROM audit_log WHERE date(created_at, 'localtime') = date('now', 'localtime')
      ORDER BY datetime(created_at) DESC LIMIT ?`, [50]),
  };

  if (intent === 'zabbix_problems') {
    const result = await zabbixApi.getProblems();
    return { intent, answer: result.zabbix_connected ? 'Recent Zabbix problems' : 'Zabbix is offline or not configured', items: result.problems || [], total: result.total || 0 };
  }

  const items = await queries[intent]();
  return { intent, answer: items.length ? `${items.length} matching records` : 'No matching records', items };
}

module.exports = { MAX_QUESTION_LENGTH, answerFixedIntent, classifyIntent };