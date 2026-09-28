'use strict';

const crypto = require('node:crypto');
const net = require('node:net');

const PORT_SERVICES = new Map([
  [22, 'ssh'], [23, 'telnet'], [25, 'mail'], [53, 'dns'], [80, 'http'], [110, 'mail'],
  [143, 'mail'], [443, 'https'], [445, 'smb'], [3389, 'rdp'], [3306, 'db'], [5432, 'db'],
  [6379, 'redis'], [8080, 'http'], [8081, 'http'], [9200, 'db'], [10050, 'zabbix-agent'],
  [10051, 'zabbix-server'], [1433, 'db'], [27017, 'db'],
]);

const PATH_PATTERNS = [
  ['zabbix-web', /\/zabbix|api_jsonrpc|zabbix/i],
  ['wp-admin', /wp-admin|wp-login|xmlrpc/i],
  ['sensitive-file', /\.env|\.git|backup|config(?:uration)?\.php/i],
  ['phpmyadmin', /phpmyadmin/i],
  ['actuator', /actuator/i],
  ['cgi-bin', /cgi-bin/i],
  ['admin-panel', /\/admin|admin panel/i],
  ['shell-like', /webshell|shell|cmd\.exe|powershell/i],
  ['traversal', /\.\.|%2e%2e|\/etc\/passwd/i],
  ['sqli-like', /union(?:\s|%20)+select|sql.?injection|or\s+1=1/i],
  ['rce-probe', /\brce\b|command.?injection|;\s*(?:id|whoami)|\$\(/i],
  ['log4j-like', /jndi|\$\{.*lower:/i],
  ['login', /login|signin|auth/i],
];

const PRIORS = {
  S1: [['ssh_bruteforce', 0.55, '1h'], ['broader_port_scan', 0.25, '1h'], ['go_quiet_return_later', 0.20, '24h']],
  S2: [['continued_bruteforce_wider_userlist', 0.60, '1h'], ['switch_to_other_service', 0.20, '24h'], ['success_attempt_common_creds', 0.20, '1h']],
  S3: [['post_access_recon_commands', 0.55, '15m'], ['payload_download_dropper', 0.30, '15m'], ['persistence_attempt', 0.15, '1h']],
  S4: [['rdp_bruteforce', 0.60, '1h'], ['smb_probe', 0.20, '1h'], ['go_quiet_return_later', 0.20, '24h']],
  S5: [['iot_default_cred_bruteforce', 0.65, '15m'], ['botnet_payload_drop', 0.25, '1h'], ['go_quiet_return_later', 0.10, '24h']],
  S6: [['web_login_bruteforce', 0.50, '1h'], ['plugin_theme_exploit_probe', 0.30, '24h'], ['sqli_xss_probe', 0.20, '1h']],
  S7: [['credential_harvest_then_reuse', 0.45, '24h'], ['source_disclosure_followup', 0.35, '1h'], ['cloud_key_abuse_attempt', 0.20, '7d']],
  S8: [['exploit_attempt_same_cve', 0.60, '15m'], ['second_cve_probe', 0.25, '1h'], ['callback_beacon_test', 0.15, '1h']],
  S9: [['unauthenticated_access_attempt', 0.55, '1h'], ['db_bruteforce', 0.30, '1h'], ['data_dump_attempt', 0.15, '24h']],
  S10: [['zabbix_default_credential_login', 0.50, '1h'], ['zabbix_api_enumeration', 0.30, '1h'], ['known_zabbix_vuln_probe', 0.20, '24h']],
  S11: [['targeted_service_followup', 0.50, '24h'], ['idle_then_return', 0.35, '7d'], ['ignore_other', 0.15, '24h']],
  S12: [['command_execution_attempt', 0.50, '15m'], ['second_stage_download', 0.30, '15m'], ['lateral_probe', 0.20, '1h']],
  S13: [['more_sibling_ips_join', 0.65, '1h'], ['campaign_service_followup', 0.25, '24h'], ['campaign_go_quiet', 0.10, '7d']],
};

const MITRE_BY_SIGNATURE = {
  S1: 'T1595', S2: 'T1110', S3: 'T1059', S4: 'T1133', S5: 'T1110', S6: 'T1190',
  S7: 'T1552', S8: 'T1190', S9: 'T1190', S10: 'T1078', S11: 'T1595', S12: 'T1059', S13: 'T1583',
};

function dbAll(db, sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));
}

function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(error) { error ? reject(error) : resolve(this.changes); }));
}

async function initializePredictorTables(db) {
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_ip_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ts TEXT NOT NULL,
    action_class TEXT NOT NULL, port INTEGER, service TEXT NOT NULL, stage TEXT NOT NULL,
    weight INTEGER NOT NULL, UNIQUE(ip, ts, action_class, port)
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_attacker_profiles (
    ip TEXT PRIMARY KEY, features_json TEXT NOT NULL, updated_at TEXT NOT NULL
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_playbook_priors (
    signature TEXT NOT NULL, next_action TEXT NOT NULL, probability REAL NOT NULL,
    window TEXT NOT NULL, version INTEGER NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY(signature, next_action, version)
  )`);
  await dbRun(db, `CREATE TABLE IF NOT EXISTS ai_mitre_map (
    signature TEXT PRIMARY KEY, technique_key TEXT NOT NULL, description TEXT NOT NULL
  )`);
  const now = new Date().toISOString();
  for (const [signature, entries] of Object.entries(PRIORS)) {
    for (const [nextAction, probability, window] of entries) {
      await dbRun(db, 'INSERT OR IGNORE INTO ai_playbook_priors (signature, next_action, probability, window, version, updated_at) VALUES (?, ?, ?, ?, 1, ?)', [signature, nextAction, probability, window, now]);
    }
  }
  for (const [signature, technique] of Object.entries(MITRE_BY_SIGNATURE)) {
    await dbRun(db, 'INSERT OR IGNORE INTO ai_mitre_map (signature, technique_key, description) VALUES (?, ?, ?)', [signature, technique, 'Seeded technique mapping; advisory lookup only']);
  }
}

async function readPlaybookPriors(db) {
  const rows = await dbAll(db, `SELECT signature, next_action, probability, window
    FROM ai_playbook_priors AS priors
    WHERE version = (SELECT MAX(version) FROM ai_playbook_priors WHERE signature = priors.signature)
    ORDER BY signature, probability DESC`);
  const priors = {};
  for (const row of rows) (priors[row.signature] ||= []).push([row.next_action, Number(row.probability), row.window]);
  return priors;
}

async function readMitreMap(db) {
  const rows = await dbAll(db, 'SELECT signature, technique_key FROM ai_mitre_map');
  return Object.fromEntries(rows.map(row => [row.signature, row.technique_key]));
}

async function persistProfile(db, ip, features) {
  const sanitized = { ...features };
  delete sanitized.ip;
  await dbRun(db, `INSERT INTO ai_attacker_profiles (ip, features_json, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET features_json = excluded.features_json, updated_at = excluded.updated_at`,
  [ip, JSON.stringify(sanitized), new Date().toISOString()]);
}

async function findCampaignSiblings(db, ip, events = []) {
  if (net.isIP(String(ip)) !== 4) return { siblings: 0, similarity: 0 };
  const parts = String(ip).split('.');
  const prefix = `${parts[0]}.${parts[1]}.${parts[2]}.`;
  const rows = await dbAll(db, `SELECT src_ip, created_at, dest_port, rule, description, user_agent
    FROM security_events WHERE src_ip LIKE ? AND src_ip <> ?
    AND datetime(created_at) >= datetime('now', '-1 day')
    ORDER BY id DESC LIMIT 200`, [`${prefix}%`, ip]);
  if (!rows.length) return { siblings: 0, similarity: 0 };
  const reference = buildFeatureVector(ip, events);
  const grouped = new Map();
  for (const row of rows) {
    if (!grouped.has(row.src_ip)) grouped.set(row.src_ip, []);
    grouped.get(row.src_ip).push(row);
  }
  let siblings = 0;
  let matchedSignals = 0;
  for (const [siblingIp, siblingEvents] of grouped) {
    const candidate = buildFeatureVector(siblingIp, siblingEvents);
    const serviceMatch = candidate.service_classes.some(service => reference.service_classes.includes(service));
    const pathMatch = candidate.path_classes.some(path => path !== 'other' && reference.path_classes.includes(path));
    const uaMatch = candidate.ua_classes.some(ua => ua !== 'unknown' && reference.ua_classes.includes(ua));
    if (candidate.signature === reference.signature && (serviceMatch || pathMatch || uaMatch)) {
      siblings += 1;
      matchedSignals += Number(serviceMatch) + Number(pathMatch) + Number(uaMatch);
    }
  }
  return { siblings, similarity: siblings ? Math.min(1, matchedSignals / (siblings * 3)) : 0 };
}

function textOf(event) {
  return [event.rule, event.description, event.path, event.request_path, event.uri, event.user_agent]
    .filter(value => typeof value === 'string').join(' ').slice(0, 1000);
}

function classifyUserAgent(value) {
  const text = String(value || '').toLowerCase();
  if (!text) return 'empty';
  if (/masscan/.test(text)) return 'masscan';
  if (/nmap/.test(text)) return 'nmap';
  if (/zgrab/.test(text)) return 'zgrab';
  if (/nuclei/.test(text)) return 'nuclei';
  if (/sqlmap/.test(text)) return 'sqlmap';
  if (/curl/.test(text)) return 'curl';
  if (/python/.test(text)) return 'python';
  if (/go-http-client/.test(text)) return 'go-http';
  if (/mozilla|chrome|safari|firefox|edg\//.test(text)) return 'browser-like';
  return 'unknown';
}

function classifyPath(text) {
  const match = PATH_PATTERNS.find(([, pattern]) => pattern.test(text));
  return match?.[0] || 'other';
}

function classifyStage(features) {
  if (features.impact_signal || features.exfil_signal) return 'impact_exfil';
  if (features.lateral_signal) return 'lateral_movement';
  if (features.persistence_signal) return 'persistence';
  if (features.success_on_decoy || features.command_signal) return 'execution_post_access';
  if (features.rce_signal || features.cve_signal) return 'initial_access_attempt';
  if (features.auth_attempts > 0) return 'credential_access';
  if (features.path_classes.some(path => path !== 'other')) return 'enumeration';
  if (features.distinct_ports > 1) return 'recon';
  return 'recon';
}

function buildFeatureVector(ip, events = [], incidents = [], campaign = {}) {
  const ports = [];
  const services = new Set();
  const paths = new Set();
  const userAgents = new Set();
  let authAttempts = 0;
  let successOnDecoy = false;
  let cveSignal = false;
  let rceSignal = false;
  let commandSignal = false;
  let sensitiveFileSignal = false;
  let webLoginSignal = false;
  let knownScannerSignal = false;
  let persistenceSignal = false;
  let lateralSignal = false;
  let exfilSignal = false;
  let impactSignal = false;
  const usernameClasses = new Set();
  const methods = new Set();
  const eventTimes = [];
  let errorCount = 0;
  let eventCount = 0;
  let minTs = Infinity;
  let maxTs = -Infinity;

  for (const event of events.slice(0, 200)) {
    const count = Math.max(1, Math.min(1000, Number(event.count) || 1));
    eventCount += count;
    const method = String(event.method || '').toUpperCase();
    if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method)) methods.add(method);
    if (Number(event.status_code) >= 400) errorCount += count;
    const text = textOf(event);
    const lower = text.toLowerCase();
    if (/shodan|censys|binaryedge|qualys/.test(lower)) knownScannerSignal = true;
    if (/\broot\b/.test(lower)) usernameClasses.add('root');
    if (/\badmin(?:istrator)?\b/.test(lower)) usernameClasses.add('admin');
    if (/\b(?:guest|test|default|zabbix)\b/.test(lower)) usernameClasses.add('default');
    if (/user(name)?\s*[:=]\s*[a-z0-9_-]{1,4}\b/.test(lower)) usernameClasses.add('random_or_short');
    const portValues = [event.dest_port, event.port, ...(Array.isArray(event.ports) ? event.ports : [])]
      .map(Number).filter(port => Number.isInteger(port) && port > 0 && port <= 65535);
    for (const port of portValues) {
      if (!ports.includes(port)) ports.push(port);
      if (PORT_SERVICES.has(port)) services.add(PORT_SERVICES.get(port));
    }
    for (const match of lower.matchAll(/(?:port\s*)(\d{1,5})/g)) {
      const port = Number(match[1]);
      if (port > 0 && port <= 65535 && !ports.includes(port)) ports.push(port);
      if (PORT_SERVICES.has(port)) services.add(PORT_SERVICES.get(port));
    }
    const pathClass = classifyPath(text);
    paths.add(pathClass);
    const uaClass = classifyUserAgent(event.user_agent || event.user_agent_class);
    userAgents.add(uaClass);
    const isAuth = /login|authentication|credential|brute.?force|failed auth|password attempt/.test(lower);
    if (isAuth) authAttempts += count;
    if (/success(?:ful)? login|accepted password|session opened|authenticated successfully/.test(lower)) successOnDecoy = true;
    if (/cve-\d{4}-\d+|kev match|known exploited vulnerability/.test(lower)) cveSignal = true;
    if (/\brce\b|command.?injection|webshell|shell upload|;\s*(?:id|whoami)|\$\(/.test(lower)) rceSignal = true;
    if (/command execution|post.?access command|shell command/.test(lower)) commandSignal = true;
    if (/\.env|\.git|backup|config(?:uration)?\.php/.test(lower)) sensitiveFileSignal = true;
    if (/wp-login|xmlrpc|admin panel|\/login|phpmyadmin/.test(lower)) webLoginSignal = true;
    if (/cron|scheduled task|startup item|service install|registry run key/.test(lower)) persistenceSignal = true;
    if (/lateral|psexec|winrm|remote service|smb share/.test(lower)) lateralSignal = true;
    if (/exfil|archive upload|data staging/.test(lower)) exfilSignal = true;
    if (/ransomware|wiper|service disruption|destructive impact/.test(lower)) impactSignal = true;
    for (const rawTimestamp of [event.first_seen, event.created_at, event.ts]) {
      const timestamp = Date.parse(rawTimestamp || '');
      if (!Number.isFinite(timestamp)) continue;
      minTs = Math.min(minTs, timestamp);
      maxTs = Math.max(maxTs, timestamp);
      eventTimes.push(timestamp);
    }
  }

  const distinctPorts = ports.length;
  const pathClasses = [...paths].sort();
  const serviceClasses = [...services].sort();
  const uaClasses = [...userAgents].sort();
  const usernames = [...usernameClasses].sort();
  const orderedPorts = ports.slice(0, 32);
  const sortedTimes = [...new Set(eventTimes)].sort((a, b) => a - b);
  const deltas = sortedTimes.slice(1).map((time, index) => time - sortedTimes[index]);
  const meanDelta = deltas.length ? deltas.reduce((sum, value) => sum + value, 0) / deltas.length : 0;
  const variance = deltas.length ? deltas.reduce((sum, value) => sum + ((value - meanDelta) ** 2), 0) / deltas.length : 0;
  const intervalRegularity = deltas.length < 2 ? 'unknown' : Math.sqrt(variance) / Math.max(meanDelta, 1) <= 0.25 ? 'regular' : 'irregular';
  const sequentialPorts = orderedPorts.length >= 3 && orderedPorts.slice(1).every((port, index) => port - orderedPorts[index] === 1);
  const topPorts = new Set([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8081, 9200, 27017]);
  const scanStyle = sequentialPorts ? 'sequential' : orderedPorts.length >= 3 && orderedPorts.every(port => topPorts.has(port)) ? 'top-ports' : orderedPorts.length >= 3 ? 'random' : 'unknown';
  const distinctSignals = new Set([...serviceClasses, ...pathClasses, ...uaClasses]).size;
  const signature = detectSignature({ distinctPorts, serviceClasses, pathClasses, authAttempts, successOnDecoy, cveSignal, rceSignal, commandSignal, sensitiveFileSignal, webLoginSignal, campaign });
  const currentStage = classifyStage({ success_on_decoy: successOnDecoy, command_signal: commandSignal, rce_signal: rceSignal, cve_signal: cveSignal, auth_attempts: authAttempts, path_classes: pathClasses, distinct_ports: distinctPorts, persistence_signal: persistenceSignal, lateral_signal: lateralSignal, exfil_signal: exfilSignal, impact_signal: impactSignal });
  const evidence = [];
  if (distinctPorts) evidence.push(`ports_touched:${distinctPorts}`);
  if (authAttempts) evidence.push(`auth_attempts:${Math.min(authAttempts, 10000)}`);
  if (serviceClasses.length) evidence.push(`services:${serviceClasses.join(',')}`);
  if (pathClasses.some(path => path !== 'other')) evidence.push(`path_classes:${pathClasses.filter(path => path !== 'other').join(',')}`);
  if (cveSignal) evidence.push('known_cve_signal');
  if (successOnDecoy) evidence.push('decoy_success_signal');
  if (knownScannerSignal) evidence.push('known_scanner_intel_match');
  if (usernames.length) evidence.push(`username_classes:${usernames.join(',')}`);
  if (Number(campaign.siblings) > 0) evidence.push(`campaign_siblings:${Math.min(Number(campaign.siblings), 10000)}`);

  return {
    event_count: Math.min(eventCount, 100000),
    distinct_ports: distinctPorts,
    ports_ordered: orderedPorts,
    scan_style: scanStyle,
    service_classes: serviceClasses,
    path_classes: pathClasses,
    ua_classes: uaClasses,
    username_classes: usernames,
    known_scanner_signal: knownScannerSignal,
    auth_attempts: Math.min(authAttempts, 100000),
    auth_attempts_per_minute: Math.round(authAttempts / Math.max(1, Number.isFinite(minTs) && Number.isFinite(maxTs) ? (maxTs - minTs) / 60000 : 1)),
    http_methods: [...methods].sort(),
    error_rate_bucket: eventCount ? errorCount / eventCount >= 0.75 ? 'high' : errorCount / eventCount >= 0.25 ? 'medium' : 'low' : 'unknown',
    success_on_decoy: successOnDecoy,
    cve_signal: cveSignal,
    rce_signal: rceSignal,
    command_signal: commandSignal,
    sensitive_file_signal: sensitiveFileSignal,
    web_login_signal: webLoginSignal,
    persistence_signal: persistenceSignal,
    lateral_signal: lateralSignal,
    exfil_signal: exfilSignal,
    impact_signal: impactSignal,
    incidents: Math.min(incidents.length, 1000),
    active_duration_min: Number.isFinite(minTs) && Number.isFinite(maxTs) ? Math.max(0, Math.round((maxTs - minTs) / 60000)) : null,
    interval_regularity: intervalRegularity,
    burstiness: eventCount >= 10 ? 'bursty' : eventCount >= 3 ? 'steady' : 'sparse',
    time_of_day: Number.isFinite(maxTs) ? ['night', 'morning', 'afternoon', 'evening'][Math.floor(new Date(maxTs).getUTCHours() / 6)] : 'unknown',
    distinct_signals: distinctSignals,
    signature,
    current_stage: currentStage,
    evidence: evidence.slice(0, 12),
  };
}

function detectSignature(features) {
  if (Number(features.campaign?.siblings) >= 4) return 'S13';
  if (features.successOnDecoy || features.commandSignal) return 'S3';
  if (features.cveSignal) return 'S8';
  if (features.rceSignal || features.pathClasses.includes('shell-like') || features.pathClasses.includes('traversal') || features.pathClasses.includes('rce-probe')) return 'S12';
  if (features.serviceClasses.includes('zabbix-agent') || features.serviceClasses.includes('zabbix-server') || features.pathClasses.includes('zabbix-web')) return 'S10';
  if (features.serviceClasses.includes('db') || features.serviceClasses.includes('redis')) return 'S9';
  if (features.sensitiveFileSignal || features.pathClasses.includes('sensitive-file')) return 'S7';
  if (features.authAttempts > 0 && features.serviceClasses.includes('ssh')) return 'S2';
  if (features.webLoginSignal || features.pathClasses.some(path => ['wp-admin', 'login', 'admin-panel', 'phpmyadmin'].includes(path))) return 'S6';
  if (features.serviceClasses.includes('telnet')) return 'S5';
  if (features.serviceClasses.includes('rdp')) return 'S4';
  if (features.serviceClasses.includes('ssh')) return 'S1';
  if (features.distinctPorts >= 5) return 'S11';
  return 'insufficient_pattern';
}

function scoreProfiles(features, campaign = {}) {
  const scores = [
    ['opportunistic_mass_scanner', features.distinct_ports >= 5 ? 75 : 15, ['distinct_ports']],
    ['known_benign_scanner', features.known_scanner_signal ? 60 : 0, ['known_scanner_intel_match']],
    ['credential_bruteforcer', features.auth_attempts >= 3 ? Math.min(100, 45 + features.auth_attempts * 4) : 0, ['auth_attempts']],
    ['web_exploit_hunter', features.cve_signal || features.rce_signal || features.path_classes.some(path => ['sqli-like', 'log4j-like', 'traversal'].includes(path)) ? 80 : 0, ['path_class', 'cve_signal']],
    ['botnet_worm_style', features.service_classes.includes('telnet') ? 70 : 0, ['service_class']],
    ['targeted_recon', features.distinct_ports <= 2 && features.event_count >= 2 ? 55 : 0, ['narrow_port_set', 'event_count']],
    ['post_access_operator', features.success_on_decoy || features.command_signal ? 90 : 0, ['success_signal', 'command_signal']],
    ['campaign_participant', Number(campaign.siblings) >= 2 ? Math.min(100, 45 + Number(campaign.siblings) * 5) : 0, ['campaign_siblings']],
  ];
  return scores.filter(([, score]) => score > 0).sort((left, right) => right[1] - left[1]).slice(0, 2)
    .map(([key, score, evidence]) => ({ key, score, evidence }));
}

function inferMindset(features, campaign = {}) {
  const access = features.success_on_decoy || features.auth_attempts ? 'access' : features.cve_signal || features.rce_signal ? 'exploitation' : features.distinct_ports ? 'discovery' : 'unknown';
  const automation = features.ua_classes.some(ua => ['masscan', 'nmap', 'zgrab', 'nuclei', 'sqlmap', 'python', 'go-http'].includes(ua)) ? 'bot' : features.ua_classes.includes('browser-like') ? 'human-like' : 'semi';
  const attributes = {
    intent: { value: access, reasons: [features.auth_attempts ? 'auth_attempts' : null, features.cve_signal ? 'cve_signal' : null, features.distinct_ports ? 'distinct_ports' : null].filter(Boolean) },
    sophistication: { value: features.cve_signal || features.rce_signal ? 'high' : features.path_classes.some(path => path !== 'other') ? 'medium' : 'low', reasons: [features.cve_signal ? 'cve_signal' : null, features.rce_signal ? 'rce_signal' : null, features.path_classes.some(path => path !== 'other') ? 'path_class' : null, features.distinct_ports >= 8 ? 'scan_breadth' : null].filter(Boolean) },
    automation: { value: automation, reasons: features.ua_classes.map(ua => `ua_class:${ua}`).slice(0, 4) },
    targeting: { value: features.service_classes.includes('zabbix-agent') || features.service_classes.includes('zabbix-server') || features.path_classes.includes('zabbix-web') ? 'asset-focused' : features.distinct_ports > 4 ? 'random' : 'service-focused', reasons: [...features.service_classes.map(service => `service:${service}`), ...features.path_classes.filter(path => path !== 'other').map(path => `path:${path}`), features.distinct_ports ? `distinct_ports:${features.distinct_ports}` : null].filter(Boolean).slice(0, 5) },
    persistence: { value: Number(campaign.siblings) >= 4 ? 'long-campaign' : features.incidents > 0 ? 'recurring' : 'one-shot', reasons: [features.incidents ? 'prior_incidents' : null, Number(campaign.siblings) >= 4 ? 'campaign_siblings' : null, features.event_count ? 'observed_event_count' : null].filter(Boolean) },
    patience: { value: features.active_duration_min === null ? null : features.active_duration_min >= 60 ? 'slow-low-and-slow' : 'fast-noisy', reasons: [features.active_duration_min !== null ? `active_duration_min:${features.active_duration_min}` : null] .filter(Boolean) },
  };
  return Object.fromEntries(Object.entries(attributes).filter(([, attribute]) => attribute.reasons.length && attribute.value));
}

function recommendationTemplates(signature, features) {
  const service = features.service_classes[0] || 'observed service';
  const port = features.ports_ordered[0] || 'observed port';
  const ip = features.ip;
  const templates = {
    S1: [['review_ssh_auth', `Review SSH authentication events from ${ip} on port ${port}.`, 1, true], ['check_rate_limit', 'Confirm rate limiting covers the observed SSH service.', 2, false]],
    S2: [['review_ssh_auth', `Review failed and successful SSH logins from ${ip}.`, 1, true], ['check_lockout_policy', 'Confirm account lockout and MFA policy for the exposed service.', 2, false]],
    S3: [['verify_post_access', `Verify whether ${ip} established a session on ${service}.`, 1, true], ['review_egress', 'Check endpoint and proxy logs for follow-on downloads.', 2, false]],
    S4: [['review_rdp_auth', `Review RDP authentication attempts from ${ip}.`, 1, true], ['check_smb_exposure', 'Confirm SMB exposure is restricted to trusted networks.', 2, false]],
    S5: [['review_iot_auth', `Review telnet authentication attempts from ${ip}.`, 1, true], ['check_default_credentials', 'Confirm default credentials are disabled on the exposed device.', 2, false]],
    S6: [['review_web_auth', `Review web login requests from ${ip}.`, 1, true], ['verify_web_exposure', 'Confirm exposed login and plugin routes are patched and rate-limited.', 2, false]],
    S7: [['verify_sensitive_files', 'Verify sensitive files and backups were not served successfully.', 1, true], ['rotate_exposed_secrets', 'Rotate credentials only if exposure is confirmed.', 2, false]],
    S8: [['verify_cve_exposure', 'Verify the matched CVE applies to the observed asset and check patch status.', 1, true], ['review_followup', 'Review subsequent requests for the same CVE before escalation.', 2, false]],
    S9: [['verify_database_exposure', `Check whether ${service} on port ${port} permits unauthenticated access.`, 1, true], ['review_database_auth', 'Review database authentication and audit logs for the source IP.', 2, false]],
    S10: [['verify_zabbix_credentials', 'Confirm Zabbix default credentials are changed and login audit is reviewed.', 1, true], ['restrict_zabbix_api', 'Restrict Zabbix web and JSON-RPC access to trusted networks.', 2, false]],
    S11: [['review_scan_scope', `Review the ${features.distinct_ports} distinct ports touched by ${ip}.`, 1, true], ['monitor_service_followup', 'Monitor for focused follow-up against identified services.', 2, false]],
    S12: [['verify_command_probe', 'Check whether the shell, traversal, or command probe reached an execution sink.', 1, true], ['review_second_stage', 'Review proxy and endpoint telemetry for a second-stage request.', 2, false]],
    S13: [['review_campaign_members', 'Compare sibling IP telemetry and preserve campaign evidence.', 1, true], ['consider_range_review', 'Consider range-level controls only after analyst validation.', 2, false]],
  };
  return (templates[signature] || [['collect_more_telemetry', `Collect more telemetry for ${ip}; no signature matched.`, 1, true]])
    .slice(0, 5).map(([action_key, text, priority, check_first]) => ({ action_key, text, priority, check_first }));
}

function campaignId(ip, signature, features) {
  if (net.isIP(String(ip)) !== 4) return null;
  const subnet = String(ip).split('.').slice(0, 3).join('.') + '.0/24';
  return crypto.createHash('sha256').update(`${subnet}|${signature}|${features.ua_classes.join(',')}|${features.service_classes.join(',')}`).digest('hex').slice(0, 16);
}

function predictNextAttacks(ip, events = [], incidents = [], campaign = {}, options = {}) {
  const features = buildFeatureVector(ip, events, incidents, campaign);
  const profiles = scoreProfiles(features, campaign);
  const mindset = inferMindset(features, campaign);
  const prior = options.priors?.[features.signature] || PRIORS[features.signature] || [];
  const mitreMap = options.mitreMap || MITRE_BY_SIGNATURE;
  const predictions = prior.map(([next_action, probability, window]) => ({
    next_action,
    probability,
    window,
    likely_target: features.signature === 'S10' ? 'zabbix-web/api_jsonrpc' : features.service_classes[0] || features.path_classes.find(path => path !== 'other') || 'unknown',
    technique_key: mitreMap[features.signature] || null,
    why: features.evidence.slice(0, 4),
    would_change_if: ['new successful authentication', 'new service or exploit-specific path'],
    leading_indicators: [`watch:${next_action}`, 'watch:new port or path class'],
  }));
  if (!predictions.length) predictions.push({
    next_action: 'insufficient_pattern', probability: 0, window: '24h', likely_target: 'unknown', technique_key: null,
    why: ['insufficient_distinct_signals'], would_change_if: ['observe a repeated service or path pattern'], leading_indicators: ['new distinct port', 'authentication or exploit-specific path'],
  });
  const siblings = Math.max(0, Math.min(10000, Number(campaign.siblings) || 0));
  return {
    engine: 'predictor-v1',
    playbook_version: 'seed-1',
    signature: features.signature,
    features,
    profile: { top: profiles },
    mindset,
    stage: { current: features.current_stage, mitre_key: mitreMap[features.signature] || null, progress_pct: features.current_stage === 'recon' ? 12 : features.current_stage === 'execution_post_access' ? 62 : 35 },
    predictions: predictions.slice(0, 3),
    campaign: { id: siblings ? campaignId(ip, features.signature, features) : null, siblings, similarity: siblings ? Math.min(1, 0.65 + siblings * 0.05) : 0, expected_new_ips: siblings ? Math.max(1, Math.round(siblings * 0.25)) : 0 },
    confidence: { ai: 0, evidence: Math.min(100, features.distinct_signals * 15 + Math.min(features.event_count, 5) * 5), source_trust: 50, prediction_calibrated: null },
    recommendations: recommendationTemplates(features.signature, features),
    data_quality: { events: features.event_count, distinct_signals: features.distinct_signals, window_min: features.active_duration_min, warnings: features.event_count < 3 ? ['low_event_count'] : [] },
  };
}

function timelineRows(ip, events = []) {
  return events.slice(0, 200).map(event => {
    const text = textOf(event);
    const lower = text.toLowerCase();
    const port = Number(event.dest_port || event.port || event.ports?.[0]) || null;
    const service = PORT_SERVICES.get(port) || 'other';
    const pathClass = classifyPath(text);
    const actionClass = /login|auth|credential|brute.?force/i.test(lower) ? 'auth_attempt'
      : /cve-\d{4}-\d+|kev/i.test(lower) ? 'known_cve_probe'
        : /rce|shell|command.?injection|traversal/i.test(lower) ? 'exploit_probe'
          : pathClass !== 'other' ? `web_${pathClass}`
            : service !== 'other' ? `service_${service}_probe` : 'security_event';
    const ts = event.created_at || event.ts;
    if (!ts) return null;
    return { ip, ts: String(ts).slice(0, 40), action_class: actionClass, port, service, stage: /auth_attempt/.test(actionClass) ? 'credential_access' : /exploit/.test(actionClass) ? 'initial_access_attempt' : 'recon', weight: Math.max(1, Math.min(10, Number(event.count) || 1)) };
  }).filter(Boolean);
}

async function persistTimeline(db, ip, events) {
  const rows = timelineRows(ip, events);
  if (!rows.length) return 0;
  await initializePredictorTables(db);
  let inserted = 0;
  for (const row of rows) {
    inserted += await new Promise((resolve, reject) => db.run(
      'INSERT OR IGNORE INTO ai_ip_timeline (ip, ts, action_class, port, service, stage, weight) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [row.ip, row.ts, row.action_class, row.port, row.service, row.stage, row.weight],
      function(error) { error ? reject(error) : resolve(this.changes); }
    ));
  }
  return inserted;
}

module.exports = { buildFeatureVector, classifyPath, classifyUserAgent, detectSignature, findCampaignSiblings, initializePredictorTables, persistProfile, persistTimeline, predictNextAttacks, readMitreMap, readPlaybookPriors, scoreProfiles, timelineRows };