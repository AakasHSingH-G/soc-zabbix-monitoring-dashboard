// ============================================================
//  zabbix-api.js — Zabbix JSON-RPC API Wrapper
//  Real data only. If Zabbix is unavailable, the API reports OFFLINE.
// ============================================================

const config = require('./config');

const ZABBIX_URL = config.zabbixUrl;
const ZABBIX_USER = config.zabbixUser;
const ZABBIX_PASS = config.zabbixPass;
const ZABBIX_ENABLED = Boolean(ZABBIX_URL && ZABBIX_URL.trim());

let _authToken = null;
let _lastAuth = 0;
let zabbixOfflineUntil = 0;
let zabbixErrorLogged = false;
const acknowledgedProblemIds = new Set();
const TOKEN_TTL = 25 * 60 * 1000; // 25 minutes
const ZABBIX_RETRY_INTERVAL = 60 * 1000; // try reconnect after 1 minute

function isZabbixAvailable() {
  return ZABBIX_ENABLED && Date.now() > zabbixOfflineUntil;
}

// ── JSON-RPC Helper ───────────────────────────────────────────────────────────
async function zabbixRPC(method, params, useAuth = true) {
  if (!ZABBIX_ENABLED) {
    throw new Error('Zabbix API not configured');
  }

  const body = {
    jsonrpc: '2.0',
    method,
    params,
    id: Date.now(),
  };
  if (useAuth && _authToken) body.auth = _authToken;

  const res = await fetch(ZABBIX_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5000), // 5 second timeout
  });

  if (!res.ok) {
    const bodyText = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${bodyText || res.statusText}`);
  }

  const data = await res.json();
  if (data.error) throw new Error(`Zabbix API error: ${data.error.data || data.error.message}`);
  return data.result;
}

function markZabbixOffline(err) {
  zabbixOfflineUntil = Date.now() + ZABBIX_RETRY_INTERVAL;
  if (!zabbixErrorLogged) {
    console.warn('[Zabbix API] Offline, using mock data:', err.message);
    zabbixErrorLogged = true;
  }
}

// ── Auth Token (auto-renew) ───────────────────────────────────────────────────
async function ensureAuth() {
  if (!isZabbixAvailable()) {
    throw new Error('Zabbix API is not configured or is currently unavailable');
  }

  const now = Date.now();
  if (_authToken && (now - _lastAuth) < TOKEN_TTL) return _authToken;

  try {
    // Zabbix 6.4+ uses 'username', older uses 'user'
    let token = null;
    try {
      token = await zabbixRPC('user.login', { username: ZABBIX_USER, password: ZABBIX_PASS }, false);
    } catch {
      token = await zabbixRPC('user.login', { user: ZABBIX_USER, password: ZABBIX_PASS }, false);
    }
    _authToken = token;
    _lastAuth = now;
    zabbixErrorLogged = false;
    console.log('[Zabbix API] Authenticated successfully.');
    return token;
  } catch (err) {
    _authToken = null;
    markZabbixOffline(err);
    throw new Error('Zabbix login failed: ' + err.message);
  }
}

// Real data only; no mock fallback is used in shipped code.

// ── Public API Functions ──────────────────────────────────────────────────────

async function getHosts() {
  if (!ZABBIX_ENABLED) {
    return { hosts: [], zabbix_connected: false, total: 0, status: 'OFFLINE' };
  }

  try {
    await ensureAuth();

    const hosts = await zabbixRPC('host.get', {
      output: ['hostid', 'host', 'name', 'status', 'available'],
      selectInterfaces: ['ip'],
      selectGroups: ['name'],
    });

    const enriched = await Promise.all(hosts.map(async (h) => {
      const ip = h.interfaces?.[0]?.ip || '0.0.0.0';
      let cpu = 0, ram = 0, disk = 0, problems = 0;

      try {
        const items = await zabbixRPC('item.get', {
          hostids: h.hostid,
          search: { key_: 'system.cpu.util' },
          output: ['lastvalue'],
          limit: 1,
        });
        if (items.length) cpu = Math.round(parseFloat(items[0].lastvalue));
      } catch (e) {
        console.debug('[Zabbix API] host CPU item fetch failed:', e.message);
      }

      try {
        const items = await zabbixRPC('item.get', {
          hostids: h.hostid,
          search: { key_: 'vm.memory.utilization' },
          output: ['lastvalue'],
          limit: 1,
        });
        if (items.length) ram = Math.round(parseFloat(items[0].lastvalue));
      } catch (e) {
        console.debug('[Zabbix API] host RAM item fetch failed:', e.message);
      }

      try {
        const items = await zabbixRPC('item.get', {
          hostids: h.hostid,
          search: { key_: 'vfs.fs.size[/,pused]' },
          output: ['lastvalue'],
          limit: 1,
        });
        if (items.length) disk = Math.round(parseFloat(items[0].lastvalue));
      } catch (e) {
        console.debug('[Zabbix API] host disk item fetch failed:', e.message);
      }

      try {
        const probs = await zabbixRPC('problem.get', {
          hostids: h.hostid,
          output: 'count',
        });
        problems = Array.isArray(probs) ? probs.length : parseInt(probs) || 0;
      } catch (e) {
        console.debug('[Zabbix API] host problems fetch failed:', e.message);
      }

      return {
        hostid: h.hostid,
        name: h.name || h.host,
        ip,
        status: h.status,
        available: h.available,
        groups: (h.groups || []).map(g => g.name),
        cpu, ram, disk, problems,
      };
    }));

    return { hosts: enriched, zabbix_connected: true, total: enriched.length };
  } catch (err) {
    markZabbixOffline(err);
    return { hosts: [], zabbix_connected: false, total: 0, status: 'OFFLINE', error: err.message };
  }
}

async function getProblems() {
  if (!ZABBIX_ENABLED) {
    return { problems: [], zabbix_connected: false, total: 0, status: 'OFFLINE' };
  }

  try {
    await ensureAuth();

    const problems = await zabbixRPC('problem.get', {
      output: ['eventid', 'name', 'severity', 'clock', 'acknowledged'],
      selectTags: ['tag', 'value'],
      recent: true,
      sortfield: ['eventid'],
      sortorder: 'DESC',
      limit: 50,
    });

    const triggerIds = problems.map(p => p.objectid).filter(Boolean);
    let hostMap = {};
    if (triggerIds.length) {
      try {
        const triggers = await zabbixRPC('trigger.get', {
          triggerids: triggerIds,
          output: ['triggerid', 'description'],
          selectHosts: ['name'],
          limit: 50,
        });
        triggers.forEach(t => {
          hostMap[t.triggerid] = t.hosts?.[0]?.name || 'Unknown';
        });
      } catch (e) {
        console.debug('[Zabbix API] trigger host mapping failed:', e.message);
      }
    }

    const SEVERITY_MAP = ['Not classified', 'Information', 'Warning', 'Average', 'High', 'Disaster'];
    const normalized = problems.map(p => ({
      eventid: p.eventid,
      name: p.name,
      host: hostMap[p.objectid] || 'Unknown',
      severity: parseInt(p.severity),
      severityName: SEVERITY_MAP[parseInt(p.severity)] || 'Unknown',
      clock: parseInt(p.clock),
      timestamp: new Date(parseInt(p.clock) * 1000).toISOString(),
      acknowledged: p.acknowledged === '1',
    }));

    return { problems: normalized, zabbix_connected: true, total: normalized.length };
  } catch (err) {
    markZabbixOffline(err);
    return { problems: [], zabbix_connected: false, total: 0, status: 'OFFLINE', error: err.message };
  }
}

/**
 * Returns Zabbix server info + connection status.
 */
async function getZabbixStatus() {
  if (!ZABBIX_ENABLED) {
    return { connected: false, error: 'Zabbix API not configured', url: ZABBIX_URL };
  }

  try {
    await ensureAuth();
    const info = await zabbixRPC('apiinfo.version', {}, false);
    return { connected: true, version: info, url: ZABBIX_URL };
  } catch (err) {
    markZabbixOffline(err);
    return { connected: false, error: err.message, url: ZABBIX_URL };
  }
}

async function acknowledgeProblem(eventid) {
  if (!ZABBIX_ENABLED) {
    acknowledgedProblemIds.add(String(eventid));
    return { acknowledged: true, zabbix_connected: false, status: 'OFFLINE' };
  }

  try {
    await ensureAuth();
    await zabbixRPC('event.acknowledge', {
      eventids: [String(eventid)],
      action: 6,
      message: 'Acknowledged from Zabbix SOC Dashboard',
    });
    acknowledgedProblemIds.add(String(eventid));
    return { acknowledged: true, zabbix_connected: true };
  } catch (err) {
    markZabbixOffline(err);
    acknowledgedProblemIds.add(String(eventid));
    return { acknowledged: true, zabbix_connected: false, status: 'OFFLINE', error: err.message };
  }
}

module.exports = { getHosts, getProblems, getZabbixStatus, acknowledgeProblem };
