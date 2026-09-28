const { predictNextAttacks } = require('./predictor');

function createAttackerFallback(ip, events, incidents = [], fallbackReason = '') {
  const levels = { LOW: 1, MED: 2, HIGH: 3, CRIT: 4, DISASTER: 4 };
  const eventCount = events.reduce((total, event) => total + Math.max(1, Number(event.count) || 1), 0);
  const eventSeverity = events.reduce((highest, item) => {
    const current = String(item.severity || 'LOW').toUpperCase();
    return (levels[current] || 0) > (levels[highest] || 0) ? current : highest;
  }, 'LOW');
  const pageEvents = events.filter(event =>
    String(event.event_source || event.source || '').toLowerCase() === 'decoy_ecommerce' ||
    /^DECOY_PAGE_/.test(String(event.rule || ''))
  );
  const pageOnly = events.length > 0 && pageEvents.length === events.length;
  const observedDetails = [...new Set(events.map(event => {
    const detail = String(event.description || event.rule || event.source || 'Security event');
    return Number(event.count) > 1 ? `${detail} (${event.count} occurrences)` : detail;
  }).filter(Boolean))].slice(0, 4);
  const incidentDetails = incidents.slice(0, 3).map(incident => {
    const evidence = String(incident.evidence || '').trim();
    return `${incident.severity || 'Unknown'} incident ${incident.id || ''}: ${evidence || incident.title || incident.rule || 'correlated security events'}`.trim();
  });
  const privateSource = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.)/.test(ip);
  const allEvidence = events.map(event => `${event.rule || ''} ${event.description || ''}`).join(' ').toLowerCase();
  const signature = pageOnly ? 'decoy_page_access'
    : /zabbix|10050|10051|api_jsonrpc/.test(allEvidence) ? 'zabbix_probe'
      : /\.env|\.git|backup|config(?:uration)? file/.test(allEvidence) ? 'sensitive_file_probe'
        : /ssh|brute.?force|failed login|authentication/.test(allEvidence) ? 'ssh_auth_activity'
          : /wp-login|xmlrpc|admin panel|\/login/.test(allEvidence) ? 'web_login_probe'
            : 'unknown_activity';
  const leadingIndicators = signature === 'decoy_page_access'
    ? ['POST to login or payment routes', 'new sensitive-file probes']
    : signature === 'ssh_auth_activity'
      ? ['successful login after failures', 'new usernames or ports']
      : signature === 'sensitive_file_probe'
        ? ['successful sensitive-file response', 'repeated requests for secrets']
        : signature === 'zabbix_probe'
          ? ['authentication attempts against Zabbix', 'API JSON-RPC enumeration']
          : ['repeated requests on new paths or ports', 'authentication or POST activity'];
  const routes = [...new Set(pageEvents.map(event => {
    const description = String(event.description || '');
    return description.match(/accessed:\s*(.+?)\.?$/i)?.[1] || String(event.rule || 'decoy page');
  }))].slice(0, 5);
  const pageSummary = pageOnly
    ? `${eventCount} ${eventSeverity} decoy page access(es) were recorded${routes.length ? ` on ${routes.join(', ')}` : ''}.`
    : `${eventCount} stored security event(s) were recorded.`;
  const incidentSummary = incidents.length
    ? ` A linked ${String(incidents[0].severity || 'unknown').toUpperCase()} incident indicates a rule-based event cluster; it is corroboration of frequency, not proof of malicious intent.`
    : '';
  const hasFrequencyOnlyIncident = incidents.some(incident =>
    /cluster|within\s+\d+\s+seconds|frequency/i.test(String(incident.evidence || ''))
  );
  const severity = pageOnly && hasFrequencyOnlyIncident
    ? eventSeverity
    : [...events, ...incidents].reduce((highest, item) => {
      const current = String(item.severity || 'LOW').toUpperCase();
      return (levels[current] || 0) > (levels[highest] || 0) ? current : highest;
    }, 'LOW');
  const confidence = pageOnly && hasFrequencyOnlyIncident ? 40 : incidents.length ? 55 : eventCount >= 5 ? 45 : 35;
  const insufficientData = eventCount < 3;
  const summary = insufficientData
    ? `Only ${eventCount} event(s) seen. Not enough to predict reliably. Watch for: ${leadingIndicators.slice(0, 2).join('; ')}.`
    : `${pageSummary}${incidentSummary} ${privateSource ? 'This is a private-network address. ' : ''}Current telemetry does not establish credential submission, payment submission, or compromise.`;
  const recommendationMap = {
    decoy_page_access: ['monitor', 'investigate'],
    ssh_auth_activity: ['investigate', 'rate_limit'],
    sensitive_file_probe: ['investigate', 'monitor'],
    zabbix_probe: ['investigate', 'monitor'],
    web_login_probe: ['investigate', 'rate_limit'],
    unknown_activity: ['monitor'],
  };
  const allowedReasons = new Set(['ai_disabled', 'offline', 'timeout', 'invalid_json', 'incomplete_think', 'queue_dropped', 'circuit_open', 'unknown']);
  const reason = allowedReasons.has(fallbackReason) ? fallbackReason : 'unknown';
  const prediction = predictNextAttacks(ip, events, incidents);

  return {
    engine: 'predictor-v1',
    method: 'rules+stats',
    llm_used: false,
    fallback_reason: reason,
    signature,
    stage: incidents[0]?.stage || 'Detected',
    severity: severity === 'DISASTER' ? 'CRIT' : severity,
    confidence,
    summary,
    evidence: [...observedDetails, ...incidentDetails].slice(0, 5),
    next_steps: [
      {
        step: privateSource ? 'Confirm whether this LAN address belongs to an expected user, test device, or scanner.' : 'Verify the source address against trusted asset and proxy records.',
        reason: privateSource ? 'Private-network traffic can be legitimate; ownership is not present in the captured events.' : 'The event feed alone does not establish who controlled this address.',
      },
      {
        step: signature === 'ssh_auth_activity' ? `Check authentication logs for failed and successful attempts from ${ip}.`
          : signature === 'sensitive_file_probe' ? 'Verify sensitive files were not served successfully; rotate exposed credentials if confirmed.'
            : signature === 'zabbix_probe' ? 'Review Zabbix authentication logs and restrict API access to trusted networks.'
              : signature === 'web_login_probe' ? 'Check authentication logs for repeated login attempts and successful sessions.'
                : pageOnly ? 'Check decoy HTTP logs for POST requests, login attempts, or payment actions.'
                  : 'Correlate these events with authentication, proxy, and endpoint logs.',
        reason: pageOnly ? 'Stored events describe page access only, not form submission or account access.' : 'Use direct logs to confirm whether the suspected follow-up occurred.',
      },
      {
        step: 'Monitor for repeated sensitive actions and escalate only if corroborating evidence appears.',
        reason: 'A frequency-based incident can be a false positive without suspicious request content or follow-on activity.',
      },
    ],
    recommendations: recommendationMap[signature],
    prediction,
    recommendation_items: prediction.recommendations,
    leading_indicators: leadingIndicators,
  };
}

module.exports = { createAttackerFallback };
