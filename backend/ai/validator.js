const STAGES = new Set([
  'Detected', 'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact',
  'Contained', 'Unknown',
]);
const SEVERITIES = new Set(['LOW', 'MED', 'HIGH', 'CRIT']);
const RECOMMENDATIONS = new Set(['monitor', 'investigate', 'rate_limit', 'manual_block_review', 'close_as_false_positive']);
const SEVERITY_RANK = { LOW: 0, MED: 1, HIGH: 2, CRIT: 3 };
const ANALYSIS_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['stage', 'severity', 'confidence', 'summary', 'evidence', 'next_steps', 'recommendations'],
  properties: {
    stage: { type: 'string', enum: [...STAGES] },
    severity: { type: 'string', enum: [...SEVERITIES] },
    confidence: { type: 'integer', minimum: 0, maximum: 100 },
    summary: { type: 'string' },
    evidence: { type: 'array', maxItems: 3, items: { type: 'string' } },
    next_steps: {
      type: 'array',
      maxItems: 2,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['step', 'reason'],
        properties: { step: { type: 'string' }, reason: { type: 'string' } },
      },
    },
    recommendations: { type: 'array', maxItems: 3, items: { type: 'string', enum: [...RECOMMENDATIONS] } },
  },
});

function cleanText(value, maximum) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, maximum);
}

function validateAnalysis(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const stage = STAGES.has(value.stage) ? value.stage : null;
  const severity = SEVERITIES.has(String(value.severity || '').toUpperCase()) ? String(value.severity).toUpperCase() : null;
  const confidence = Number(value.confidence);
  if (!stage || !severity || !Number.isFinite(confidence)) return null;

  const nextSteps = Array.isArray(value.next_steps) ? value.next_steps.slice(0, 3).map(item => ({
    step: cleanText(item?.step, 180),
    reason: cleanText(item?.reason, 220),
  })).filter(item => item.step) : [];

  return {
    stage,
    severity,
    confidence: Math.max(0, Math.min(100, Math.round(confidence))),
    summary: cleanText(value.summary, 700),
    evidence: Array.isArray(value.evidence) ? value.evidence.slice(0, 5).map(item => cleanText(item, 220)).filter(Boolean) : [],
    next_steps: nextSteps,
    recommendations: Array.isArray(value.recommendations) ? [...new Set(value.recommendations.filter(item => RECOMMENDATIONS.has(item)))].slice(0, 5) : [],
  };
}

function groundAnalysis(analysis, events = [], incidents = []) {
  if (!analysis || !events.length) return analysis;
  const isDecoyPageEvent = event =>
    String(event.source || '').toLowerCase() === 'decoy_ecommerce' ||
    String(event.rule || '').startsWith('DECOY_PAGE_');
  const pageOnly = events.every(isDecoyPageEvent);
  const eventSeverity = events.reduce((highest, event) => {
    const severity = String(event.severity || 'LOW').toUpperCase();
    return (SEVERITY_RANK[severity] ?? -1) > (SEVERITY_RANK[highest] ?? -1) ? severity : highest;
  }, 'LOW');
  const frequencyOnlyIncident = incidents.some(incident =>
    /cluster|within\s+\d+\s+seconds|frequency/i.test(String(incident.evidence || ''))
  );

  if (pageOnly && frequencyOnlyIncident && SEVERITY_RANK[analysis.severity] > SEVERITY_RANK[eventSeverity]) {
    analysis.severity = eventSeverity;
    analysis.confidence = Math.min(analysis.confidence, 50);
    analysis.summary = `Direct evidence contains only ${eventSeverity} decoy page-view events. The linked incident is frequency-based and does not prove malicious intent, compromise, or submitted data.`;
    analysis.recommendations = analysis.recommendations.filter(item => !['rate_limit', 'manual_block_review'].includes(item));
    if (!analysis.recommendations.includes('monitor')) analysis.recommendations.unshift('monitor');
  }

  return analysis;
}

module.exports = { STAGES, SEVERITIES, RECOMMENDATIONS, ANALYSIS_SCHEMA, cleanText, validateAnalysis, groundAnalysis };
