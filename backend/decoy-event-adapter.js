'use strict';

function getAttackerIp(req) {
  return String(req.socket?.remoteAddress || req.ip || 'unknown').replace(/^::ffff:/, '');
}

function createDecoyEventAdapter({ collectEvent }) {
  if (typeof collectEvent !== 'function') throw new TypeError('collectEvent callback is required');

  return async function emitDecoyEvent(req, details = {}) {
    const event = {
      event_id: details.event_id,
      attacker_ip: getAttackerIp(req),
      event_type: String(details.event_type || 'Decoy Interaction').slice(0, 80),
      severity: String(details.severity || 'MED').toUpperCase(),
      event_source: 'decoy_ecommerce',
      method: req.method,
      path: String(req.path || req.originalUrl || '/').slice(0, 240),
      user_agent: String(req.get('user-agent') || '').slice(0, 240),
      rule: String(details.rule || 'DECOY_ECOMMERCE_INTERACTION').slice(0, 120),
      description: String(details.description || 'Synthetic e-commerce decoy interaction').slice(0, 500),
      dest_port: Number(details.dest_port || 0),
      metadata: details.metadata && typeof details.metadata === 'object' ? details.metadata : {},
    };

    return collectEvent(event);
  };
}

module.exports = { createDecoyEventAdapter };
