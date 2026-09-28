'use strict';

const os = require('os');

function normalizePolicyIp(ip) {
  return String(ip || '').trim().replace(/^::ffff:/i, '').toLowerCase();
}

function isLocalSystemIp(ip) {
  const value = normalizePolicyIp(ip);
  if (!value) return false;
  if (value === '127.0.0.1' || value === '::1') return true;
  return Object.values(os.networkInterfaces()).some(interfaces =>
    interfaces?.some(entry => normalizePolicyIp(entry.address) === value)
  );
}

function isHoneyAllowlistedIp(ip) {
  const value = normalizePolicyIp(ip);
  if (!value || value === 'unknown' || value === '0.0.0.0') return true;
  return isLocalSystemIp(value);
}

module.exports = { isHoneyAllowlistedIp, isLocalSystemIp };