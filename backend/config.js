const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

function readAuthConfig(environment = process.env) {
  const isConfigured = value => typeof value === 'string' && value.trim() !== '' && value !== 'CHANGE_ME';
  const apiKey = environment.API_KEY;
  if (!isConfigured(apiKey)) throw new Error('API_KEY is required.');

  const zabbixUrl = environment.ZABBIX_URL || '';
  const zabbixUser = environment.ZABBIX_USER;
  const zabbixPass = environment.ZABBIX_PASS;
  if (zabbixUrl && (!isConfigured(zabbixUser) || !isConfigured(zabbixPass))) {
    throw new Error('ZABBIX_USER and ZABBIX_PASS are required when ZABBIX_URL is configured.');
  }

  const demoCredentials = String(environment.DEMO_CREDENTIALS || 'false').toLowerCase() === 'true';
  const demoPasswords = {
    admin: environment.DEMO_ADMIN_PASSWORD,
    analyst: environment.DEMO_ANALYST_PASSWORD,
    viewer: environment.DEMO_VIEWER_PASSWORD,
  };
  if (demoCredentials && Object.values(demoPasswords).some(password => !isConfigured(password))) {
    throw new Error('DEMO_ADMIN_PASSWORD, DEMO_ANALYST_PASSWORD, and DEMO_VIEWER_PASSWORD are required when DEMO_CREDENTIALS is enabled.');
  }

  return { apiKey, zabbixUrl, zabbixUser, zabbixPass, demoCredentials, demoPasswords };
}

const authConfig = readAuthConfig();

module.exports = {
  readAuthConfig,
  ...authConfig,
  port: process.env.PORT || 3001,
  dbPath: process.env.DB_PATH
    ? (path.isAbsolute(process.env.DB_PATH) ? process.env.DB_PATH : path.resolve(__dirname, process.env.DB_PATH))
    : path.join(__dirname, 'database.sqlite'),
  frontendOrigins: (process.env.FRONTEND_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean),
  n8nAllowedOrigins: (process.env.N8N_ALLOWED_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean),

  // Zabbix Server Connection (optional — mock data fallback if offline)
  // If you do not have a running Zabbix API available, leave ZABBIX_URL blank.
  // Telegram bot configuration
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
  telegramBotUsername: process.env.TELEGRAM_BOT_USERNAME || '@ZserverSoC_bot',
  telegramChatId: process.env.TELEGRAM_CHAT_ID || '',

  // Internal SOC bot for incident automation + periodic heartbeat
  internalTelegramBotToken: process.env.INTERNAL_TELEGRAM_BOT_TOKEN || process.env.TELEGRAM_BOT_TOKEN || '',
  internalTelegramChatId: process.env.INTERNAL_TELEGRAM_CHAT_ID || process.env.TELEGRAM_CHAT_ID || '',
  internalTelegramAlertsEnabled: String(process.env.INTERNAL_TELEGRAM_ALERTS_ENABLED ?? 'false').toLowerCase() !== 'false',

  // External honey-port alert bot kept completely separate from the internal SOC bot
  honeyTelegramBotToken: process.env.HONEY_TELEGRAM_BOT_TOKEN || '',
  honeyTelegramChatId: process.env.HONEY_TELEGRAM_CHAT_ID || process.env.INTERNAL_TELEGRAM_CHAT_ID || process.env.TELEGRAM_CHAT_ID || '',
  honeyTelegramAlertsEnabled: String(process.env.HONEY_TELEGRAM_ALERTS_ENABLED ?? 'false').toLowerCase() !== 'false',

  // Demo mode: treat private/LAN probes as EXTERNAL for live presentation or lab validation
  honeyDemoForceExternal: String(process.env.HONEY_FORCE_EXTERNAL ?? 'false').toLowerCase() === 'true',

  // n8n automation webhook
  n8nWebhookUrl: process.env.N8N_WEBHOOK_URL || '',
  n8nWebhookSecret: process.env.N8N_WEBHOOK_SECRET || '',

  localAi: {
    enabled: String(process.env.LOCAL_AI_ENABLED ?? 'true').toLowerCase() === 'true',
    url: process.env.LOCAL_AI_URL || 'http://127.0.0.1:8090',
    model: process.env.LOCAL_AI_MODEL || 'soc-brain',
    apiKey: process.env.LOCAL_AI_API_KEY || '',
  },
  // E-commerce decoy is opt-in and isolated from the existing honey-port module.
  decoy: {
    enabled: String(process.env.DECOY_ENABLED || 'false').toLowerCase() === 'true',
    port: Number.parseInt(process.env.DECOY_PORT || '8081', 10),
    baselinePath: process.env.DECOY_BASELINE_PATH
      ? (path.isAbsolute(process.env.DECOY_BASELINE_PATH) ? process.env.DECOY_BASELINE_PATH : path.resolve(__dirname, process.env.DECOY_BASELINE_PATH))
      : path.join(__dirname, '../honeypot-site-baseline'),
    liveSitePath: process.env.DECOY_SITE_PATH
      ? (path.isAbsolute(process.env.DECOY_SITE_PATH) ? process.env.DECOY_SITE_PATH : path.resolve(__dirname, process.env.DECOY_SITE_PATH))
      : path.join(__dirname, '../honeypot-site'),
    dbPath: process.env.DECOY_DB_PATH
      ? (path.isAbsolute(process.env.DECOY_DB_PATH) ? process.env.DECOY_DB_PATH : path.resolve(__dirname, process.env.DECOY_DB_PATH))
      : path.join(__dirname, 'decoy.sqlite'),
  },

  deception: {
    freeze: String(process.env.DECEPTION_FREEZE || 'false').toLowerCase() === 'true',
    maxRotationsPerHour: Number.parseInt(process.env.MAX_ROTATIONS_PER_HOUR || '10', 10) || 10,
    applyResponsePolicy: String(process.env.APPLY_RESPONSE_POLICY || 'false').toLowerCase() === 'true',
    applyApiRotation: String(process.env.APPLY_API_ROTATION || 'false').toLowerCase() === 'true',
    applyApiSchema: String(process.env.APPLY_API_SCHEMA || 'false').toLowerCase() === 'true',
    socTargetWatcher: String(process.env.SOC_TARGET_WATCHER || 'true').toLowerCase() !== 'false',
    integrityWatcher: String(process.env.DECOY_INTEGRITY_WATCHER || 'true').toLowerCase() !== 'false',
    allowedWebRoutes: ['/admin', '/login', '/products', '/checkout'],
    allowedApiRoutes: ['/api/login', '/api/products', '/api/orders', '/api/admin'],
  },
};

