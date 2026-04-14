const path = require('path');
require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3001,
  dbPath: process.env.DB_PATH || path.join(__dirname, 'database.sqlite'),
  apiKey: process.env.API_KEY || 'zabbix-soc-secret-key-123',
};
