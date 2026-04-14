const sqlite3 = require('sqlite3').verbose();
const config = require('./config');

const db = new sqlite3.Database(config.dbPath, (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      full_name TEXT,
      email TEXT,
      role TEXT,
      status TEXT,
      last_login TEXT
    )`, (err) => {
      if (err) {
        console.error('Error creating users table', err.message);
      } else {
        // Create demo users if the table is empty
        db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
          if (!err && row.count === 0) {
            console.log('Initializing database with default users...');
            const insert = 'INSERT INTO users (username, password, full_name, email, role, status, last_login) VALUES (?,?,?,?,?,?,?)';
            const now = new Date().toISOString();
            
            db.run(insert, ['admin', 'admin123', 'System Administrator', 'admin@company.com', 'admin', 'active', now]);
            db.run(insert, ['viewer', 'viewer123', 'Read-Only User', 'viewer@company.com', 'viewer', 'active', now]);
            db.run(insert, ['analyst', 'analyst123', 'SOC Analyst', 'analyst@company.com', 'analyst', 'active', now]);
          }
        });
      }
    });
  }
});

module.exports = db;
