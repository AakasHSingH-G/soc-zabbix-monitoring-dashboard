const express = require('express');
const cors = require('cors');
const db = require('./database');
const config = require('./config');
const initializeWebSocket = require('./websocket');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// API Endpoints for Users

// 0. Health Check (to verify backend is reachable)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Backend is reachable', timestamp: new Date().toISOString() });
});

// 1. Authenticate user (for frontend login)
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const sql = `SELECT * FROM users WHERE username = ? AND password = ?`;
  db.get(sql, [username, password], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row) {
      // Simulate token generation and save last login
      const token = `token-${Date.now()}`;
      
      const updateLogin = `UPDATE users SET last_login = ? WHERE id = ?`;
      db.run(updateLogin, [new Date().toISOString(), row.id]);

      // Remove password before sending to frontend
      delete row.password;
      
      res.json({
        message: 'Login successful',
        token,
        user: { ...row, fullName: row.full_name }
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// 2. Get all users
app.get('/api/users', (req, res) => {
  const sql = `SELECT id, username, full_name, email, role, status, last_login FROM users`;
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// 3. Create a new user
app.post('/api/users', (req, res) => {
  const { username, password, full_name, email, role } = req.body;
  const status = 'active';
  const last_login = new Date().toISOString();

  if (!username || !password || !full_name || !email || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const sql = `INSERT INTO users (username, password, full_name, email, role, status, last_login) VALUES (?, ?, ?, ?, ?, ?, ?)`;
  db.run(sql, [username, password, full_name, email, role, status, last_login], function (err) {
    if (err) {
      // Typically 19 corresponds to a UNIQUE constraint failure in SQLite
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({
      message: 'User created successfully',
      id: this.lastID
    });
  });
});

// 4. Delete a user
app.delete('/api/users/:id', (req, res) => {
  const id = req.params.id;
  const sql = `DELETE FROM users WHERE id = ?`;
  
  db.run(sql, id, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted' });
  });
});

// Start Server
app.listen(config.port, () => {
  console.log(`Zabbix SOC Backend running on http://localhost:${config.port}`);
  // Start WebSocket Server on 8080
  initializeWebSocket(8080);
});
