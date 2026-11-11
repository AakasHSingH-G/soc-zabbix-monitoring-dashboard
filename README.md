<div align="center">

# 🔷 Zabbix SOC Dashboard

### Unified Security Operations & Network Monitoring Platform

![Version](https://img.shields.io/badge/version-2.0.0-00f2fe?style=for-the-badge)
![Node.js](https://img.shields.io/badge/Node.js-20.x-339933?style=for-the-badge&logo=nodedotjs)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite)
![License](https://img.shields.io/badge/license-MIT-c084fc?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Raspberry%20Pi-E30B5C?style=for-the-badge&logo=raspberrypi)
![Status](https://img.shields.io/badge/status-Active-10b981?style=for-the-badge)

> **Real-time SOC dashboard** with Zabbix integration, Wazuh SIEM alerts, MITRE ATT&CK incident tracking, threat intelligence, and network flow visualization — all in one premium dark-themed interface.
> 
> 🐧 **Platform Compatibility:** Tested and optimized specifically for **Linux** (Kali Linux, Ubuntu, Debian) and **Raspberry Pi** (Raspberry Pi OS / ARM64).

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Setup Installer](#-setup-installer-windows)
- [All API Endpoints](#-all-api-endpoints)
- [Tab Guide](#-tab-guide)
- [Real Zabbix Connection](#-connecting-real-zabbix-server)
- [Default Credentials](#-default-credentials)
- [Environment Variables](#-environment-variables)
- [Network Discovery & Alerts](#-network-discovery--new-device-alerts)
- [Architecture](#-architecture-diagram)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)

---

## 🌐 Overview

### E-Commerce Decoy (opt-in)

The synthetic e-commerce decoy is disabled by default. Enable it only in an authorized lab with `DECOY_ENABLED=true`; it uses `/decoy/` and `/api/decoy/*`, synthetic data, and the existing normalized security event pipeline with `event_source=decoy_ecommerce`. It does not contact payment, email, or external service providers.

Useful environment variables:

```bash
DECOY_ENABLED=false
DECOY_PORT=8081
```

Zabbix SOC Dashboard ek **enterprise-grade Security Operations Center** web application hai jo:

- Tumhare **network ke saare devices ko monitor** karta hai (hosts, servers, switches)
- **Real-time security alerts** dikhata hai (Wazuh SIEM integration)
- **MITRE ATT&CK framework** ke through incident response track karta hai
- **Threat Intelligence** — top attacker IPs, threat scores, risk analysis
- **SOC Flow** — drag-and-drop network topology builder
- **Zabbix API** se real CPU/RAM/Disk metrics fetch karta hai
- **Naya device connect ho** toh automatic notification deta hai

> Zabbix Server available na ho toh **mock data automatically use** hota hai — dashboard hamesha functional rahega.

---

## ✨ Features

### 🛡️ Security Module (Wazuh SIEM)
- Live event feed — real-time security alerts (15–25 events)
- Severity badges: **CRIT / HIGH / MED / LOW**
- Alert volume chart — last 24 hours (bar graph)
- Severity distribution — doughnut chart
- Auto-refresh every 5 seconds

### 🔎 Threat Intelligence
- Top 10 attacker IPs with hit counts
- Threat score bars (0–100)
- Risk level classification: **High / Medium / Low**
- Filter by risk level
- Last seen timestamps

### 🚨 Incident Response (MITRE ATT&CK)
- IR cards with full workflow stages: `Detected → Investigated → Contained → Resolved`
- MITRE ATT&CK technique IDs (T1110.001, T1046, T1190, T1486)
- Action logs with detailed forensics
- Severity-coded cards

### 💻 Host Monitoring
- Real hosts from Zabbix API (CPU, RAM, Disk per host)
- Online/Offline status badges
- Host group classification
- Export to CSV
- Add/Delete hosts (Admin only)

### 🚨 Problems Tab
- Active problems list from Zabbix
- Acknowledge problems one-click
- Severity classification

### 📈 Graphs Tab
- CPU utilization — real-time timeseries
- Memory usage — live chart
- Network throughput — animated
- Auto-rotation every 60 seconds

### 🔀 SOC Flow (Network Topology)
- Drag-and-drop security operations pipeline
- Current nodes: Zabbix, Wazuh SIEM, Honeyport Sensors, Event Correlation, Threat Intelligence, Incident Queue, Response Automation, Notifications, and SIEM Evidence Store
- Live `/api/security/*` telemetry with mock fallback when the backend is unavailable
- Severity counters for CRIT, HIGH, MED, LOW, and sensor events
- Zoom in/out, pan, fit-to-screen
- Connection lines with animation
- Node detail panel

### ⚙️ Config Tab
- Zabbix API connection test
- WebSocket status
- n8n webhook integration
- SIEM endpoint configuration

### 👥 Admin Panel (Admin only)
- User management (create, delete, view)
- Role-based access: **admin / analyst / viewer**
- Audit log of all actions

---

## 📁 Project Structure

```
soc-zabbix-monitoring-dashboard/
│
├── 📄 README.md                    ← Yeh file (tumhara guide)
├── 🔧 setup-zabbix.bat             ← One-click Windows installer
├── 🔧 start.bat                    ← Quick start script
├── 🔧 start.sh                     ← Linux/Mac start script
│
├── 📂 Frontend/
│   ├── 🌐 final.html               ← Main dashboard (single-page app)
│   ├── 🎨 style.css                ← Complete CSS (cyberpunk dark theme)
│   ├── ⚡ n8n-addon.js             ← n8n automation addon
│   └── 🎨 n8n-addon.css           ← n8n addon styles
│
├── 📂 backend/
│   ├── 🚀 server.js                ← Express.js API server (main)
│   ├── 🔗 zabbix-api.js            ← Zabbix JSON-RPC API wrapper
│   ├── 🗄️ database.js             ← SQLite database setup
│   ├── ⚙️ config.js               ← Server configuration
│   ├── 🔌 websocket.js             ← WebSocket server (new-device alerts)
│   ├── 📦 package.json             ← Node.js dependencies
│   ├── 🔐 .env                     ← Environment variables (gitignored)
│   └── 💾 database.sqlite          ← SQLite users database
│
├── 📂 Imags/                       ← Project screenshots/images
├── 📂 zabbix-marketing-site/       ← Zabbix reference site
└── 📄 .gitignore
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | HTML5 + Vanilla CSS + JS | Single-page dashboard |
| **Fonts** | Rajdhani + Share Tech Mono | Cyberpunk aesthetic |
| **Charts** | Chart.js 4.4 | Real-time graphs |
| **Backend** | Node.js + Express.js | REST API server |
| **Database** | SQLite 3 | Users & auth storage |
| **Real-time** | WebSocket (ws) | Live device notifications |
| **Monitoring** | Zabbix API (JSON-RPC) | Real host metrics |
| **SIEM** | Wazuh (alerts.json) | Security events |
| **Automation** | n8n webhooks | Alert routing |

---

## 🚀 Quick Start

### Prerequisites
- **Node.js** v18+ ([nodejs.org](https://nodejs.org))
- **npm** (Node.js ke saath aata hai)

### Steps

```bash
# 1. Backend folder mein jao
cd backend

# 2. Dependencies install karo
npm install

# 3. Server start karo
node server.js

# 4. Browser mein open karo
# http://localhost:3001
```

**Login karo:**
- See `backend/.env.example` for required initial credential environment variables. No passwords are included here.

### Credential Setup

Copy `backend/.env.example` to `backend/.env` and provide `API_KEY`. When `ZABBIX_URL` is configured, provide `ZABBIX_USER` and `ZABBIX_PASS` as well. `INITIAL_ADMIN_PASSWORD`, `INITIAL_ANALYST_PASSWORD`, and `INITIAL_VIEWER_PASSWORD` are required only when initializing an empty users table; `ADMIN_PANEL_PASSWORD` is required only when an admin panel credential must be initialized. Demo login remains disabled by default; enabling it requires the three `DEMO_*_PASSWORD` environment variables. Do not put passwords in source files or documentation.
---

## 🔧 Setup Installer (Windows)

**Ek click mein sab kuch automatic setup:**

```
1. setup-zabbix.bat pe Right-click karo
2. "Run as Administrator" select karo
3. Zabbix Server IP dalo (agar available hai)
4. Sab kuch automatically install hoga:
   ✅ Node.js (agar install nahi hai)
   ✅ npm install (backend dependencies)
   ✅ .env file create
   ✅ Zabbix Agent 2 download + install (Windows x64)
   ✅ Firewall rules (ports 3001, 10050)
   ✅ Backend server start
   ✅ Browser mein dashboard open
```

---

## 📡 All API Endpoints

### 🔐 Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | User login → token |
| `GET`  | `/api/health` | Backend health check |

### 👥 Users
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/users` | All users list |
| `POST` | `/api/users` | Create new user |
| `DELETE` | `/api/users/:id` | Delete user |

### 🛡️ Security (Wazuh SIEM)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/security/health` | Wazuh connection status |
| `GET` | `/api/security/events` | Live events (max 25) |
| `GET` | `/api/security/stats` | CRIT/HIGH/MED/LOW counts |
| `GET` | `/api/security/attackers` | Top 10 attacker IPs |
| `GET` | `/api/security/chart/hourly` | 24-bucket hourly chart data |
| `GET` | `/api/security/rules` | Detection rules panel |
| `GET` | `/api/security/incidents` | MITRE ATT&CK incidents |

### 🔗 Zabbix (Real Host Data)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/zabbix/hosts` | Real monitored hosts (CPU/RAM/Disk) |
| `GET` | `/api/zabbix/problems` | Active Zabbix problems |
| `GET` | `/api/zabbix/status` | Zabbix Server connection info |

### 🔔 Webhook
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/webhook/new-device` | Zabbix discovery → new device alert |

**Ports:**
- `3001` — HTTP API + Frontend serving
- `3001/ws` — WebSocket (real-time notifications)
- `10050` — Zabbix Agent (agar install hai)

---

## 🖥️ Tab Guide

| Tab | Shortcut | What it shows |
|-----|----------|---------------|
| 📊 **Overview** | Default | Stats cards, recent problems, charts |
| 💻 **Hosts** | Click | All monitored hosts, CPU/RAM/Disk |
| 🚨 **Problems** | Click | Active alerts, acknowledge actions |
| 📈 **Graphs** | Click | CPU/Memory/Network live timeseries |
| 🔀 **SOC Flow** | Click | Drag-drop network topology |
| ⚙️ **Config** | Click | API connections, settings |
| 🛡️ **Security** | Click | Wazuh SIEM events, charts |
| 🔎 **Threat Intel** | Click | Top attackers, threat scores |
| 🚨 **Incidents** | Click | MITRE ATT&CK IR workflow |
| 👥 **Admin** | Admin only | User management, audit log |

---

## 🔗 Connecting Real Zabbix Server

> ⚠️ **Important**: Zabbix Server sirf Linux pe chalta hai. Windows pe sirf Zabbix **Agent** install hota hai.

### Option A — Virtual Machine (Recommended)

```bash
# Ubuntu 22.04/24.04 VM pe yeh commands chalao:

# 1. Zabbix repository add karo
wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.0+ubuntu24.04_all.deb
dpkg -i zabbix-release_latest_7.0+ubuntu24.04_all.deb
apt update

# 2. Zabbix Server install karo
apt install zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent2 -y

# 3. MySQL setup
mysql -u root -p
# CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
# CREATE USER 'zabbix'@'localhost' IDENTIFIED BY 'password';
# GRANT ALL PRIVILEGES ON zabbix.* TO 'zabbix'@'localhost';
# FLUSH PRIVILEGES;

# 4. Import Zabbix schema
zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -u zabbix -p zabbix

# 5. Services start karo
systemctl start zabbix-server zabbix-agent2 apache2
systemctl enable zabbix-server zabbix-agent2 apache2
```

### Option B — WSL2 (Windows Subsystem for Linux)

```bash
# WSL2 Ubuntu mein:
sudo apt update
sudo apt install zabbix-server-mysql zabbix-frontend-php -y
# (same steps as above)
```

### Dashboard Connect Karna

```bash
# backend/.env file update karo:
ZABBIX_URL=http://192.168.1.100/zabbix/api_jsonrpc.php
ZABBIX_USER=Admin
ZABBIX_PASS=zabbix

# Backend restart karo:
node server.js
```

Bas! Dashboard automatically real data fetch karna shuru kar dega. Zabbix offline ho toh mock data fallback hoga.

### Doosre Laptops pe Zabbix Agent Install Karna

**Windows:**
```
1. https://www.zabbix.com/download_agents se MSI download karo
2. Install karo, config mein Zabbix Server IP dalo
3. Service start: sc start "Zabbix Agent 2"
```

**Linux:**
```bash
apt install zabbix-agent2 -y
nano /etc/zabbix/zabbix_agent2.conf
# Server= [Zabbix Server IP]
# ServerActive= [Zabbix Server IP]
systemctl start zabbix-agent2
```

---

## 🔐 Default Credentials

| Username | Password | Role | Access |
|----------|----------|------|--------|
| `admin` | `see `backend/.env.example`` | **Admin** | Full access (all tabs + user management) |
| `analyst` | `see `backend/.env.example`` | **Analyst** | Read + acknowledge (no admin tab) |
| `viewer` | `see `backend/.env.example`` | **Viewer** | Read-only |

> ⚠️ **Production mein passwords zaroor change karo!** Database mein `database.sqlite` directly edit karo ya API se naya user banao.

---

## 🔧 Environment Variables

`backend/.env` file:

```env
# Server Port
PORT=3001

# Zabbix Server Connection
ZABBIX_URL=
ZABBIX_USER=CHANGE_ME
ZABBIX_PASS=CHANGE_ME

# Database
DB_PATH=./database.sqlite

# API Security Key
API_KEY=CHANGE_ME
```

### AI Brain Provider

The bundled loopback model is used by default. Administrators can optionally configure an OpenAI-compatible API base URL, model, and API key in the dashboard Config tab. The available modes are API-first with local fallback, or local analysis followed by API review. Prompts and relevant SOC evidence are sent to the configured API in either remote mode. The API key is encrypted in the database; keep `backend/.env.ai-provider-key` with the database when backing up or moving the installation.

---

## 🔔 Network Discovery & New Device Alerts

Jab switch pe koi naya laptop/device connect ho, yeh flow kaam karta hai:

```
New Device connects to Switch
    ↓
Zabbix Server auto-discovers it (Discovery Rule)
    ↓
Zabbix Action fires → Webhook call
    ↓
POST http://[dashboard-server]:3001/api/webhook/new-device
    ↓
Backend → WebSocket broadcast
    ↓
Frontend → 🔍 Popup notification "New Device Discovered"
    ↓
Hosts tab automatically refresh
```

**Zabbix mein Discovery Rule setup:**
1. `Configuration → Discovery → Create discovery rule`
2. IP range: `192.168.1.1-254`
3. Checks: Zabbix Agent (port 10050) + ICMP ping
4. `Configuration → Actions → Discovery actions → Create`
5. Operation: `Send message → Custom webhook`
6. Webhook URL: `http://[tumhara-IP]:3001/api/webhook/new-device`

---

## 🏗️ Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    BROWSER (Frontend)                       │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ final.html  │  │  style.css   │  │   n8n-addon.js   │  │
│  │  (9 tabs)   │  │ (dark theme) │  │  (automation)    │  │
│  └──────┬──────┘  └──────────────┘  └──────────────────┘  │
│         │ HTTP REST + WebSocket                            │
└─────────┼───────────────────────────────────────────────────┘
          │
┌─────────▼───────────────────────────────────────────────────┐
│              NODE.JS BACKEND (port 3001)                    │
│                                                             │
│  server.js ──► CORS ──► Routes:                            │
│    /api/auth/*         (SQLite login)                       │
│    /api/users/*        (User CRUD)                          │
│    /api/security/*     (Wazuh SIEM)                        │
│    /api/zabbix/*   ──► zabbix-api.js ──► Zabbix Server     │
│    /api/webhook/*      (Discovery alerts)                   │
│                                                             │
│  websocket.js (/ws on port 3001) ──► Browser notifications  │
│  database.js ──► database.sqlite (users)                   │
└─────────────────────────────────────────────────────────────┘
          │                    │
┌─────────▼──────┐   ┌────────▼────────────┐
│  Zabbix Server │   │    Wazuh SIEM       │
│  (Linux VM)    │   │  /var/ossec/logs/   │
│  port 80       │   │  alerts.json        │
│                │   │  (optional)         │
│  Zabbix Agents │   └─────────────────────┘
│  on all hosts  │
└────────────────┘
```

---

## 🐛 Troubleshooting

### Dashboard kholne ke baad blank screens?
```
Cause: Backend server chal nahi raha
Fix:   cd backend && node server.js
Check: http://localhost:3001/api/health
```

### Security/Threat Intel/Incidents tab blank?
```
Cause: Pehle CORS bug tha (ab fix ho gaya v2.0 mein)
Fix:   Latest code pull karo, backend restart karo
```

### Login nahi ho raha?
```
Cause: Backend offline ya database issue
Fix 1: Check → cd backend && node server.js
Fix 2: database.sqlite delete karo → restart karo (fresh DB)
Credentials: admin / see `backend/.env.example`
```

### Zabbix data nahi aa raha?
```
Cause: Zabbix Server offline ya URL galat
Fix:   backend/.env check karo → ZABBIX_URL update karo
Note:  Mock data automatic use hoga — koi error nahi aayegi
```

### Port 3001 already in use?
```powershell
# Windows PowerShell:
netstat -ano | findstr :3001
taskkill /PID [PID_NUMBER] /F

# Phir restart:
node server.js
```

### npm install fail ho raha hai?
```bash
# Node.js version check:
node --version  # 18+ chahiye

# Cache clear karke retry:
npm cache clean --force
npm install
```

### Zabbix Agent service nahi chal raha?
```powershell
# Windows:
sc query "Zabbix Agent 2"
sc start "Zabbix Agent 2"

# Config file location:
C:\Program Files\Zabbix Agent 2\zabbix_agent2.conf
```

---

## 🗺️ Roadmap

### ✅ Completed (v2.0)
- [x] CORS bug fix — Security/Threat Intel/Incidents tabs working
- [x] Zabbix API real data integration (getHosts, getProblems)
- [x] WebSocket new-device broadcast
- [x] Graceful mock data fallback
- [x] Windows one-click installer (setup-zabbix.bat)
- [x] .env environment configuration
- [x] Auto-refresh real data (30s interval)
- [x] New device popup notification

### 🔜 Planned (v3.0)
- [ ] Zabbix network discovery auto-configure
- [ ] Email/Telegram alert notifications
- [ ] Dark/Light theme toggle
- [ ] PDF report export
- [ ] Multi-tenant support
- [ ] Docker compose deployment
- [ ] Grafana integration
- [ ] Custom dashboard widgets

---

## 📊 File Sizes & Lines

| File | Size | Lines | Description |
|------|------|-------|-------------|
| `Frontend/final.html` | ~95 KB | ~2050 | Complete dashboard UI + JS |
| `Frontend/style.css` | ~37 KB | 618 | All CSS styles |
| `backend/server.js` | ~20 KB | ~410 | Main API server |
| `backend/zabbix-api.js` | ~7 KB | ~220 | Zabbix API wrapper |
| `backend/websocket.js` | ~1.5 KB | 55 | WebSocket server |
| `backend/database.js` | ~1.5 KB | 41 | SQLite setup |
| `backend/config.js` | ~0.5 KB | 14 | Config |
| `setup-zabbix.bat` | ~5 KB | ~160 | Windows installer |

---

## 👨‍💻 Development

```bash
# Development mode (auto-restart on changes):
cd backend
node --watch server.js

# Frontend changes:
# Directly edit Frontend/final.html ya style.css
# Browser refresh karo — no build step needed
```

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

<div align="center">

**Enterprise Network Monitoring & Security Operations Center (SOC) Platform**

🔷 **Zabbix SOC Dashboard v2.0** 🔷

*Real-time monitoring | SIEM Integration | MITRE ATT&CK | Threat Intelligence*

</div>
