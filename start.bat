@echo off
timeout /t 2 /nobreak >nul
echo Starting Zabbix SOC Backend...
cd backend

IF NOT EXIST "node_modules" (
    echo Installing dependencies...
    npm install
)

echo Starting Node.js Server...
npm start
pause
