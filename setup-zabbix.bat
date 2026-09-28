@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Zabbix SOC Dashboard - Windows Setup Installer
color 0A

:: --- Step 0: Admin Check & Auto-Elevation -------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ============================================================
    echo   Administrator privileges required. Elevating privileges...
    echo ============================================================
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo.
    echo   A new elevated installer window should now be open.
    echo   Keep that window open while setup is running.
    pause
    exit /b 0
)

echo.
echo ============================================================
echo   ZABBIX SOC - Complete Windows Setup Installer
echo ============================================================
echo   Version 2.1 - Setup by: setup-zabbix.bat (Auto-Elevated)
echo ============================================================
echo.

:: --- Detect script location ---------------------------------------------------
set "ROOT_DIR=%~dp0"
set "BACKEND_DIR=%ROOT_DIR%backend"
set "FRONTEND_DIR=%ROOT_DIR%Frontend"
set "DOWNLOADS_DIR=%ROOT_DIR%_downloads"

if not exist "%DOWNLOADS_DIR%" mkdir "%DOWNLOADS_DIR%"

echo.
echo ============================================================
echo   STEP 1: Checking Node.js Installation
echo ============================================================
where node >nul 2>&1
if %errorlevel% equ 0 goto :node_found

echo   [INFO] Node.js not found. Downloading and installing...
echo   [INFO] Downloading Node.js LTS from nodejs.org...
powershell -Command "& {Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.15.0/node-v20.15.0-x64.msi' -OutFile '%DOWNLOADS_DIR%\nodejs.msi' -UseBasicParsing}"
if not exist "%DOWNLOADS_DIR%\nodejs.msi" goto :node_download_fail

echo   [INFO] Installing Node.js...
msiexec /i "%DOWNLOADS_DIR%\nodejs.msi" /quiet /norestart
echo   [OK] Node.js installed. Please rerun this script after installation completes.
pause
exit /b 0

:node_download_fail
echo   [ERROR] Node.js download failed. Please install manually from https://nodejs.org
pause
exit /b 1

:node_found
for /f "tokens=*" %%v in ('node --version') do set NODE_VER=%%v
echo   [OK] Node.js found: !NODE_VER!

:: --- Step 2: npm install -------------------------------------------------------
echo.
echo ============================================================
echo   STEP 2: Installing Backend Dependencies (npm install)
echo ============================================================
if not exist "%BACKEND_DIR%\package.json" (
    echo   [ERROR] backend\package.json not found. Check your project folder.
    pause
    exit /b 1
)
cd /d "%BACKEND_DIR%"
echo   [INFO] Running npm install in: %BACKEND_DIR%
call npm install
if %errorlevel% neq 0 (
    echo   [ERROR] npm install failed. Check your internet connection.
    pause
    exit /b 1
)
echo   [OK] Backend dependencies installed.

:: --- Step 3: .env setup -------------------------------------------------------
echo.
echo ============================================================
echo   STEP 3: Environment Configuration (.env)
echo ============================================================
if not exist "%BACKEND_DIR%\.env" (
    echo   [INFO] Creating default .env file...
    (
        echo # Zabbix SOC Dashboard Environment
        echo PORT=3001
        echo ZABBIX_URL=
        echo ZABBIX_USER=CHANGE_ME
        echo ZABBIX_PASS=CHANGE_ME
        echo DB_PATH=./database.sqlite
        echo API_KEY=CHANGE_ME
    ) > "%BACKEND_DIR%\.env"
    echo   [OK] .env file created at backend\.env
    echo   [INFO] NOTE: Update ZABBIX_URL with your Zabbix Server IP when ready.
) else (
    echo   [OK] .env file already exists - skipping.
)

:: --- Step 4: Zabbix Agent 2 Download + Install --------------------------------
echo.
echo ============================================================
echo   STEP 4: Zabbix Agent 2 for Windows
echo ============================================================
echo.
echo   Zabbix Agent monitors THIS Windows machine and sends
echo   real CPU/RAM/Disk data to Zabbix Server.
echo.

:: Check if already installed
sc query "Zabbix Agent 2" >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] Zabbix Agent 2 is already installed.
    goto :zabbix_agent_done
)

echo   [?] Where is your Zabbix Server?
echo       (This is the Linux VM / Ubuntu machine IP)
echo.
set /p ZABBIX_SERVER_IP="  Enter Zabbix Server IP [default: 127.0.0.1]: "
if "!ZABBIX_SERVER_IP!"=="" set ZABBIX_SERVER_IP=127.0.0.1

echo.
echo   [INFO] Preparing Zabbix Agent 2 MSI...
set "ZBX_MSI=%DOWNLOADS_DIR%\zabbix_agent2.msi"
set "ZBX_URL=https://cdn.zabbix.com/zabbix/binaries/stable/7.0/latest/zabbix_agent2-7.0-latest-windows-amd64-openssl.msi"

if exist "%ZBX_MSI%" (
    echo   [OK] Using existing local Zabbix Agent 2 MSI: %ZBX_MSI%
) else (
    echo   [INFO] Downloading Zabbix Agent 2 v7.0 (Windows x64)...
    powershell -Command "& {Invoke-WebRequest -Uri '%ZBX_URL%' -OutFile '%ZBX_MSI%' -UseBasicParsing}"
)

if not exist "%ZBX_MSI%" goto :zabbix_download_fail
set "ZBX_LOG=%DOWNLOADS_DIR%\zabbix_agent2_install.log"

echo   [INFO] Installing Zabbix Agent 2 (silent install)...
msiexec /i "%ZBX_MSI%" /quiet /norestart /l*v "%ZBX_LOG%" ADDLOCAL=AgentFeature SERVER=!ZABBIX_SERVER_IP! SERVERACTIVE=!ZABBIX_SERVER_IP! HOSTNAME=%COMPUTERNAME%
if %errorlevel% neq 0 (
    echo   [ERROR] MSI installation failed with exit code %errorlevel%.
    echo   [ERROR] Review install log: %ZBX_LOG%
    goto :zabbix_install_fail
)

:: Start service
sc start "Zabbix Agent 2" >nul 2>&1
timeout /t 3 /nobreak >nul
sc query "Zabbix Agent 2" | findstr "RUNNING" >nul
if %errorlevel% neq 0 goto :zabbix_service_fail

echo   [OK] Zabbix Agent 2 installed and running
echo   [OK] Reporting to: !ZABBIX_SERVER_IP!
echo   [OK] Hostname: %COMPUTERNAME%

:: Update .env with the same IP
powershell -Command "(Get-Content '%BACKEND_DIR%\.env') -replace 'ZABBIX_URL=.*', 'ZABBIX_URL=http://!ZABBIX_SERVER_IP!/zabbix/api_jsonrpc.php' | Set-Content '%BACKEND_DIR%\.env'"
echo   [OK] Updated .env with Zabbix Server IP: !ZABBIX_SERVER_IP!
goto :zabbix_agent_done

:zabbix_service_fail
echo   [WARN] Zabbix Agent installed but service may need manual start.
echo   [WARN] Run: sc start "Zabbix Agent 2"
goto :zabbix_agent_done

:zabbix_download_fail
echo   [ERROR] Could not download Zabbix Agent MSI.
echo   [ERROR] Manual install: https://www.zabbix.com/download_agents
echo   [ERROR] After install, set Server to: !ZABBIX_SERVER_IP!

goto :finish

:zabbix_install_fail
echo   [ERROR] Zabbix MSI install failed. See log file in downloads folder.
goto :finish

:zabbix_agent_done

goto :finish

:finish

:: --- Step 5: Firewall rules ----------------------------------------------------
echo.
echo ============================================================
echo   STEP 5: Windows Firewall Rules
echo ============================================================
echo   [INFO] Adding firewall rule: Zabbix Agent (port 10050)...
netsh advfirewall firewall add rule name="Zabbix Agent 2" dir=in action=allow protocol=TCP localport=10050 >nul 2>&1
echo   [INFO] Adding firewall rule: SOC Dashboard Backend (port 3001)...
netsh advfirewall firewall add rule name="Zabbix SOC Backend" dir=in action=allow protocol=TCP localport=3001 >nul 2>&1
echo   [INFO] WebSocket uses the backend HTTP port (3001)...
echo   [OK] Firewall rules added.

:: --- Step 6: Start backend ----------------------------------------------------
echo.
echo ============================================================
echo   STEP 6: Starting Zabbix SOC Backend Server
echo ============================================================
cd /d "%BACKEND_DIR%"
if not exist "server.js" (
    echo   [ERROR] backend\server.js not found: %BACKEND_DIR%
    pause
    exit /b 1
)
echo   [INFO] Starting backend on port 3001...
start "Zabbix SOC Backend" /min cmd /k "node server.js"
timeout /t 2 /nobreak >nul

:: Verify backend is running. Do not report success until the health endpoint responds.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ok=$false; 1..10 ^| ForEach-Object { try { Invoke-WebRequest -Uri 'http://localhost:3001/api/health' -UseBasicParsing -TimeoutSec 2 ^| Out-Null; $ok=$true; break } catch { Start-Sleep -Seconds 1 } }; if (-not $ok) { exit 1 }"
if errorlevel 1 goto :backend_start_fail
echo   [OK] Backend is running on http://localhost:3001
goto :summary

:backend_start_fail
echo   [ERROR] Backend did not respond on http://localhost:3001/api/health.
echo   [ERROR] Keep the "Zabbix SOC Backend" window open and read the Node.js error there.
echo   [ERROR] Common causes: npm install failed, port 3001 is busy, or backend/server.js crashed.
pause
exit /b 1

:: --- Summary ------------------------------------------------------------------
:summary
echo.
echo ============================================================
echo   SETUP COMPLETE
echo ============================================================
echo.
echo   Dashboard URL   : http://localhost:3001
echo   Backend API     : http://localhost:3001/api
echo   WebSocket       : ws://localhost:3001/ws
echo   Zabbix API      : http://localhost:3001/api/zabbix
echo.
echo   Login Credentials:
echo     Username: admin     Password: %INITIAL_ANALYST_PASSWORD%
echo     Username: analyst   Password: %INITIAL_ANALYST_PASSWORD%
echo     Username: viewer    Password: %INITIAL_ANALYST_PASSWORD%
echo.
echo ============================================================
echo   NEXT STEPS (Zabbix Server - Linux required):
echo ============================================================
echo.
echo   1. Setup a Linux VM (Ubuntu 22.04) with VirtualBox/VMware
echo   2. In VM, run these commands:
echo.
echo      wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release_latest_7.0+ubuntu24.04_all.deb
echo      dpkg -i zabbix-release_latest_7.0+ubuntu24.04_all.deb
echo      apt update
echo      apt install zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent2
echo.
echo   3. Configure MySQL and start Zabbix
echo   4. Update backend\.env with VM IP:
echo      ZABBIX_URL=http://[VM-IP]/zabbix/api_jsonrpc.php
echo   5. Restart backend server
echo.
echo ============================================================
echo.

:: Open dashboard in browser
echo   [INFO] Opening dashboard in browser...
start "" "http://localhost:3001"

echo   Press any key to exit setup...
pause >nul

echo.
echo ============================================================
echo   Setup finished. If the window closes, run from an elevated Command Prompt next time.
echo   If you need help, open the log file: %DOWNLOADS_DIR%\zabbix_agent2_install.log

echo.
echo   Press any key to close.
pause >nul

echo ============================================================
echo   Setup complete. If this window closes unexpectedly, run the script from an elevated command prompt.
echo.
echo   Press any key to close.
pause >nul
endlocal
