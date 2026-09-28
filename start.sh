#!/bin/bash
# ============================================================
#   Zabbix SOC Dashboard Launcher for Kali Linux
#   Auto-installs ALL requirements, then starts the server
#   and opens the dashboard in the default browser.
# ============================================================

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$DIR/backend"
AI_DIR="$DIR/Local AI "
LOG="$DIR/.zabbix-soc.log"
PID_FILE="$DIR/.zabbix-soc.pid"
AI_PID_FILE="$AI_DIR/ai.pid"
PORT=3001
DECOY_ENABLED="${DECOY_ENABLED:-true}"
DECOY_PORT="${DECOY_PORT:-8081}"
HONEYPORT_PORTS="${HONEYPORT_PORTS:-2323}"
DECEPTION_FREEZE="${DECEPTION_FREEZE:-false}"
MAX_ROTATIONS_PER_HOUR="${MAX_ROTATIONS_PER_HOUR:-10}"
APPLY_RESPONSE_POLICY="${APPLY_RESPONSE_POLICY:-false}"
APPLY_API_ROTATION="${APPLY_API_ROTATION:-false}"
APPLY_API_SCHEMA="${APPLY_API_SCHEMA:-false}"
SOC_TARGET_WATCHER="${SOC_TARGET_WATCHER:-true}"
DECOY_INTEGRITY_WATCHER="${DECOY_INTEGRITY_WATCHER:-true}"
STOPPING=false
AI_STARTED_BY_LAUNCHER=false
export DECOY_ENABLED DECOY_PORT HONEYPORT_PORTS DECEPTION_FREEZE MAX_ROTATIONS_PER_HOUR APPLY_RESPONSE_POLICY APPLY_API_ROTATION APPLY_API_SCHEMA SOC_TARGET_WATCHER DECOY_INTEGRITY_WATCHER
LAN_IP=$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '$1 ~ /^192\.168\./ || $1 ~ /^10\./ || $1 ~ /^172\./ {print; exit}' || hostname -I 2>/dev/null | awk '{print $1; exit}' || echo '127.0.0.1')

port_is_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN
    elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$port$"
    else
        (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
    fi
}

check_required_ports_are_free() {
    local port
    if [ "$DECOY_ENABLED" = "true" ] && port_is_listening "$DECOY_PORT"; then
        err "E-commerce decoy port $DECOY_PORT is already in use. Set DECOY_PORT to a free port."
        return 1
    fi
    IFS=',' read -r -a HONEY_PORT_LIST <<< "$HONEYPORT_PORTS"
    for port in "${HONEY_PORT_LIST[@]}"; do
        port="$(echo "$port" | tr -d '[:space:]')"
        [ -z "$port" ] && continue
        if [ "$DECOY_ENABLED" = "true" ] && [ "$port" = "$DECOY_PORT" ]; then
            err "Honey port $port conflicts with e-commerce decoy port $DECOY_PORT."
            return 1
        fi
        if port_is_listening "$port"; then
            err "Honey port $port is already in use. Set HONEYPORT_PORTS to free port(s)."
            return 1
        fi
    done
}

select_available_port() {
    local candidate
    for candidate in 3001 3002 3003 3004 3005 3006 3007 3008 3009 3010; do
        if command -v ss >/dev/null 2>&1; then
            if ! ss -ltn "sport = :$candidate" 2>/dev/null | grep -q LISTEN; then
                echo "$candidate"
                return 0
            fi
        elif command -v lsof >/dev/null 2>&1; then
            if ! lsof -nP -iTCP:"$candidate" -sTCP:LISTEN >/dev/null 2>&1; then
                echo "$candidate"
                return 0
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if ! netstat -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$candidate$"; then
                echo "$candidate"
                return 0
            fi
        else
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

select_free_port_range() {
    local start="$1"
    local end="$2"
    local candidate excluded skip
    shift 2

    for ((candidate=start; candidate<=end; candidate++)); do
        skip=false
        for excluded in "$@"; do
            if [ "$candidate" = "$excluded" ]; then
                skip=true
                break
            fi
        done
        if [ "$skip" = false ] && ! port_is_listening "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_service_ports() {
    local selected requested port conflict
    local -a honey_ports resolved_honey excluded_ports

    IFS=',' read -r -a honey_ports <<< "$HONEYPORT_PORTS"

    if [ "$DECOY_ENABLED" = "true" ]; then
        conflict=false
        if port_is_listening "$DECOY_PORT" || [ "$DECOY_PORT" = "$PORT" ]; then
            conflict=true
        fi
        for port in "${honey_ports[@]}"; do
            port="$(echo "$port" | tr -d '[:space:]')"
            if [ -n "$port" ] && [ "$port" = "$DECOY_PORT" ]; then
                conflict=true
            fi
        done

        if [ "$conflict" = "true" ]; then
            excluded_ports=("$PORT" "${honey_ports[@]}")
            selected="$(select_free_port_range 8081 8090 "${excluded_ports[@]}" || true)"
            if [ -z "$selected" ]; then
                err "No free e-commerce decoy port found in the range 8081-8090."
                return 1
            fi
            warn "E-commerce decoy port $DECOY_PORT is unavailable. Switching launcher to port $selected."
            DECOY_PORT="$selected"
        fi
    fi

    resolved_honey=()
    for requested in "${honey_ports[@]}"; do
        requested="$(echo "$requested" | tr -d '[:space:]')"
        [ -z "$requested" ] && continue
        conflict=false
        if port_is_listening "$requested" || [ "$requested" = "$PORT" ]; then
            conflict=true
        fi
        if [ "$DECOY_ENABLED" = "true" ] && [ "$requested" = "$DECOY_PORT" ]; then
            conflict=true
        fi
        for port in "${resolved_honey[@]}"; do
            if [ "$requested" = "$port" ]; then
                conflict=true
            fi
        done

        if [ "$conflict" = "true" ]; then
            excluded_ports=("$PORT" "${honey_ports[@]}" "${resolved_honey[@]}")
            if [ "$DECOY_ENABLED" = "true" ]; then
                excluded_ports+=("$DECOY_PORT")
            fi
            selected="$(select_free_port_range 2323 2399 "${excluded_ports[@]}" || true)"
            if [ -z "$selected" ]; then
                err "No free Honey Port found in the range 2323-2399."
                return 1
            fi
            warn "Honey port $requested is unavailable. Switching launcher to port $selected."
            requested="$selected"
        fi
        resolved_honey+=("$requested")
    done

    if [ "${#resolved_honey[@]}" -gt 0 ]; then
        HONEYPORT_PORTS="$(IFS=,; echo "${resolved_honey[*]}")"
    fi
    export DECOY_PORT HONEYPORT_PORTS
}

# ── Colors ───────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

log()     { echo -e "${C}[Zabbix]${NC} $1" | tee -a "$LOG"; }
ok()      { echo -e "${G}[  OK  ]${NC} $1" | tee -a "$LOG"; }
warn()    { echo -e "${Y}[ WARN ]${NC} $1" | tee -a "$LOG"; }
err()     { echo -e "${R}[ERROR ]${NC} $1" | tee -a "$LOG"; }
step()    { echo -e "\n${B}${C}══ $1 ══${NC}" | tee -a "$LOG"; }

backend_env_value() {
    local key="$1" value
    [ -f "$BACKEND_DIR/.env" ] || return 0
    value=$(sed -n "s/^${key}=//p" "$BACKEND_DIR/.env" | tail -n 1)
    value="${value%$'\r'}"
    value="${value#\"}"; value="${value%\"}"
    value="${value#\'}"; value="${value%\'}"
    printf '%s' "$value"
}

start_local_ai() {
    local available_mib minimum_mib ai_port pid
    [ "$LOCAL_AI_ENABLED" = "true" ] || { warn "Local AI is disabled by LOCAL_AI_ENABLED."; return 0; }

    if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "http://127.0.0.1:${LOCAL_AI_PORT}/health" >/dev/null 2>&1; then
        ok "Local AI is already healthy on 127.0.0.1:${LOCAL_AI_PORT}."
        return 0
    fi

    if [ -f "$AI_PID_FILE" ]; then
        pid=$(cat "$AI_PID_FILE" 2>/dev/null || true)
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
            warn "Local AI process is already starting (PID $pid); SOC startup will continue."
            return 0
        fi
    fi

    if port_is_listening "$LOCAL_AI_PORT"; then
        warn "Local AI port $LOCAL_AI_PORT is occupied by another process; leaving it untouched."
        return 0
    fi
    if [ ! -x "$AI_DIR/llamafile-0.10.6" ] || [ ! -f "$AI_DIR/qwen3-4b-thinking-2507.Q4_K_M.gguf" ]; then
        warn "Bundled Local AI binary/model is missing; SOC will start with AI offline fallback."
        return 0
    fi

    minimum_mib="${LOCAL_AI_MIN_MEMORY_MIB:-1800}"
    [[ "$minimum_mib" =~ ^[0-9]+$ ]] || minimum_mib=1800
    available_mib=$(awk '/MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "$available_mib" -lt "$minimum_mib" ] && [ "${LOCAL_AI_FORCE_START:-false}" != "true" ]; then
        warn "Skipping model start: ${available_mib} MiB available, ${minimum_mib} MiB required. Set LOCAL_AI_FORCE_START=true to override."
        return 0
    fi

    log "Starting local Qwen model on 127.0.0.1:${LOCAL_AI_PORT}..."
    if LOCAL_AI_PORT="$LOCAL_AI_PORT" LOCAL_AI_MODEL="$LOCAL_AI_MODEL" "$DIR/start-ai.sh" >>"$LOG" 2>&1; then
        AI_STARTED_BY_LAUNCHER=true
        ok "Local AI launch requested; status will appear in Config after model load."
    else
        warn "Local AI failed to start; SOC will continue without model inference."
    fi
}

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo &>/dev/null; then
    SUDO="sudo"
else
    err "This launcher needs sudo for system packages. Install sudo or run it as root."
    exit 1
fi

echo "========================================" | tee "$LOG"
echo "  Zabbix SOC Dashboard — Kali Linux Launcher"  | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"
echo ""

# ── Operating system check ───────────────────────────────────
step "1/6 — Identity Verification"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    ok "Detected ${PRETTY_NAME:-${NAME:-Linux}}."
else
    warn "Could not detect the Linux distribution — proceeding."
fi

cd "$DIR" || { err "Cannot cd to $DIR"; exit 1; }

if [ ! -f "$BACKEND_DIR/package.json" ] || [ ! -f "$BACKEND_DIR/server.js" ]; then
    err "Backend files are missing from $BACKEND_DIR."
    exit 1
fi

LOCAL_AI_ENABLED="${LOCAL_AI_ENABLED:-$(backend_env_value LOCAL_AI_ENABLED)}"
LOCAL_AI_ENABLED="${LOCAL_AI_ENABLED:-true}"
LOCAL_AI_ENABLED="$(printf '%s' "$LOCAL_AI_ENABLED" | tr '[:upper:]' '[:lower:]')"
LOCAL_AI_URL="${LOCAL_AI_URL:-$(backend_env_value LOCAL_AI_URL)}"
LOCAL_AI_URL="${LOCAL_AI_URL:-http://127.0.0.1:8090}"
LOCAL_AI_MODEL="${LOCAL_AI_MODEL:-$(backend_env_value LOCAL_AI_MODEL)}"
LOCAL_AI_MODEL="${LOCAL_AI_MODEL:-soc-brain}"
LOCAL_AI_PORT="${LOCAL_AI_PORT:-${LOCAL_AI_URL##*:}}"
LOCAL_AI_PORT="${LOCAL_AI_PORT%%/*}"
if ! [[ "$LOCAL_AI_PORT" =~ ^[0-9]+$ ]]; then
    warn "Could not read a Local AI port from LOCAL_AI_URL; using 8090."
    LOCAL_AI_PORT=8090
fi
export LOCAL_AI_ENABLED LOCAL_AI_URL LOCAL_AI_MODEL LOCAL_AI_PORT

# Reuse an already running SOC backend instead of selecting another port and
# colliding with the backend's single-instance lock.
if command -v curl >/dev/null 2>&1; then
    for EXISTING_PORT in 3001 3002 3003 3004 3005 3006 3007 3008 3009 3010; do
        HEALTH_RESPONSE=$(curl -fsS --max-time 2 "http://127.0.0.1:${EXISTING_PORT}/api/health" 2>/dev/null || true)
        if [[ "$HEALTH_RESPONSE" == *'"message":"Backend is reachable"'* ]]; then
            PORT="$EXISTING_PORT"
            ok "Existing Zabbix SOC backend is healthy on port $PORT. Reusing it."
            start_local_ai
            ok "Dashboard URL: http://${LAN_IP}:${PORT}"
            if command -v xdg-open &>/dev/null; then
                xdg-open "http://${LAN_IP}:${PORT}" >/dev/null 2>&1 &
            fi
            exit 0
        fi
    done
fi

if [ ! -f "$BACKEND_DIR/.env" ]; then
    log "Creating default backend/.env..."
    cat > "$BACKEND_DIR/.env" <<'EOF'
PORT=3001
DB_PATH=./database.sqlite
API_KEY=CHANGE_ME
DECEPTION_FREEZE=false
MAX_ROTATIONS_PER_HOUR=10
APPLY_RESPONSE_POLICY=false
APPLY_API_ROTATION=false
APPLY_API_SCHEMA=false
SOC_TARGET_WATCHER=true
DECOY_INTEGRITY_WATCHER=true
ZABBIX_URL=
ZABBIX_USER=Admin
ZABBIX_PASS=zabbix
EOF
    ok "Created backend/.env. Zabbix remains optional; mock data will be used if it is offline."
fi

CONFIGURED_PORT=$(sed -n 's/^PORT=//p' "$BACKEND_DIR/.env" | tail -n 1)
if [[ "$CONFIGURED_PORT" =~ ^[0-9]+$ ]]; then
    PORT="$CONFIGURED_PORT"
fi

SELECTED_PORT=$(select_available_port || true)
if [ -n "$SELECTED_PORT" ] && [ "$SELECTED_PORT" != "$PORT" ]; then
    warn "Port $PORT is already in use. Switching launcher to port $SELECTED_PORT."
    PORT="$SELECTED_PORT"
fi

if [ -z "$SELECTED_PORT" ]; then
    err "No free port found in the expected range (3001-3010)."
    exit 1
fi

resolve_service_ports || exit 1

# ── Step 2: Ensure APT tools are available ───────────────────
step "2/6 — Checking System Requirements"

# Auto-install curl if missing (needed for health-check)
if ! command -v curl &>/dev/null; then
    log "curl not found — installing..."
    $SUDO apt-get update -qq && $SUDO apt-get install -y curl 2>>"$LOG" || \
    { err "Could not install curl. Check internet connection."; }
else
    ok "curl is available."
fi

# Auto-install wget if missing
if ! command -v wget &>/dev/null; then
    log "wget not found — installing..."
    $SUDO apt-get install -y wget 2>>"$LOG" || true
fi

# ── Step 3: Ensure Node.js is installed ──────────────────────
step "3/6 — Node.js Setup"

install_node() {
    log "Installing Node.js LTS via NodeSource..."
    $SUDO apt-get update -qq >>"$LOG" 2>&1

    # Try NodeSource 20.x LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO bash - >>"$LOG" 2>&1 && \
    $SUDO apt-get install -y nodejs >>"$LOG" 2>&1

    if command -v node &>/dev/null; then
        ok "Node.js $(node --version) installed via NodeSource."
        return 0
    fi

    # Fallback: try apt directly
    warn "NodeSource failed — trying apt..."
    $SUDO apt-get install -y nodejs npm >>"$LOG" 2>&1

    if command -v node &>/dev/null; then
        ok "Node.js $(node --version) installed via apt."
        return 0
    fi

    # Last resort: download binary directly
    warn "apt failed — downloading Node.js binary directly..."
    NODE_VER="v20.14.0"
    ARCH=$(uname -m)
    [ "$ARCH" = "x86_64" ] && NODE_ARCH="x64" || NODE_ARCH="arm64"
    NODE_TAR="node-${NODE_VER}-linux-${NODE_ARCH}.tar.xz"
    NODE_URL="https://nodejs.org/dist/${NODE_VER}/${NODE_TAR}"

    wget -q --show-progress "$NODE_URL" -O /tmp/$NODE_TAR >>"$LOG" 2>&1 && \
    $SUDO tar -xJf /tmp/$NODE_TAR -C /usr/local --strip-components=1 >>"$LOG" 2>&1 && \
    rm -f /tmp/$NODE_TAR

    if command -v node &>/dev/null; then
        ok "Node.js $(node --version) installed via binary."
        return 0
    fi

    err "FATAL: Could not install Node.js. Please connect to internet and retry."
    return 1
}

if command -v node &>/dev/null; then
    NODE_VER=$(node --version)
    ok "Node.js $NODE_VER already installed."
    # Check minimum version (need >= 14)
    NODE_MAJOR=$(echo "$NODE_VER" | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_MAJOR" -lt 14 ]; then
        warn "Node.js $NODE_VER is too old (need >= v14). Upgrading..."
        install_node || exit 1
    fi
else
    install_node || exit 1
fi

# Ensure npm is available
if ! command -v npm &>/dev/null; then
    log "npm not found — installing..."
    $SUDO apt-get install -y npm >>"$LOG" 2>&1 || true
fi
ok "npm $(npm --version 2>/dev/null || echo 'unknown') ready."

# ── Step 4: Install Build Tools (for sqlite3 native addon) ───
step "4/6 — Build Tools & Dependencies"

# build-essential is needed to compile sqlite3 native bindings
if ! dpkg -l build-essential &>/dev/null 2>&1; then
    log "Installing build-essential (required for sqlite3)..."
    $SUDO apt-get install -y build-essential python3 make g++ >>"$LOG" 2>&1 || true
    ok "Build tools installed."
else
    ok "Build tools already present."
fi

# libsqlite3-dev for native sqlite3 binding
if ! dpkg -l libsqlite3-dev &>/dev/null 2>&1; then
    log "Installing libsqlite3-dev..."
    $SUDO apt-get install -y libsqlite3-dev >>"$LOG" 2>&1 || true
fi

# ── Step 5: npm install (auto-download all packages) ─────────
step "5/6 — Installing Node.js Packages"

if [ ! -f "$BACKEND_DIR/package.json" ]; then
    err "package.json not found in $BACKEND_DIR — cannot install dependencies!"
    exit 1
fi

# Always run npm install if node_modules is missing or incomplete
NEEDS_INSTALL=false
if [ ! -d "$BACKEND_DIR/node_modules" ]; then
    log "node_modules missing — running npm install..."
    NEEDS_INSTALL=true
elif [ ! -d "$BACKEND_DIR/node_modules/express" ]; then
    log "node_modules incomplete — running npm install..."
    NEEDS_INSTALL=true
elif [ ! -d "$BACKEND_DIR/node_modules/sqlite3" ]; then
    log "sqlite3 module missing — running npm install..."
    NEEDS_INSTALL=true
fi

if [ "$NEEDS_INSTALL" = true ]; then
    # Set npm cache to writable location
    export npm_config_cache="/tmp/npm-cache-zabbix"
    mkdir -p "$npm_config_cache"

    log "Running: npm install in backend (this may take 2-5 minutes on first boot)..."
    cd "$BACKEND_DIR"
    npm install --omit=dev --no-audit --no-fund >>"$LOG" 2>&1

    if [ $? -ne 0 ]; then
        warn "npm install had errors — trying with --legacy-peer-deps..."
        npm install --omit=dev --legacy-peer-deps --no-audit --no-fund >>"$LOG" 2>&1
    fi

    if [ ! -d "$BACKEND_DIR/node_modules/express" ]; then
        err "npm install failed! Check $LOG for details."
        err "Possible causes: No internet, disk full, or broken package.json"
        exit 1
    fi
    ok "All npm packages installed successfully."
    cd "$DIR"
else
    ok "node_modules already complete. Skipping install."
fi

# ── Step 5.5: Check & Rebuild Native Bindings ─────────────────
log "Verifying native database bindings compatibility..."
if ! (cd "$BACKEND_DIR" && node -e "require('sqlite3')") &>/dev/null; then
    warn "sqlite3 native module is missing or incompatible. Rebuilding..."
    export npm_config_cache="/tmp/npm-cache-zabbix"
    mkdir -p "$npm_config_cache"
    
    cd "$BACKEND_DIR"
    # Try npm rebuild first
    npm rebuild sqlite3 >>"$LOG" 2>&1
    
    # If still failing, perform force clean install of sqlite3
    if ! node -e "require('sqlite3')" &>/dev/null; then
        warn "npm rebuild failed. Performing clean forced install of sqlite3..."
        npm install sqlite3 --omit=dev --no-audit --no-fund --force >>"$LOG" 2>&1
    fi
    
    # Final verification
    if node -e "require('sqlite3')" &>/dev/null; then
        ok "sqlite3 successfully rebuilt and configured!"
    else
        err "Failed to load sqlite3 after rebuild. Dashboard server might fail."
    fi
    cd "$DIR"
else
    ok "Database bindings verified."
fi


# ── Ensure database file exists and is writable ──────────────
touch "$BACKEND_DIR/database.sqlite" 2>/dev/null || true
chmod 664 "$BACKEND_DIR/database.sqlite" 2>/dev/null || true

# ── Step 6: Start Server & Open Browser ──────────────────────
step "6/6 — Starting Zabbix SOC Dashboard"

# Stop only a previous instance started by this launcher.
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        warn "Stopping previous Zabbix SOC process (PID $OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$PID_FILE"
fi

# If the backend was started manually outside this launcher, make sure the
# configured port is released before we try to start the app again.
PORT_PID=""
if command -v fuser &>/dev/null; then
    PORT_PID=$(fuser "$PORT/tcp" 2>/dev/null || true)
fi
if [ -z "$PORT_PID" ] && command -v lsof &>/dev/null; then
    PORT_PID=$(lsof -ti tcp:"$PORT" 2>/dev/null | head -n 1 || true)
fi
if [ -z "$PORT_PID" ] && command -v ss &>/dev/null; then
    PORT_PID=$(ss -ltnp "sport = :$PORT" 2>/dev/null | awk 'NR>1 {print $NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | head -n 1 || true)
fi

if [ -n "$PORT_PID" ]; then
    PROCESS_INFO=$(ps -p "$PORT_PID" -o args= 2>/dev/null | tr -d '\n' || true)
    if echo "$PROCESS_INFO" | grep -Eq 'node .*server\.js|server\.js' || echo "$PROCESS_INFO" | grep -Eq 'node.*backend'; then
        warn "Port $PORT is occupied by a stale Zabbix SOC backend (PID $PORT_PID). Clearing it..."
        kill "$PORT_PID" 2>/dev/null || true
        sleep 1
        if kill -0 "$PORT_PID" 2>/dev/null; then
            kill -9 "$PORT_PID" 2>/dev/null || true
        fi
    elif [ "$PORT" != "3001" ]; then
        warn "Port $PORT is already in use by another process. Retrying on the next free port."
    else
        warn "Port $PORT is already in use by another process. Falling back to the next free port."
    fi
fi

check_required_ports_are_free || exit 1
start_local_ai
log "Starting SOC + Honey Port + E-Commerce Decoy: dashboard=$PORT honey=$HONEYPORT_PORTS decoy=$DECOY_PORT"
cd "$BACKEND_DIR"
PORT="$PORT" LOCAL_AI_ENABLED="$LOCAL_AI_ENABLED" LOCAL_AI_URL="$LOCAL_AI_URL" LOCAL_AI_MODEL="$LOCAL_AI_MODEL" DECOY_ENABLED="$DECOY_ENABLED" DECOY_PORT="$DECOY_PORT" HONEYPORT_PORTS="$HONEYPORT_PORTS" DECEPTION_FREEZE="$DECEPTION_FREEZE" MAX_ROTATIONS_PER_HOUR="$MAX_ROTATIONS_PER_HOUR" node server.js >> "$LOG" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

cleanup() {
    STOPPING=true
    trap - INT TERM EXIT
    if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ "$AI_STARTED_BY_LAUNCHER" = true ]; then
        "$DIR/stop-ai.sh" >>"$LOG" 2>&1 || true
    fi
    rm -f "$PID_FILE"
}
trap cleanup INT TERM EXIT

# Wait for server to be ready
log "Waiting for server on http://127.0.0.1:${PORT} ..."
COUNT=0
MAX=60
READY=false
while [ $COUNT -lt $MAX ]; do
    DASHBOARD_READY=false
    DECOY_READY=true
    HONEY_READY=false
    if curl -sf --max-time 2 "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then DASHBOARD_READY=true; fi
    if [ "$DECOY_ENABLED" = "true" ] && curl -sf --max-time 2 "http://127.0.0.1:${DECOY_PORT}/api/decoy/status" >/dev/null 2>&1; then DECOY_READY=true; elif [ "$DECOY_ENABLED" = "true" ]; then DECOY_READY=false; fi
    HONEY_READY=true
    IFS=',' read -r -a HONEY_PORT_LIST <<< "$HONEYPORT_PORTS"
    for HONEY_PORT in "${HONEY_PORT_LIST[@]}"; do
        HONEY_PORT="$(echo "$HONEY_PORT" | tr -d '[:space:]')"
        [ -z "$HONEY_PORT" ] && continue
        if ! port_is_listening "$HONEY_PORT"; then HONEY_READY=false; break; fi
    done
    if [ "$DASHBOARD_READY" = true ] && [ "$DECOY_READY" = true ] && [ "$HONEY_READY" = true ]; then
        READY=true
        break
    fi
    # Also check if process died
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        err "Server process died! Last 20 lines of log:"
        tail -20 "$LOG"
        exit 1
    fi
    echo -n "."
    sleep 1
    COUNT=$((COUNT+1))
done
echo ""

if [ "$READY" = true ]; then
    ok "════════════════════════════════════════"
    ok "  Zabbix SOC Dashboard is LIVE!"
    ok "  URL: http://${LAN_IP}:${PORT}"
    ok "  Log: $LOG"
    ok "════════════════════════════════════════"

    # Open the default browser without assuming X11 or Firefox.
    log "Opening dashboard in the default browser..."
    if command -v xdg-open &>/dev/null; then
        xdg-open "http://${LAN_IP}:${PORT}" >/dev/null 2>&1 &
    elif command -v firefox-esr &>/dev/null; then
        firefox-esr "http://${LAN_IP}:${PORT}" >/dev/null 2>&1 &
    elif command -v firefox &>/dev/null; then
        firefox "http://${LAN_IP}:${PORT}" >/dev/null 2>&1 &
    else
        warn "No browser found. Open manually: http://${LAN_IP}:${PORT}"
    fi

    # Show desktop notification
    notify-send "Zabbix SOC" "Dashboard is ready! http://${LAN_IP}:${PORT}" \
        -i dialog-information 2>/dev/null || true

    # Keep running & monitor the server process
    log "Server running (PID $SERVER_PID). Press Ctrl+C to stop."
    wait $SERVER_PID
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ] && [ "$STOPPING" != true ]; then
        err "Server exited with code $EXIT_CODE. Check $LOG"
    fi
else
    err "Server did not respond after ${MAX} seconds."
    err "Last 30 lines of log:"
    tail -30 "$LOG"
    cleanup
    exit 1
fi
