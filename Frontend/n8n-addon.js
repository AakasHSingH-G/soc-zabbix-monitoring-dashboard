/**
 * n8n Automation Add-On for Zabbix SOC Dashboard
 * Modular, non-intrusive plugin.
 */

(function() {
  console.log("n8n Automation Add-On Initializing...");

  // ── CONFIGURATION ──
  const N8N_CONFIG = {
    simulationInterval: 5000, // 5 seconds
    stepDuration: 1200,      // Time between steps
    issueTypes: [
      { id: 'cpu', name: 'CPU Spike Detected', icon: '⚡', fix: 'Process Optimization Applied' },
      { id: 'server', name: 'Server Down (ICMP Fail)', icon: '🖥️', fix: 'Service Restart Initiated' },
      { id: 'api', name: 'API Failure (5xx Spike)', icon: '🌐', fix: 'Traffic Rerouted / Cache Cleared' },
      { id: 'disk', name: 'Disk Space Critical', icon: '💾', fix: 'Log Purge & Cleanup Task' },
      { id: 'security', name: 'Brute Force Attempt', icon: '🛡️', fix: 'IP Blacklisted via Firewall' }
    ]
  };

  let executionHistory = [];
  let currentIssue = null;
  let isExecuting = false;
  let totalResolved = 0;
  let startTime = Date.now();
  let simIntervalId = null;

  // ── DOM INJECTION ──
  function injectStyles() {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'n8n-addon.css';
    document.head.appendChild(link);
  }

  function injectConfigCard() {
    const configGrid = document.querySelector('.config-grid');
    if (!configGrid) return;

    const card = document.createElement('div');
    card.className = 'config-card';
    card.innerHTML = `
      <div class="config-card-title"><span class="n8n-config-id">🔀</span> n8n Automation Settings <span class="n8n-badge-new">NEW</span></div>
      <div class="config-status">
        <div class="cs-dot cs-ok"></div><span class="cs-txt">Simulation Engine Active</span>
      </div>
      <div class="form-row">
        <label>Simulation Speed</label>
        <select id="n8nCfgSpeed">
          <option value="10000">Slow (10s intervals)</option>
          <option value="5000" selected>Normal (5s intervals)</option>
          <option value="2000">Fast (2s intervals)</option>
        </select>
      </div>
      <div class="form-row">
        <label>History Management</label>
        <button class="btn btn-secondary btn-sm" id="n8nClearHistory">Reset All Stats</button>
      </div>
      <div class="admin-notice" style="margin-bottom:0; padding:12px; font-size:11px;">
        Modular Add-on v1.0.0 is running in independent mode.
      </div>
    `;
    configGrid.appendChild(card);

    document.getElementById('n8nCfgSpeed').addEventListener('change', (e) => {
      N8N_CONFIG.simulationInterval = parseInt(e.target.value);
      restartSimulation();
      addLog(`Simulation interval updated to ${N8N_CONFIG.simulationInterval/1000}s`, 'highlight');
    });

    document.getElementById('n8nClearHistory').addEventListener('click', () => {
      totalResolved = 0;
      executionHistory = [];
      document.getElementById('n8nHistoryList').innerHTML = '';
      updateStats();
      addLog('Simulation statistics reset.', 'warning');
    });
  }

  function injectTab() {
    if (document.getElementById('n8nNavBtn')) return; // Prevent duplicate injection

    const navTabs = document.querySelector('.nav-tabs');
    const mainContent = document.getElementById('mainContent');

    if (!navTabs || !mainContent) {
      console.error("n8n Add-On: Could not find dashboard elements for injection.");
      return;
    }

    // Add Nav Tab
    const tabBtn = document.createElement('button');
    tabBtn.className = 'nav-tab';
    tabBtn.id = 'n8nNavBtn';
    tabBtn.innerHTML = '🔀 n8n Automation';
    tabBtn.onclick = function() {
      // Use existing global function to clear others
      if (typeof window.switchMainTab === 'function') {
        window.switchMainTab('n8nAutomation', this);
      }
      
      // Since window.switchMainTab uses a hardcoded map, we MUST manually activate our content
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
      
      const ourContent = document.getElementById('n8nAutomationTab');
      if (ourContent) {
        ourContent.classList.add('active');
        this.classList.add('active');
      }
      
      // Recalculate arrows once visible
      setTimeout(drawArrows, 50);
    };

    // Find the Config tab button (exact match by onclick)
    const configTab = document.querySelector('button[onclick*="\'config\'"]');
    if (configTab) {
      navTabs.insertBefore(tabBtn, configTab);
    } else {
      navTabs.appendChild(tabBtn);
    }

    // Add Tab Content
    const tabContent = document.createElement('div');
    tabContent.id = 'n8nAutomationTab';
    tabContent.className = 'tab-content';
    tabContent.innerHTML = `
      <div class="n8n-stat-bar">
        <div class="n8n-stat">
          <span class="n8n-stat-label">Automation Status</span>
          <span class="n8n-stat-value" style="color:var(--accent-green)">ACTIVE</span>
        </div>
        <div class="n8n-stat">
          <span class="n8n-stat-label">Total Resolved</span>
          <span class="n8n-stat-value" id="n8nTotalResolved">0</span>
        </div>
        <div class="n8n-stat">
          <span class="n8n-stat-label">Uptime</span>
          <span class="n8n-stat-value" id="n8nUptime">00:00</span>
        </div>
      </div>
      <div class="n8n-layout">
        <div class="n8n-canvas">
          <!-- Connectors Layer -->
          <svg class="n8n-connector-layer" id="n8nConnectors"></svg>
          
          <div class="n8n-nodes-container">
            <!-- Node 1: Detection -->
            <div class="n8n-node" data-type="trigger" id="node-detect">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">📡</div>
                <div class="n8n-node-title">Detection</div>
              </div>
              <div class="n8n-node-status" id="status-detect">Waiting...</div>
            </div>

            <!-- Node 2: Analysis -->
            <div class="n8n-node" data-type="function" id="node-analyze">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">🧠</div>
                <div class="n8n-node-title">Analysis</div>
              </div>
              <div class="n8n-node-status" id="status-analyze">Idle</div>
            </div>

            <!-- Node 3: Fix -->
            <div class="n8n-node" data-type="action" id="node-fix">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">🛠️</div>
                <div class="n8n-node-title">Fix</div>
              </div>
              <div class="n8n-node-status" id="status-fix">Idle</div>
            </div>

            <!-- Node 4: Resolution -->
            <div class="n8n-node" data-type="output" id="node-resolve">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">✅</div>
                <div class="n8n-node-title">Resolution</div>
              </div>
              <div class="n8n-node-status" id="status-resolve">Stable</div>
            </div>
          </div>
        </div>

        <div class="n8n-log-panel">
          <div class="n8n-log-header">
            <div class="n8n-log-title">Live Automation logs</div>
            <div class="l-dot"></div>
          </div>
          <div class="n8n-log-list" id="n8nLogList">
            <div class="n8n-log-entry">
              <div class="n8n-log-time">${new Date().toLocaleTimeString()}</div>
              <div class="n8n-log-msg">System initialized. Awaiting triggers...</div>
            </div>
          </div>
          <div class="n8n-history">
            <div class="n8n-history-title">Recent Resolutions</div>
            <div id="n8nHistoryList"></div>
          </div>
        </div>
      </div>
    `;
    mainContent.appendChild(tabContent);
    
    // Draw SVG Arrows
    setTimeout(drawArrows, 100);
  }

  // ── LOGIC ──
  function addLog(msg, type = '') {
    const list = document.getElementById('n8nLogList');
    if (!list) return;
    
    const entry = document.createElement('div');
    entry.className = 'n8n-log-entry';
    entry.innerHTML = `
      <div class="n8n-log-time">${new Date().toLocaleTimeString()}</div>
      <div class="n8n-log-msg ${type}">${msg}</div>
    `;
    list.prepend(entry);
    
    // Keep only last 20 logs
    if (list.children.length > 20) list.lastChild.remove();
  }

  function updateNode(id, status, active = false) {
    const node = document.getElementById(`node-${id}`);
    const statusText = document.getElementById(`status-${id}`);
    if (!node || !statusText) return;

    statusText.textContent = status;
    if (active) {
      node.classList.add('active');
    } else {
      node.classList.remove('active');
    }
  }

  async function runWorkflow() {
    if (isExecuting) return;
    isExecuting = true;

    // Pick a random issue
    const issue = N8N_CONFIG.issueTypes[Math.floor(Math.random() * N8N_CONFIG.issueTypes.length)];
    currentIssue = issue;

    // Step 1: Detect
    addLog(`Issue detected: ${issue.name}`, 'error');
    updateNode('detect', issue.name, true);
    setArrowActive(0, true);
    
    await wait(N8N_CONFIG.stepDuration);
    updateNode('detect', 'Detected', false);
    
    // Step 2: Analyze
    updateNode('analyze', 'Analyzing root cause...', true);
    addLog(`Analyzing ${issue.id} incident...`, 'highlight');
    setArrowActive(1, true);

    await wait(N8N_CONFIG.stepDuration);
    updateNode('analyze', 'Root cause found', false);

    // Step 3: Fix
    updateNode('fix', 'Applying fix...', true);
    addLog(`Action: ${issue.fix}`, 'warning');
    setArrowActive(2, true);

    await wait(N8N_CONFIG.stepDuration);
    updateNode('fix', 'Fix applied', false);

    // Step 4: Resolve
    updateNode('resolve', 'Resolved ✅', true);
    addLog(`System stabilized. ${issue.id} cleared.`, 'success');
    
    // Add to history
    addToHistory(issue);

    await wait(N8N_CONFIG.stepDuration);
    resetWorkflow();
    isExecuting = false;
  }

  function updateStats() {
    const elResolved = document.getElementById('n8nTotalResolved');
    const elUptime = document.getElementById('n8nUptime');
    
    if (elResolved) elResolved.textContent = totalResolved;
    
    if (elUptime) {
      const diff = Math.floor((Date.now() - startTime) / 1000);
      const m = Math.floor(diff / 60).toString().padStart(2, '0');
      const s = (diff % 60).toString().padStart(2, '0');
      elUptime.textContent = `${m}:${s}`;
    }
  }

  function restartSimulation() {
    if (simIntervalId) clearInterval(simIntervalId);
    simIntervalId = setInterval(() => {
      if (!isExecuting) runWorkflow();
    }, N8N_CONFIG.simulationInterval);
  }

  function resetWorkflow() {
    updateNode('detect', 'Waiting...');
    updateNode('analyze', 'Idle');
    updateNode('fix', 'Idle');
    updateNode('resolve', 'Stable');
    document.querySelectorAll('.n8n-node').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.n8n-arrow').forEach(a => a.classList.remove('active'));
  }

  function addToHistory(issue) {
    totalResolved++;
    updateStats();
    
    const historyList = document.getElementById('n8nHistoryList');
    if (!historyList) return;

    const item = document.createElement('div');
    item.className = 'n8n-history-item';
    item.innerHTML = `
      <span>${issue.name}</span>
      <span class="n8n-history-status">RESOLVED</span>
    `;
    historyList.prepend(item);

    if (historyList.children.length > 5) historyList.lastChild.remove();
  }

  function setArrowActive(index, active) {
    const arrows = document.querySelectorAll('.n8n-arrow');
    if (arrows[index]) {
      if (active) arrows[index].classList.add('active');
      else arrows[index].classList.remove('active');
    }
  }

  function drawArrows() {
    const svg = document.getElementById('n8nConnectors');
    if (!svg) return;

    const nodes = [
      document.getElementById('node-detect'),
      document.getElementById('node-analyze'),
      document.getElementById('node-fix'),
      document.getElementById('node-resolve')
    ];

    svg.innerHTML = ''; // Clear

    for (let i = 0; i < nodes.length - 1; i++) {
      const start = nodes[i];
      const end = nodes[i+1];
      
      const startRect = start.getBoundingClientRect();
      const endRect = end.getBoundingClientRect();
      const canvasRect = svg.getBoundingClientRect();

      const x1 = (startRect.right - canvasRect.left);
      const y1 = (startRect.top + startRect.height / 2 - canvasRect.top);
      const x2 = (endRect.left - canvasRect.left);
      const y2 = (endRect.top + endRect.height / 2 - canvasRect.top);

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      // Simple quadratic curve for that n8n look
      const midX = (x1 + x2) / 2;
      path.setAttribute('d', `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`);
      path.setAttribute('class', 'n8n-arrow');
      svg.appendChild(path);
    }
  }

  function wait(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

  // ── INITIALIZE ──
  function init() {
    injectStyles();
    injectTab();
    injectConfigCard();
    
    // Start interval
    restartSimulation();

    // Start stats updater
    setInterval(updateStats, 1000);

    // Redraw arrows on resize
    window.addEventListener('resize', drawArrows);
  }

  // Run when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
