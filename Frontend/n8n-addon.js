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
      { id: 'ssh', name: 'SSH Brute Force', icon: '🔐', fix: 'Source IP blocked at firewall' },
      { id: 'sqli', name: 'SQL Injection Pattern', icon: '🧪', fix: 'WAF rule applied and IP rate-limited' },
      { id: 'malware', name: 'Known Malware Hash', icon: '☣', fix: 'Endpoint isolated for investigation' },
      { id: 'honeyport', name: 'Honeyport Probe', icon: '◉', fix: 'Probe recorded and threat score raised' },
      { id: 'ransomware', name: 'Ransomware Behaviour', icon: '⚠', fix: 'Host contained and recovery started' }
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

    injectIpBlockCard();
  }

  function injectIpBlockCard() {
    if (document.getElementById('attackerIpConfig')) return;
    const configGrid = document.querySelector('.config-grid');
    if (!configGrid) return;

    const card = document.createElement('section');
    card.className = 'config-card ip-block-card';
    card.id = 'attackerIpConfig';
    card.innerHTML = `
      <div class="config-card-title">Attacker IP Controls</div>
      <div class="config-status" aria-live="polite">
        <div class="cs-dot cs-warn" id="ipBlockStatusDot"></div>
        <span class="cs-txt" id="ipBlockStatus">Loading attacker IPs...</span>
      </div>
      <form class="ip-block-form" id="ipBlockForm">
        <div class="form-row">
          <label for="manualBlockIp">IP address</label>
          <input type="text" id="manualBlockIp" name="ip" placeholder="203.0.113.10" autocomplete="off" required>
        </div>
        <div class="form-row">
          <label for="manualBlockReason">Reason</label>
          <input type="text" id="manualBlockReason" name="reason" placeholder="Manual SOC block">
        </div>
        <div class="ip-form-actions">
          <button type="submit" class="ip-form-action is-block">Block IP</button>
          <button type="button" class="ip-form-action is-unblock" id="unblockManualIp">Unblock IP</button>
          <button type="reset" class="ip-form-action is-clear">Clear</button>
          <button type="button" class="ip-refresh-btn" id="refreshAttackerIps" title="Refresh attacker list" aria-label="Refresh attacker list">↻</button>
        </div>
      </form>
      <div class="ip-block-table-wrap">
        <table class="ip-block-table">
          <thead><tr><th>IP address</th><th>Hits</th><th>Last seen</th><th>Attack</th><th>State</th><th>Action</th></tr></thead>
          <tbody id="attackerIpRows"><tr><td colspan="6">Waiting for backend data</td></tr></tbody>
        </table>
      </div>
    `;
    configGrid.appendChild(card);

    const statusText = card.querySelector('#ipBlockStatus');
    const statusDot = card.querySelector('#ipBlockStatusDot');
    const rows = card.querySelector('#attackerIpRows');
    const setStatus = (message, state = 'warn') => {
      statusText.textContent = message;
      statusDot.className = `cs-dot cs-${state}`;
    };

    async function loadAttackerIps() {
      const apiUrl = window.CONFIG?.apiUrl;
      if (!apiUrl) return setStatus('Backend configuration is unavailable.', 'err');
      try {
        const options = { credentials: 'include', headers: { Accept: 'application/json' }, cache: 'no-store' };
        const [attackerResponse, blockResponse] = await Promise.all([
          fetch(`${apiUrl}/security/attackers?all=true`, options),
          fetch(`${apiUrl}/security/blocks`, options),
        ]);
        if (!attackerResponse.ok || !blockResponse.ok) {
          const response = !attackerResponse.ok ? attackerResponse : blockResponse;
          const detail = await response.json().catch(() => ({}));
          throw new Error(detail.error || (response.status === 401 ? 'Sign in to manage IP blocks.' : 'Unable to load IP controls.'));
        }

        const attackerData = await attackerResponse.json();
        const blockData = await blockResponse.json();
        const attackers = attackerData.attackers || [];
        const activeBlocks = new Map((blockData.active || []).map(block => [block.ip, block]));
        const combined = new Map(attackers.map(attacker => [attacker.ip, attacker]));
        activeBlocks.forEach((block, ip) => {
          if (!combined.has(ip)) combined.set(ip, { ip, hits: 0, attackType: block.reason || 'Manual block' });
        });
        const sorted = [...combined.values()].sort((left, right) => Number(right.hits || 0) - Number(left.hits || 0));
        rows.replaceChildren();

        if (!sorted.length) {
          const emptyRow = document.createElement('tr');
          const emptyCell = document.createElement('td');
          emptyCell.colSpan = 6;
          emptyCell.textContent = 'No attacker IPs recorded.';
          emptyRow.appendChild(emptyCell);
          rows.appendChild(emptyRow);
        }

        sorted.forEach(attacker => {
          const block = activeBlocks.get(attacker.ip);
          const row = document.createElement('tr');
          const values = [
            attacker.ip,
            String(attacker.hits || 0),
            attacker.lastSeen ? new Date(attacker.lastSeen).toLocaleString() : '—',
            attacker.attackType || 'Unknown',
            block ? `Blocked (${block.mode || 'active'})` : 'Allowed',
          ];
          values.forEach(value => {
            const cell = document.createElement('td');
            cell.textContent = value;
            row.appendChild(cell);
          });
          const actionCell = document.createElement('td');
          const actionButton = document.createElement('button');
          actionButton.type = 'button';
          actionButton.className = block ? 'ip-action-btn is-unblock' : 'ip-action-btn';
          actionButton.textContent = block ? 'Unblock' : 'Block';
          actionButton.addEventListener('click', () => changeIpBlock(attacker.ip, block ? 'unblock' : 'block', block?.reason || 'Manual block'));
          actionCell.appendChild(actionButton);
          row.appendChild(actionCell);
          rows.appendChild(row);
        });
        setStatus(`${sorted.length} attacker or blocked IP address(es)`, 'ok');
      } catch (error) {
        rows.replaceChildren();
        setStatus(error.message, 'err');
      }
    }

    async function changeIpBlock(ip, action, reason) {
      try {
        const response = await fetch(`${window.CONFIG.apiUrl}/security/blocks`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ ip, action, reason }),
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok || !result.success) throw new Error(result.error || `Could not ${action} ${ip}.`);
        setStatus(`${ip} ${action === 'block' ? 'blocked until manually unblocked.' : 'unblocked.'}`, 'ok');
        await loadAttackerIps();
      } catch (error) {
        setStatus(error.message, 'err');
      }
    }

    card.querySelector('#ipBlockForm').addEventListener('submit', event => {
      event.preventDefault();
      const ip = card.querySelector('#manualBlockIp').value.trim();
      const reason = card.querySelector('#manualBlockReason').value.trim() || 'Manual block';
      changeIpBlock(ip, 'block', reason);
    });
    card.querySelector('#unblockManualIp').addEventListener('click', () => {
      const ip = card.querySelector('#manualBlockIp').value.trim();
      const reason = card.querySelector('#manualBlockReason').value.trim() || 'Manual unblock';
      if (!ip) return setStatus('Enter an IP address to unblock.', 'err');
      changeIpBlock(ip, 'unblock', reason);
    });
    card.querySelector('#refreshAttackerIps').addEventListener('click', loadAttackerIps);
    document.querySelector('button[onclick*="config"]')?.addEventListener('click', loadAttackerIps);
    loadAttackerIps();
    setInterval(() => {
      if (document.getElementById('configTab')?.classList.contains('active')) loadAttackerIps();
    }, 30000);
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

            <!-- Node 2: Normalization -->
            <div class="n8n-node" data-type="function" id="node-analyze">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">🧠</div>
                <div class="n8n-node-title">Normalize</div>
              </div>
              <div class="n8n-node-status" id="status-analyze">Idle</div>
            </div>

            <!-- Node 3: Enrichment -->
            <div class="n8n-node" data-type="action" id="node-fix">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">🛠️</div>
                <div class="n8n-node-title">Enrichment</div>
              </div>
              <div class="n8n-node-status" id="status-fix">Idle</div>
            </div>

            <!-- Node 4: Triage -->
            <div class="n8n-node" data-type="function" id="node-triage">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">⚖</div>
                <div class="n8n-node-title">Triage / IR</div>
              </div>
              <div class="n8n-node-status" id="status-triage">Idle</div>
            </div>

            <!-- Node 5: Containment -->
            <div class="n8n-node" data-type="action" id="node-contain">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">🛡</div>
                <div class="n8n-node-title">Containment</div>
              </div>
              <div class="n8n-node-status" id="status-contain">Idle</div>
            </div>

            <!-- Node 6: Notification -->
            <div class="n8n-node" data-type="action" id="node-notify">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">📣</div>
                <div class="n8n-node-title">Notify</div>
              </div>
              <div class="n8n-node-status" id="status-notify">Idle</div>
            </div>

            <!-- Node 7: Evidence -->
            <div class="n8n-node" data-type="output" id="node-resolve">
              <div class="pulse"></div>
              <div class="n8n-node-header">
                <div class="n8n-node-icon">✅</div>
                <div class="n8n-node-title">Evidence / Close</div>
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

    const issue = N8N_CONFIG.issueTypes[0] || { id: 'UNCONFIGURED', name: 'Not configured', fix: 'Configure n8n' };
    currentIssue = issue;

    const steps = [
      ['detect', issue.name, 'Security event received', 'error'],
      ['analyze', 'Normalizing event...', 'Event normalized and severity mapped', 'highlight'],
      ['fix', 'Enriching indicators...', `Threat score calculated for ${issue.id}`, 'highlight'],
      ['triage', 'Creating IR case...', 'Incident stage set to Investigated', 'warning'],
      ['contain', 'Applying containment...', `Action: ${issue.fix}`, 'warning'],
      ['notify', 'Escalating...', 'SOC channels notified', 'highlight'],
      ['resolve', 'Evidence recorded', `Incident ${issue.id} closed`, 'success']
    ];
    for (let i = 0; i < steps.length; i++) {
      const [id, activeStatus, message, logType] = steps[i];
      addLog(message, logType);
      updateNode(id, activeStatus, true);
      setArrowActive(i, true);
      await wait(N8N_CONFIG.stepDuration);
      updateNode(id, id === 'resolve' ? 'Resolved' : 'Complete', false);
    }
    
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
    updateNode('triage', 'Idle');
    updateNode('contain', 'Idle');
    updateNode('notify', 'Idle');
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

    const nodes = Array.from(document.querySelectorAll('.n8n-node'));

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
