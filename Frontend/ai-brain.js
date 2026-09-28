(function() {
  const SETTING_LABELS = {
    ai_analysis: 'Attacker and incident analysis',
    ai_chat: 'Ask the Brain (fixed intents)',
    ai_auto_analyze: 'Live triage for HIGH/CRIT incidents (planned)',
    ai_learning: 'Learn from observed outcomes',
    ai_reports: 'Nightly reports (planned)',
    ai_telegram_enrich: 'Telegram follow-up insights (planned)',
    ai_block_dryrun: 'Dry-run (policy gate planned)',
    ai_priority_pause: 'Pause background work during attack bursts (planned)',
  };
  const BOOLEAN_KEYS = Object.keys(SETTING_LABELS);
  const IMPLEMENTED_FEATURES = new Set(['ai_analysis', 'ai_chat', 'ai_learning']);
  const NUMBER_LABELS = {
    ai_timeout_sec: ['Timeout', 'seconds'],
    ai_max_tokens: ['Maximum tokens', 'tokens'],
    ai_queue_max: ['Queue limit', 'jobs'],
  };
  let status = null;
  let settings = null;
  let loading = false;
  let activeJobId = null;
  let activeJobStartedAt = 0;
  let pollTimer = null;

  function injectStyles() {
    if (document.getElementById('aibStyles')) return;
    const link = document.createElement('link');
    link.id = 'aibStyles';
    link.rel = 'stylesheet';
    link.href = 'ai-brain.css';
    document.head.appendChild(link);
  }

  function request(path, options = {}) {
    return fetch(`${window.CONFIG.apiUrl}${path}`, {
      credentials: 'include',
      cache: 'no-store',
      headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
      ...options,
    });
  }

  function isAdmin() {
    return document.getElementById('hUserRole')?.textContent.trim().toLowerCase() === 'admin';
  }

  function setStatus(message, state = 'loading') {
    const target = document.getElementById('aibConfigStatus');
    const brainTarget = document.getElementById('aibBrainStatus');
    [target, brainTarget].filter(Boolean).forEach(element => {
      element.textContent = message;
      element.dataset.state = state;
    });
  }

  function injectConfigCard() {
    const grid = document.querySelector('#configTab .config-grid');
    if (!grid || document.getElementById('aibConfigCard')) return;

    const card = document.createElement('section');
    card.className = 'config-card aib-card';
    card.id = 'aibConfigCard';
    card.innerHTML = `
      <header class="aib-card-header">
        <div><div class="aib-eyebrow">Local AI Brain</div><div class="aib-status-line" id="aibConfigStatus" aria-live="polite">Checking AI module...</div></div>
        <label class="aib-master-control" title="Master AI enable/disable switch">
          <input id="aibMasterSwitch" type="checkbox" disabled>
          <span>AI Active</span>
        </label>
      </header>
      <div class="aib-provider-row">
        <span id="aibProviderStatus">Provider: unknown</span>
        <span id="aibModelName">Model: unknown</span>
        <span id="aibLatency">Latency: --</span>
        <span id="aibQueueStatus">Queue: --</span>
        <button type="button" class="aib-button aib-secondary" id="aibTestNow">Test now</button>
      </div>
      <fieldset class="aib-fieldset" id="aibFeatureSettings">
        <legend>Features</legend>
        <div class="aib-feature-grid" id="aibFeatureGrid"></div>
      </fieldset>
      <fieldset class="aib-fieldset" id="aibPolicySettings">
        <legend>IP block control</legend>
        <div class="aib-inline-fields">
          <label>Mode <select id="aibBlockMode"><option value="off">Off</option><option value="suggest">Suggest</option><option value="auto_temp">Auto temporary</option></select></label>
          <label class="aib-check"><input id="aibDryRun" type="checkbox"> Dry-run</label>
        </div>
        <p class="aib-warning" id="aibAutoBlockWarning">AI block actions are not available in this phase. The policy gate is not wired; existing manual SOC block controls are unchanged.</p>
      </fieldset>
      <fieldset class="aib-fieldset" id="aibLimitsSettings">
        <legend>Limits</legend>
        <div class="aib-inline-fields" id="aibNumberGrid"></div>
      </fieldset>
      <footer class="aib-card-footer">
        <span class="aib-readonly-note" id="aibRoleNote"></span>
        <div class="aib-actions">
          <button type="button" class="aib-button aib-primary" id="aibSaveSettings" disabled>Save</button>
          <button type="button" class="aib-button aib-secondary" id="aibOpenBrain">Open AI Brain tab</button>
        </div>
      </footer>
      <p class="aib-disclaimer">AI is advisory. Analyst review is required. Local endpoint and model are configured in backend environment variables.</p>
    `;

    const featureGrid = card.querySelector('#aibFeatureGrid');
    BOOLEAN_KEYS.forEach(key => {
      const label = document.createElement('label');
      label.className = 'aib-check';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.dataset.setting = key;
      input.disabled = !IMPLEMENTED_FEATURES.has(key);
      const text = document.createElement('span');
      text.textContent = SETTING_LABELS[key];
      label.append(input, text);
      featureGrid.appendChild(label);
    });

    const numberGrid = card.querySelector('#aibNumberGrid');
    Object.entries(NUMBER_LABELS).forEach(([key, [labelText, units]]) => {
      const label = document.createElement('label');
      label.className = 'aib-number-field';
      const text = document.createElement('span');
      text.textContent = labelText;
      const input = document.createElement('input');
      input.type = 'number';
      input.dataset.setting = key;
      input.min = key === 'ai_timeout_sec' ? '10' : key === 'ai_max_tokens' ? '128' : '1';
      input.max = key === 'ai_timeout_sec' ? '600' : key === 'ai_max_tokens' ? '6000' : '20';
      input.title = units;
      input.disabled = true;
      label.append(text, input);
      numberGrid.appendChild(label);
    });

    grid.appendChild(card);
    card.querySelector('#aibMasterSwitch').addEventListener('change', () => card.querySelector('#aibSaveSettings').disabled = false);
    card.querySelectorAll('[data-setting], #aibBlockMode').forEach(input => {
      input.addEventListener('change', () => card.querySelector('#aibSaveSettings').disabled = false);
    });
    card.querySelector('#aibSaveSettings').addEventListener('click', saveSettings);
    card.querySelector('#aibTestNow').addEventListener('click', loadStatus);
    card.querySelector('#aibOpenBrain').addEventListener('click', () => window.switchMainTab?.('ai_brain', document.getElementById('aibBrainNav'), null));
    document.querySelector('button[onclick*="config"]')?.addEventListener('click', refresh);
    card.querySelector('#aibBlockMode').addEventListener('change', updateBlockWarning);
    updateRoleState();
  }

  function injectBrainTab() {
    const nav = document.querySelector('.nav-tabs');
    const content = document.getElementById('mainContent');
    if (!nav || !content) return;

    let button = nav.querySelector('button[onclick*="ai_brain"]');
    if (!button) {
      button = document.createElement('button');
      button.type = 'button';
      button.className = 'nav-tab aib-nav-tab';
      button.textContent = 'AI Brain';
      button.addEventListener('click', event => window.switchMainTab?.('ai_brain', button, event));
      const configNav = document.querySelector('button[onclick*="\'config\'"]');
      nav.insertBefore(button, configNav?.nextSibling || null);
    }
    button.id = 'aibBrainNav';

    let panel = document.getElementById('aiBrainTab');
    if (!panel) {
      panel = document.createElement('section');
      panel.className = 'tab-content scroll-tab aib-brain-tab';
      panel.id = 'aiBrainTab';
      content.appendChild(panel);
    }
    panel.classList.add('aib-brain-tab');
    if (!panel.querySelector('#aibBrainStatus')) panel.innerHTML = `
      <div class="aib-brain-header">
        <div><div class="aib-eyebrow">Local reasoning service</div><h2>AI Brain</h2><p id="aibBrainStatus" aria-live="polite">Checking AI module...</p></div>
        <button type="button" class="aib-button aib-secondary" id="aibBrainRefresh">Refresh status</button>
      </div>
      <section class="aib-analysis-panel">
        <form class="aib-analysis-form" id="aibAnalyzeForm">
          <label for="aibAttackerIp">Attacker IP</label>
          <input id="aibAttackerIp" type="text" inputmode="text" placeholder="203.0.113.10" autocomplete="off" required>
          <button type="submit" class="aib-button aib-primary" id="aibAnalyzeButton">Analyze attacker</button>
        </form>
        <form class="aib-analysis-form" id="aibAskForm">
          <label for="aibAskQuestion">Ask the Brain</label>
          <textarea id="aibAskQuestion" maxlength="500" rows="2" placeholder="Top attackers in the last day?" required></textarea>
          <button type="submit" class="aib-button aib-secondary" id="aibAskButton">Ask</button>
        </form>
        <div id="aibAskResult" class="aib-result-meta" aria-live="polite"></div>
        <ul id="aibAskItems" class="aib-history-list"></ul>
        <div class="aib-thinking" id="aibThinking" aria-live="polite" hidden></div>
        <button type="button" class="aib-button aib-secondary" id="aibCancelAnalysis" hidden>Cancel analysis</button>
        <div class="aib-analysis-result" id="aibAnalysisResult" aria-live="polite"></div>
      </section>
      <section class="aib-history-panel" aria-labelledby="aibHistoryHeading">
        <h3 id="aibHistoryHeading">Recent analyses</h3>
        <p class="aib-result-meta" id="aibHistoryStatus" aria-live="polite">Loading analysis history...</p>
        <ul class="aib-history-list" id="aibHistoryList"></ul>
      </section>
      <section class="aib-history-panel" aria-labelledby="aibMetricsHeading">
        <h3 id="aibMetricsHeading">Prediction accuracy</h3>
        <p class="aib-result-meta" id="aibMetricsStatus" aria-live="polite">Loading outcome metrics...</p>
        <ul class="aib-history-list" id="aibMetricsList"></ul>
        <ul class="aib-history-list" id="aibPendingCasesList"></ul>
      </section>
      <div class="aib-brain-empty"><strong>Local model analysis</strong><p>Analysis runs on the configured loopback llamafile server; on this CPU it may take up to 10 minutes. If the model is unavailable, a clearly labelled rule-based fallback is returned.</p><span>AI output is advisory and requires analyst review.</span></div>
    `;
    panel.querySelector('#aibBrainRefresh')?.addEventListener('click', loadStatus);
    panel.querySelector('#aibAnalyzeForm')?.addEventListener('submit', event => {
      event.preventDefault();
      analyzeAttacker(panel.querySelector('#aibAttackerIp').value.trim());
    });
    panel.querySelector('#aibAskForm')?.addEventListener('submit', event => {
      event.preventDefault();
      askBrain(panel.querySelector('#aibAskQuestion').value.trim());
    });
    panel.querySelector('#aibCancelAnalysis')?.addEventListener('click', cancelAnalysis);
  }

  function updateRoleState() {
    const admin = isAdmin();
    const note = document.getElementById('aibRoleNote');
    if (note) note.textContent = admin ? 'Administrator controls' : 'Read-only settings; administrator access is required to change them.';
    const card = document.getElementById('aibConfigCard');
    if (card) {
      card.querySelectorAll('input, select, #aibSaveSettings').forEach(control => {
        if (control.id === 'aibTestNow' || control.id === 'aibOpenBrain') return;
        control.disabled = !admin || !status?.enabled ||
          (control.dataset.setting && !IMPLEMENTED_FEATURES.has(control.dataset.setting)) ||
          ['aibBlockMode', 'aibDryRun'].includes(control.id);
      });
      card.querySelector('#aibSaveSettings').disabled = !admin || !status?.enabled;
    }
    const analyzeButton = document.getElementById('aibAnalyzeButton');
    if (analyzeButton) analyzeButton.disabled = Boolean(activeJobId) || !['admin', 'analyst'].includes(document.getElementById('hUserRole')?.textContent.trim().toLowerCase()) || status?.active !== true || status?.settings?.ai_analysis !== 'true';
    const askButton = document.getElementById('aibAskButton');
    if (askButton) askButton.disabled = !['admin', 'analyst'].includes(document.getElementById('hUserRole')?.textContent.trim().toLowerCase()) || status?.active !== true || status?.settings?.ai_chat !== 'true';
  }

  function fillSettings(values) {
    settings = { ...values };
    const master = document.getElementById('aibMasterSwitch');
    if (master) master.checked = settings.ai_active === 'true';
    document.querySelectorAll('#aibConfigCard [data-setting]').forEach(input => {
      const value = settings[input.dataset.setting];
      if (input.type === 'checkbox') input.checked = value === 'true';
      else input.value = value ?? '';
    });
    const blockMode = document.getElementById('aibBlockMode');
    if (blockMode) blockMode.value = settings.ai_block_mode || 'off';
    const dryRun = document.getElementById('aibDryRun');
    if (dryRun) dryRun.checked = settings.ai_block_dryrun === 'true';
    const save = document.getElementById('aibSaveSettings');
    if (save) save.disabled = true;
    updateBlockWarning();
    updateRoleState();
  }

  function updateBlockWarning() {
    const selected = document.getElementById('aibBlockMode')?.value;
    const warning = document.getElementById('aibAutoBlockWarning');
    if (warning) warning.hidden = selected !== 'auto_temp';
  }

  function appendTextElement(parent, tagName, className, text) {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    element.textContent = text;
    parent.appendChild(element);
    return element;
  }

  function renderAnalysis(job) {
    const container = document.getElementById('aibAnalysisResult');
    if (!container) return;
    container.replaceChildren();
    const result = job.result;
    const analysis = result?.analysis;
    if (!analysis) {
      appendTextElement(container, 'p', 'aib-result-error', job.error || 'Analysis returned no result.');
      return;
    }
    const heading = document.createElement('div');
    heading.className = 'aib-result-heading';
    appendTextElement(heading, 'span', result.source === 'fallback' ? 'aib-source-badge is-fallback' : 'aib-source-badge', result.source === 'fallback' ? 'DETERMINISTIC PREDICTOR' : 'LOCAL AI');
    appendTextElement(heading, 'span', 'aib-chip', analysis.stage || 'Unknown');
    appendTextElement(heading, 'span', 'aib-chip', analysis.severity || 'Unknown');
    const displayedSignature = analysis.prediction?.signature || analysis.signature;
    if (displayedSignature) appendTextElement(heading, 'span', 'aib-chip', displayedSignature.replace(/_/g, ' '));
    analysis.prediction?.profile?.top?.forEach(profile => appendTextElement(heading, 'span', 'aib-chip', `${profile.key.replace(/_/g, ' ')} ${profile.score}`));
    container.appendChild(heading);
    appendTextElement(container, 'p', 'aib-result-summary', analysis.summary || 'No summary available.');
    const confidence = appendTextElement(container, 'p', 'aib-confidence', result.source === 'fallback'
      ? `Rule-based heuristic: ${analysis.confidence}% (not model confidence)`
      : `Model confidence: ${analysis.confidence}%`);
    confidence.title = result.source === 'fallback'
      ? 'Uncalibrated rule-based estimate from stored events and incident corroboration.'
      : 'The model estimate is not a guarantee.';
    const fallbackReason = result.fallback_reason || analysis.fallback_reason;
    if (result.source === 'fallback' && fallbackReason) {
      appendTextElement(container, 'p', 'aib-result-error', `LLM narrative unavailable: ${fallbackReason}`);
    }

    if (analysis.prediction?.mindset) {
      appendTextElement(container, 'h3', '', 'Mindset signals');
      const mindsetList = document.createElement('ul');
      Object.entries(analysis.prediction.mindset).forEach(([key, attribute]) => {
        const item = appendTextElement(mindsetList, 'li', '', `${key}: ${attribute.value}${attribute.reasons?.length ? ` · evidence: ${attribute.reasons.join(', ')}` : ''}`);
        item.title = attribute.reasons?.join(', ') || '';
      });
      if (mindsetList.childElementCount) container.appendChild(mindsetList);
    }
    if (analysis.prediction?.stage) {
      appendTextElement(container, 'p', 'aib-result-meta', `Kill-chain: ${analysis.prediction.stage.current} · MITRE ${analysis.prediction.stage.mitre_key || 'not mapped'} · ${analysis.prediction.stage.progress_pct}%`);
    }
    if (analysis.prediction) {
      const accuracy = analysis.prediction.accuracy;
      const reliability = !accuracy ? 'not yet measured'
        : accuracy.n < 30 ? `not enough data (${accuracy.n} evaluated)`
          : `${accuracy.status} · top-3 ${(accuracy.top3_hit_rate * 100).toFixed(0)}% over ${accuracy.n} outcomes`;
      appendTextElement(container, 'p', 'aib-result-meta', `Prediction reliability: ${reliability} · evidence ${analysis.prediction.confidence?.evidence ?? 0}%`);
    }

    if (analysis.evidence?.length) {
      appendTextElement(container, 'h3', '', 'Evidence');
      const evidenceList = document.createElement('ul');
      analysis.evidence.forEach(item => appendTextElement(evidenceList, 'li', '', item));
      container.appendChild(evidenceList);
    }
    if (analysis.next_steps?.length) {
      appendTextElement(container, 'h3', '', 'Suggested next steps');
      const steps = document.createElement('ul');
      analysis.next_steps.forEach(item => appendTextElement(steps, 'li', '', `${item.step}${item.reason ? `: ${item.reason}` : ''}`));
      container.appendChild(steps);
    }
    if (analysis.prediction?.predictions?.length) {
      appendTextElement(container, 'h3', '', 'Predicted next moves');
      const predictionList = document.createElement('ul');
      analysis.prediction.predictions.slice(0, 3).forEach(item => {
        appendTextElement(predictionList, 'li', '', `${item.next_action.replace(/_/g, ' ')} · ${(item.probability * 100).toFixed(0)}% · ${item.window} · ${item.likely_target || 'unknown target'}${item.why?.length ? ` · why: ${item.why.join(', ')}` : ''}`);
      });
      container.appendChild(predictionList);
    }
    if (analysis.prediction?.campaign?.siblings) {
      const campaign = analysis.prediction.campaign;
      appendTextElement(container, 'p', 'aib-result-meta', `Campaign ${campaign.id} · ${campaign.siblings} sibling IPs · estimated additional participants: ${campaign.expected_new_ips}`);
    }
    if (analysis.prediction?.similar_cases?.length) {
      appendTextElement(container, 'h3', '', 'Approved similar cases');
      const casesList = document.createElement('ul');
      analysis.prediction.similar_cases.slice(0, 3).forEach(item => {
        appendTextElement(casesList, 'li', '', `Similarity ${Math.round(item.score * 100)}% · ${item.verdict} · ${item.outcome} · influence cap ${item.influence_cap.toFixed(2)}`);
      });
      container.appendChild(casesList);
    }
    if (analysis.recommendation_items?.length) {
      appendTextElement(container, 'h3', '', 'What to do now');
      const recommendationList = document.createElement('ul');
      analysis.recommendation_items.slice(0, 5).forEach(item => appendTextElement(recommendationList, 'li', '', item.text));
      container.appendChild(recommendationList);
    } else if (analysis.recommendations?.length) {
      appendTextElement(container, 'h3', '', 'Recommended actions');
      appendTextElement(container, 'p', 'aib-result-meta', analysis.recommendations.map(item => item.replace(/_/g, ' ')).join(' · '));
    }
    appendTextElement(container, 'p', 'aib-result-meta', `Engine: ${result.engine || analysis.engine || 'local-ai'} (${result.method || 'rules+stats+llm'}) · LLM: ${result.llm_used === false ? `not used - ${fallbackReason || 'unknown'}` : 'used'} · ${result.latency_ms ?? '--'} ms · ${result.prompt_version || 'attacker-v4'}`);
    appendTextElement(container, 'p', 'aib-disclaimer', 'Predictions are probabilistic estimates. Accuracy is measured on this SOC\'s own history and shown only after enough data. Analyst review required.');
    if (result.analysis_id && ['admin', 'analyst'].includes(document.getElementById('hUserRole')?.textContent.trim().toLowerCase())) {
      const feedbackForm = document.createElement('form');
      feedbackForm.className = 'aib-feedback-form';
      appendTextElement(feedbackForm, 'h3', '', 'Analyst feedback');
      const verdictLabel = appendTextElement(feedbackForm, 'label', '', 'Verdict');
      const verdict = document.createElement('select');
      verdict.required = true;
      verdict.name = 'verdict';
      [['correct', 'Correct'], ['wrong', 'Wrong'], ['partial', 'Partial'], ['false_positive', 'False positive']].forEach(([value, label]) => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = label;
        verdict.appendChild(option);
      });
      verdictLabel.appendChild(verdict);
      const noteLabel = appendTextElement(feedbackForm, 'label', '', 'Note (optional, 300 characters max)');
      const note = document.createElement('textarea');
      note.name = 'note';
      note.maxLength = 300;
      note.rows = 2;
      noteLabel.appendChild(note);
      const submit = document.createElement('button');
      submit.type = 'submit';
      submit.className = 'aib-button aib-secondary';
      submit.textContent = 'Submit feedback';
      feedbackForm.appendChild(submit);
      const feedbackStatus = appendTextElement(feedbackForm, 'p', 'aib-result-meta', '');
      feedbackForm.addEventListener('submit', async event => {
        event.preventDefault();
        submit.disabled = true;
        try {
          const response = await request(`/ai/feedback/${encodeURIComponent(result.analysis_id)}`, {
            method: 'POST',
            body: JSON.stringify({ verdict: verdict.value, note: note.value }),
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(payload.error || 'Feedback could not be saved.');
          feedbackStatus.textContent = 'Feedback recorded.';
          feedbackForm.querySelectorAll('select, textarea, button').forEach(control => { control.disabled = true; });
          await loadPredictionMetrics();
        } catch (error) {
          feedbackStatus.textContent = error.message || 'Feedback could not be saved.';
          submit.disabled = false;
        }
      });
      container.appendChild(feedbackForm);
    }
    loadHistory();
    loadPredictionMetrics();
  }

  async function loadHistory() {
    const list = document.getElementById('aibHistoryList');
    const historyStatus = document.getElementById('aibHistoryStatus');
    if (!list || !historyStatus || !status?.enabled) return;
    try {
      const response = await request('/ai/history');
      if (!response.ok) throw new Error('Analysis history unavailable.');
      const payload = await response.json();
      list.replaceChildren();
      const items = (payload.items || []).slice(0, 10);
      if (!items.length) {
        historyStatus.textContent = 'No analyses recorded.';
        return;
      }
      historyStatus.textContent = `${items.length} recent analysis${items.length === 1 ? '' : 'es'}`;
      items.forEach(item => {
        const row = document.createElement('li');
        row.className = 'aib-history-item';
        const details = document.createElement('div');
        details.className = 'aib-history-details';
        appendTextElement(details, 'span', '', `${item.attacker_ip} · ${item.created_at || 'time unavailable'} · ${item.source || 'unknown source'} · ${item.prompt_version || 'unknown version'}`);
        if (item.legacy || item.prompt_version === 'attacker-v1') {
          appendTextElement(details, 'span', 'aib-legacy-badge', 'legacy (attacker-v1)');
        }
        row.appendChild(details);
        const reanalyze = document.createElement('button');
        reanalyze.type = 'button';
        reanalyze.className = 'aib-button aib-secondary';
        reanalyze.textContent = 'Re-analyze';
        reanalyze.disabled = status?.active !== true || Boolean(activeJobId);
        reanalyze.addEventListener('click', () => {
          const input = document.getElementById('aibAttackerIp');
          if (input) input.value = item.attacker_ip;
          analyzeAttacker(item.attacker_ip);
        });
        row.appendChild(reanalyze);
        list.appendChild(row);
      });
    } catch (error) {
      historyStatus.textContent = error.message || 'Analysis history unavailable.';
    }
  }

  async function loadPredictionMetrics() {
    const metricsStatus = document.getElementById('aibMetricsStatus');
    const metricsList = document.getElementById('aibMetricsList');
    if (!metricsStatus || !metricsList || !status?.enabled) return;
    try {
      const response = await request('/ai/prediction-metrics');
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || 'Prediction metrics unavailable.');
      const metrics = payload.metrics || {};
      metricsStatus.textContent = `${metrics.n || 0} evaluated outcome${metrics.n === 1 ? '' : 's'} · ${String(metrics.status || 'not_enough_data').replace(/_/g, ' ')}`;
      metricsList.replaceChildren();
      if (metrics.top1_hit_rate == null) {
        appendTextElement(metricsList, 'li', '', 'Not enough matured outcomes to calculate accuracy.');
      } else {
        appendTextElement(metricsList, 'li', '', `Top-1 ${Math.round(metrics.top1_hit_rate * 100)}% · top-3 ${Math.round(metrics.top3_hit_rate * 100)}%`);
        appendTextElement(metricsList, 'li', '', `Baselines: repeat-last ${Math.round(metrics.baseline_repeat_last * 100)}% · most-common ${Math.round(metrics.baseline_most_common * 100)}%`);
        appendTextElement(metricsList, 'li', '', `Brier score ${metrics.brier_score.toFixed(3)} · calibration gap ${Math.round(metrics.calibration_gap * 100)}%`);
      }
      const feedback = payload.feedback || {};
      appendTextElement(metricsList, 'li', '', feedback.meaningful_feedback >= 30
        ? `Analyst feedback accuracy ${Math.round(feedback.accuracy * 100)}% · ${feedback.meaningful_feedback} correct/wrong votes`
        : 'Analyst feedback accuracy: Not enough data yet');
      const pendingList = document.getElementById('aibPendingCasesList');
      pendingList?.replaceChildren();
      if (pendingList && isAdmin()) {
        const pendingResponse = await request('/ai/cases/pending');
        const pendingPayload = await pendingResponse.json().catch(() => ({}));
        if (!pendingResponse.ok) throw new Error(pendingPayload.error || 'Pending case review unavailable.');
        (pendingPayload.items || []).forEach(item => {
          const row = document.createElement('li');
          appendTextElement(row, 'span', '', `Case ${item.id} · ${item.verdict} · ${item.outcome} · ${item.features.severity}`);
          const approve = document.createElement('button');
          approve.type = 'button';
          approve.className = 'aib-button aib-secondary';
          approve.textContent = 'Approve precedent';
          approve.addEventListener('click', async () => {
            approve.disabled = true;
            const result = await request(`/ai/cases/${item.id}/approve`, { method: 'PUT' });
            if (result.ok) await loadPredictionMetrics();
            else approve.disabled = false;
          });
          row.appendChild(approve);
          pendingList.appendChild(row);
        });
      }
    } catch (error) {
      metricsStatus.textContent = error.message || 'Prediction metrics unavailable.';
      metricsList.replaceChildren();
    }
  }

  async function analyzeAttacker(ip) {
    if (!ip || activeJobId || !status?.active || settings?.ai_analysis !== 'true') return;
    const result = document.getElementById('aibAnalysisResult');
    document.getElementById('aibAnalyzeButton').disabled = true;
    result?.replaceChildren();
    try {
      const response = await request(`/ai/analyze/attacker/${encodeURIComponent(ip)}`, { method: 'POST' });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || 'Could not queue attacker analysis.');
      activeJobId = payload.job_id;
      activeJobStartedAt = Date.now();
      document.getElementById('aibCancelAnalysis').hidden = false;
      pollJob();
    } catch (error) {
      appendTextElement(result, 'p', 'aib-result-error', error.message);
      document.getElementById('aibAnalyzeButton').disabled = false;
    }
  }

  async function askBrain(question) {
    const result = document.getElementById('aibAskResult');
    const list = document.getElementById('aibAskItems');
    const button = document.getElementById('aibAskButton');
    if (!question || question.length > 500 || !result || !list || !button) return;
    button.disabled = true;
    result.textContent = 'Querying fixed SOC data...';
    list.replaceChildren();
    try {
      const response = await request('/ai/ask', { method: 'POST', body: JSON.stringify({ question }) });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || 'Ask the Brain is unavailable.');
      result.textContent = payload.answer || 'No answer available.';
      (payload.items || []).slice(0, 50).forEach(item => appendTextElement(list, 'li', '', JSON.stringify(item).slice(0, 1000)));
    } catch (error) {
      result.textContent = error.message || 'Ask the Brain is unavailable.';
    } finally {
      updateRoleState();
    }
  }

  function pollJob() {
    if (!activeJobId) return;
    const thinking = document.getElementById('aibThinking');
    if (thinking) {
      thinking.hidden = false;
      const elapsed = Math.floor((Date.now() - activeJobStartedAt) / 1000);
      thinking.textContent = `Analysis queued/running · ${elapsed}s elapsed · CPU analysis may take up to 10 minutes.`;
    }
    if (document.visibilityState === 'visible' && document.getElementById('aiBrainTab')?.classList.contains('active')) {
      request(`/ai/jobs/${encodeURIComponent(activeJobId)}`).then(async response => {
        const job = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(job.error || 'Could not read analysis job.');
        if (job.status === 'completed') {
          renderAnalysis(job);
          finishJob();
          return;
        }
        if (job.status === 'failed' || job.status === 'cancelled') {
          renderAnalysis(job);
          finishJob();
          return;
        }
        pollTimer = setTimeout(pollJob, 3000);
      }).catch(error => {
        appendTextElement(document.getElementById('aibAnalysisResult'), 'p', 'aib-result-error', error.message);
        finishJob();
      });
      return;
    }
    pollTimer = setTimeout(pollJob, 3000);
  }

  function finishJob() {
    activeJobId = null;
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
    document.getElementById('aibCancelAnalysis').hidden = true;
    document.getElementById('aibThinking').hidden = true;
    updateRoleState();
  }

  async function cancelAnalysis() {
    if (!activeJobId) return;
    try {
      await request(`/ai/jobs/${encodeURIComponent(activeJobId)}/cancel`, { method: 'POST' });
    } finally {
      finishJob();
    }
  }

  async function loadStatus() {
    if (loading || !window.CONFIG?.apiUrl) return;
    loading = true;
    setStatus('Checking local AI status...');
    try {
      const [statusResponse, settingsResponse] = await Promise.all([
        request('/ai/status'),
        request('/ai/settings'),
      ]);
      if (statusResponse.status === 404 || settingsResponse.status === 404) {
        status = { enabled: false };
        setStatus('Deactivated: enable LOCAL_AI_ENABLED in backend/.env and restart.', 'off');
        const historyStatus = document.getElementById('aibHistoryStatus');
        if (historyStatus) historyStatus.textContent = 'History unavailable while Local AI is deactivated.';
        document.getElementById('aibProviderStatus').textContent = 'Provider: hard-disabled';
        document.getElementById('aibModelName').textContent = 'Model: unavailable';
        document.getElementById('aibLatency').textContent = 'Latency: --';
        fillSettings({});
        updateRoleState();
        return;
      }
      const statusData = await statusResponse.json();
      const settingsData = await settingsResponse.json();
      if (!statusResponse.ok || !settingsResponse.ok) throw new Error(statusData.error || settingsData.error || 'Could not load AI status.');
      status = statusData;
      setStatus(statusData.configuration_error || (statusData.state === 'healthy' ? 'Active and online' : statusData.active ? 'Active but offline; fallback mode' : 'Deactivated'), statusData.configuration_error ? 'error' : statusData.state);
      document.getElementById('aibProviderStatus').textContent = `Provider: ${statusData.provider?.status || 'unknown'}`;
      document.getElementById('aibModelName').textContent = `Model: ${statusData.model || 'unknown'}`;
      document.getElementById('aibLatency').textContent = `Latency: ${statusData.provider?.latency_ms == null ? '--' : `${statusData.provider.latency_ms} ms`}`;
      document.getElementById('aibQueueStatus').textContent = `Queue: ${statusData.queue?.pending || 0} pending / ${statusData.queue?.running || 0} running`;
      fillSettings(settingsData.settings || statusData.settings || {});
      await Promise.all([loadHistory(), loadPredictionMetrics()]);
    } catch (error) {
      setStatus(error.message || 'AI status unavailable.', 'error');
    } finally {
      loading = false;
    }
  }

  function collectSettings() {
    const values = { ai_active: document.getElementById('aibMasterSwitch').checked };
    document.querySelectorAll('#aibConfigCard [data-setting]').forEach(input => {
      values[input.dataset.setting] = input.type === 'checkbox' ? input.checked : Number(input.value);
    });
    values.ai_block_mode = document.getElementById('aibBlockMode').value;
    values.ai_block_dryrun = document.getElementById('aibDryRun').checked;
    return values;
  }

  async function saveSettings() {
    if (!isAdmin() || !status?.enabled) return;
    const nextSettings = collectSettings();
    if (settings?.ai_active === 'true' && !nextSettings.ai_active && !window.confirm('AI deactivate karein? Pending jobs cancel honge.')) {
      fillSettings(settings);
      return;
    }
    const button = document.getElementById('aibSaveSettings');
    button.disabled = true;
    button.textContent = 'Saving...';
    try {
      const response = await request('/ai/settings', { method: 'PUT', body: JSON.stringify({ settings: nextSettings }) });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'AI settings were not saved.');
      fillSettings(result.settings || {});
      setStatus('Settings saved and confirmed by backend.', 'healthy');
      await loadStatus();
    } catch (error) {
      await loadStatus();
      setStatus(error.message, 'error');
    } finally {
      button.textContent = 'Save';
    }
  }

  function refresh() {
    updateRoleState();
    loadStatus();
  }

  function init() {
    injectStyles();
    injectBrainTab();
    injectConfigCard();
    window.AIB = {
      refresh,
      open: () => window.switchMainTab?.('ai_brain', document.getElementById('aibBrainNav'), null),
      analyzeAttacker,
      getStatus: () => status,
    };
    document.getElementById('aibBrainNav')?.addEventListener('click', refresh);
    if (window.CONFIG?.apiUrl) refresh();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
