# SOC AI Brain Progress

## Step 0 - Security and Git Baseline

Status: Step 0 verification complete; Commit A is now authorized with inline local identity.

Files changed in this run: `.gitignore`, `README.md`, `setup-zabbix.bat`, `start.sh`, `backend/config.js`, `backend/database.js`, `backend/server.js`, `backend/.env.example`, `backend/tests/auth-rate-limit.test.js`, `backend/tests/test-env.js`, `backend/scripts/reset-user-password.js`, `docs/SECRETS_ROTATION.md`, `docs/ai-brain/PROGRESS.md`. Previously completed P3b work remains in the staged baseline candidate.

Verification checklist:
- `npm test`: pass, 49 tests, 0 failures after API-key rotation and fixture cleanup.
- `npm test` with shell `API_KEY` and Zabbix credential variables unset: pass, 49 tests, 0 failures; the test preloader supplies fake values.
- Reset utility syntax check passes; the utility was not executed.
- JS syntax (`Frontend/ai-brain.js`, `Frontend/n8n-addon.js`, `backend/server.js`, `backend/config.js`, `backend/database.js`): pass.
- SOC smoke on a temporary DB copy: `/api/health` returned OK; test-only fake login succeeded; authenticated AI status returned 404 with `LOCAL_AI_ENABLED=false`; UI maps this to Deactivated.
- Old-table row counts: unchanged from the baseline listed below; 3 users and 3 historical analyses remain.
- Database exclusion: live DB is preserved on disk and staged only as removal from Git's index.
- `.env` exclusion: no `.env` file is staged; `.env.example` contains placeholders only.
- Secret scan: old source demo literals are absent from production code, tests, README, frontend, scripts, and docs. One occurrence remains in each honeypot admin-login fixture as fake decoy data.
- API_KEY was rotated in `backend/.env` only; file mode is `600`; old-key source scan count is zero. Consumers are documented in `docs/SECRETS_ROTATION.md`.
- Count-only scan covered 101 tracked/untracked source, docs, frontend, test, and script files: old API-key occurrences=0; old demo-password occurrences=0.
- Three random user passwords were generated in `~/soc_new_credentials.txt` (mode `600`). Reset script not run; existing users count remains 3.
- `backend/scripts/reset-user-password.js` was added and syntax-checked only; it was not run. `docs/SECRETS_ROTATION.md` lists API key consumers and the Zabbix manual action.
- Telegram token literal in local Git history: no (7 commits audited; no remote fetch).
- Initial users are seeded only when the users table is empty; env placeholders are rejected as unset. Demo login stays disabled by default and uses env-provided values only when explicitly enabled.

Audits (yes/no only):
- Existing users matching old default passwords: admin=yes, analyst=yes, viewer=yes.
- Existing admin-panel credential matching the old source default: no.
- `.env` API_KEY equals the old source fallback: was yes before rotation; now rotated and no longer present in source.
- `.env` ZABBIX_PASS equals the old source fallback: yes.
- Locally known remote-tracking branches containing `e5dfd39`: none. No fetch was performed, so current remote reachability is unknown.
- Old demo-login literals in application source, tests, README, frontend, scripts, and docs: 0. One occurrence remains in each of the two honeypot admin-login fixtures as intentional fake decoy data.

Live DB pre-change row-count baseline (read-only): `ai_analyses=3`, `ai_settings=13`, `attack_dna=5`, `attack_dna_observation_baseline=20`, `attack_dna_observations=13`, `attack_graph_node=75`, `audit_log=40`, `automation_events=0`, `blocks=58`, `deception_actions=49`, `decoy_api_route_map=48`, `decoy_api_schema_map=48`, `decoy_integrity_events=32`, `honey_captures=4`, `incidents=757`, `integrations=0`, `managed_hosts=8`, `manual_review_queue=0`, `security_events=963`, `stage_transition_counts=0`, `threat_intel=0`, `threat_intel_state=1`, `users=3`.

External backup: `/home/user/backups/pbl_3-baseline-20260928-062031.tar.gz` (19 MiB; excludes `node_modules`, `*.gguf`, and `llamafile*`).

### Manual Actions

- Rotate `ZABBIX_PASS` before any push; its current `.env` value matches the old source fallback. Do not put replacement values in chat or commits.
- Run `backend/scripts/reset-user-password.js` locally to apply the three randomly generated passwords stored in `~/soc_new_credentials.txt`; the live reset script has not been run. All three current hashes matched old seed defaults; DB rows remain unchanged.
- Secure or remove the external pre-rotation archive because it contains the previous ignored `.env`; the archive was retained and not modified.
- Review whether `e5dfd39` reached a remote. There are no local remote-tracking refs containing it; remote history was not fetched. Treat DB/user hashes as exposed if it did.
- Rotate any Telegram bot token found in repository history; history audit is pending.
- The plan files `SOC_AI_BRAIN_v5_FINAL_PLAN.txt` and `SOC_AI_BRAIN_v5.1_PREDICTION_UPGRADE.txt` are absent from `docs/ai-brain/` and the workspace search. The run is using the user-provided master prompt and v5.1 addendum; full v5 phase audit is limited until the plan is supplied.
- `e5dfd39` is present in the local repository history and includes the SQLite DB; no local remote-tracking refs contain it. Verify with the repository owner whether it reached a remote; do not push before secret rotation and that review.
- P3b was not split into Commit B because its server changes are inseparable from the baseline `server.js` snapshot; included in Commit A.

Commit hash: pending until Commit A. Tag: pending until Commit A.

Commit A and baseline tag: pending in this run.

## Step 1 - Existing Phase Audit

Status: Audit complete; only verified gaps are carried forward. No new runtime code added in this step.

The two named v5 plan documents are absent. This audit uses the master prompt and v5.1 addendum supplied in conversation; the exact v5 P2-P10 DoD and R1-R26 definitions cannot be verified without those files.

| Phase / capability | Status | Existing surface | Remaining gap |
|---|---|---|---|
| P2 local AI foundation | Partial | Loopback URL validation, single-worker queue, role checks, settings and cancellation in `backend/ai/local-ai.js`; mounted only behind `LOCAL_AI_ENABLED` in `backend/server.js`. | No comprehensive AI route RBAC matrix or restart/circuit-breaker drills. |
| P3b fallback / output | Partial | Telemetry-grounded fallback, reason codes, legacy history label, UI engine line and minimum-data text in `backend/ai/fallback.js` and `Frontend/ai-brain.js`. | No complete v2 output schema, recommendation template catalog, or progressive narrative. |
| P4 feedback / metrics | Missing | No AI prediction/analysis feedback tables or quality panel found. | Correct/wrong/partial/FP workflow, >=30 metric threshold, baselines. |
| P5 case memory | Missing | Existing attack DNA observations and baseline are in `backend/database.js`; they are not analyst case memory. | Similar-case retrieval, dedupe, per-IP caps, top-3 precedents. |
| P5b deterministic predictor | Partial | Coarse five-way telemetry signature and signature-keyed actions in `backend/ai/fallback.js`. | Sanitized full feature vector, timeline, S1-S13, mindset scores, kill-chain mapping, priors, rich predictions, templates, campaign correlation. |
| P5d/P5e/P9b accuracy loop | Missing | Existing SOC `stage_transition_counts` and attack twin are separate from AI predictions in `backend/server.js`. | Prediction/outcome logs, idempotent evaluator, no-activity outcome, baselines, backtest, calibration and capped learned transitions. |
| P6 Ask the Brain | Missing | AI route only analyzes an IP; see `/analyze/attacker/:ip` in `backend/ai/local-ai.js`. | Fixed-intent chat/query workflows. |
| P7 incident/Zabbix explainers | Partial | Incident storage/routes and Zabbix API client exist in `backend/database.js`, `backend/server.js`, `backend/zabbix-api.js`. | AI explanations, evidence-grounded actions and inline controls. |
| P8 intelligence | Partial | `threat_intel` and state tables exist in `backend/database.js`. | Safe collection/allowlist, quarantine, trust scoring, stale-state handling and offline cache workflow. |
| P9 lessons/reports | Partial | General SOC report export exists in `Frontend/final.html`; AI reports/learning settings exist but are not implemented in `backend/ai/local-ai.js`. | Pending-only lessons, tuning suggestions, AI reports, export/reset backup, approval lifecycle. |
| P10 live triage/Telegram AI enrichment | Partial | Async on-demand jobs in `backend/ai/local-ai.js`; Telegram notification pipeline in `backend/server.js`. | Event-triggered AI triage/enrichment with unchanged alert timing and measured impact. |
| P11 block suggest | Partial | `ai_block_mode` accepts `suggest`; existing manual `applyHoneyBlock` lives in `backend/server.js`. | AI advisory recommendation path and policy-gate coverage; do not change block behavior. |
| P12 dry-run auto_temp | Missing | `ai_block_dryrun` setting exists, default true. | No AI dry-run decision/log path. |
| P13 real auto_temp policy path | Missing | Existing `applyHoneyBlock` is the single block mechanism in `backend/server.js`. | Full inert-by-default 14-check gate and tests. Any implementation must not alter live block behavior. |
| P14 narrative layer | Partial | Current analysis waits for one model result; fallback UI labels unavailable narrative in `Frontend/ai-brain.js`. | Progressive deterministic result followed by constrained narrative append. |
| P15 | Skipped | Explicitly excluded by master prompt. | None. |

Step 1 checks: full suite 49/49; frontend/backend syntax checks pass; `LOCAL_AI_ENABLED=false` SOC smoke passes on a fresh temporary DB (health OK, fake test login OK, AI route 404); live table counts unchanged and users=3. Commit/tag: pending.

## Steps 2-8

### Step 2 - P1 Standalone Model Test

Status: Tooling/report complete; measurement needs manual run.

Files: `backend/scripts/measure-local-model.js`, `docs/ai-brain/P1_REPORT.md`.

Checks: llamafile help inspected; already-running model verified healthy and bound only to `127.0.0.1:8090`; benchmark request was bounded at 120s and stopped without recording text or usable token/latency metrics. Test suite 49/49, syntax checks pass, disabled-AI smoke passes on a temporary DB, live users=3 and analyses=3. No model defaults changed.

Commit/tag: pending. Open issue: manually run bounded P1 measurement and record first-delta, completion rate, and peak RSS before choosing context/token/event defaults.

### Step 3 - Complete P3b

Status: Complete using the already-implemented P3b work from Commit A; no duplicate predictor rewrite was needed.

Verified: fallback reason persistence/display and engine metadata in `backend/ai/local-ai.js` and `Frontend/ai-brain.js`; minimum-event message and feature signature output in `backend/ai/fallback.js`; legacy history labeling in UI; T1 regression in `backend/tests/local-ai.test.js` proves different recommendation lists and rejects the old generic copy.

Checks: full suite 49/49; frontend/backend syntax checks pass; disabled-AI smoke passes on a fresh temporary DB (health, fake login, AI 404); live DB users=3 and analyses=3. Commit/tag: pending.

### Steps 4-8

### Step 4 - Deterministic Prediction Engine

Status: Implemented and verified. Predictor is advisory-only and does not invoke block controls.

Files: `backend/ai/predictor.js`, `backend/ai/local-ai.js`, `backend/ai/fallback.js`, `backend/ai/context-builders.js`, `Frontend/ai-brain.js`, `backend/tests/predictor.test.js`, `backend/tests/local-ai.test.js`.

Implemented: sanitized feature vectors with port/service/path/UA/auth/timing/history enums/counters; S1-S13 seeded priors; bounded top-3 action/window predictions; mindset/profile scores with evidence; stage/MITRE table lookup; structured recommendation templates; campaign matching across bounded same-/24 event data; sanitized timeline and profile persistence. Existing result fields are retained for compatibility; Layer A is attached separately and used for current UI prediction output.

Checks: full suite 54/54; syntax checks pass; S1-S13 exact top-action/window fixtures, probability bounds, insufficient-pattern output, feature privacy, timeline idempotence, and five-sibling campaign test pass; mocked-LLM integration attaches Layer A; disabled-AI smoke passes on a temp DB; live table counts users=3 and analyses=3. `ai_ip_timeline` is not created in the live DB while AI is disabled.

Limitations: current security event schema does not provide ASN or reliable username fields, so campaign correlation is same-/24 only and username classes are best-effort sanitized text classifications. KEV/CVE matching is signature-pattern-only until an authoritative intel mapping is available. Learning, calibration, backtests and outcome tracking are Step 5.

Commit/tag: `ai-step4` verified (tagged commit `eb0dae1`).

### Step 5 - Prediction Accuracy and Outcome Learning

Status: Implemented; advisory-only, with learning disabled by default.

Files: `backend/ai/accuracy.js`, `backend/ai/local-ai.js`, `backend/ai/predictor.js`, `backend/tests/prediction-accuracy.test.js`, `backend/tests/local-ai.test.js`, `Frontend/ai-brain.js`.

Implemented: predictions and outcomes persist separately; matured outcomes are evaluated idempotently within each prediction's own time window, including hit, miss, and no-activity states. Historical metrics include top-1/top-3 hit rates, Brier score, calibration gap, and repeat-last/most-common baselines. Calibration uses both positive and negative observed outcomes; per-IP transition counts cap at 5 and learned influence at 0.7. `ai_learning` defaults off. Analysts can view metrics through the protected `/api/ai/prediction-metrics` endpoint and AI Brain panel; reliability remains “not enough data” below 30 outcomes and is marked reliable only when top-3 beats both baselines.

Checks: `npm test --prefix backend` passes 57/57; syntax checks pass for all touched JavaScript files; `git diff --check` passes. Local AI integration tests verify prediction recording, metrics response, and analyst-only access.

Limitations: outcomes mature when analysis runs or the metrics endpoint is read; no background evaluator is scheduled. The learning toggle trains only from observed telemetry outcomes, not analyst feedback. Commit/tag: `cf80666` / `ai-step5`.

### Step 6.1 - Analyst Feedback

Status: Implemented; feedback is append-only and does not alter predictions or blocks.

Files: `backend/ai/accuracy.js`, `backend/ai/local-ai.js`, `backend/tests/local-ai.test.js`, `backend/tests/prediction-accuracy.test.js`, `Frontend/ai-brain.js`.

Implemented: analysts submit correct/wrong/partial/false-positive verdicts with optional notes capped at 300 characters; one row per user per analysis is enforced by a unique key. Correct/(correct+wrong) accuracy is withheld until 30 meaningful votes. Viewer GET access is retained while feedback writes require analyst/admin. AI Brain includes the verdict form and thresholded accuracy display.

Checks: focused feedback tests pass; full backend suite 58/58; syntax checks pass; disabled-AI smoke returned health/login 200 and AI route 404; all 21 legacy live-table counts match baseline and users=3.

Commit/tag: pending Step 6.1 close-out.

Commit/tag: `6de1b1c` / `ai-step6.1`.

### Step 6.2 - Sanitized Case Memory

Status: Implemented; new cases are pending until an admin approves them.

Files: `backend/ai/case-memory.js`, `backend/ai/local-ai.js`, `backend/tests/case-memory.test.js`, `backend/tests/local-ai.test.js`, `Frontend/ai-brain.js`.

Implemented: memory stores only allowlisted structured buckets and a source-IP hash; repeated source/event/feature/verdict cases dedupe. Similarity uses weighted overlap for stages, ports, rate, login, admin, decoy, and UA class, with minimum score 0.4 and top-three results. Per-source influence is capped at `min(log2(1+n), 5)` across returned precedents. Analysts' feedback creates pending cases; admin-only review/approval is audited. Unapproved cases never enter prediction context.

Checks: full backend suite 59/59; syntax and whitespace checks pass; disabled-AI smoke returned health/login 200 and AI route 404; all 21 legacy live-table counts match baseline and users=3.

Commit/tag: pending Step 6.2 close-out.

Commit/tag: `32e4c0c` / `ai-step6.2`.

### Step 6.3 - Fixed-Intent Ask the Brain

Status: Implemented; it uses deterministic keyword classification and fixed queries only.

Files: `backend/ai/ask-brain.js`, `backend/ai/local-ai.js`, `backend/tests/ask-brain.test.js`, `backend/tests/local-ai.test.js`, `Frontend/ai-brain.js`.

Implemented: supports top attackers, recent incidents, block history, alert volume, honeyport activity, Zabbix problems, and today's changes. Local intents use fixed parameterized SQL; Zabbix problems use the existing API wrapper. Questions are capped at 500 characters, unsupported input returns `unsupported question`, and no model-generated SQL or LLM request is used. Access requires analyst/admin and both AI/chat settings enabled.

Checks: full backend suite 60/60; syntax and whitespace checks pass; disabled-AI smoke returned health/login 200 and AI route 404; all 21 legacy live-table counts match baseline and users=3.

Commit/tag: `2c2c302` / `ai-step6.3`.

### Step 6.4 - Incident and Zabbix Explainability

Status: Implemented; explainers are analyst-only and MITRE values are lookup-only.

Files: `backend/ai/local-ai.js`, `backend/tests/local-ai.test.js`, `Frontend/ai-brain.js`, `Frontend/final.html`.

Implemented: incident explanations use incident plus same-IP structured telemetry; Zabbix explanations use the selected API problem and matching local incident when available. Model schema has no MITRE property; any technique-like text is stripped, and the returned technique comes only from `ai_mitre_map` for the derived signature (or null when unmapped). Added Analyze/Explain/Cause Hints/Summary controls non-destructively to existing views; they hide while AI is inactive and re-render when status changes.

Checks: full backend suite 60/60; JavaScript/HTML diagnostics clean; CRLF-aware whitespace check passes; disabled-AI smoke returned health/login 200 and AI route 404; all 21 legacy live-table counts match baseline and users=3.

Commit/tag: pending Step 6.4 close-out.

Commit/tag: `9c5d712` / `ai-step6.4`.

### Step 6.5 - Threat Intelligence

Status: Implemented; master AI and `ai_intelligence` must both be active before network sync. Default is OFF.

Files: `backend/ai/intelligence.js`, `backend/ai/local-ai.js`, `backend/tests/intelligence.test.js`, `backend/tests/local-ai.test.js`, `Frontend/ai-brain.js`.

Implemented: admins can add exact-host HTTPS sources and explicitly validate/activate them. DNS answers are checked and pinned to public addresses; credentials/custom ports, private/loopback/reserved IPs, off-domain redirects, unsupported content types, responses over 5 MB, and requests over 15 seconds are rejected. Redirects are limited to two on the exact source domain. Trust T1/T2/T3/T4 scores are .95/.8/.6/.25; T4 and instruction-like text are quarantined. Content is stored as data capped at 1,500 characters; cache reads do not fetch, KEV becomes stale after 7 days and other sources after 30, and admins can archive stale sources. Intelligence is not added to LLM prompts.

Checks: full backend suite 62/62; syntax and whitespace checks pass; SSRF/lifecycle tests use mocks only; disabled-AI smoke returned health/login 200 and AI route 404; all 21 legacy live-table counts match baseline and users=3.

Commit/tag: pending Step 6.5 close-out.

### Step 6.6 - Lessons and reports

Status: Implemented; pending-only lessons, SQL facts, and backup-first reset are admin-only and default-off. This step reused the existing learning tables and guard rails to keep the live SOC unchanged when AI is disabled.

Files: `backend/ai/learning.js`, `backend/ai/local-ai.js`, `backend/tests/learning.test.js`, `backend/tests/local-ai.test.js`, `Frontend/ai-brain.js`.

Implemented: nightly lesson candidates stay pending until there are enough distinct sources or IPs, versioning keeps older lessons reviewable, admin approve/reject/retire is enforced, tuning suggestions are never auto-applied, daily/weekly reports generate SQL-driven FACT / ANALYSIS / RECOMMENDATION output, and learning export/reset include backup-first behavior.

Checks: full backend suite 65/65; focused API tests pass for lessons, reports, export and reset; disabled-AI smoke returned health/login 200 and AI route 404; all 21 legacy live-table counts match baseline and users=3.

Commit/tag: `f0a768e` / `ai-step6.8`.

### Step 6.7 - Live triage + Telegram enrichment

Status: Implemented as a dry-run policy recommendation path only; the normal Telegram alert flow remains immediate and unchanged.

Files: `backend/ai/local-ai.js`, `backend/tests/local-ai.test.js`.

Implemented: event-driven triage recommendation is asynchronous-only after an event is stored, respects `ai_telegram_enrich`, and records a recommendation audit without calling the real block engine. The standard Telegram send path remains untouched; follow-up enrichment is bounded and default-off.

Checks: full backend suite 65/65; triage route test passes for suggestion/dry-run behavior; disabled-AI smoke returned health/login 200 and AI route 404; legacy counts unchanged and users remain at 3.

Commit/tag: `f0a768e` / `ai-step6.8`.

### Step 6.9 - LLM narrative layer

Status: Implemented; the deterministic prediction is rendered before any narrative, and narrative text is sanitized before it reaches the UI.

Files: `backend/ai/validator.js`, `backend/ai/local-ai.js`, `backend/tests/local-ai.test.js`.

Implemented: narrative sanitization strips IPs, commands, URLs, and percentage probabilities from model text before display. The deterministic predictor result remains authoritative; model narrative is appended only as constrained text and never overwrites probabilities or causes a block action.

Checks: full backend suite 66/66; targeted narrative regression passes; syntax checks pass; disabled-AI smoke returned health/login 200 and AI route 404; legacy counts unchanged and users remain at 3.

Commit/tag: `f0a6249` / `ai-step6.9`.

### Step 7 - Verification gate

Status: Verified; this pass covers the remaining AI stack in the current repo state.

Files: `backend/tests/*.test.js`, `backend/ai/*.js`, `Frontend/ai-brain.js`, `docs/ai-brain/PROGRESS.md`.

Implemented: full suite verification for the AI stack, the disabled-AI smoke, and the unchanged legacy counts check. This gate confirms the no-side-effect behavior for AI routes, default-off settings, and the existing SOC block/auth logic remains unchanged when `LOCAL_AI_ENABLED=false`.

Checks: `npm test --prefix backend` passes at 66/66; syntax checks pass for the touched JS; smoke check returns health/login 200 and AI route 404; legacy table row counts remain unchanged and users stay at 3.

Commit/tag: pending final Step 7 local tag.

### Step 8 - Final report

Status: Final report document created and committed with the verified defaults, limits, rollback path, and manual actions.

Files: `docs/ai-brain/FINAL_REPORT.md`.

Commit/tag: pending final Step 8 local tag.
