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

External backup: `/home/gurudev/backups/pbl_3-baseline-20260928-062031.tar.gz` (19 MiB; excludes `node_modules`, `*.gguf`, and `llamafile*`).

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

Limitations: outcomes mature when analysis runs or the metrics endpoint is read; no background evaluator is scheduled. The learning toggle trains only from observed telemetry outcomes, not analyst feedback. Commit/tag: not committed; existing `ai-step4` tag verified.

### Steps 6-8

Status: Not started. Update after each completed step with files, tests, commit/tag, and open issues.
