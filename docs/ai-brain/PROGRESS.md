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

## Steps 1-8

Status: Not started. Update this section after each completed step with files, checks, commit/tag, and open issues.
