# Secrets Rotation Record

## API_KEY

Rotation performed on 2026-09-28. The new value is stored only in `backend/.env`, whose mode is `600`. No key value is recorded here, in source, or in commits. The previous value is absent from repository source after a count-only scan. `backend/.env.example` and first-run setup scripts use placeholders.

Consumers use the shared `config.apiKey`; there are no per-consumer copies:

- `backend/config.js`: reads `API_KEY` from environment and fails startup if it is missing or still a placeholder.
- `backend/server.js`: compares the configured key for decoy collector authorization, webhook authorization, and decoy adapter authorization.
- `backend/decoy-server.js`: sends the configured key on decoy event and route/schema adapter requests.
- `backend/ai/local-ai.js` and `backend/ai/llm-client.js`: use `LOCAL_AI_API_KEY`, a separate optional local model credential, not `API_KEY`.

Optional external AI provider keys are entered by an administrator in the AI Brain Config panel. They are encrypted in the SQLite database with the installation-specific `backend/.env.ai-provider-key` file; back up and restore both together. The key is never returned by the settings API.

## User Passwords

Three new random passwords were generated into `~/soc_new_credentials.txt` with mode `600`. `backend/scripts/reset-user-password.js` hashes and updates only the existing admin, analyst, and viewer rows after checking that the users table contains exactly those three accounts. The utility was not run. Current database user count remains three; password rotation remains a manual action.

## Manual Actions

- Rotate `ZABBIX_PASS` in `backend/.env` before any push. Its current value matched the former source fallback. It is not copied into this document or source.
- Review whether commit `e5dfd39` reached the remote. No remote-tracking ref contains it locally; no fetch was performed. If it reached the remote, treat DB contents and old user hashes as exposed.
- Run the password reset utility locally only after reviewing it. The credential file is not tracked and its values are never printed by the utility.
