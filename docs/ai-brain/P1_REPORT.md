# P1 Local Model Measurement

Status: Needs manual measurement run. Model inference validation remains mocked in automated tests.

## Environment Findings

- Bundled runtime: llamafile 0.10.6; `--help` completed and reports server/host/port, context, token, streaming, and reasoning controls.
- Existing launcher `start-ai.sh` binds to `127.0.0.1:8090`, uses CPU inference, context 4096, and the local Qwen GGUF. Existing `stop-ai.sh` is present.
- Existing service was already running when inspected. `ss` showed only `127.0.0.1:8090`; `/health` returned success.
- Model file size: 2,497,280,256 bytes. Binary size: 368,094,430 bytes.
- Process snapshot before the benchmark request: RSS 4,216 KiB, about 15% CPU. During the request: RSS 586,212 KiB, about 20% CPU, sampled after approximately three minutes. RSS is only the resident portion; the multi-gigabyte model is memory mapped.

## Attempt

A synthetic 25-event streaming chat request with a `<think>` section and a 192-token cap was sent only to `127.0.0.1:8090`. The client was stopped after its 120-second tool deadline without printing or storing model text. No first-delta, token-rate, or completion metric was obtained, so this attempt is not a valid latency measurement.

## Reproducible Measurement

With the local server already running, execute from the repository root:

```sh
P1_MODEL_PID=<local-llamafile-pid> node backend/scripts/measure-local-model.js
```

The script enforces a loopback HTTP endpoint, uses a 25-event synthetic prompt, caps output at 96 tokens by default, times out by 120 seconds, and prints timings/counters only. It never prints model response text. For another bounded run, set `P1_MAX_TOKENS` (32-192) or `P1_TIMEOUT_MS` (30,000-180,000).

## Deferred Decisions

Do not choose `ctx`, `max_tokens`, or event caps from the failed measurement. Keep existing safe settings unchanged until a successful manual run records first-delta latency, total latency, output rate, peak RSS, and CPU. Automated LLM tests use the existing mocked HTTP server.
