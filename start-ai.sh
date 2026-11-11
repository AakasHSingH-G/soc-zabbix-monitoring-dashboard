#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AI_DIR="$ROOT_DIR/Local AI "
MODEL_PATH="$AI_DIR/qwen3-4b-thinking-2507.Q4_K_M.gguf"
BINARY_PATH="$AI_DIR/llamafile-0.10.6"
PID_FILE="$AI_DIR/ai.pid"
LOG_FILE="$AI_DIR/ai.log"
AI_PORT="${LOCAL_AI_PORT:-8090}"
AI_MODEL="${LOCAL_AI_MODEL:-soc-brain}"

if [ ! -x "$BINARY_PATH" ]; then
  echo "llamafile is missing or not executable: $BINARY_PATH" >&2
  exit 1
fi
if [ ! -f "$MODEL_PATH" ]; then
  echo "Qwen model is missing: $MODEL_PATH" >&2
  exit 1
fi
if [ -f "$PID_FILE" ]; then
  EXISTING_PID=$(cat "$PID_FILE" 2>/dev/null || true)
  case "$EXISTING_PID" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "$EXISTING_PID" 2>/dev/null; then
        EXISTING_COMMAND=$(ps -p "$EXISTING_PID" -o args= 2>/dev/null || true)
        case "$EXISTING_COMMAND" in
          *"$BINARY_PATH"*)
            echo "Local AI is already running (PID $EXISTING_PID)."
            exit 0
            ;;
          *) echo "Discarding stale Local AI PID file (PID was reused)." ;;
        esac
      fi
      ;;
  esac
  rm -f "$PID_FILE"
fi

nohup "$BINARY_PATH" --server -m "$MODEL_PATH" --host 127.0.0.1 --port "$AI_PORT" --alias "$AI_MODEL" --device none --gpu-layers 0 --reasoning off --reasoning-budget 0 --reasoning-format none -c 4096 >"$LOG_FILE" 2>&1 &
echo "$!" >"$PID_FILE"
echo "Local AI starting on http://127.0.0.1:$AI_PORT (PID $(cat "$PID_FILE"))."
echo "Log: $LOG_FILE"
