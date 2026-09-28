#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE="$ROOT_DIR/Local AI /ai.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "Local AI PID file not found; no managed server is running."
  exit 0
fi

PID=$(cat "$PID_FILE")
case "$PID" in
  ''|*[!0-9]*)
    echo "Invalid PID file: $PID_FILE" >&2
    exit 1
    ;;
esac

if kill -0 "$PID" 2>/dev/null; then
  PROCESS_COMMAND=$(ps -p "$PID" -o args= 2>/dev/null || true)
  case "$PROCESS_COMMAND" in
    *"$ROOT_DIR/Local AI /llamafile-0.10.6"*)
      kill "$PID"
      echo "Stopped Local AI (PID $PID)."
      ;;
    *)
      echo "PID $PID is not the bundled Local AI process; leaving it untouched."
      ;;
  esac
else
  echo "Local AI process $PID was not running."
fi
rm -f "$PID_FILE"
