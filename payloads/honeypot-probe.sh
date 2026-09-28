#!/usr/bin/env bash
set -u

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORTS=(2222 2323 8081)

printf '[*] Probing honeypot at %s\n' "$TARGET_HOST"

for port in "${TARGET_PORTS[@]}"; do
  printf '[+] TCP probe %s:%s\n' "$TARGET_HOST" "$port"
  if command -v nc >/dev/null 2>&1; then
    printf 'HONEYPOT-TEST tcp\n' | nc -w 2 "$TARGET_HOST" "$port" || true
  else
    printf '[!] nc is not installed; skipping TCP probe\n'
  fi
done

if command -v nc >/dev/null 2>&1; then
  printf '[+] SSH signature probe %s:2222\n' "$TARGET_HOST"
  printf 'SSH-2.0-Honeypot-Test\r\n' | nc -w 2 "$TARGET_HOST" 2222 || true

  printf '[+] HTTP probe %s:8081\n' "$TARGET_HOST"
  printf 'GET /honeypot-test HTTP/1.1\r\nHost: honeypot-test\r\nUser-Agent: honeypot-probe/1.0\r\nConnection: close\r\n\r\n' \
    | nc -w 2 "$TARGET_HOST" 8081 || true

  printf '[+] TLS signature probe %s:2323\n' "$TARGET_HOST"
  printf '\026\003\001\000\005\001\000\000\001\000' | nc -w 2 "$TARGET_HOST" 2323 || true
fi

printf '[*] Probe complete. Check /api/security/honeyports for events.\n'