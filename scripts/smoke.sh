#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000/v1}"
TOKEN="${TOKEN:-${CODEX_GATEWAY_TOKEN:-}}"
MODEL="${MODEL:-gpt-5.2}"

AUTH_ARGS=()
if [[ -n "${TOKEN}" ]]; then
  AUTH_ARGS=(-H "Authorization: Bearer ${TOKEN}")
fi

echo "[smoke] GET ${BASE_URL%/v1}/healthz"
curl -sS "${BASE_URL%/v1}/healthz" "${AUTH_ARGS[@]}" | cat
echo

echo "[smoke] GET ${BASE_URL}/models"
curl -sS "${BASE_URL}/models" "${AUTH_ARGS[@]}" | head -c 800
echo
echo

echo "[smoke] POST ${BASE_URL}/chat/completions (non-stream)"
curl -sS "${BASE_URL}/chat/completions" \
  -H "Content-Type: application/json" \
  "${AUTH_ARGS[@]}" \
  -d "{\"model\":\"${MODEL}\",\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}]}" | head -c 800
echo
echo

echo "[smoke] POST ${BASE_URL}/chat/completions (stream; showing first 40 lines)"
# `head` will close the pipe early; curl exits with 23 (write error). Treat that as success.
set +e
curl -sS -N "${BASE_URL}/chat/completions" \
  -H "Content-Type: application/json" \
  "${AUTH_ARGS[@]}" \
  -d "{\"model\":\"${MODEL}\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Stream OK\"}]}" 2>/dev/null | head -n 40
STATUS=${PIPESTATUS[0]}
set -e
if [[ "${STATUS}" -ne 0 && "${STATUS}" -ne 23 ]]; then
  exit "${STATUS}"
fi
echo

echo "[smoke] done"
