# codex-api

Expose `codex exec` as a small OpenAI-compatible HTTP API (local or deployable).

## Requirements

- Python 3.10+ (tested on 3.13)
- `codex` CLI installed and authenticated on the machine that runs this server

## Install

### Option A: uv (recommended)

```bash
uv sync
```

### Option B: pip

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

By default it only binds to localhost (`127.0.0.1`) and uses `--sandbox read-only`.

```bash
export CODEX_WORKSPACE=/path/to/your/workspace
export CODEX_GATEWAY_TOKEN=devtoken   # optional but recommended
uv run uvicorn main:app --host 127.0.0.1 --port 8000
```

If you installed via pip + activated a venv:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

To allow “online access”, bind to `0.0.0.0` and put it behind a reverse proxy / firewall:

```bash
uv run uvicorn main:app --host 0.0.0.0 --port 8000
```

## API

- `GET /healthz`
- `GET /v1/models`
- `POST /v1/chat/completions` (supports `stream`)

### Example (non-stream)

```bash
curl -s http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer devtoken" \
  -d '{
    "model":"gpt-5.2",
    "messages":[{"role":"user","content":"总结一下这个仓库结构"}],
    "reasoning": {"effort":"low"},
    "stream": false
  }'
```

### Example (stream)

```bash
curl -N http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer devtoken" \
  -d '{
    "model":"gpt-5-codex",
    "messages":[{"role":"user","content":"用一句话解释这个项目的目的"}],
    "stream": true
  }'
```

## Configuration (env vars)

- `CODEX_WORKSPACE`: directory passed to `codex exec --cd`
- `CODEX_CLI_HOME`: override HOME for the `codex` subprocess (use a minimal `~/.codex/config.toml` here to avoid starting MCP servers)
- `CODEX_MODEL`: default model id (default: `gpt-5-codex`)
- `CODEX_MODEL_REASONING_EFFORT`: `low|medium|high|xhigh` (default: `high`)
- `CODEX_SANDBOX`: `read-only` | `workspace-write` | `danger-full-access` (default: `read-only`)
- `CODEX_APPROVAL_POLICY`: `untrusted|on-failure|on-request|never` (default: `never`)
- `CODEX_ENABLE_SEARCH`: `1/0` (default: `0`)
- `CODEX_ADD_DIRS`: comma-separated extra writable dirs (default: empty)
- `CODEX_SKIP_GIT_REPO_CHECK`: `1/0` (default: `1`)
- `CODEX_GATEWAY_TOKEN`: if set, require `Authorization: Bearer ...`
- `CODEX_TIMEOUT_SECONDS`: (default: `600`)
- `CODEX_MAX_CONCURRENCY`: (default: `2`)
- `CODEX_MAX_PROMPT_CHARS`: (default: `200000`)
- `CODEX_CORS_ORIGINS`: comma-separated origins for CORS (default: empty/disabled)

## Security notes

You are exposing an agent that can read files and run commands depending on `CODEX_SANDBOX`.
Keep it private by default, use a token, and run in an isolated environment when deploying.

## Performance notes (important)

If your normal `~/.codex/config.toml` has many `mcp_servers.*` entries, **Codex will start them for every `codex exec` call**
and include their tool schemas in the prompt. This can add **seconds of startup time** and **10k+ prompt tokens** per request.

For an HTTP gateway, it’s usually best to run Codex with a minimal config (no MCP servers):

```bash
mkdir -p .codex-gateway-home/.codex
cp ~/.codex/auth.json .codex-gateway-home/.codex/auth.json   # or set CODEX_API_KEY instead
cat > .codex-gateway-home/.codex/config.toml <<'EOF'
model = "gpt-5.2"
model_reasoning_effort = "low"

[projects."/path/to/your/workspace"]
trust_level = "trusted"
EOF

export CODEX_CLI_HOME=$PWD/.codex-gateway-home
```
