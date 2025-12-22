# agent-cli-to-api

Expose popular **agent CLIs** as a small **OpenAI-compatible** HTTP API (`/v1/*`).

Works great as a local gateway (localhost) or behind a reverse proxy.

Think of it as **LiteLLM for agent CLIs**: you point existing OpenAI SDKs/tools at `base_url`, and choose a backend by `model`.

Supported backends:
- **OpenAI Codex** - defaults to backend `/responses` for vision; falls back to `codex exec`
- **Cursor Agent** - via `cursor-agent` CLI
- **Claude Code** - via CLI or **direct API** (auto-detects `~/.claude/settings.json` config)
- **Gemini** - via CLI or CloudCode direct (set `GEMINI_USE_CLOUDCODE_API=1`)

Why this exists:
- Many tools/SDKs only speak the OpenAI API (`/v1/chat/completions`) — this lets you plug agent CLIs into that ecosystem.
- One gateway, multiple CLIs: pick a backend by `model` (with optional prefixes like `cursor:` / `claude:` / `gemini:`).

## Requirements

- Python 3.10+ (tested on 3.13)
- Install and authenticate the CLI(s) you want to use (`codex`, `cursor-agent`, `claude`, `gemini`)

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

## Run (No `.env` Needed)

Pick a provider and start the gateway:

```bash
uv run agent-cli-to-api codex
uv run agent-cli-to-api gemini
uv run agent-cli-to-api claude
uv run agent-cli-to-api cursor-agent
uv run agent-cli-to-api doctor
```

By default `agent-cli-to-api` does NOT load `.env` implicitly.

Optional auth:

```bash
CODEX_GATEWAY_TOKEN=devtoken uv run agent-cli-to-api codex
```

Custom bind host/port:

```bash
uv run agent-cli-to-api codex --host 127.0.0.1 --port 8000
```

Notes:
- If `CODEX_WORKSPACE` is unset, the gateway creates an empty temp workspace under `/tmp` (so you don't need to configure a repo path).
- When you start with a fixed provider (e.g. `... gemini`), the client-sent `model` string is accepted but ignored by default (gateway uses the provider's default model).
- Each provider still requires its own local CLI login state (no API key is required for Codex / Gemini CloudCode / Claude OAuth).
- **Claude auto-detects** `~/.claude/settings.json` and uses direct API mode if `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL` are configured.
- `uv run agent-cli-to-api cursor-agent` defaults to Cursor Auto routing (`CURSOR_AGENT_MODEL=auto`). If you want faster responses, run with `--preset cursor-fast`.
- When running in an interactive terminal (TTY), the gateway enables colored logs and Markdown rendering by default. To disable: `CODEX_RICH_LOGS=0` or `CODEX_LOG_RENDER_MARKDOWN=0`.

Quick smoke test (optional):

```bash
# In another terminal, run:
#   uv run agent-cli-to-api codex
# Then:
BASE_URL=http://127.0.0.1:8000/v1 ./scripts/smoke.sh
# If you enabled auth:
TOKEN=devtoken BASE_URL=http://127.0.0.1:8000/v1 ./scripts/smoke.sh
```

## API

- `GET /healthz`
- `GET /debug/config` (effective runtime config; requires auth if `CODEX_GATEWAY_TOKEN` is set)
- `GET /v1/models`
- `POST /v1/chat/completions` (supports `stream`)

Tip: any OpenAI SDK that supports `base_url` should work by pointing it at this server.

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

### Example (vision / screenshot)

When `CODEX_LOG_MODE=full` (or `CODEX_LOG_EVENTS=1`), the gateway logs `image[0] ext=... bytes=...` and `decoded_images=N` so you can confirm images are being received/decoded.

```bash
python - <<'PY' > /tmp/payload.json
import base64, json
img_b64 = base64.b64encode(open("screenshot.png","rb").read()).decode()
print(json.dumps({
  "model": "gpt-5-codex",
  "stream": False,
  "messages": [{
    "role": "user",
    "content": [
      {"type": "text", "text": "读取图片里的文字，只输出文字本身"},
      {"type": "image_url", "image_url": {"url": "data:image/png;base64," + img_b64}},
    ],
  }],
}))
PY

curl -s http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer devtoken" \
  -d @/tmp/payload.json
```

### OpenAI SDK examples

Python:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="devtoken")
resp = client.chat.completions.create(
    model="gpt-5.2",
    messages=[{"role": "user", "content": "Hi"}],
)
print(resp.choices[0].message.content)
```

TypeScript:

```ts
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://127.0.0.1:8000/v1",
  apiKey: process.env.CODEX_GATEWAY_TOKEN ?? "devtoken",
});

const resp = await client.chat.completions.create({
  model: "gpt-5.2",
  messages: [{ role: "user", content: "Hi" }],
});

console.log(resp.choices[0].message.content);
```

<details>
<summary><strong>Advanced (Optional): .env / env vars / multi-provider / tunnels</strong></summary>

### Use `.env`

```bash
cp .env.example .env
uv run agent-cli-to-api codex --env-file .env
```

Tip: you can also opt-in to loading `.env` from the current directory with `--auto-env`.

### Prettier terminal logs (optional)

Enable colored logs (Rich handler):

```bash
export CODEX_RICH_LOGS=1
uv run agent-cli-to-api codex
```

Render assistant output as Markdown in the terminal (best-effort; prints a separate block to stderr):

```bash
export CODEX_LOG_RENDER_MARKDOWN=1
uv run agent-cli-to-api codex
```

### Presets

```bash
export CODEX_PRESET=codex-fast
uv run agent-cli-to-api codex
```

Supported presets:
- `codex-fast`
- `autoglm-phone`
- `cursor-auto`
- `cursor-fast` (Cursor model pinned for speed)
- `gemini-cloudcode` (defaults to `gemini-3-flash-preview`)
- `claude-oauth`
- `gemini-cloudcode`

### Claude direct API (recommended)

The gateway **auto-detects** your Claude CLI configuration from `~/.claude/settings.json`:

```bash
# If you have Claude CLI configured with a custom API endpoint (e.g. 小米 MiMo, 腾讯混元, etc.)
# Just run - no extra config needed:
uv run agent-cli-to-api claude
```

The gateway will automatically:
1. Read `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL` from `~/.claude/settings.json`
2. Use direct HTTP API calls (fast, ~0ms gateway overhead)
3. Log timing breakdown: `auth_ms`, `prepare_ms`, `api_latency_ms`

**Alternative: Claude OAuth (Anthropic official)**

```bash
uv run python -m codex_gateway.claude_oauth_login
CLAUDE_USE_OAUTH_API=1 uv run agent-cli-to-api claude
```

### Multi-provider routing

Use `CODEX_PROVIDER=auto` and select providers per-request by prefixing `model`:
- Codex: `"gpt-5.2"`
- Cursor: `"cursor:<model>"`
- Claude: `"claude:<model>"`
- Gemini: `"gemini:<model>"`

### `uvx` (no venv)

```bash
uvx --from git+https://github.com/leeguooooo/agent-cli-to-api agent-cli-to-api codex
```

### Cloudflare Tunnel

```bash
CODEX_GATEWAY_TOKEN=devtoken uv run agent-cli-to-api codex
cloudflared tunnel --url http://127.0.0.1:8000
```

For advanced env vars, see `.env.example` and `codex_gateway/config.py`.

</details>

## Keywords (SEO)

OpenAI-compatible API, chat completions, SSE streaming, agent gateway, CLI to API proxy, Codex CLI, Cursor Agent, Claude Code, Gemini CLI.

## Security notes

You are exposing an agent that can read files and run commands depending on `CODEX_SANDBOX`.
Keep it private by default, use a token, and run in an isolated environment when deploying.

## Logging & Performance Diagnosis

The gateway provides detailed timing logs to help diagnose latency:

```
INFO  claude-oauth request: url=https://api.example.com/v1/messages model=xxx auth_ms=0 prepare_ms=0
INFO  claude-oauth response: status=200 api_latency_ms=2886 parse_ms=0 total_ms=2887
```

| Metric | Description |
|--------|-------------|
| `auth_ms` | Time to load/refresh credentials |
| `prepare_ms` | Time to build request payload |
| `api_latency_ms` | **Upstream API response time** (main bottleneck) |
| `parse_ms` | Time to parse response |
| `total_ms` | Total gateway processing time |

If `api_latency_ms` ≈ `total_ms`, the latency is entirely from the upstream API (not the gateway).

### Log modes

```bash
CODEX_LOG_MODE=summary  # one line per request (default)
CODEX_LOG_MODE=qa       # show Q (question) and A (answer)
CODEX_LOG_MODE=full     # full prompt + response
```

## Performance notes (important)

If your normal `~/.codex/config.toml` has many `mcp_servers.*` entries, **Codex will start them for every `codex exec` call**
and include their tool schemas in the prompt. This can add **seconds of startup time** and **10k+ prompt tokens** per request.

For an HTTP gateway, it’s usually best to run Codex with a minimal config (no MCP servers).

By default the gateway uses your system `~/.codex` (so auth stays in sync).
If you want a minimal, isolated config (no MCP servers), set `CODEX_CLI_HOME` to a gateway-local directory.
On first run it will try to copy `~/.codex/auth.json` into that directory (so you don’t have to).

If you want to set it up manually or customize it:

```bash
export CODEX_CLI_HOME=$PWD/.codex-gateway-home
mkdir -p "$CODEX_CLI_HOME/.codex"
cp ~/.codex/auth.json "$CODEX_CLI_HOME/.codex/auth.json"   # or set CODEX_API_KEY instead
cat > "$CODEX_CLI_HOME/.codex/config.toml" <<'EOF'
model = "gpt-5.2"
model_reasoning_effort = "low"

[projects."/path/to/your/workspace"]
trust_level = "trusted"
EOF
```
