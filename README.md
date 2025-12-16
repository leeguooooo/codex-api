# agent-cli-to-api

Expose popular **agent CLIs** as a small **OpenAI-compatible** HTTP API (`/v1/*`).

Works great as a local gateway (localhost) or behind a reverse proxy.

Think of it as **LiteLLM for agent CLIs**: you point existing OpenAI SDKs/tools at `base_url`, and choose a backend by `model`.

Supported backends:
- OpenAI Codex (defaults to backend `/responses` for vision; falls back to `codex exec`)
- Cursor Agent CLI (`cursor-agent`)
- Claude Code CLI (`claude`)
- Gemini CLI (`gemini`)

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

## Run

By default it only binds to localhost (`127.0.0.1`) and uses `--sandbox read-only`.

### With `.env` + helper script (recommended)

```bash
cp .env.example .env
./scripts/serve.sh
```

### With the `agent-cli-to-api` CLI

```bash
cp .env.example .env
uv run agent-cli-to-api
```

By default it auto-loads `.env` from the current directory, or falls back to the `codex-api/.env` next to the installed package (and prints which one it loaded).

### With `uvx` (no venv, no clone)

You still need the agent CLI(s) (`codex`, `cursor-agent`, `claude`, `gemini`) installed on your system `PATH`.

```bash
cp .env.example .env
uvx --from git+https://github.com/leeguooooo/agent-cli-to-api --env-file .env agent-cli-to-api
```

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

### Expose to the internet (Cloudflare Tunnel)

If you want to provide an “online API” without binding to `0.0.0.0`, use a tunnel and keep the server on localhost:

```bash
export CODEX_GATEWAY_TOKEN=devtoken
uv run uvicorn main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

Keep `CODEX_GATEWAY_TOKEN` enabled, and consider Cloudflare Access / IP allowlists before exposing any sandbox other than `read-only`.

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

When `CODEX_DEBUG_LOG=1`, the gateway logs `image[0] ext=... bytes=...` and `decoded_images=N` so you can confirm images are being received/decoded.

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

## Configuration (env vars)

- `CODEX_WORKSPACE`: directory passed to `codex exec --cd`
- `CODEX_CLI_HOME`: override HOME for the `codex` subprocess (default: `./.codex-gateway-home`)
- `CODEX_USE_SYSTEM_CODEX_HOME`: `1/0` (default: `0`) use your normal `~/.codex` config instead of the gateway home
- `CODEX_USE_CODEX_RESPONSES_API`: `1/0` (default: `0`) use the Codex backend `/responses` API for all Codex requests (vision requests auto-use it)
  - Note: `/responses` mode sets `tool_choice=none` (no MCP/tools); use `codex exec` for tool-driven coding tasks.
- `CODEX_CODEX_BASE_URL`: Codex backend base URL (default: `https://chatgpt.com/backend-api/codex`)
- `CODEX_CODEX_VERSION`: Codex backend `Version` header (default: `0.21.0`)
- `CODEX_CODEX_USER_AGENT`: Codex backend `User-Agent` header (default: `codex_cli_rs/...`)
- `CODEX_MODEL`: default model id (default: `gpt-5-codex`)
- `CODEX_MODEL_ALIASES`: JSON map of request model -> real model (e.g. `{"autoglm-phone":"gpt-5.2"}`)
- `CODEX_ADVERTISED_MODELS`: comma-separated list for `GET /v1/models` (defaults to `CODEX_MODEL`)
- `CODEX_PROVIDER`: `auto|codex|cursor-agent|claude|gemini` (default: `auto`) choose which CLI/provider this gateway uses
  - If not `auto`, the gateway ignores request-side provider prefixes like `cursor:...` by default (operator-controlled).
- `CODEX_ALLOW_CLIENT_PROVIDER_OVERRIDE`: `1/0` (default: `0`) allow request-side provider prefixes to override `CODEX_PROVIDER`
- `CODEX_ALLOW_CLIENT_MODEL_OVERRIDE`: `1/0` (default: `0`) allow the client to override the provider-specific model via request `model`
- `CODEX_MODEL_REASONING_EFFORT`: `low|medium|high|xhigh` (default: `low`)
- `CODEX_FORCE_REASONING_EFFORT`: if set, overrides any request-provided effort (e.g. force `low` for automation)
- `CODEX_SANDBOX`: `read-only` | `workspace-write` | `danger-full-access` (default: `read-only`)
- `CODEX_APPROVAL_POLICY`: `untrusted|on-failure|on-request|never` (default: `never`)
- `CODEX_DISABLE_SHELL_TOOL`: `1/0` (default: `1`) disable Codex shell tool so responses stay "model-like" and avoid surprise command executions
- `CODEX_DISABLE_VIEW_IMAGE_TOOL`: `1/0` (default: `1`) disable Codex `view_image_tool` so models prefer native vision (reduces MCP tool calls; helpful for screenshot-based agents like Open-AutoGLM)
- `CODEX_ENABLE_SEARCH`: `1/0` (default: `0`)
- `CODEX_ADD_DIRS`: comma-separated extra writable dirs (default: empty)
- `CODEX_SKIP_GIT_REPO_CHECK`: `1/0` (default: `1`)
- `CODEX_GATEWAY_TOKEN`: if set, require `Authorization: Bearer ...`
- `CODEX_TIMEOUT_SECONDS`: (default: `600`)
- `CODEX_MAX_CONCURRENCY`: (default: `2`)
- `CODEX_MAX_PROMPT_CHARS`: (default: `200000`)
- `CODEX_SUBPROCESS_STREAM_LIMIT`: asyncio stream limit for subprocess pipes (default: `16777216`)
- `CODEX_CORS_ORIGINS`: comma-separated origins for CORS (default: empty/disabled)
- `CODEX_SSE_KEEPALIVE_SECONDS`: send SSE keep-alives to prevent client read timeouts (default: `2`)
- `CODEX_STRIP_ANSWER_TAGS`: `1/0` (default: `1`) strip `<think>/<answer>` tags for action-parsing clients (e.g. Open-AutoGLM)
- `CODEX_ENABLE_IMAGE_INPUT`: `1/0` (default: `1`) decode OpenAI-style `image_url` parts and pass them to `codex exec --image`
- `CODEX_MAX_IMAGE_COUNT`: (default: `4`)
- `CODEX_MAX_IMAGE_BYTES`: (default: `8388608`)
- `CODEX_DEBUG_LOG`: `1/0` (default: `0`) log prompt/events/response to server logs
- `CODEX_LOG_MAX_CHARS`: truncate long log lines (default: `4000`)

## Multi-provider (optional)

If you have other agent CLIs installed, you can either:

- Force a single provider via `CODEX_PROVIDER=codex|cursor-agent|claude|gemini` (recommended for “API callers can’t choose agent”).
  - For Cursor “auto”: set `CURSOR_AGENT_MODEL=auto` and keep `CODEX_ALLOW_CLIENT_MODEL_OVERRIDE=0` so client `model` strings are ignored.
- Or keep `CODEX_PROVIDER=auto` and select providers per-request by prefixing `model`:

- Codex CLI: `"gpt-5.2"` (default) or any Codex model id
- Cursor Agent: `"cursor-agent:<model>"` or `"cursor:<model>"` (e.g. `cursor:sonnet-4-thinking`)
- Claude Code: `"claude:<model>"` or `"claude-code:<model>"` (e.g. `claude:sonnet`)
- Gemini CLI: `"gemini:<model>"` or `"gemini"` (e.g. `gemini:gemini-2.0-flash`)

Optional env vars:

- `CURSOR_AGENT_BIN`, `CLAUDE_BIN`, `GEMINI_BIN`: override the CLI binary names/paths
- `CURSOR_AGENT_API_KEY` / `CURSOR_API_KEY`: Cursor authentication for `cursor-agent`
- `CURSOR_AGENT_MODEL`, `CLAUDE_MODEL`, `GEMINI_MODEL`: default model when the prefix doesn’t include `:<model>`

## Keywords (SEO)

OpenAI-compatible API, chat completions, SSE streaming, agent gateway, CLI to API proxy, Codex CLI, Cursor Agent, Claude Code, Gemini CLI.

## Security notes

You are exposing an agent that can read files and run commands depending on `CODEX_SANDBOX`.
Keep it private by default, use a token, and run in an isolated environment when deploying.

## Performance notes (important)

If your normal `~/.codex/config.toml` has many `mcp_servers.*` entries, **Codex will start them for every `codex exec` call**
and include their tool schemas in the prompt. This can add **seconds of startup time** and **10k+ prompt tokens** per request.

For an HTTP gateway, it’s usually best to run Codex with a minimal config (no MCP servers).

This project **defaults** to a gateway-local HOME at `./.codex-gateway-home` so it doesn’t inherit your global `~/.codex/config.toml`.
On first run it will try to copy `~/.codex/auth.json` into `./.codex-gateway-home/.codex/auth.json` (so you don’t have to).

If you want to set it up manually or customize it:

```bash
mkdir -p .codex-gateway-home/.codex
cp ~/.codex/auth.json .codex-gateway-home/.codex/auth.json   # or set CODEX_API_KEY instead
cat > .codex-gateway-home/.codex/config.toml <<'EOF'
model = "gpt-5.2"
model_reasoning_effort = "low"

[projects."/path/to/your/workspace"]
trust_level = "trusted"
EOF

# Optional override (the default is already ./.codex-gateway-home):
export CODEX_CLI_HOME=$PWD/.codex-gateway-home
```
