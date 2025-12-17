# agent-cli-to-api

Expose popular **agent CLIs** as a small **OpenAI-compatible** HTTP API (`/v1/*`).

Works great as a local gateway (localhost) or behind a reverse proxy.

Think of it as **LiteLLM for agent CLIs**: you point existing OpenAI SDKs/tools at `base_url`, and choose a backend by `model`.

Supported backends:
- OpenAI Codex (defaults to backend `/responses` for vision; falls back to `codex exec`)
- Cursor Agent CLI (`cursor-agent`)
- Claude Code CLI (`claude`) or Claude OAuth direct (set `CLAUDE_USE_OAUTH_API=1`)
- Gemini CLI (`gemini`) or Gemini CloudCode direct (set `GEMINI_USE_CLOUDCODE_API=1`)

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

### Presets

```bash
export CODEX_PRESET=codex-fast
uv run agent-cli-to-api codex
```

Supported presets:
- `codex-fast`
- `autoglm-phone`
- `cursor-auto`
- `claude-oauth`
- `gemini-cloudcode`

### Claude OAuth direct (no API key)

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
