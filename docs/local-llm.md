# Local and self-hosted models

LG-SOTF can triage with a model that runs on your own hardware: Ollama, vLLM
or any server that speaks the OpenAI chat completions API (llama.cpp
`llama-server`, LM Studio, LocalAI, TGI, ...). Prompts, alert data and model
answers then never leave your network, and there is no per-token bill.

This page covers the setup, the endpoint rules, how structured output works
with local models, which models to start with, how to measure a model on your
own alerts before trusting it, and the trade-offs.

## Providers

| `llm.provider` | For | API key | Default `llm.base_url` | Structured output | Usage cost |
|---|---|---|---|---|---|
| `anthropic` | Claude API or a gateway | required | `https://api.anthropic.com` | native (structured outputs / tools) | price table |
| `openai` | OpenAI, or a **paid** OpenAI-compatible cloud API | required | OpenAI | tool calling | price table |
| `gemini` | Gemini API | required | Google | tool calling | price table |
| `ollama` | Ollama | optional | `http://ollama:11434/v1` (the compose overlay) | `llm.structured_output` | 0 |
| `openai_compatible` | vLLM, llama.cpp, LM Studio, ... that **you** run | optional | none: required | `llm.structured_output` | 0 |
| `fake` | tests and demos | none | - | synthesised | 0 |

`ollama` and `openai_compatible` are the self-hosted providers. Both use the
OpenAI client with `max_tokens` (which every compatible server accepts) and
never the Responses API. Without `llm.api_key` they send a placeholder bearer
token: an `OPENAI_API_KEY` in the environment is never forwarded to a local
server. Use `openai` with `llm.base_url` for a hosted service that bills you,
so its usage is priced.

## Setup

### Ollama inside the stack (recommended)

`docker/docker-compose.ollama.yml` adds an `ollama` service that is attached
only to an internal network: it publishes no port and has no route out of the
host. The api and worker are switched to `provider=ollama`.

```sh
# 1. choose the model(s) (fast tier, and optionally a larger deep tier)
echo "OLLAMA_MODEL=qwen3:8b" >> .env
echo "OLLAMA_DEEP_MODEL=qwen3:14b" >> .env      # optional; default = OLLAMA_MODEL

C="docker compose -f docker/docker-compose.yml -f docker/docker-compose.ollama.yml"
# production-like: -f docker/docker-compose.yml -f docker/docker-compose.prod.yml -f docker/docker-compose.ollama.yml

# 2. download the models into the ollama-models volume (the only step that needs internet)
$C --profile ollama-pull run --rm ollama-pull

# 3. start (or recreate) the stack
$C up -d --wait
```

Or in one go with the quickstart: `scripts/quickstart.sh --ollama qwen3:8b`
(docs/quickstart.md). For an air-gapped host, carry the image and the models
over with `scripts/airgap/` (docs/air-gapped.md).

Overlay variables: `OLLAMA_MODEL`, `OLLAMA_DEEP_MODEL`,
`OLLAMA_STRUCTURED_OUTPUT`, `OLLAMA_CONTEXT_LENGTH` (default 16384),
`OLLAMA_NUM_PARALLEL` (default 2; also the app's per-tier concurrency),
`OLLAMA_TIMEOUT_S` (default 600), `OLLAMA_KEEP_ALIVE` (default 24h) and
`OLLAMA_IMAGE`. The image is pinned by tag and digest
(`ollama/ollama:0.35.0@sha256:2a6e...`). For an NVIDIA GPU install the NVIDIA
Container Toolkit and uncomment the `deploy:` block of the `ollama` service;
for AMD use `OLLAMA_IMAGE=ollama/ollama:0.35.0-rocm` and pass `/dev/kfd` and
`/dev/dri`.

**Context length matters.** Triage prompts reach about 10,000 tokens (the alert
block is capped by `llm.max_input_chars`, 24,000 characters by default, plus
instructions and the schema). Ollama silently drops the start of a prompt that
exceeds its context window, which removes the instructions. The overlay sets
`OLLAMA_CONTEXT_LENGTH=16384`; with a server of your own set at least that, or
lower `llm.max_input_chars`.

### Ollama on the host, outside compose

```sh
ollama pull qwen3:8b
LG_SOTF_LLM__PROVIDER=ollama
LG_SOTF_LLM__BASE_URL=http://host.docker.internal:11434/v1   # from containers (add extra_hosts: host-gateway on Linux)
# LG_SOTF_LLM__BASE_URL=http://127.0.0.1:11434/v1           # from a process on the host
LG_SOTF_LLM__FAST__MODEL=qwen3:8b
LG_SOTF_LLM__DEEP__MODEL=qwen3:8b
LG_SOTF_LLM__PROMPT_CACHING=false
```

Start Ollama with `OLLAMA_CONTEXT_LENGTH=16384` (see above).

### vLLM (throughput, multi-GPU)

```sh
docker run --gpus all -p 127.0.0.1:8000:8000 vllm/vllm-openai:<tag> \
    --model Qwen/Qwen3-32B --max-model-len 16384 --api-key "$VLLM_API_KEY"
```

```sh
LG_SOTF_LLM__PROVIDER=openai_compatible
LG_SOTF_LLM__BASE_URL=http://vllm.internal:8000/v1     # or https://... behind TLS
LG_SOTF_LLM__API_KEY=$VLLM_API_KEY                      # optional; set it when vLLM uses --api-key
LG_SOTF_LLM__FAST__MODEL=Qwen/Qwen3-32B
LG_SOTF_LLM__DEEP__MODEL=Qwen/Qwen3-32B
LG_SOTF_LLM__STRUCTURED_OUTPUT=json_schema              # guided decoding
LG_SOTF_LLM__PROMPT_CACHING=false
```

vLLM's guided decoding enforces the JSON schema, so `json_schema` is the right
method. Keep `--max-model-len` at 16384 or more. For llama.cpp
(`llama-server --jinja -c 16384`) and LM Studio the same settings apply; if a
server rejects `response_format: json_schema`, use `json_mode`.

### Check it

**Settings → Language model → Test model** in the web UI (or
`POST /api/v1/tenant/llm/test`, docs/api.md) sends a tiny structured request
to both tiers and shows the model, latency and, on failure, a hint:
`HTTP 404` usually means the model was not pulled, `connection` that the
server is not reachable from the api container, `invalid_output` that the
model cannot produce the JSON the platform needs (try `json_schema`, a larger
model or a higher `max_tokens`).

## Where the model may be

`llm.base_url` decides where every prompt goes, so it is checked for every
provider before a model is built and by the production safety checks:

* `https://` anywhere; `http://` only when the host is **internal**: a
  loopback or private address (RFC 1918, 100.64.0.0/10, `fc00::/7`),
  `localhost`, a single-label name (a compose service such as `ollama` or
  `vllm`) or a name under `.internal` (`host.docker.internal`,
  `gpu01.lab.internal`). Plain HTTP to anything else would carry alert data
  in clear text across networks you do not control.
* Link-local and cloud metadata addresses (`169.254.169.254`, `fe80::/10`),
  multicast, unspecified and reserved addresses are refused whatever the
  scheme; so are credentials in the URL (`llm.api_key` is the place for a
  key).
* Names are classified by their spelling, not resolved. Point
  `openai_compatible` at a name you control.

## Structured output

Every agent asks the model for a JSON object that matches a schema (the triage
verdict, the analysis conclusion, ...). Cloud models do this with native
features. Many local models lack reliable tool calling, so the self-hosted
providers default to JSON text, chosen with `llm.structured_output`:

| Value | Request | Best for |
|---|---|---|
| `json_schema` (`auto`) | `response_format: {type: json_schema, schema}` and the schema in the system prompt | Ollama 0.5+, vLLM, llama.cpp: decoding is constrained to the schema |
| `json_mode` | `response_format: {type: json_object}` and the schema in the system prompt | servers without JSON-schema support |
| `function_calling` | a forced tool call (LangChain) | servers with a tool parser for the model (vLLM `--enable-auto-tool-choice`) |

With the JSON-text methods the reply is parsed tolerantly: a `<think>` block
(reasoning models), a markdown code fence and prose around the object are
ignored. If the object still does not validate, the platform makes **exactly
one repair call**: the same conversation plus a user turn that lists the
failed field locations and error types (never values) and quotes the previous
reply as untrusted data (escaped, inside `<previous_reply>`). A second failure
is an `invalid_output` error and the agent falls back to rules, as it does for
any model error. Truncated output (`finish_reason=length`) and refusals are
not retried. Both calls are metered.

The untrusted-data boundary is the same as with cloud models: alert content
only ever appears inside `<alert_data>`/`<tool_data>` blocks with `<` and `>`
escaped, the schema is appended to the trusted system prompt, and no model
answer is trusted for a decision without rule corroboration.

## Which model

Starting points, not recommendations: measure them on your own alerts (next
section). Sizes are for 4-bit (Q4_K_M) weights as Ollama ships them; add room
for the context (KV cache, about 1-2 GB at 16k tokens for an 8B model).

| Hardware | Fast tier | Deep tier | Notes |
|---|---|---|---|
| CPU only, 16-32 GB RAM | `qwen3:4b` (~2.5 GB) | `qwen3:8b` (~5 GB) | Tens of seconds per call; a lab or a few dozen alerts a day. Raise `OLLAMA_TIMEOUT_S`. |
| 1 GPU, 8-12 GB VRAM | `qwen3:8b` | `qwen3:8b` | One model for both tiers avoids reloading. |
| 1 GPU, 16-24 GB VRAM | `qwen3:8b` | `qwen3:14b` (~9 GB) or `gpt-oss:20b` (~14 GB) | Keep both loaded: `OLLAMA_MAX_LOADED_MODELS=2` if memory allows. |
| 48 GB VRAM (1-2 GPUs) | `qwen3:14b` | `qwen3:32b` (~20 GB) or `qwen3:30b` (MoE, fast) | |
| 80 GB+ (H100/A100 class) | vLLM `Qwen/Qwen3-32B` | vLLM `openai/gpt-oss-120b` | vLLM for concurrency and throughput. |

Prefer instruction-tuned models with good JSON adherence; the Qwen3, gpt-oss,
Gemma 3/4 and Llama 3.1+ families all work with `json_schema`. Reasoning
models ("thinking") produce better analyses but spend output tokens: keep
`llm.deep.max_tokens` generous (the overlay uses 8192).

## Evaluate a model on your data

Never switch the model that closes alerts without measuring it. `lg-sotf eval`
(docs/evaluation.md) replays a labelled dataset through the real pipeline and
reports missed malicious alerts, auto-closed noise, escalations, errors,
tokens and latency; a thresholds file turns the report into a pass/fail gate.

```sh
# A dedicated evaluation database and Redis DB, migrated once (docs/evaluation.md).
export LG_SOTF_DATABASE__URL=postgresql://soc:<password>@127.0.0.1:5432/soc_eval
export LG_SOTF_REDIS__URL=redis://127.0.0.1:6379/7

# 1. Baseline: your current model on your own labelled alerts
lg-sotf eval --dataset ~/lg-sotf-eval/acme-feedback.jsonl --report ~/lg-sotf-eval/baseline.json

# 2. The candidate local model, same dataset, compared with the baseline
LG_SOTF_LLM__PROVIDER=ollama \
LG_SOTF_LLM__BASE_URL=http://127.0.0.1:11434/v1 \
LG_SOTF_LLM__FAST__MODEL=qwen3:8b LG_SOTF_LLM__DEEP__MODEL=qwen3:14b \
LG_SOTF_LLM__FAST__TIMEOUT_S=600 LG_SOTF_LLM__DEEP__TIMEOUT_S=600 \
LG_SOTF_LLM__PROMPT_CACHING=false \
lg-sotf eval --dataset ~/lg-sotf-eval/acme-feedback.jsonl --report ~/lg-sotf-eval/qwen3.json \
    --thresholds ~/lg-sotf-eval/gate.yaml --baseline ~/lg-sotf-eval/baseline.json
```

`docs/tools/export_feedback.sql` builds the dataset from your analysts'
decisions (mind the selection bias described in docs/evaluation.md; add a
labelled sample of auto-closed alerts). Before a real dataset, the shipped
synthetic set (`tests/fixtures/eval/synthetic_v1.jsonl`, with an adversarial
prompt-injection split) is a quick smoke test of a model's JSON adherence and
injection resistance.

What to look at for a local model:

* `malicious_false_negative_rate` (and the `adversarial` split's): must not
  rise against the baseline. Gate it at 0 with `max_increase: 0`.
* `error_rate`: invalid output after the repair turn becomes a rules-only
  assessment. More than a few percent means the model (or method) does not
  follow the schema well; try `json_schema`, a larger model or more
  `max_tokens`.
* `llm_calls_per_alert` against the baseline: repair turns show up here.
* `benign_auto_close_rate` and `escalation_rate`: the analyst time the model
  actually saves.
* `latency_s.p95`: with `worker.concurrency` and `OLLAMA_NUM_PARALLEL` this
  sets your alert throughput. `cost_per_alert_usd` is 0 for local models; your
  real cost is the hardware.

## Metering

Calls to self-hosted models are metered as `local/<model>` (for example
`local/qwen3:8b`) in `/usage/llm`, the dashboard and each alert's
`summary.llm_usage`, at zero cost, so no `llm.price_unknown` warning is logged.
To charge an internal GPU rate back to tenants, price the tagged id:
`LG_SOTF_LLM__PRICES='{"local/qwen3:8b": {"input": 0.05, "output": 0.10}}'`
(USD per million tokens). Token budgets (`llm.daily_token_budget_per_tenant`)
still apply: they bound load as well as spend.

## Trade-offs

* **Quality.** Open models of the sizes above are clearly weaker than frontier
  cloud models at multi-step investigation. Expect more escalations and
  inconclusive verdicts; measure how many before you rely on them. A common
  split is a local fast tier (noise triage) with a cloud deep tier, or the
  reverse for data that must stay on site; the tiers share one provider today,
  so that needs two installs or a gateway.
* **Prompt injection.** Smaller models follow injected instructions more
  easily. The platform's defences (untrusted-data blocks, rule corroboration
  before closing, no auto-close of high/critical alerts, guardrailed response
  actions) do not depend on the model, but check the `adversarial` split.
* **Throughput and latency.** A CPU or a single consumer GPU serves a few
  requests at a time; size `OLLAMA_NUM_PARALLEL`, `worker.concurrency` and the
  timeouts together, and watch `lgsotf_llm_slot_wait_seconds`.
* **Operations.** You own model updates, GPU drivers and capacity. Pin model
  tags (and re-run the evaluation when you change one).
* **Features.** No provider prompt caching and no server-side refusal
  fallback; a refusal escalates the alert as usual.
* **Sovereignty.** Nothing leaves your network, no third-party data
  processing agreement is needed for the model, and the install works fully
  offline (docs/air-gapped.md).
