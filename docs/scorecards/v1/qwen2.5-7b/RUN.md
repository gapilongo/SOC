# Scorecard v1 run: qwen2.5 7B on a local Ollama

The run behind [scorecard.md](scorecard.md). The reports
([synthetic.json](synthetic.json), [phishing.json](phishing.json)) are the
unedited output of `lg-sotf eval`; the scorecard is generated from them.

## Setup

| Item | Value |
|---|---|
| Model | `qwen2.5:7b` from the Ollama library (Qwen2.5 7B Instruct, Q4_K_M, blob `sha256:2bada8a74506`), one model for both tiers |
| Server | Ollama 0.35.0 (the version `docker/docker-compose.ollama.yml` pins), run natively on the host, bound to 127.0.0.1 |
| Server settings | `OLLAMA_CONTEXT_LENGTH=16384`, `OLLAMA_NUM_PARALLEL=1`, `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0` |
| Hardware | Laptop: NVIDIA RTX 4050 Laptop GPU (6 GB), 16 CPU threads, 23 GB RAM, WSL2. 23 of 29 layers fit on the GPU; the rest ran on the CPU |
| Provider | `llm.provider=ollama`, `llm.base_url=http://127.0.0.1:11500/v1`, `llm.structured_output=json_schema`, `llm.prompt_caching=false` |
| Tiers | fast and deep `max_tokens` 2048 / 8192, timeouts 600 s, concurrency 1 (as in the compose overlay) |
| Eval | `lg-sotf eval` defaults: `--isolate splits`, concurrency 1, every item of both sets, no enrichment providers configured |
| Code | lg-sotf 1.2.3 at commit `3026d805` (prompts as shipped in that commit) |

The `ollama` provider is the product's OpenAI-compatible client for
self-hosted servers (docs/local-llm.md); the `openai` provider with a
`base_url` is meant for paid cloud APIs and would price the tokens.

## Commands

```sh
LG_SOTF_LLM__PROVIDER=ollama LG_SOTF_LLM__BASE_URL=http://127.0.0.1:11500/v1 \
LG_SOTF_LLM__STRUCTURED_OUTPUT=json_schema \
LG_SOTF_LLM__FAST__MODEL=qwen2.5:7b LG_SOTF_LLM__DEEP__MODEL=qwen2.5:7b \
LG_SOTF_LLM__FAST__MAX_TOKENS=2048 LG_SOTF_LLM__DEEP__MAX_TOKENS=8192 \
LG_SOTF_LLM__FAST__TIMEOUT_S=600 LG_SOTF_LLM__DEEP__TIMEOUT_S=600 \
LG_SOTF_LLM__FAST__MAX_CONCURRENCY=1 LG_SOTF_LLM__DEEP__MAX_CONCURRENCY=1 \
LG_SOTF_LLM__PROMPT_CACHING=false \
lg-sotf eval --dataset tests/fixtures/eval/synthetic_v1.jsonl --report synthetic.json
# same environment
lg-sotf eval --dataset tests/fixtures/eval/phishing_v1.jsonl --report phishing.json

lg-sotf eval-scorecard synthetic.json phishing.json \
    --output scorecard.md --json scorecard.json --title "Scorecard v1: qwen2.5:7b (local, Ollama)" \
    --prompt-version "prompts as shipped in lg-sotf 1.2.3, commit 3026d805 (no per-prompt hashes yet)" \
    --note "..."   # the hardware and run notes listed in the scorecard
```

## What the run shows

* **No malicious item was closed without a human** on either set (0 of 35,
  0 of 24). With these sample sizes that bounds the miss rate below about
  10% and 14% (95%), no tighter.
* **The model itself was fooled; the policy was not.** Its verdict was
  `benign` for 8 items labelled malicious, all from the prompt-injection and
  adversarial scenarios: `adv-001`, `adv-002`, `adv-004`, `adv-006` and
  `phish-033`, `phish-034`, `phish-036`, `phish-037`. Every one was escalated
  (grey zone or false-positive review) because closing needs rule
  corroboration and high or critical alerts are never closed as benign by
  automation. These items are where a larger or better-defended model has to
  improve before automation may close more.
* **Against the fake keyword model** on the same sets: escalation fell from
  89% to 69% (synthetic) and from 92% to 64% (phishing); benign auto-close
  stayed at 6 of 21 on the synthetic set and rose from 3 of 11 to 5 of 11 on
  phishing; macro F1 rose from 0.62 to 0.72 and from 0.17 to 0.60. Every
  auto-close was correct (11 of 11).
* **Speed.** About 28 s (synthetic) and 40 s (phishing) per alert on this
  laptop, 30 and 26 minutes for the two sets; $0 in API fees.

## Why this model

A 7B instruction model is the largest that runs at a usable speed on the
available 6 GB GPU, and Qwen2.5 follows a JSON schema reliably. It is a
local baseline: nothing left the machine, there is no data processing
agreement to sign, and it costs $0 per alert. An EU-hosted model (Mistral
API) needs an API key from the owner; Mistral 7B on Ollama is the obvious
next local run for the EU story.
