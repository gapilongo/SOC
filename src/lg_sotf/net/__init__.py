"""Network kernel: SSRF egress policy, TLS verification and Retry-After parsing.

Every outbound HTTP stack (pull connectors, integrations, webhooks, Microsoft
Graph, enrichment, the LLM endpoint check and the MCP client) uses these.

Leaf rule (ADR-0001, import-linter contract ``net-is-leaf``): modules here
import only the kernel (``lg_sotf.errors``, ``observability``, ``security``,
``settings``) and ``httpx``. Importing this package has no side effects.
"""
