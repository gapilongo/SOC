# Synthetic vendor payloads

Every file here is **synthetic**: hand-written to match the documented shape of
each product's API or export, using documentation address ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC 1918), `example.com`
domains and made-up identifiers. None of it is real customer or telemetry data.

Each file is `{"_synthetic": "...", "events": [...]}`; tests read `events`.
