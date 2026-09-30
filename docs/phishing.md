# Phishing triage (user-reported email)

Users report suspicious email; most of it is harmless. LG-SOTF ingests the
reported message, analyses it deterministically (authentication verdicts,
links, attachments, lookalike domains, impersonation), lets the model weigh
in through the usual untrusted-data boundary, and closes the harmless reports
it can prove harmless, sends the rest to an analyst, and proposes the
response for the malicious ones (purge the message, block the sender and
links, tell the reporter).

## How a report flows

```
report mailbox (M365 / IMAP)  ─┐
POST /ingest/email            ─┼─> MIME parser ─> email normalizer ─> alert (source_type email, category phishing)
lg-sotf eval (source "email") ─┘                                        │
                                  triage (phishing signals) ─> correlation ─> analysis ─> decide
                                                                        │
                        close benign │ escalate to an analyst │ plan_response (phishing playbook)
```

* **Parsing** (`lg_sotf.ingestion.email`): stdlib `email` with
  `policy.default`. A report is usually the suspicious message forwarded *as
  an attachment* (`message/rfc822` or `.eml`); the first such attachment is
  the message analysed, and the outer sender becomes the **reporter**. HTML
  is tokenised with `html.parser`, never rendered; attachments are hashed
  (SHA-256) and sniffed, never stored or executed. Only a short body excerpt
  (4 KB by default) is kept.
* **The alert**: `source_type` `email` whichever path delivered it,
  `category` `phishing`, rule name `user_reported_email`, title
  `Reported email: <subject>`, `occurred_at` = when the report was received.
  Entities: sender, Reply-To and Return-Path addresses and their domains,
  links (suspicious ones first), the relay IP, attachment hashes, and the
  reporter as a user. The parsed facts are kept in `normalized.email` (shown
  in the alert drawer's **Email** panel) and the redacted parse document in
  `raw`.
* **Deduplication**: per source, on the reported message's Message-ID plus
  the reporter (a content hash when there is no Message-ID). Two people
  reporting the same message give two alerts; correlation and escalation
  grouping bring them together.

## Signals

Computed at triage against the tenant's profile
(`lg_sotf.core.phishing`) and recorded in the triage digest (`rule_tp`,
`rule_fp`, `phishing`).

| Signal | Meaning | Strong |
|---|---|---|
| `email_dmarc_fail` | The trusted Authentication-Results header reports DMARC failure (or M365 `compauth=fail`) | yes |
| `email_spf_fail`, `email_dkim_fail` | SPF fail/softfail, DKIM fail | |
| `email_reply_to_mismatch` | Reply-To on another site than From | |
| `email_return_path_mismatch` | Bounce address on another site (weak: bulk senders do this) | |
| `email_display_name_impersonation` | External sender whose display name shows another address, an internal domain, a configured executive or a protected brand | yes |
| `email_lookalike_domain` | A sender, reply or link domain imitating an internal domain or protected brand: homoglyphs (also punycode), one or two edits, the same name under another suffix, or the name embedded in another domain | yes |
| `email_link_text_mismatch` | Link text shows one domain, the link goes to another | yes |
| `email_ip_url` | Link to a raw IP address (including numeric IPv4 spellings) | yes |
| `email_url_shortener` | Link through a known shortener | |
| `email_risky_attachment` | Macro Office, HTML/SVG, ISO/IMG/VHD, LNK, scripts and executables, OneNote, password-protected archives or documents, archives listing such files, executable content under a harmless name, right-to-left-override file names | yes |
| `email_credential_wording` | Credential-harvest or urgency phrases (weak, never strong) | |
| `email_internal_sender_authenticated` (benign) | Sender in the tenant's internal domains with SPF, DKIM **and** DMARC passing in the trusted header, and no strong signal | |

How they are used, within the existing policy:

* True-positive signals raise triage's rules score (never its *trusted*
  score, so they never make the model unnecessary on their own). The benign
  signal lowers it, and lowers analysis's rule threat score further, so a
  benign model verdict can be *corroborated* by rules. Nothing else changed
  in routing: high/critical alerts still never close automatically, a
  benign close still needs the model and the rules to agree, and a model
  refusal still ends with an analyst.
* Strong signals are evidence (weight 1 each) for analysis: two of them
  corroborate an automatic response. They corroborate the message, the
  deceptive links and lookalike domains, and the sender only when its
  identity is authenticated or its domain is itself a lookalike: a spoofed
  sender is someone else's address.
* Prompt injection anywhere in the message (CSS-hidden HTML and a
  plain-text part that differs from the HTML are included in what is
  scanned) voids the benign signal and blocks rule corroboration.
* The subject is sender-controlled, so email alerts are flagged
  `title_from_message` and their title never yields false-positive keywords
  ("scheduled maintenance test" in a subject closes nothing). Do not write
  suppression rules on the title of email alerts for the same reason.
* Correlation ignores the reporter and the tenant's own domains and links,
  so ordinary internal mail and a prolific reporter never look like a
  campaign.

Severity is set at ingestion from facts that need no tenant context: `high`
for a risky attachment, or a DMARC failure together with a deceptive or
raw-IP link; `medium` for failed SPF/DMARC, deceptive, raw-IP or shortened
links, a Reply-To elsewhere, credential wording, or a message that could not
be analysed; otherwise `low`.

## Tenant settings

`PATCH /api/v1/tenant/settings` (admin, audited), or **Tenant settings,
Phishing context** in the UI (one entry per line; saving replaces the whole
`phishing` section):

```json
{
  "tools": {"internal_domains": ["example.com", "example.org"]},
  "phishing": {
    "protected_brands": ["Example Bank", "examplebank.example"],
    "executives": ["Jane Doe", "John Smith"],
    "trusted_authserv_ids": ["mx.example.com"]
  }
}
```

* `tools.internal_domains` (already used by enrichment) are your mail
  domains: the benign signal, lookalike references, correlation and the
  `block_sender` guardrail use them. List every domain you own.
* `protected_brands`: names (`Example Bank`) or domains
  (`examplebank.example`) to protect; a domain entry also tells the checks
  which domain is legitimately the brand's. At most 200.
* `executives`: display names attackers impersonate. At most 500.
* `trusted_authserv_ids`: the `authserv-id` your receiving servers write at
  the start of `Authentication-Results` (`mx.google.com` for Gmail, your
  gateway's name for on-premises MTAs). **Set it.** A sender can put forged
  `Authentication-Results` headers into the message; your servers add theirs
  on top, and with this list only the first header from your servers is
  read. Without it the topmost header is read. Microsoft 365 writes no
  `authserv-id`; leave the list empty there (the topmost header is Microsoft's).

## Microsoft 365: a reported-phish mailbox

1. **Reporting mailbox.** Create a shared or user mailbox, for example
   `phish-reports@example.com`. In the Microsoft Defender portal, *Settings >
   Email & collaboration > User reported settings*, send reported messages
   to *My reporting mailbox only* (or both) and choose that mailbox. Reports
   arrive with the original message attached.
2. **App registration.** In Entra ID, register an application, add the
   Microsoft Graph **application** permission `Mail.ReadWrite` (read the
   message, then mark it read or move it) and grant admin consent. Create a
   client secret.
3. **Scope the app to that one mailbox.** `Mail.ReadWrite` alone reaches
   every mailbox in the tenant. Restrict it with an application access
   policy (Exchange Online PowerShell):

   ```powershell
   New-DistributionGroup -Name "LG-SOTF phish mailbox" -Type Security -Members phish-reports@example.com
   New-ApplicationAccessPolicy -AppId <application-id> -PolicyScopeGroupId "LG-SOTF phish mailbox" `
       -AccessRight RestrictAccess -Description "LG-SOTF reads only the reporting mailbox"
   Test-ApplicationAccessPolicy -Identity phish-reports@example.com -AppId <application-id>   # Granted
   Test-ApplicationAccessPolicy -Identity someone.else@example.com -AppId <application-id>    # Denied
   ```

   (RBAC for Applications in Exchange Online, with a management scope, is
   the newer equivalent.)
4. **Source.** *Sources > Add source > Microsoft 365 reported-phish
   mailbox*: Azure tenant id or domain, the mailbox, optionally the folder
   (`inbox` by default); credentials `client_id` and `client_secret`
   (encrypted, never shown again). `after_processing` is `mark_read`
   (default) or `move` with a `processed_folder` (folder id or well-known
   name such as `archive`). Sovereign clouds set `authority_url` and
   `graph_url`; `trusted_relays` (CIDRs of your own relays) goes in the
   additional configuration. *Test* reads the folder.

Each poll lists the folder's unread (or not yet moved) messages oldest first,
fetches each message's MIME (`/messages/{id}/$value`, capped), creates the
alerts and then marks the messages read or moves them; the message ids ride
in the cursor so an interrupted acknowledgement is finished on the next
poll. A message that is too large or cannot be parsed still becomes an alert
(flagged `email_unparsed`, severity `medium`), so no report is dropped. Every
call goes through the source HTTP client: destination policy (SSRF),
TLS verification, timeouts, bounded retries and response caps.

## Google Workspace or any IMAP server

1. Create a dedicated reporting account, for example `phish-reports@example.com`,
   and ask users to forward suspicious mail **as an attachment** (Gmail:
   select the message, *More > Forward as attachment*; Outlook: *More
   actions > Forward as attachment*). A compliance or routing rule that
   copies reports to it works too.
2. Google Workspace: turn on 2-Step Verification for the account, allow IMAP
   for it (Admin console, *Apps > Google Workspace > Gmail > End User Access*)
   and create an **app password**. Other servers: a normal password for a
   dedicated account.
3. *Sources > Add source > IMAP reported-phish mailbox*: host
   (`imap.gmail.com`), port (993), folder (`INBOX`), credentials `username`
   and `password`. `after_processing` is `mark_read` (`\Seen`, default) or
   `move` to `processed_folder` (Gmail label names such as `Processed` work).

IMAPS only, certificate verification always on (`ca_cert_pem` for a private
CA; `tls_verify: false` is refused). Before connecting, the host is resolved
and every address checked against the destination policy; the connection is
then pinned to the checked address with the host name kept for SNI and
certificate checks. On-premises servers on private addresses need the
install-level `ingestion.allow_private_destinations`. The cursor is the
mailbox's UIDVALIDITY and the last UID; sizes are checked (`RFC822.SIZE`)
before a bounded partial fetch. OAuth (XOAUTH2) is not supported yet.

## Pushing reports from your own tooling

Create an API key with the `ingest` scope (*Settings > API keys*) and post
the raw message:

```sh
curl -sS https://soc.example.com/api/v1/ingest/email?reporter=alice%40example.com \
  -H "X-API-Key: $LG_SOTF_INGEST_KEY" \
  -H "Content-Type: message/rfc822" \
  --data-binary @reported.eml
```

`202` answers with one item (`inserted`, `duplicate` or `rejected` with the
reason). `reporter` is optional: without it a forwarded report's sender is
the reporter. A message that cannot be parsed (for example nested beyond
the limits) is `rejected`; one above the size limit is refused with `413`.
Alerts are stored under the source id `email:<api key id>`.

## Response

The phishing playbook proposes, in order: `purge_message` (high risk, at most
10 per hour by default: removes the message from every mailbox; the ledger
params carry the Message-ID *and* the sender and subject, and your SOAR
should match on all of them, since a Message-ID is sender-chosen),
`block_sender` (medium, 20 per hour; the sender and Reply-To addresses),
`block_url` (medium; suspicious links first), `notify_reporter` (low,
non-containment; only when a reporter is known, params carry the address)
and `create_ticket`. They go through the tenant's connector (dry run by
default, or the signed SOAR webhook) under the usual autonomy policy,
guardrails and approvals. Guardrails added: sender addresses must be valid,
a sender of one of the tenant's `internal_domains` is never blocked
(`internal_sender`: disable or reset the account instead), and protected
domains and protected users (full addresses) are never blocked.

## Limits

`ingestion.email` in the settings file (all optional):

| Key | Default | Meaning |
|---|---|---|
| `max_message_bytes` | 10485760 | Larger messages are refused (push: 413; pull: an `email_unparsed` alert) |
| `max_parts` / `max_depth` | 200 / 8 | MIME parts visited and nesting followed; messages with implausibly many boundaries are refused |
| `max_headers` / `max_header_chars` | 1000 / 16384 | Headers read and length of each value (truncated, flagged) |
| `max_received` / `max_auth_results` | 30 / 10 | `Received` hops and `Authentication-Results` headers read |
| `max_recipients` | 100 | To/Cc addresses read |
| `max_urls` / `max_attachments` | 100 / 50 | Links and attachments recorded (flagged when reached) |
| `max_body_excerpt_chars` | 4096 | Body text kept in `raw` (1,500 characters in the email section) |
| `max_scan_chars` / `max_total_scan_chars` | 1000000 / 4000000 | Text scanned for links and wording per part and per message |

## Evaluation

`tests/fixtures/eval/phishing_v1.jsonl` holds 39 synthetic reported emails
(malicious, benign, inconclusive and an adversarial split with injected
bodies, forged authentication and response steering) and
`phishing_smoke_thresholds.yaml` its fake-model gate; see
`docs/evaluation.md`. Build a labelled set from your own reports (items
take the raw `.eml` text; the analyst-decisions export does not cover email
alerts, whose stored `raw` is the parse, not the message) before trusting any
automatic-close rate.

## Known limitations

* The relay IP is the first external `Received` hop; hosted mail (Microsoft
  365, Google) adds its own public hops, so set `trusted_relays` or rely on
  the authentication verdicts.
* Only harmless reports from fully authenticated internal senders can close
  automatically; external newsletters always reach an analyst.
* Outlook `.msg` attachments are not parsed (report as `.eml`/`message/rfc822`).
* `notify_reporter` is proposed with a malicious response only; benign
  closes do not notify the reporter yet.
