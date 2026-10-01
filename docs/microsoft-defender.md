# Microsoft Defender for Endpoint direct response

LG-SOTF 1.1 can isolate devices, block network and file indicators, stop and
quarantine files, and collect investigation packages directly in the
customer's Microsoft Defender for Endpoint (MDE) tenant. This page covers
the five Defender capabilities. The shared framework (the four live
switches, routing, rehearsal, verification, rollback, background execution
and the connection test) is described in [Microsoft direct response](microsoft.md).

## 1. Overview

| Capability | Executes | Reversible |
|---|---|---|
| `defender.isolation` | `isolate_host`, and `release_host` for its rollback | yes |
| `defender.indicators` | `block_ip`, `block_domain`, `block_url`, and `unblock_ip`, `unblock_domain`, `unblock_url` for their rollbacks | yes |
| `defender.file_indicators` | `quarantine_file` as a file indicator, and `unblock_file` for its rollback | yes |
| `defender.stop_quarantine` | `quarantine_file` as a stop-and-quarantine machine action (SHA-1 only) | no |
| `defender.forensics` | `collect_forensics` (investigation package) | no |

`defender.file_indicators` and `defender.stop_quarantine` both execute
`quarantine_file`, so they exclude each other: an integration can enable
one of them, never both (the Integrations page and the API refuse the
combination).

Every capability calls the Defender for Endpoint API with a token for the
WindowsDefenderATP application permissions, and exists in the `global`
cloud only. Nothing reaches Defender until the capability is **Enabled**
and **Live** and both dry-run switches are off; an enabled capability that
is not live rehearses with GET requests only (it resolves the device or
looks up the indicator) and records `dry_run` with `rehearsal: true`.

Every object LG-SOTF creates carries the action marker
`LG-SOTF action <uuid>`: in the machine action `Comment` (and so the
`requestorComment` Defender stores) and in the indicator `description`. A
re-run of an interrupted execution looks for its marker before it writes,
so it adopts what it already requested instead of acting twice.

## 2. Actions and Microsoft calls

Paths are relative to the Defender host (section 3). Body parameters are
case-sensitive in the Defender API and are sent exactly as written here.

### Finding the device (`isolate_host`, `collect_forensics`, `quarantine_file` by stop and quarantine)

1. The target host name is validated (an RFC 1123 name; an IP address is
   `unsupported_target`) and lower-cased.
2. `GET /api/machines?$filter=computerDnsName eq '<host>'`. Defender answers
   `404` when it has no recent machines, which counts as "none".
3. Nothing found: `GET /api/machines?$filter=startswith(computerDnsName,'<first label>')&$top=100`,
   keeping the machines whose first DNS label equals the target's first
   label. When both the target and the machine carry a domain, the domains
   must match too (`ws-042.corp` is never `ws-042.lab`).
4. One candidate: that device. Several: the single one whose `healthStatus`
   is `Active`. Otherwise the action fails with `ambiguous_target` (and the
   count), or `not_found`. LG-SOTF never guesses a device.

### `isolate_host` (`defender.isolation`)

1. Find the device.
2. `GET /api/machineactions?$filter=machineId eq '<id>' and type eq 'Isolate'&$top=50`
   (the list is filtered on `machineId` and `type` with `and`, and statuses
   are checked client-side):
   * an `Isolate` of this action that is `Pending`, `InProgress` or
     `Succeeded` is adopted;
   * a pending `Isolate` requested by someone else is adopted as `already`
     (nothing changed, not reversible);
   * when the latest succeeded `Isolate` is newer than the latest succeeded
     `Unisolate` (a second list call, `type eq 'Unisolate'`) and younger
     than seven days, the device is already isolated: `succeeded` with
     `already: true`, `changed: false`, not reversible.
3. Checkpoint `{machine_id, requested}`, then
   `POST /api/machines/{id}/isolate` with
   `{"Comment": "LG-SOTF action <uuid>: <alert title>", "IsolationType": "Full" | "Selective"}`.
   `IsolationType` is always sent (no default is documented). Defender
   answers `201` with a machine action.
4. A `400` while an isolation is pending on the device (for example
   `ActiveRequestAlreadyExists` or "Action is already in progress") adopts
   the pending action. LG-SOTF never reads Microsoft's message text: the
   pending action in the list is the evidence. `ActiveRequestAlreadyExists`
   with nothing listed yet defers the action for a minute.
5. Checkpoint the machine action id. The result is `succeeded` with
   `changed: true`, `external_ref.reversible: true` and a rollback window of
   ten days (the 7-day automatic lift plus 3 days of offline retries).

Option `isolation_type` (`Full` by default, or `Selective`).

### `release_host` (the rollback of `isolate_host`)

* The original isolation changed nothing (`already`), or its machine action
  ended `Failed`, `TimeOut` or `Cancelled`: `failed` with
  `rollback_not_needed`, without a request.
* The original isolation is still `Pending`/`InProgress`:
  `POST /api/machineactions/{id}/cancel` with
  `{"Comment": "LG-SOTF action <rollback uuid>: rollback"}` (200).
* Otherwise: adopt a pending `Unisolate` of this rollback; treat a newer
  succeeded `Unisolate` (someone already released the device) or an
  isolation older than seven days (lifted automatically) as already
  released; adopt someone else's pending `Unisolate` as `already`; else
  `POST /api/machines/{id}/unisolate` with
  `{"Comment": "LG-SOTF action <rollback uuid>: rollback"}` (201). Defender
  documents that repeated release requests answer "pending machine action"
  or `400` "Action is already in progress": both adopt the latest pending
  `Unisolate`.

### `block_ip`, `block_domain`, `block_url` (`defender.indicators`) and `quarantine_file` (`defender.file_indicators`)

| Action | `indicatorType` | Target check | `action` |
|---|---|---|---|
| `block_ip` | `IpAddress` | one global IPv4/IPv6 address (IPv6 is sent with all eight groups, never `::`); private, loopback, link-local and other non-global addresses are `unsupported_target`, CIDR is `invalid_target` | `Block` |
| `block_domain` | `DomainName` | a DNS name of at least two labels (IDNA) | `Block` |
| `block_url` | `Url` | an `http`/`https` URL with a host and no credentials | `Block` |
| `quarantine_file` | `FileSha256`, `FileSha1` or `FileMd5` by hash length | hexadecimal; SHA-512 is `unsupported_target` | `BlockAndRemediate` |

1. `GET /api/indicators?$filter=indicatorValue eq '<value>' and indicatorType eq '<type>'`
   (it lists active indicators only):
   * an `Allowed` or `Warn` indicator for the value: `failed` with
     `conflicting_indicator` (Defender applies Allow over Warn over Block,
     so a block would not take effect);
   * a blocking indicator (`Block`, `BlockAndRemediate` or the legacy
     `AlertAndBlock`) whose description carries this action's marker is
     adopted (a re-run);
   * a blocking indicator of someone else: `succeeded` with `already: true`,
     `changed: false` and `external_ref = {indicator_id, created: false,
     reversible: false}`; a rollback never deletes it.
2. Checkpoint `{indicator_value, indicator_type, requested}`, then
   `POST /api/indicators` with
   `indicatorValue`, `indicatorType`, `action`,
   `title: "LG-SOTF <action_type> <value, first 60 characters>"`,
   `description: "LG-SOTF action <uuid>; alert <alert id>"`,
   `expirationTime` (now plus `expiration_days`, always set),
   `severity`, `generateAlert` and, when configured, `rbacGroupNames`.
   Defender answers `200`. The legacy `Alert` and `AlertAndBlock` actions
   and `Warn` are never sent.
3. Checkpoint the indicator id. `POST /api/indicators` is an upsert on a
   key Microsoft does not document: when the answer carries the id of an
   indicator that existed before (for example an `Audit` indicator of the
   same value), that indicator was updated in place and is recorded as not
   created by LG-SOTF (not reversible).
4. Repeat the lookup (section 4).

Options (both capabilities): `expiration_days` (1-365, default 30),
`severity` (`Informational`, `Low`, `Medium`, `High`; default `High`),
`generate_alert` (default on), `rbac_group_names` (device groups, at most
50; empty means every device).

### `quarantine_file` (`defender.stop_quarantine`)

1. The hash must be SHA-1: `POST .../StopAndQuarantineFile` takes a `Sha1`
   only. SHA-256 and MD5 are `unsupported_target` with the hint "enable
   defender.file_indicators for SHA-256/MD5".
2. The devices are the alert's host scope (`params.scope.hosts`, at most
   ten per alert): none is `invalid_target` ("no hosts in scope"), more than
   the `max_machines` option (1-50, default 10) is `too_many_targets`.
3. Per device, recorded as one step in `external_ref.steps`
   (`host`, `machine_id`, `status`, `machine_action_id`, `error`): find the
   device; adopt a pending or succeeded `StopAndQuarantineFile` of this
   action; else checkpoint and
   `POST /api/machines/{id}/StopAndQuarantineFile` with
   `{"Comment": "LG-SOTF action <uuid>", "Sha1": "<sha1>"}` (201).
4. Every device requested: `succeeded`. Some failed (not found, ambiguous,
   an unsupported OS or client version): `failed` with `partial` and
   `external_ref.partial: true`; **Retry** resumes only the failed devices.
   All failed: `failed` with the first device's error. Throttling, a `403`
   or a server error stops the call with the steps checkpointed; the re-run
   resumes from them.

### `collect_forensics` (`defender.forensics`)

1. Find the device; adopt a pending or succeeded
   `CollectInvestigationPackage` of this action.
2. Checkpoint, then `POST /api/machines/{id}/collectInvestigationPackage`
   with `{"Comment": "LG-SOTF action <uuid>"}` (201). Defender answers `400`
   when a collection is already running: the running collection is adopted
   (someone else's counts as `already`).
3. The package stays in Defender. LG-SOTF never calls `getPackageUri` and
   never stores a download link.

### Rehearsal and connection test

Rehearsals resolve the device, or look up the indicator, with GET requests
only and record `result.resolved.would_execute` (`method`,
`path_template`, `body_keys`) and the device (`id`, `computer_dns_name`,
`health_status`) or the existing indicators. The connection test runs
`GET /api/machines?$top=1` (404 counts as ok) and
`GET /api/machineactions?$top=1` for `defender.isolation`,
`GET /api/indicators?$top=1` for both indicator capabilities, and
`GET /api/machineactions?$top=1` for `defender.stop_quarantine` and
`defender.forensics`.

## 3. Permissions and setup

### App registration and permissions

Use the customer directory's app registration described in
[Microsoft direct response](microsoft.md#2-app-registration). Add the
Defender permissions under *API permissions > Add a permission > APIs my
organization uses*, type **WindowsDefenderATP** (it is not listed until you
type it), choose **Application permissions**, then select **Grant admin
consent** (again after every change).

| Capability | WindowsDefenderATP application permission | Used for |
|---|---|---|
| `defender.isolation` | `Machine.Isolate` | isolate and release (and cancel a pending isolation) |
| `defender.isolation` | `Machine.ReadWrite.All` | find machines and poll machine actions |
| `defender.indicators` | `Ti.ReadWrite.All` | create, find and delete indicators |
| `defender.file_indicators` | `Ti.ReadWrite.All` | create, find and delete indicators |
| `defender.stop_quarantine` | `Machine.StopAndQuarantine` | stop and quarantine files |
| `defender.stop_quarantine` | `Machine.ReadWrite.All` | find machines and poll machine actions |
| `defender.forensics` | `Machine.CollectForensics` | collect investigation packages |
| `defender.forensics` | `Machine.ReadWrite.All` | find machines and poll machine actions |

`Machine.Read.All` is not needed: `Machine.ReadWrite.All` also lists
machines and is the permission Microsoft documents for machine actions.
`Ti.ReadWrite.All` exposes every indicator of the tenant (with
`Ti.ReadWrite` an app only sees the indicators it created, which would hide
conflicting and existing blocks).

The token is requested for the legacy audience
`https://api.securitycenter.microsoft.com` (scope
`https://api.securitycenter.microsoft.com/.default`): Microsoft notes that
some Defender for Endpoint APIs refuse tokens for the newer resource with
`403`, even on `api.security.microsoft.com`. The connection test shows the
token's `roles` so a missing permission is visible before the first action.

### Hosts

Hosts are fixed in the code; no setting holds a URL.

| Defender API region (`defender_geo`) | Host |
|---|---|
| (none) | `api.security.microsoft.com` |
| `us`, `eu`, `uk`, `au`, `swa`, `ina`, `aea` | `{geo}.api.security.microsoft.com` |

Microsoft suggests the geo host closest to the tenant's data for
performance. Only the `global` cloud is supported: the US Government clouds
(GCC High and DoD, `api-gov.securitycenter.microsoft.us`), GCC tenants whose
Defender for Endpoint runs on `api-gcc.securitycenter.microsoft.us`, and the
China cloud are not, because Microsoft documents no token scope for those
hosts. GCC tenants that run Defender for Endpoint in the commercial cloud
use the `global` cloud.

### Advanced features to turn on

In the Microsoft Defender portal, *Settings > Endpoints > General >
Advanced features*:

| Feature | Needed by |
|---|---|
| **Custom network indicators** | `defender.indicators` (IP, domain and URL indicators) |
| **Allow or block file** | `defender.file_indicators` |

And on the devices:

* **Network Protection in block mode** and **Microsoft Defender Antivirus in
  active mode** (with behaviour monitoring and cloud-delivered protection):
  outside Microsoft Edge, network indicators are enforced only with these;
  indicators are not supported while Defender Antivirus runs in passive
  mode.
* **Microsoft Defender Antivirus in active mode** (with behaviour monitoring
  and cloud protection) for file indicators; stop and quarantine needs at
  least passive mode.

A disabled feature answers `403 DisabledFeature`; the action fails with
`feature_disabled` and a hint naming the feature.

## 4. Verification

| Action | How it is proven | Window |
|---|---|---|
| `isolate_host` | the machine action is polled: `Succeeded` -> `verified`; `Failed`, `TimeOut` or `Cancelled` -> `failed` | first check after 60 s, up to 76 h (an offline device is retried for 3 days) |
| `release_host` (unisolate) | the `Unisolate` machine action, as above | 60 s, up to 76 h |
| `release_host` (cancel) | the isolation machine action reads `Cancelled` (or ended without isolating) -> `verified`; it reached `Succeeded` before the cancel took effect -> `failed` (`isolation_completed_before_cancel`) | 60 s, up to 76 h |
| `block_*`, `quarantine_file` (file indicator) | inline: the lookup is repeated after the `POST`; present, blocking and not expired -> `verified` with `enforcement: "configured; takes effect in up to 48 h"` (network) or `"configured; file blocks typically apply in 15-30 min"` (files); missing -> `failed` with `not_verified` (retryable: a retry adopts the indicator by its marker) | immediate |
| `unblock_*` | inline: the lookup no longer shows the indicator | immediate |
| `quarantine_file` (stop and quarantine) | every step's machine action: any `Failed`/`TimeOut`/`Cancelled` -> `failed`; all `Succeeded` -> `verified` | 60 s, up to 76 h |
| `collect_forensics` | the machine action, as for isolation | 60 s, up to 24 h |

Both spellings of the machine action update time are read
(`lastUpdateDateTimeUtc` on the entity and by id, `lastUpdateTimeUtc` in
lists). Indicator verification proves the configuration exists in
Defender; enforcement on the devices follows Microsoft's timing
(section 6). **Re-check** re-runs the same reads.

## 5. Rollback

| Original | Rollback | What LG-SOTF does | Not possible when |
|---|---|---|---|
| `isolate_host` | `release_host` (high risk) | cancels a still pending isolation, else unisolates | the device was already isolated by someone else (`nothing_changed`); more than 10 days after the request (`window_expired`: Defender has lifted the isolation by then) |
| `block_ip` / `block_domain` / `block_url` | `unblock_ip` / `unblock_domain` / `unblock_url` (medium) | deletes the indicator LG-SOTF created (`DELETE /api/indicators/{id}`, 204; 404 counts as done) | the value was already blocked by someone else, or an existing indicator was updated in place (`nothing_changed` / `irreversible`); after the indicator's expiry (`window_expired`) |
| `quarantine_file` (file indicator) | `unblock_file` (medium) | deletes the file indicator; files already quarantined stay quarantined (`result.note`) | as for network indicators |
| `quarantine_file` (stop and quarantine) | none | stop-and-quarantine cannot be undone through the API | always (`irreversible`) |
| `collect_forensics` | none | collected evidence cannot be recalled | always (`irreversible`) |

A rollback runs in the background, pinned to the integration that executed
the original, even when the capability is no longer live (never while a
kill switch is on). It re-reads before it writes: an indicator whose
description no longer carries the original action's marker was changed by
someone else and is left alone (`conflicting_indicator`); an isolation that
never took effect needs no release (`rollback_not_needed`).

## 6. Limits and licensing

### Licensing

| Capability | Defender for Endpoint Plan 1 | Plan 2 | Defender for Business |
|---|---|---|---|
| `defender.isolation` | yes | yes | yes |
| `defender.file_indicators` | yes | yes | yes (file indicators always apply to the whole tenant; no device groups) |
| `defender.indicators` | not confirmed by Microsoft's plan tables; needs the Custom network indicators feature | yes | not confirmed |
| `defender.stop_quarantine` | unconfirmed (Microsoft's pages disagree) | yes | no |
| `defender.forensics` | no | yes | not confirmed |

API access applies to Defender for Business and Defender for Endpoint
Plans 1 and 2. Servers need a server licence (Defender for Servers, or
Defender for Business servers); Plan 1 and Plan 2 do not include one. A
capability the tenant is not licensed for fails with `not_licensed` or
`403`; the connection test shows it before the first action.

### Isolation caveats

* Defender lifts an isolation **automatically after 7 days**.
* An offline device is retried for **3 days**; after that the isolation must
  be requested again (verification ends `inconclusive` or `failed`).
* **Full-tunnel VPN**: an isolated device cannot reach the Defender service
  over a full-tunnel VPN; configure split tunnelling for Defender traffic.
* **Proxy networks** (PAC, WPAD, static or direct proxy): a fully isolated
  device might not recover; use `isolation_type: Selective` there.
* Isolating a **Hyper-V host** cuts the network of all its child VMs.
* On **Linux**, an administrator changing or adding an **iptables** rule
  removes the isolation; isolation needs iptables, ip6tables and the
  netfilter kernel options.

### Indicators

* **Timing**: network indicators can take **up to 48 hours** (in most cases
  under two); file blocks are typically enforced within **15 minutes, 30
  on average**, and can take over 2 hours. Verification proves the
  configuration, not the enforcement on every device.
* **IP addresses**: external single addresses only (no CIDR, ranges or
  wildcards; IPv6 as a full address: LG-SOTF writes all eight groups, e.g.
  `2606:4700:4700:0000:0000:0000:0000:1111`).
* **Domains** also match their subdomains.
* **URLs**: full HTTPS URL paths are enforced only in Microsoft Edge; HTTP
  URLs are enforced in any browser. Blocking host names in non-Microsoft
  browsers requires QUIC and Encrypted Client Hello to be disabled.
* **Files**: on Windows, portable executables only (`.exe`, `.dll`); macOS
  and Linux support their own executable and script types.
* The tenant holds at most **15,000 indicators** (not increasable): every
  indicator LG-SOTF creates has an `expirationTime`, and a rollback deletes
  it early.

### Rate limits

Defender allows **100 calls per minute and 1,500 per hour** per API for
these calls (machines, machine actions, isolate, unisolate, cancel, stop and
quarantine, investigation package, indicators). LG-SOTF limits itself to
**60 requests per minute** per integration. A `429` honours `Retry-After`;
when the wait is longer than the call's deadline the action is deferred
(`executing`, re-run by the scheduler) instead of waiting.

### Advanced hunting

Not used. Microsoft is retiring the Defender for Endpoint and Defender XDR
advanced hunting APIs (MC1220762; they stop returning data on 1 February
2027). Whether the retirement also covers the machines, machine actions and
indicators APIs is not confirmed by Microsoft; LG-SOTF uses only those.

## 7. Troubleshooting

| Symptom | Ledger error | What to check |
|---|---|---|
| `403 Forbidden` on every call | `permission_denied` | the WindowsDefenderATP permission in the table of section 3 and its admin consent; the connection test's token `roles`. A token for the wrong audience also answers `403`; LG-SOTF always requests `https://api.securitycenter.microsoft.com/.default`, so check that the permission was added under WindowsDefenderATP, not Microsoft Graph |
| `403 DisabledFeature` | `feature_disabled` | the advanced feature named in the hint (Custom network indicators, Allow or block file) |
| `400 OsPlatformNotSupported` / `ClientVersionNotSupported` | `unsupported_target` | the device's OS and Defender client version support the action |
| device not found | `not_found` | the host name, and that the device is onboarded and seen recently (Defender lists devices within its retention only) |
| several devices match | `ambiguous_target` (`count`) | use the fully qualified name, or offboard stale duplicates |
| an `Allowed` or `Warn` indicator exists | `conflicting_indicator` | the existing indicator in *Settings > Endpoints > Indicators* |
| private or non-global IP | `unsupported_target` | Defender indicators take public addresses only; contain internal hosts with isolation |
| SHA-256 or MD5 with stop and quarantine | `unsupported_target` | enable `defender.file_indicators` instead |
| `429` | `throttled` (deferred, then failed after 5 attempts) | other tools sharing the app's Defender quota |
| an action is `executing` for a while | (deferred) | the result's `deferred` reason; the scheduler re-runs it after `Retry-After` |
| verification `failed` after an isolation | (verification) | the machine action ended `Failed`, `TimeOut` (device offline for 3 days) or `Cancelled` |
| verification `inconclusive`, `permission_denied` | (verification) | `Machine.ReadWrite.All` (machine actions) or `Ti.ReadWrite.All` (indicators) |

Defender's error `target` (its correlation id) is kept as `request_id` in
the result; Microsoft's free-text messages are never stored.
