# Microsoft 365 mail: remove reported messages and notify reporters

Two capabilities of the Microsoft integration act on Exchange Online mailboxes
through Microsoft Graph `v1.0`. Configuration, routing, the kill switches,
rehearsal, verification and rollback in general are described in
[Microsoft direct response](microsoft.md); this page covers what the mail
capabilities do in the tenant, the permissions they need and how they fail.

| Capability | Executes | Clouds |
|---|---|---|
| `mail.remediate` (Remove reported messages) | `purge_message`, and its rollback `restore_message` | `global`, `usgov_gcc_high`, `usgov_dod` (message trace: `global` only) |
| `mail.notify` (Notify reporters) | `notify_reporter` | `global`, `usgov_gcc_high`, `usgov_dod` |

## 1. Overview

The phishing playbook proposes `purge_message` for the reported message
(target: its Internet Message-ID, with `params.match` naming the sender and
subject) and `notify_reporter` for the user who reported it. Once such an
action is approved and routed to Microsoft (an enabled capability, see
[routing](microsoft.md#4-routing)):

* `purge_message` finds the message in every recipient mailbox and
  soft-deletes it (default) or moves it to Deleted Items, recording where
  each copy was so a rollback can put it back;
* `restore_message` (created only by a rollback) moves those copies back;
* `notify_reporter` sends the reporter a fixed plain-text update from the
  SOC mailbox.

Nothing is changed until the capability is **Live** and both kill switches
are off. An enabled capability that is not live rehearses: it resolves the
recipients and looks the message up in the first five mailboxes with GET
requests only, and records the action as `dry_run` with
`result.resolved` = `{would_execute: {mode, mailboxes}, found: {mailbox: copies}}`
(`mail.notify`: `{would_execute: {from, to, subject}}`).

`block_sender` has no direct capability: see
[Limits and licensing](#6-limits-and-licensing).

## 2. Actions and Microsoft calls

Every request goes to Microsoft Graph `v1.0` with the header
`Prefer: IdType="ImmutableId"` (message ids then stay the same when a
message moves between folders of the mailbox). Mailbox paths are
`/v1.0/users/{address}` with the validated, lower-cased address as one
percent-encoded path segment, or `/v1.0/users/{object id}` for an address
that is not the user principal name (see step 2). Message-IDs reach `$filter` as OData string
literals (`'` doubled) and the whole filter is percent-encoded once
(`<` `%3C`, `@` `%40`, `+` `%2B`, `#` `%23`, `&` `%26`, `%` `%25`).
Addresses, Message-IDs and ids Microsoft returned are validated before use;
an invalid target fails the action with `invalid_target` before any request.

### purge_message (`mail.remediate`)

1. **Recipients.** With `recipient_source=alert` (default): the alert's
   recipients, plus the reporter with `include_reporter`. With
   `recipient_source=message_trace` (global cloud only), every recipient
   Exchange message trace reports:

   ```
   GET /v1.0/admin/exchange/tracing/messageTraces?$filter=messageId eq '<id>' and receivedDateTime ge <start> and receivedDateTime le <end>&$top=1000
   ```

   following `@odata.nextLink` (at most 5,000 rows). The email's `Date`
   header is set by the sender, so the search is anchored on the time the
   report reached LG-SOTF (the alert's ingestion): one window covers the
   nine days before the report and the day after, whatever the `Date` says.
   When the `Date` lies further back (a message reported long after
   delivery), a second window starts one day before it (at most 10 days,
   never past now). Windows are kept within the last 90 days; with none
   left the action is refused (`invalid_target`, "message older than 90
   days").
   Addresses are validated, lower-cased and de-duplicated; invalid ones are
   counted in `result.invalid_recipients`. More than `max_mailboxes`
   refuses the action (`too_many_recipients`, with `count`) before any
   change. The mailboxes are then recorded as `pending` steps.

2. **Per mailbox** (four mailboxes at a time, one request at a time in each):

   ```
   GET    /v1.0/users/{mailbox}/messages?$filter=internetMessageId eq '<id>'&$select=id,parentFolderId,internetMessageId,from,subject,receivedDateTime&$top=10
   GET    /v1.0/users/{mailbox}/mailFolders/sentitems?$select=id
   GET    /v1.0/users/{mailbox}/mailFolders/recoverableitemsdeletions?$select=id   (move mode: also deleteditems)
   GET    /v1.0/users/{mailbox}/mailFolders/inbox?$select=id
   DELETE /v1.0/users/{mailbox}/messages/{id}                                      soft_delete: 204
   POST   /v1.0/users/{mailbox}/messages/{id}/move  {"destinationId":"deleteditems"}  move_to_deleted_items: 201
   ```

   Graph addresses a mailbox only by the user principal name or the object
   id, so a 404 for an address is ambiguous: an alias or proxy address
   (common in hybrid tenants, and what message trace reports) answers 404
   too. On a 404 LG-SOTF looks the address up (`User.Read.All`):

   ```
   GET /v1.0/users?$filter=mail eq '<address>'&$select=id
   GET /v1.0/users?$filter=proxyAddresses/any(x:x eq 'smtp:<address>')&$select=id   (and 'SMTP:<address>')
   ```

   One match: the mailbox is searched again as `/v1.0/users/{object id}`,
   and the id is recorded on the step (`user_id`) for re-runs, the proof
   and the restore. No match (an external recipient, a typo), or a user
   without a mailbox: `mailbox_not_found`. More than one match: the step
   fails with `ambiguous_target`. No copy is `not_found`. Copies
   from another sender than `params.match.sender` are ignored
   (`skipped`, `sender_mismatch`), and so are the Sent Items copy (the
   sender's own, `sent_items`) and copies already removed
   (`already_removed`). The copies' ids and folders are recorded in the row
   **before** anything is changed; then each copy is deleted or moved. A 404
   on the write means it is already gone.

3. **Re-runs.** An interrupted execution (throttling, a network error with
   an unknown outcome, a crash) is run again by the scheduler. Mailboxes
   already `done` are skipped. For a mailbox whose copies were recorded,
   each copy is re-read (`GET /v1.0/users/{mailbox}/messages/{id}?$select=id,parentFolderId`):
   one Graph no longer finds, or finds in Recoverable Items (move mode:
   Deleted Items or Recoverable Items), is done; only the others are acted
   on. A copy is never deleted or moved twice. Other mailboxes are looked
   up again. The recipients are never asked of message trace again.

4. **Outcome.**

   | Steps | Ledger |
   |---|---|
   | every mailbox final, none failed | `succeeded`; `changed` when a copy was removed (then reversible until the rollback window ends) |
   | some removed, others failed or unfinished | `failed`, `error: "partial"`, retryable, `external_ref.partial` and reversible: **Retry** continues, **Roll back** restores what was removed |
   | nothing removed, some failed | `failed` with the most common mailbox error (for example `permission_denied`) |

   `result` has `summary`, `changed`, `counts` (per step status), `mailboxes`,
   `removed`, `mode` and, on failure, `failed_mailboxes` (at most 20).
   `external_ref` has `mode`, `internet_message_id`, `started_at`,
   `steps` (one `{mailbox, status, items: [{id, folder}], error, reason}`
   per mailbox; `folder` is `inbox` or the id of the folder the copy was
   in), `reversible` and `rollback_until`.

   Step statuses: `pending`, `done`, `not_found`, `mailbox_not_found`,
   `skipped` (with `reason`), `failed` (with `error`: a ledger error code,
   `ms_code` and `retryable`).

### restore_message (`mail.remediate`, rollback only)

For every copy the purge recorded (also in a failed step of a partial
purge), in each mailbox:

```
GET  /v1.0/users/{mailbox}/messages/{id}?$select=id,parentFolderId
GET  /v1.0/users/{mailbox}/mailFolders/recoverableitemsdeletions/messages?$filter=internetMessageId eq '<id>'&$select=id   (on 404; move mode: deleteditems first)
POST /v1.0/users/{mailbox}/messages/{id}/move  {"destinationId":"<saved folder>"}                                           201
```

A copy already back in its folder is not moved (`skipped`,
`already_in_place`). When the saved folder no longer exists (404 or
`ErrorItemNotFound`), the copy goes to the Inbox. The restore records its
own steps the same way (the move target before each move), so a re-run
never moves a copy twice. Nothing found in any mailbox is `succeeded` with
`changed: false` and `error: "rollback_not_needed"`, or `failed` with
`rollback_window_expired` once the purge's `rollback_until` has passed. A
restore is not itself reversible.

### notify_reporter (`mail.notify`)

1. `params.reporter` must be an address in `recipient_domains` (exact
   domains; empty means the domain of `sender_mailbox`), else
   `recipient_not_allowed`. With `require_known_disposition`, an alert
   whose final verdict is unknown gives `disposition_unknown`. Nothing is
   sent in either case.
2. Idempotency: the reply carries a single-value extended property
   `String {<LG-SOTF property set>} Name LGSOTFAction` whose value is the
   action id.

   ```
   GET  /v1.0/users/{soc}/mailFolders/sentitems/messages?$filter=singleValueExtendedProperties/any(ep: ep/id eq '<property>' and ep/value eq '<action id>')&$select=id,sentDateTime
   GET  /v1.0/users/{soc}/messages/{draft_id}?$select=id,isDraft          (a draft recorded by an interrupted run)
   GET  /v1.0/users/{soc}/mailFolders/drafts/messages?$filter=<same>&$select=id,isDraft   (a draft not recorded yet)
   POST /v1.0/users/{soc}/messages                                        201: the draft
   POST /v1.0/users/{soc}/messages/{id}/send                              202
   ```

   Found in Sent Items: `succeeded` with `already: true`, verified. A
   recorded draft that is still a draft is sent; one that is no longer a
   draft waits for verification. Otherwise the draft is created (plain
   text, the reporter as only recipient, the tag), recorded, and sent.
3. The text is fixed English: one paragraph per verdict (malicious,
   suspicious, benign, unknown) and a fixed closing. It contains no link, no
   HTML and nothing internal to the alert. The subject is
   `Update on the email you reported: ` followed by the reported subject,
   stripped of control and formatting characters and of `<` `>`, with web
   addresses defanged (`hxxps[:]//`, `www[.]`), cut to 120 characters.
4. A `202` means Microsoft accepted the message, not that it was
   delivered. A sent email cannot be recalled: `notify_reporter` is not
   reversible.

### Options

`mail.remediate`:

| Option | Default | Meaning |
|---|---|---|
| `recipient_source` | `alert` | `alert` or `message_trace` (global cloud only) |
| `mode` | `soft_delete` | `soft_delete` (`DELETE`: into Recoverable Items, out of every folder view) or `move_to_deleted_items` (stays visible in Deleted Items) |
| `max_mailboxes` | `50` | 1 to 200; more recipients refuses the action before any change |
| `rollback_window_days` | `14` | 1 to 30; match the mailboxes' deleted item retention |
| `include_reporter` | `true` | with `recipient_source=alert`, also clean the reporter's mailbox |
| `probe_mailbox` | empty | a mailbox inside the Exchange RBAC scope the connection test reads |

`mail.notify`:

| Option | Default | Meaning |
|---|---|---|
| `sender_mailbox` | empty (required to enable) | the SOC mailbox the reply is sent from |
| `recipient_domains` | empty | at most 50 domains a reporter may be in; empty: the sender mailbox's domain |
| `require_known_disposition` | `false` | send nothing while the alert has no final verdict |

## 3. Permissions and setup

| Capability | Application permission (Microsoft Graph) | Exchange RBAC for Applications role | Used for |
|---|---|---|---|
| `mail.remediate` | `Mail.ReadWrite` | `Application Mail.ReadWrite` | find, remove and restore the reported message in recipient mailboxes |
| `mail.remediate` | `User.Read.All` | (not scopable) | find the mailbox of a recipient address that is not the user principal name (an alias or proxy address) |
| `mail.remediate` with `recipient_source=message_trace` | `ExchangeMessageTrace.Read.All` | (not scopable) | find every recipient of the message |
| `mail.notify` | `Mail.Send` | `Application Mail.Send` | send the reply from the SOC mailbox |
| `mail.notify` | `Mail.ReadWrite` | `Application Mail.ReadWrite` | create the draft and find it in Sent Items (idempotency and proof) |

Grant the mail permissions **through Exchange RBAC for Applications**,
scoped to the mailboxes LG-SOTF may touch, and **do not** consent
`Mail.ReadWrite` or `Mail.Send` tenant-wide in Microsoft Entra ID.
Effective permissions are the union of both systems: an Entra consent
grants every mailbox and makes the Exchange scope meaningless. `Mail.Send`
consented in Entra means "send mail as any user". Both `mail.notify` roles
belong on the SOC mailbox only; `Application Mail Full Access` covers both.

Steps (Exchange Online PowerShell, as Organization Management or Exchange
Administrator):

1. Find the app's service principal object id: Entra admin center >
   **Enterprise applications** > the LG-SOTF app > **Object ID** (not the
   object id shown under App registrations).
2. Register it in Exchange Online:

   ```powershell
   Connect-ExchangeOnline
   New-ServicePrincipal -AppId <application (client) id> -ObjectId <enterprise application object id> -DisplayName "LG-SOTF"
   ```

3. Create the scopes: a management scope, or an Entra administrative unit
   (`-RecipientAdministrativeUnitScope <au id>` in the next step instead of
   `-CustomResourceScope`):

   ```powershell
   New-ManagementScope -Name "LG-SOTF mailboxes" -RecipientRestrictionFilter "RecipientTypeDetails -eq 'UserMailbox'"
   New-ManagementScope -Name "LG-SOTF SOC mailbox" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'soc@contoso.com'"
   ```

4. Assign the roles, `Application Mail.ReadWrite` to the user mailboxes and
   `Application Mail.Send` to the SOC mailbox only:

   ```powershell
   New-ManagementRoleAssignment -App <enterprise application object id> -Role "Application Mail.ReadWrite" -CustomResourceScope "LG-SOTF mailboxes"
   New-ManagementRoleAssignment -App <enterprise application object id> -Role "Application Mail.Send" -CustomResourceScope "LG-SOTF SOC mailbox"
   # mail.notify also reads and writes the SOC mailbox (draft, Sent Items):
   New-ManagementRoleAssignment -App <enterprise application object id> -Role "Application Mail.ReadWrite" -CustomResourceScope "LG-SOTF SOC mailbox"
   ```

5. Check a mailbox (`InScope` must be `True`; this test bypasses the cache):

   ```powershell
   Test-ServicePrincipalAuthorization -Identity <enterprise application object id> -Resource alice@contoso.com
   ```

6. Allow **30 minutes to 2 hours** before the assignments take effect
   (caching), then run the connection test with `probe_mailbox` set.

Message trace (`recipient_source=message_trace`, global cloud only):
`ExchangeMessageTrace.Read.All` is a Microsoft Graph application permission
that Exchange RBAC cannot scope; add it under API permissions and grant
admin consent. Once per tenant, provision the Exchange message trace
service principal with Microsoft Graph PowerShell:

```powershell
New-MgServicePrincipal -AppId 8bd644d1-64a1-4d4b-ae52-2e0cbf64e373
```

Do not create new Application Access Policies (Microsoft replaced them with
RBAC for Applications; they only constrain permissions consented in Entra).
LG-SOTF never uses Exchange Web Services (EWS is being turned off in
Exchange Online from October 2026): everything is Microsoft Graph.

**Connection test.** Tokens never show Exchange RBAC roles, so the test
reports `Application Mail.ReadWrite` and `Application Mail.Send` as
`unknown`. The probes are the evidence: `mail.remediate` reads the Inbox
of `probe_mailbox` (and one message trace row with message trace);
`mail.notify` reads the SOC mailbox's Sent Items. `Mail.Send` cannot be
probed without sending mail: check it with `Test-ServicePrincipalAuthorization`.

With the recommended RBAC-only setup the token also has no `Mail.ReadWrite`
or `Mail.Send` role. The test therefore lists those token permissions as
`unknown` (never `missing`) and lets the probes decide: `mailbox access: ok`
(or `sender mailbox: ok`) shows that the Exchange RBAC grant is in effect
and the capability is `ok`; without `probe_mailbox` (or `sender_mailbox`)
it is `unverified`. If the token *does* carry `Mail.ReadWrite` or
`Mail.Send`, they were consented tenant-wide in Entra: the test shows them
`granted` with a warning, because such a consent is added on top of the
Exchange scope and reaches every mailbox. Remove it and keep the RBAC
assignment. `ExchangeMessageTrace.Read.All` cannot be scoped: with
`recipient_source=message_trace` it is required and a missing consent is
`missing_permission`.

## 4. Verification

`succeeded` means Graph accepted the changes; verification proves them by
reading again (see [verification](microsoft.md#6-verification)).

| Action | Proven when | Pending | Failed |
|---|---|---|---|
| `purge_message` | for every removed copy: Graph no longer finds it by id, or finds it in Recoverable Items (move mode: Deleted Items, or Recoverable Items after the user emptied Deleted Items); and `GET /v1.0/users/{mailbox}/mailFolders/{original folder}/messages?$filter=internetMessageId eq '<id>'&$select=id` is empty | first check after 120 s, then with backoff for 30 minutes | a copy is back in its original folder (`reason: message_reappeared`, `mailbox`) |
| `restore_message` | each restored copy's `parentFolderId` is its destination folder | first check after 60 s, for 15 minutes | (never) |
| `notify_reporter` | the tagged reply is in the SOC mailbox's Sent Items (`sent_at`) | first check after 60 s, for 30 minutes | (never) |

The execution checks inline first; proven mailboxes are recorded in
`verification_detail.proven` and are not read again by later checks
(`unproven` lists the rest). A copy visible in another folder (the user
moved it) keeps the verification pending until its deadline
(`inconclusive`, `deadline`). A 403 on a check is `inconclusive`
(`permission_denied`); throttling is retried. Verification only reads.

## 5. Rollback

A succeeded (or partial) `purge_message` that removed something can be
rolled back with **Roll back** until `external_ref.rollback_until`: the
first change plus `rollback_window_days` (14 by default, at most 30). The
rollback is a `restore_message` row (high risk: an analyst's request waits
for an admin's approval), executed by the scheduler even when the
capability is no longer live, never while a kill switch is on.

Set `rollback_window_days` to the mailboxes' deleted item retention:
Exchange Online keeps soft-deleted items in Recoverable Items for 14 days
by default, at most 30 days per mailbox; after that they are removed from
Exchange Online unless a hold (Litigation Hold, eDiscovery or a retention
policy) keeps them. A restore after that finds nothing
(`rollback_window_expired`).

Users can also get a removed message back themselves: from Deleted Items
(move mode), or with **Recover Deleted Items** in Outlook (soft delete).
The purge removes the message from every folder view; it is not a hard
delete. `permanentDelete` is never used (irreversible).

`notify_reporter` cannot be rolled back: a sent email cannot be recalled.

## 6. Limits and licensing

* **Licensing.** Any Exchange Online mailbox; Microsoft Defender for Office
  365 is not needed. Message trace is global cloud only.
* **Graph limits** (per app and mailbox): 4 concurrent requests and 10,000
  requests per 10 minutes. LG-SOTF sends one request at a time per mailbox
  and works on four mailboxes at once; a mailbox is not started with less
  than 5 seconds left in the call (it stays `pending` and **Retry**
  continues it). Throttling beyond the call's deadline defers the action
  (`Retry-After` honoured) and the scheduler resumes it.
* **Message trace:** 100 requests per 5 minutes; a window of at most 10
  days starting at most 90 days back. A purge searches the nine days before
  the report arrived (a backdated or future-dated `Date` header cannot move
  that window) and, when the `Date` is older, the ten days from it. A
  message reported more than about 80 days after delivery, or an alert
  re-planned 90 days after it arrived, cannot be traced; use
  `recipient_source=alert` or Microsoft Purview for it.
* At most 200 mailboxes (`max_mailboxes`) and 10 copies per mailbox. The
  handles of one purge are kept below 56 KiB in the ledger row; a mailbox
  whose handles would not fit fails with `state_limit`, unchanged.
* **In-place (online) archive mailboxes are unreachable** through Graph: a
  copy already archived there is not found and not removed.
* Not used: `permanentDelete` (irreversible, global only) and
  `security/collaboration/analyzedEmails/remediate` (Defender for Office
  365 Plan 2, no status API).
* **`block_sender` has no direct capability.** No Microsoft Graph or other
  REST API manages the Tenant Allow/Block List (the Exchange Online Admin
  API preview has no such endpoint), so `block_sender` stays on the SOAR
  webhook, or dry run. A SOAR playbook can block the sender with app-only
  Exchange Online PowerShell (`Exchange.ManageAsApp`, plus Exchange
  Administrator or a custom role group with the `Tenant AllowBlockList
  Manager` role), and unblock it on the rollback (`unblock_sender`) with
  `Remove-TenantAllowBlockListItems`:

  ```powershell
  New-TenantAllowBlockListItems -ListType Sender -Block -Entries 'bad@attacker.example' -ExpirationDate <UTC date>
  ```

  Without `-ExpirationDate` or `-NoExpiration`, a block entry expires
  after 30 days.

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| a mailbox `failed` with `permission_denied`, `ms_code` `ErrorAccessDenied`, or `403 Authorization_RequestDenied` on the probe | the mailbox is outside the Exchange RBAC scope, or the role is not assigned (yet) | `Test-ServicePrincipalAuthorization -Identity <app> -Resource <mailbox>`; fix the scope; wait 30 minutes to 2 hours |
| every mailbox fails with `permission_denied` | no `Application Mail.ReadWrite` assignment and no consent | section 3 |
| `mailbox_not_found` | no directory user has the address as its UPN, `mail` or proxy address (an external recipient, a typo), or the user has no Exchange Online mailbox (unlicensed) | none needed for external recipients |
| a mailbox `failed` with `permission_denied` although the Exchange RBAC scope is right | the address is an alias and `User.Read.All` is not consented, so its mailbox cannot be found | consent `User.Read.All` (section 3) |
| a mailbox `failed` with `ambiguous_target` | two directory users have the address | fix the directory; remove the message from that mailbox by hand |
| `not_found` | the message is not in the mailbox: never delivered, already deleted by the user, or archived to the online archive | check with message trace |
| `skipped` `sender_mismatch` | a message with the same Message-ID from another sender | expected: only the reported sender's copies are removed |
| `too_many_recipients` | more recipients than `max_mailboxes` | raise `max_mailboxes` (at most 200) or remediate in Microsoft Defender / Purview |
| `invalid_target` "message older than 90 days" | message trace cannot search that far back | `recipient_source=alert` |
| `invalid_options` | message trace outside the global cloud, or `mail.notify` without `sender_mailbox` | fix the options |
| message trace `forbidden` in the connection test | `ExchangeMessageTrace.Read.All` not consented, or the message trace service principal is missing | consent; `New-MgServicePrincipal -AppId 8bd644d1-64a1-4d4b-ae52-2e0cbf64e373` |
| `failed` `partial` | some mailboxes done, others failed or unfinished | **Retry** continues where it stopped; **Roll back** restores what was removed |
| `state_limit` on a mailbox | too many copies to record in one row | lower `max_mailboxes` and run the purge for the rest separately |
| `recipient_not_allowed` | the reporter's domain is not in `recipient_domains` | add the domain (exact match) |
| `disposition_unknown` | `require_known_disposition` and the alert has no final verdict | decide the alert, then **Retry** |
| the connection test shows `unknown` for `Mail.ReadWrite` / `Mail.Send` | RBAC-only grants: tokens show neither the Exchange roles nor these permissions (section 3) | expected; set `probe_mailbox` / `sender_mailbox` so the probes prove the grant |
| the connection test warns that `Mail.ReadWrite` or `Mail.Send` is granted tenant-wide | the permission is consented in Entra, which overrides the Exchange RBAC scope | remove the consent under API permissions; keep the RBAC assignment |
| verification `inconclusive` `deadline` on a purge | a copy is still visible (the user moved or recovered it) | check the mailbox; **Re-check** after fixing |
| `rollback_window_expired` | the removed copies are no longer in Recoverable Items | recover with eDiscovery / Content Search while a hold or single item recovery keeps them |
