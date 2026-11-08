# Microsoft SKU coverage matrix

Which Microsoft licence each Microsoft API that LG-SOTF calls needs, with the
application permission it is granted and the Microsoft Learn page that
states the requirement. Use it before you promise a customer a capability:
many MSSP customers run **Microsoft 365 Business Premium**, which lacks
several Defender for Endpoint and Entra ID Protection features that
**Microsoft 365 E5** has.

| | |
|---|---|
| Version | 1.0, 2026-11-08 (INT1.10) |
| Covers | Every Microsoft Graph, Defender for Endpoint and Log Analytics endpoint in the code: the direct Microsoft response connector ([microsoft.md](microsoft.md)), the Microsoft 365 reporting-mailbox source ([phishing.md](phishing.md)) and the Microsoft Sentinel source, plus the evidence APIs planned next (section 5) |
| Sources | Microsoft Learn, read on 2026-11-08. Microsoft changes its licensing pages; check the linked page before you sign a contract |
| Lab evidence | **Pending (Microsoft lab tenant).** No row has been verified in a real tenant yet; the lab tenant has not been bought. Section 6 lists what the lab must settle first |
| Kept in sync by | `tests/deploy/test_microsoft_skus.py`: every API path in the code must appear in section 4, and every row there must still be used by the code |

Verdicts: **Yes** (the SKU includes what the API needs), **No** (it does
not; an add-on is named where one exists), **Unconfirmed** (Microsoft's
pages are silent or contradict each other; section 6). "Yes" means the
licence allows the call; your app registration still needs the permission
and, where noted, a directory role.

## 1. What each SKU includes

Only the parts that matter to these APIs.

| SKU | Entra ID | Endpoint protection | Defender portal (XDR) | Mail |
|---|---|---|---|---|
| Microsoft 365 Business Premium | P1 | Defender for Business | Yes | Exchange Online; Defender for Office 365 Plan 1 |
| Microsoft 365 E3 | P1 | Defender for Endpoint Plan 1 | Only with the Microsoft Defender Suite or EMS E5 add-on | Exchange Online; Defender for Office 365 Plan 1 |
| Microsoft 365 E5 | P2 | Defender for Endpoint Plan 2 | Yes | Exchange Online; Defender for Office 365 Plan 2 |

Sources: [Entra ID service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/azure-active-directory)
("Plan Availability"); [Microsoft Defender service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-defender-service-description)
("Defender for Business is included as part of the Microsoft 365 Business
Premium subscription plan"; Defender for Endpoint P1 "as part of Microsoft
365 E3"); [Defender XDR prerequisites](https://learn.microsoft.com/en-us/defender-xdr/prerequisites)
(licensing list); [Defender for Business overview](https://learn.microsoft.com/en-us/defender-business/mdb-overview)
(plan comparison: APIs are available in Defender for Business, Plan 1 and
Plan 2).

Common add-ons: **Microsoft Entra ID P2** (or Entra Suite, or E5 Security)
on Business Premium or E3 for ID Protection; **Defender for Endpoint Plan 2**
(or E5 Security) for the full set of device response actions and advanced
hunting; **Defender for Business servers** or **Defender for Servers** for
servers (no plan above includes server licences).

## 2. Capabilities at a glance

| Capability | Business Premium | E3 | E5 | Needs |
|---|---|---|---|---|
| `mail.remediate`, `mail.notify`, the M365 reporting mailbox | Yes | Yes | Yes | An Exchange Online mailbox; message trace in the global cloud only |
| `entra.account`, `entra.sessions`, `entra.password` | Yes | Yes | Yes | Entra ID (any plan); the app needs the User Administrator role. See section 6 for the guard's `ownedObjects` read |
| `entra.risk` | No (add Entra ID P2) | No (add Entra ID P2) | Yes | Entra ID P2 |
| `defender.isolation` | Yes | Yes | Yes | Defender for Business or Defender for Endpoint P1/P2 |
| `defender.file_indicators` | Yes (tenant-wide only) | Yes | Yes | The "Allow or block file" advanced feature |
| `defender.indicators` (IP, domain, URL) | Unconfirmed | Unconfirmed | Yes | Custom network indicators feature, Network Protection in block mode |
| `defender.stop_quarantine` | No | Unconfirmed | Yes | Defender for Endpoint P2 is the safe assumption |
| `defender.forensics` | No | Unconfirmed | Yes | Defender for Endpoint P2 is the safe assumption |
| Microsoft Sentinel source | n/a | n/a | n/a | An Azure subscription with Microsoft Sentinel (billed on Azure consumption, not by an M365 SKU) |

## 3. Permissions model

* **Graph and Defender**: application permissions with admin consent on the
  tenant's own app registration, client-credentials tokens, one token per
  resource ([microsoft.md](microsoft.md#2-app-registration)). Each
  capability's full permission list, with what each permission is for, is in
  [microsoft-mail.md](microsoft-mail.md), [microsoft-entra.md](microsoft-entra.md)
  and [microsoft-defender.md](microsoft-defender.md), and from
  `GET /api/v1/integrations/microsoft/catalog`.
* **Least privilege.** The table names the permission LG-SOTF requests. Where
  Microsoft lists a narrower one for the call alone, the note says why the
  wider one is used (usually because the same capability also writes).
  Mail permissions can be scoped to the mailboxes involved with Exchange RBAC
  for Applications; message trace cannot be scoped.
* **Log Analytics**: an Azure RBAC role on the workspace, not a Graph
  permission.

## 4. The matrix: APIs in use

Endpoint paths are written as the code sends them: Graph paths start with
`/v1.0/` on `graph.microsoft.com`, Defender paths with `/api/` on
`api.security.microsoft.com` (or its geo host), the rest with their host.

### 4.1 Sign-in

| API | Used by | Application permission | Business Premium | E3 | E5 | Add-on or note | Microsoft Learn | Lab evidence |
|---|---|---|---|---|---|---|---|---|
| `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | every capability, the M365 and Sentinel sources | none (client credentials) | Yes | Yes | Yes | No licence; tenant-specific endpoint only | [client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow) | pending (Microsoft lab tenant) |

### 4.2 Microsoft Graph: Entra ID

| API | Used by | Application permission | Business Premium | E3 | E5 | Add-on or note | Microsoft Learn | Lab evidence |
|---|---|---|---|---|---|---|---|---|
| `GET /v1.0/users`, `GET /v1.0/users/{id}`, `GET /v1.0/users('{upn}')` | all Entra capabilities, `mail.remediate` (resolve a user or mailbox) | User.Read.All | Yes | Yes | Yes | The `signInActivity` property alone needs Entra ID P1 and AuditLog.Read.All; LG-SOTF does not read it | [list users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0), [get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `PATCH /v1.0/users/{id}` (`accountEnabled`) | `entra.account` | User.EnableDisableAccount.All, and the **User Administrator** directory role | Yes | Yes | Yes | App-only changes need an administrator role; administrators themselves need a higher role, which LG-SOTF does not hold (it refuses privileged targets) | [update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `PATCH /v1.0/users/{id}` (`passwordProfile`) | `entra.password` | User-PasswordProfile.ReadWrite.All, and the **User Administrator** directory role | Yes | Yes | Yes | The page states the role in one place and omits it in an example (section 6) | [update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `POST /v1.0/users/{id}/revokeSignInSessions` | `entra.sessions` | User.RevokeSessions.All | Yes | Yes | Yes | Whether app-only revocation needs a role for limited-administrator targets is not stated | [revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/roleManagement/directory/roleAssignments` | privileged-target guard (all Entra writes) | RoleManagement.Read.Directory | Yes | Yes | Yes | | [list role assignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/users/{id}/memberOf` | privileged-target guard | GroupMember.Read.All | Yes | Yes | Yes | Microsoft lists Directory.Read.All as least privileged; with GroupMember.Read.All other object types come back with an id and type only. Administrative units may then lack `isMemberManagementRestricted`, and the guard fails closed (section 6) | [list memberOf](https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/users/{id}/ownedObjects` | privileged-target guard | GroupMember.Read.All | Yes | Yes | Yes | **The v1.0 page marks application permissions "Not supported"** (section 6) | [list ownedObjects](https://learn.microsoft.com/en-us/graph/api/user-list-ownedobjects?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/identityProtection/riskyUsers`, `GET /v1.0/identityProtection/riskyUsers/{id}` | `entra.risk` (read and verify) | IdentityRiskyUser.Read.All | No | No | Yes | Entra ID P2 add-on: "Using the riskyUsers API requires a Microsoft Entra ID P2 license" | [get riskyUser](https://learn.microsoft.com/en-us/graph/api/riskyuser-get?view=graph-rest-1.0), [list riskyUsers](https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `POST /v1.0/identityProtection/riskyUsers/confirmCompromised`, `POST /v1.0/identityProtection/riskyUsers/dismiss` | `entra.risk` | IdentityRiskyUser.ReadWrite.All | No | No | Yes | Entra ID P2 add-on | [confirmCompromised](https://learn.microsoft.com/en-us/graph/api/riskyuser-confirmcompromised?view=graph-rest-1.0), [dismiss](https://learn.microsoft.com/en-us/graph/api/riskyuser-dismiss?view=graph-rest-1.0) | pending (Microsoft lab tenant) |

### 4.3 Microsoft Graph: Exchange Online mail

All rows need an Exchange Online mailbox, which all three SKUs include. No
API page below states a further licence; Defender for Office 365 is not
needed.

| API | Used by | Application permission | Business Premium | E3 | E5 | Add-on or note | Microsoft Learn | Lab evidence |
|---|---|---|---|---|---|---|---|---|
| `GET /v1.0/users/{id}/messages` (by Internet Message-ID) | `mail.remediate` | Mail.ReadWrite | Yes | Yes | Yes | Mail.ReadBasic.All is enough to list; Mail.ReadWrite because the capability also deletes and moves | [list messages](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/users/{id}/messages/{id}` | `mail.remediate`, `mail.notify` | Mail.ReadWrite | Yes | Yes | Yes | | [get message](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/users/{id}/messages/{id}/$value` | M365 reporting mailbox source (MIME) | Mail.ReadWrite | Yes | Yes | Yes | Mail.ReadBasic.All excludes the body; Mail.Read is the least for MIME, Mail.ReadWrite because the source also marks or moves | [get message](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `PATCH /v1.0/users/{id}/messages/{id}` (`isRead`) | M365 reporting mailbox source | Mail.ReadWrite | Yes | Yes | Yes | | [update message](https://learn.microsoft.com/en-us/graph/api/message-update?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `DELETE /v1.0/users/{id}/messages/{id}` | `mail.remediate` (soft delete) | Mail.ReadWrite | Yes | Yes | Yes | | [delete message](https://learn.microsoft.com/en-us/graph/api/message-delete?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `POST /v1.0/users/{id}/messages/{id}/move` | `mail.remediate` (and rollback), M365 source (`after_processing: move`) | Mail.ReadWrite | Yes | Yes | Yes | | [move message](https://learn.microsoft.com/en-us/graph/api/message-move?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `POST /v1.0/users/{id}/messages` (create draft) | `mail.notify` | Mail.ReadWrite | Yes | Yes | Yes | | [create message](https://learn.microsoft.com/en-us/graph/api/user-post-messages?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `POST /v1.0/users/{id}/messages/{id}/send` | `mail.notify` | Mail.Send | Yes | Yes | Yes | | [send message](https://learn.microsoft.com/en-us/graph/api/message-send?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/users/{id}/mailFolders/{id}` | `mail.remediate`, `mail.notify` (probes, Sent Items), M365 source | Mail.ReadWrite | Yes | Yes | Yes | Mail.ReadBasic.All is enough to read | [get mailFolder](https://learn.microsoft.com/en-us/graph/api/mailfolder-get?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/users/{id}/mailFolders/{id}/messages` | `mail.remediate`, M365 source | Mail.ReadWrite | Yes | Yes | Yes | | [list messages in a folder](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messages?view=graph-rest-1.0) | pending (Microsoft lab tenant) |
| `GET /v1.0/admin/exchange/tracing/messageTraces` | `mail.remediate` with `recipient_source=message_trace` | ExchangeMessageTrace.Read.All | Yes | Yes | Yes | Global cloud only; needs the message trace service principal; 90-day lookback, 10 days per query, 100 requests per 5 minutes. No licence stated beyond Exchange Online (inferred) | [list messageTraces](https://learn.microsoft.com/en-us/graph/api/messagetracingroot-list-messagetraces?view=graph-rest-1.0) | pending (Microsoft lab tenant) |

### 4.4 Defender for Endpoint API

All rows are global cloud only. "Applies to" is the plan list on each API
page. Servers need a server licence in every SKU.

| API | Used by | Application permission | Business Premium | E3 | E5 | Add-on or note | Microsoft Learn | Lab evidence |
|---|---|---|---|---|---|---|---|---|
| `GET /api/machines` | `defender.isolation`, `defender.stop_quarantine`, `defender.forensics` (find the device) | Machine.ReadWrite.All | Yes | Yes | Yes | Machine.Read.All is the least for reading; Machine.ReadWrite.All is needed for machine actions anyway. Applies to P1, P2 and Business | [list machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines) | pending (Microsoft lab tenant) |
| `GET /api/machineactions`, `GET /api/machineactions/{id}` | same (poll the action) | Machine.ReadWrite.All | Unconfirmed | Yes | Yes | The pages list P1 and P2 only; Defender for Business "uses Defender for Endpoint APIs for all available capabilities" ([FAQ](https://learn.microsoft.com/en-us/defender-business/mdb-faq)) | [list machine actions](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineactions-collection), [get machine action](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineaction-object) | pending (Microsoft lab tenant) |
| `POST /api/machines/{id}/isolate`, `POST /api/machines/{id}/unisolate` | `defender.isolation` | Machine.Isolate | Yes | Yes | Yes | Isolation is in the P1 and Business manual response actions | [isolate](https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine), [release](https://learn.microsoft.com/en-us/defender-endpoint/api/unisolate-machine), [response actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts) | pending (Microsoft lab tenant) |
| `POST /api/machineactions/{id}/cancel` | `defender.isolation` (rollback of a pending isolation) | Machine.Isolate | Unconfirmed | Yes | Yes | Any one of the machine-action permissions is accepted; the page carries a pre-release banner and lists Defender for Endpoint, P1 and P2 | [cancel machine action](https://learn.microsoft.com/en-us/defender-endpoint/api/cancel-machine-action) | pending (Microsoft lab tenant) |
| `POST /api/machines/{id}/StopAndQuarantineFile` | `defender.stop_quarantine` | Machine.StopAndQuarantine | No | Unconfirmed | Yes | "Defender for Business doesn't include the 'Stop and quarantine a file' action"; P1 is listed on the response-actions page but missing from the P1 overview | [stop and quarantine](https://learn.microsoft.com/en-us/defender-endpoint/api/stop-and-quarantine-file), [response actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts) | pending (Microsoft lab tenant) |
| `POST /api/machines/{id}/collectInvestigationPackage` | `defender.forensics` | Machine.CollectForensics | No | Unconfirmed | Yes | The API page applies to P1; the response-actions page lists P1's actions without it and says Plan 2 is needed for all response actions | [collect investigation package](https://learn.microsoft.com/en-us/defender-endpoint/api/collect-investigation-package), [response actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts) | pending (Microsoft lab tenant) |
| `GET /api/indicators`, `POST /api/indicators`, `DELETE /api/indicators/{id}` | `defender.indicators`, `defender.file_indicators` | Ti.ReadWrite.All | File: Yes. Network: Unconfirmed | File: Yes. Network: Unconfirmed | Yes | The pages apply to Defender for Endpoint and P1; Business lists "Add an indicator to block or allow a file". Network indicators need the Custom network indicators feature. Limit: 15,000 active indicators per tenant | [list](https://learn.microsoft.com/en-us/defender-endpoint/api/get-ti-indicators-collection), [submit](https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator), [delete](https://learn.microsoft.com/en-us/defender-endpoint/api/delete-ti-indicator-by-id), [Business remediation](https://learn.microsoft.com/en-us/defender-business/mdb-review-remediation-actions) | pending (Microsoft lab tenant) |

### 4.5 Azure Monitor Log Analytics (Microsoft Sentinel source)

| API | Used by | Application permission | Business Premium | E3 | E5 | Add-on or note | Microsoft Learn | Lab evidence |
|---|---|---|---|---|---|---|---|---|
| `POST https://api.loganalytics.io/v1/workspaces/{id}/query` | Microsoft Sentinel source (`SecurityAlert`, `SecurityIncident`) | Log Analytics Reader (Azure RBAC) on the workspace; API permission Data.Read | n/a | n/a | n/a | Not an M365 SKU: Microsoft Sentinel is billed on Azure consumption. Microsoft is moving the host to `api.loganalytics.azure.com`; `.io` still works | [Query - Execute](https://learn.microsoft.com/en-us/rest/api/logsquery/query/execute?view=rest-logsquery-v1), [access the API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api), [Sentinel billing](https://learn.microsoft.com/en-us/azure/sentinel/billing) | pending (Microsoft lab tenant) |

## 5. Planned evidence APIs (not in the code yet)

The evidence tools of AI-E2 will read from Microsoft. This section decides
which ones are worth building for the customers MSSPs actually have (CR6).

| API | Planned for | Application permission | Business Premium | E3 | E5 | Note | Microsoft Learn |
|---|---|---|---|---|---|---|---|
| `GET /v1.0/auditLogs/signIns` | Entra sign-ins evidence (AI-E2.3) | AuditLog.Read.All | Yes | Yes | Yes | "You must have a Microsoft Entra ID P1 or P2 license to download sign-in logs by using the Microsoft Graph API." Risk fields are `hidden` without P2 | [list signIns](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [signIn resource](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0) |
| `GET /v1.0/identityProtection/riskDetections` | risky-user evidence (AI-E2.3) | IdentityRiskEvent.Read.All | Unconfirmed | Unconfirmed | Yes | The API page says P1 or P2; the ID Protection overview says full risk reports in Graph are P2 only and P1 sees limited information | [list riskDetections](https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0), [ID Protection overview](https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection) |
| `GET /v1.0/security/alerts_v2`, `GET /v1.0/security/incidents` | Defender alerts and incidents as a source or evidence | SecurityAlert.Read.All, SecurityIncident.Read.All | Yes | Unconfirmed (Yes with the Defender Suite or EMS E5 add-on) | Yes | No licence on the API pages; it follows from Defender portal access | [list alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0), [list incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0), [XDR prerequisites](https://learn.microsoft.com/en-us/defender-xdr/prerequisites) |
| `POST /v1.0/security/runHuntingQuery` | Defender advanced hunting templates (AI-E2.2) | ThreatHunting.Read.All | **No** | No | Yes | "Advanced hunting capabilities are not included in Defender for Business"; the plan comparison marks advanced hunting for Plan 2 only | [runHuntingQuery](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0), [APIs intro](https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro), [Business overview](https://learn.microsoft.com/en-us/defender-business/mdb-overview) |

**Decision input for CR6.** Business Premium tenants get sign-in logs, user
reads and the device actions that matter most (isolation, file indicators),
but no advanced hunting and no ID Protection risk without add-ons.
Advanced hunting templates (AI-E2.2) therefore only serve E5 or Plan 2
customers, and should stay cut unless the MSSP's customer base is E5-heavy.
Entra sign-ins evidence (AI-E2.3) works on all three SKUs.

## 6. Open questions for the lab tenant

These are where Microsoft's pages are silent or contradict each other. The
lab tenant must answer them, on each SKU it can license, before the matrix is
marked verified.

1. **`ownedObjects` with an application token.** The v1.0 page lists
   application permissions as "Not supported". The privileged-target guard
   reads it before every Entra write and fails closed, so if the call is
   refused every `entra.*` write ends `privileged_guard_unavailable` and
   nothing is changed. Verify first; if it is refused, the guard needs
   another way to find owners of role-assignable groups.
2. **`memberOf` with GroupMember.Read.All.** Whether administrative units come
   back with `isMemberManagementRestricted`, or only with an id and type
   (which also fails the guard closed for any user in an administrative unit).
3. **`passwordProfile` and the User Administrator role.** The update-user page
   says the role is required in the property table and omits it in an
   example.
4. **Stop and quarantine, and investigation packages, on Plan 1 (E3).**
   Microsoft's pages disagree; until verified, sell both as E5 or Plan 2.
5. **Defender for Business and the machine-action endpoints.** `machineactions`
   and `cancel` do not list Business in "Applies to", yet isolation (which
   LG-SOTF polls through them) is a Business action.
6. **Network indicators** (IP, domain, URL) on Business Premium and E3.
7. **Risk detections on Entra ID P1** (planned API).
8. **E3 without add-ons and the Graph security alerts and incidents** (planned
   API).

Record each answer in the lab-evidence column with the tenant SKU, the date
and the request id, and record the API exchange as a cassette (INT1.2).

## 7. Keeping this page true

`tests/deploy/test_microsoft_skus.py` reads the Microsoft code (the
integration packages, the M365 and Sentinel sources) and fails when:

* an API path the code sends is not in section 4 (add a row with its licence,
  permission, source and lab evidence);
* a row in section 4 names an endpoint the code no longer calls (move it to
  section 5 or delete it);
* a row has no Microsoft Learn link or no lab-evidence entry;
* a permission a capability declares is missing from the page.
