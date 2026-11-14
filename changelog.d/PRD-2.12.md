### Added

- The console has the shell of the console v2 design (PRD-2.12): the frame
  every page lives in.
  - **The rail.** Pages are in five groups: Work, Detect and respond, Assure,
    Configure and Platform. The Queue is where work waits: the older
    Escalations list left the rail (its address `/escalations` still works,
    and the decision page leads back to the queue unless you came from that
    list). Three entries have the design's names and open the same pages as
    before: "AI usage and cost" (LLM usage), "People and keys" (Users and
    API keys) and "Tenants" (MSSP console). Counts are plain numbers next to a page's name,
    the signed-in person is at the bottom (account security, row density and
    sign out are in their menu), and on a narrow screen the rail opens from
    the menu button.
  - **The tenant is part of the address.** A platform admin chooses the
    tenant to work in with the control at the left of the top bar, and the
    address becomes `/s/<tenant>/...`. A reload, a new tab and a shared link
    now open the same tenant; before, they fell back to the home tenant
    without saying so. Someone who has one tenant and opens another
    tenant's address is told so and shown nothing under it.
  - **Search and commands.** One field in the top bar, also opened with
    Ctrl+K (Cmd+K) or `/`, finds pages, alerts by title, and (for a platform
    admin) tenants. Each alert says which tenant it is in. `>` lists
    commands. A command that changes something never runs from the field:
    it opens the page where the act is confirmed. The `/` key can be
    switched off with the command "Single-key shortcuts": the same switch,
    kept per user, as on the investigation view.
  - **Notifications.** The bell lists only what needs an act now:
    escalations past their deadline, a deadline in the next 15 minutes,
    actions waiting for your approval and, for admins, a source the API
    reports as failing or degraded. Each line names the tenant and opens the
    page where the act happens.
  - **Brand.** The console's name, logo and one accent colour come from one
    `brand` object in the runtime configuration (`/config.js`). The accent
    is checked for contrast before it is used; one that fails is refused
    with the failing pair named, and the product's colours stay. Without a
    brand the console shows the product's own.
  - **A service that is not licensed.** A service module can declare a group
    of its own in the rail. Where the licence does not include it, a
    platform admin sees the group locked and labelled "Not licensed", with a
    page that says so; a customer tenant's users do not see it. No second
    service is shipped yet.

### Changed

- The theme follows the system setting until you choose one; before, dark
  was the default. The control in the top bar steps System, Light, Dark.
- The top bar no longer repeats the page's name; the browser tab names the
  page and the console.
- "Operate" and "Report" in the navigation are now "Work", "Detect and
  respond" and "Assure". No page moved to another address.
