### Added

- `docs/microsoft-skus.md`, the Microsoft SKU coverage matrix: every
  Microsoft Graph, Defender for Endpoint and Log Analytics API LG-SOTF calls,
  with the licence it needs on Microsoft 365 Business Premium, E3 and E5 (and
  the add-on that unlocks it), the application permission it is granted, the
  Microsoft Learn page that states the requirement, and a lab-evidence column
  (pending until the Microsoft lab tenant exists). It also rates the planned
  evidence APIs (sign-in logs, risk detections, Defender alerts and
  incidents, advanced hunting) and lists the open questions the lab tenant
  must settle. A deploy test fails when the code calls a Microsoft API path
  the matrix does not list, or the matrix lists one the code no longer calls.
