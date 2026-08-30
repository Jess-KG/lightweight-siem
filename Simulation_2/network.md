# Network Overview

**Internal subnet:** 10.20.0.0/24

| Range | Purpose |
|---|---|
| 10.20.0.10–10.20.0.19 | Servers (DC, File Server, App Server) |
| 10.20.0.100–10.20.0.199 | Workstations |

## External access

SCFS has no direct internet-facing servers. Remote access for staff is
not routinely used — all listed employees work on-site. Any connection
attempt or logon from outside the 10.20.0.0/24 range should be treated
as unexpected.

## Logging

- **Domain Controller, File Server, App Server**: Windows Security
  auditing enabled (logon events, account management, privilege use).
- **All systems**: Sysmon installed, logging process creation, network
  connections, file creation, registry modification, and process access.