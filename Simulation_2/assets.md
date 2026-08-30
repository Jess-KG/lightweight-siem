# Asset Inventory

| Hostname | Role | IP Address | OS | Notes |
|---|---|---|---|---|
| WIN-DC01 | Domain Controller | 10.20.0.10 | Windows Server 2019 | Runs Active Directory, DNS |
| WIN-FS01 | File Server | 10.20.0.11 | Windows Server 2019 | Hosts Finance, HR, IT shared drives |
| WIN-APP01 | Finance Application Server | 10.20.0.12 | Windows Server 2019 | Hosts internal finance/accounting application |
| WIN-PC001 | Workstation — Finance | 10.20.0.101 | Windows 10 | Assigned to jsmith |
| WIN-PC002 | Workstation — HR | 10.20.0.102 | Windows 10 | Assigned to agarcia |
| WIN-PC003 | Workstation — Finance | 10.20.0.103 | Windows 10 | Assigned to mchen |
| WIN-PC004 | Workstation — IT | 10.20.0.104 | Windows 10 | Assigned to rpatel (IT support) |

## Notes on normal access patterns

- Finance staff (jsmith, mchen) routinely access WIN-APP01 and Finance
  shares on WIN-FS01.
- HR staff (agarcia) routinely access HR shares on WIN-FS01 only — no
  routine business reason to access WIN-APP01 or IT shares.
- rpatel (IT support) is the only account with a routine reason to RDP
  into WIN-DC01, WIN-FS01, or WIN-APP01 for maintenance.
- Service accounts (`svc_backup`, `svc_sql`) run automated, scheduled
  jobs only — they should never be used for interactive/RDP logons.