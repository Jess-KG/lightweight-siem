# Users

| Username | Full Name | Department | Role | Primary Workstation | Privileged? |
|---|---|---|---|---|---|
| admin01 | — | IT | Domain Administrator | WIN-PC004 | Yes — Domain Admins |
| rpatel | Raj Patel | IT | IT Support | WIN-PC004 | No (uses admin01 or explicit creds when needed) |
| jsmith | John Smith | Finance | Financial Analyst | WIN-PC001 | No |
| mchen | Michael Chen | Finance | Finance Manager | WIN-PC003 | No |
| agarcia | Ana Garcia | HR | HR Coordinator | WIN-PC002 | No |
| svc_backup | — | IT | Service account — nightly backup jobs | N/A (runs on WIN-FS01) | No |
| svc_sql | — | IT | Service account — finance app database | N/A (runs on WIN-APP01) | No |

## Privileged groups

- **Domain Admins**: admin01 only, currently.
- **Administrators (local, WIN-APP01)**: admin01, svc_sql.

## Notes

- No account other than `admin01` has any routine reason to be added to
  a privileged group.
- Service accounts are configured to run scheduled tasks only and are
  not expected to appear in interactive or RDP logon events.