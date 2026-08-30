# CORP-SIEM — Fictional SOC Simulation Organization

## 1. Purpose
This fictional environment is designed to simulate the work of a junior SOC analyst using the lightweight SIEM project. The XML files in this scenario contain Windows Security, Sysmon, and PowerShell Operational events. They intentionally mix routine activity, suspicious activity, and false positives.

The goal is **detection and investigation**, not exploitation.

## 2. Organization
**Organization:** Northstar Digital Services (NDS)

NDS is a fictional Australian technology company with approximately 120 employees. It develops business software and provides managed digital services to small and medium businesses.

### Sites
- Melbourne HQ
- Small Brisbane office
- Remote/hybrid workforce

### Network naming
- `WIN-DC01` — Active Directory domain controller / DNS
- `WIN-SRV01` — application/file server
- `WIN-WKS01`–`WIN-WKS04` — representative employee workstations
- Domain: `CORP.LOCAL`

## 3. Teams and Roles
| Team | Example roles | Typical access |
|---|---|---|
| IT | IT Administrator, Helpdesk | Elevated administrative access when required |
| Finance | Finance Officer | Finance systems and documents |
| HR | HR Officer | HR systems and employee records |
| Engineering | Developer | Development resources |
| Sales | Account Executive | CRM and customer data |
| Executive | Managers/Directors | Business systems |

## 4. Example Accounts
- `CORP\jdoe` — ordinary employee
- `CORP\asmith` — Finance
- `CORP\bwilson` — Engineering
- `CORP\mchen` — HR
- `CORP\slee` — Sales
- `CORP\itadmin` — IT administrator
- `CORP\jsmith` — employee account used in the simulated brute-force scenario

## 5. Security Assumptions
The fictional SOC operates during normal business hours, but endpoints remain online 24/7. Analysts are expected to distinguish between:

1. **Benign activity** — expected administrative/user behavior.
2. **Suspicious activity** — behavior requiring investigation.
3. **Confirmed malicious activity** — evidence strongly supporting compromise or abuse.
4. **False positives** — events that match a detection pattern but have a legitimate explanation.

The SIEM is intentionally imperfect. A detection alert is **not automatically proof of an incident**.

## 6. Data Sources
The scenario uses only event types supported by the current project.

### Windows Security
- 4624 — successful logon
- 4625 — failed logon
- 4648 — explicit credential logon
- 4672 — special privileges assigned
- 4740 — account locked out
- 4720/4722/4725/4726 — account lifecycle
- 4723/4724 — password change/reset
- 4732/4728/4756 — group membership added
- 4733/4729/4757 — group membership removed
- 1100 — event log service shutdown
- 1101 — event log cleared

### Sysmon
- 1 — process creation
- 3 — network connection
- 6 — driver loaded
- 7 — image/DLL loaded
- 8 — remote thread created
- 10 — process access
- 11 — file created
- 12 — registry object created
- 13 — registry value set
- 14 — registry object renamed
- 22 — DNS query

### PowerShell
- 4104 — PowerShell script block logging

## 7. Scenario Threads
The three XML files contain overlapping storylines so that an analyst has to correlate events rather than investigate every event in isolation.

### Thread A — Password attack
Multiple failed logons against `jsmith` originate from the same simulated source IP within a short period. The analyst should determine whether this represents password spraying/brute force, a misconfigured service, or a legitimate user problem.

### Thread B — Privilege escalation / account abuse
A sequence includes special privileges, membership in a highly privileged group, PowerShell activity, and subsequent log clearing. This should be treated as high-priority activity requiring correlation.

### Thread C — Endpoint activity
Sysmon process, registry, file, DNS, image-load, process-access, and network events provide endpoint context. Some are intentionally ordinary, while others are designed to resemble suspicious behavior.

## 8. Expected SOC Workflow
For each alert:

1. **Validate** — confirm the event exists and understand what generated it.
2. **Triage** — identify severity, affected account, host, source IP, process, and time.
3. **Correlate** — search for related events before and after the alert.
4. **Investigate** — determine whether activity is expected for that user/host.
5. **Classify** — benign, false positive, suspicious, or confirmed incident.
6. **Containment recommendation** — describe what an analyst would recommend, without actually changing the fictional environment.
7. **Document** — record evidence, reasoning, timeline, and conclusion.

## 9. Important Investigation Questions
For every significant alert, ask:
- Who performed the activity?
- What account was affected?
- Which computer was involved?
- What happened immediately before and after?
- Was the source internal or external?
- Is the behavior normal for this user?
- Is the process expected?
- Did privilege or group membership change?
- Were logs cleared or stopped?
- Did PowerShell execute around the same time?
- Are there related network/DNS connections?
- Is there enough evidence to call this an incident?

## 10. Suggested Analyst Output
For this simulation, produce an incident record containing:

- Alert ID
- Date/time (UTC)
- Severity
- Detection rule
- Affected host
- Affected user/account
- Source IP (if applicable)
- Summary
- Evidence
- Related events
- Timeline
- Analyst assessment
- False-positive/true-positive decision
- Recommended response
- Closure reason

## 11. Important Note
This is a fictional training environment. Hostnames, accounts, IP addresses, timestamps, and activities are simulated. The XML is intended to exercise the SIEM's parsing, normalization, detection, filtering, and analyst-reporting workflow.
