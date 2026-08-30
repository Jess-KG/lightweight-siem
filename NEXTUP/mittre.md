# Next Phase Guide: MITRE ATT&CK Mapping + GRC Fundamentals

You've built 50 working, tested detection rules across authentication,
process behavior, PowerShell, and command shells/scripting. This is the
guide for what comes after — connecting that work to the frameworks the
security industry actually uses to talk about it, and picking up the GRC
concepts you said you don't know yet.

---

## Part 1: MITRE ATT&CK

### What it actually is, in plain terms

MITRE ATT&CK is a big, publicly maintained catalog of *real attacker
behavior*, organized into a matrix. Two levels matter to you:

- **Tactics** — the *why*. The attacker's goal at a given stage (e.g.
  "Initial Access," "Persistence," "Credential Access," "Lateral Movement").
  There are 14 of these for the Enterprise matrix.
- **Techniques / sub-techniques** — the *how*. A specific method used to
  achieve a tactic (e.g. "T1110.001 — Brute Force: Password Guessing" is
  a sub-technique under the "Credential Access" tactic).

Every technique has a stable ID (like `T1110.001`) that the entire industry
uses as shorthand. When you "map a rule to MITRE," you're just labeling it
with the ID of the real-world technique it's designed to catch.

### Go look at this before anything else

Open **https://attack.mitre.org/matrices/enterprise/** and just scroll
through it for ten minutes. Don't try to memorize anything — just get a
feel for the shape of it: 14 columns (tactics), each with a list of
techniques underneath. This is the map you'll be placing your own rules
onto.

Also open the **ATT&CK Navigator** (https://mitre-attack.github.io/attack-navigator/)
— it's a tool that lets you color in a copy of the matrix. Once you've
mapped your rules, you can build a visual "heatmap" showing exactly which
parts of the matrix your SIEM currently covers, and — more usefully —
which parts it doesn't. That gap is genuinely useful information, not just
a nice picture.

### A starter mapping — some of your actual rules, done for you

This isn't the complete list. It's enough examples to show you *how* the
mapping works, so you can finish the rest yourself as an exercise (see the
task at the bottom of this section).

| Your rule | Tactic | Technique |
|---|---|---|
| `brute_force_attack` | Credential Access | T1110.001 — Brute Force: Password Guessing |
| `password_spraying` | Credential Access | T1110.003 — Brute Force: Password Spraying |
| `account_created` | Persistence | T1136.001 — Create Account: Local Account |
| `privileged_group_added` | Persistence / Privilege Escalation | T1098 — Account Manipulation |
| `log_tampering` | Defense Evasion | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| `rdp_logon` | Lateral Movement | T1021.001 — Remote Services: Remote Desktop Protocol |
| `suspicious_parent_child_chain` (Office → shell) | Execution | T1204.002 — User Execution: Malicious File |
| `system_binary_wrong_location` | Defense Evasion | T1036.005 — Masquerading: Match Legitimate Name or Location |
| `encoded_powershell_command` | Defense Evasion | T1027 — Obfuscated Files or Information |
| `hidden_powershell_execution` | Defense Evasion | T1564.003 — Hide Artifacts: Hidden Window |
| `powershell_downloading_content` | Command and Control | T1105 — Ingress Tool Transfer |
| `powershell_followed_by_persistence` | Persistence | T1547 — Boot or Logon Autostart Execution |
| `suspicious_powershell_logging_change` | Defense Evasion | T1562.002 — Impair Defenses: Disable Windows Event Logging |
| `execution_from_network_share` | Lateral Movement | T1021.002 — Remote Services: SMB/Windows Admin Shares |
| `script_followed_by_credential_access` | Credential Access | T1003.001 — OS Credential Dumping: LSASS Memory |
| `script_followed_by_lateral_movement` | Lateral Movement | T1021 — Remote Services (general) |

### The task: finish this table yourself

Go through your remaining ~35 rules and do the same thing — find the
technique on the ATT&CK website that matches what the rule is actually
catching. Use the search bar on attack.mitre.org; it's faster than
browsing the matrix by eye. A few will genuinely not have a clean match
(some of your rules, like "unusual logon type," are more of a *supporting
signal* than a technique on their own) — that's fine, note those as
"context/enrichment" rather than forcing a bad fit.

Once you're done, add a `mitre_technique` field to your alert dicts (same
place `rule`, `severity`, etc. live) so every alert your SIEM produces
carries its ATT&CK ID automatically. That's a real, useful feature — SOC
analysts expect this in any serious tool.

### Then: build the coverage heatmap

Using the Navigator tool, color in every technique you have a rule for.
Step back and look at what's *empty*. My guess, without having done this
exercise myself: you'll have strong coverage in Credential Access, Defense
Evasion, and Execution — and basically nothing in **Exfiltration**,
**Collection**, **Impact**, or **Discovery**. That's not a failure, it's
just where your 50 rules happened to focus. Deciding whether to build
toward those gaps is a real, deliberate next-phase decision, not
something to feel behind on.

---

## Part 2: GRC (Governance, Risk, and Compliance)

This is a different discipline than detection engineering — less "write
code that catches bad things," more "prove, in a structured way, that
your organization is managing risk responsibly." Here's the shape of it.

### Governance — the "who decides, and what's the rule" layer

This is policy: written documents that say what's allowed, what's
required, and who's responsible. Examples: an Acceptable Use Policy, a
password policy, an incident response policy. Governance is the reason
your detection rules *have to exist* in the first place — somewhere,
policy says "we will monitor authentication activity," and your SIEM is
how that policy gets carried out in practice.

### Risk — the "how bad, how likely" layer

Risk management is the practice of identifying things that could go
wrong, estimating how likely they are and how bad the damage would be if
they happened, and deciding what to do about each one. The classic
framing is **likelihood × impact**. Once a risk is identified, an
organization picks one of four responses:

- **Mitigate** — reduce the likelihood or impact (this is where your
  SIEM lives — detecting brute force attempts is a mitigation for the
  risk of "unauthorized account access")
- **Accept** — decide the risk is small enough to live with
- **Transfer** — push the risk elsewhere (cyber insurance is the classic
  example)
- **Avoid** — stop doing the risky thing entirely

A **risk register** is just a running list/spreadsheet of identified
risks, their likelihood/impact scores, and what's being done about each.

### Compliance — the "prove it" layer

Compliance means demonstrating, usually to an external auditor or
regulator, that governance and risk management are actually happening,
against a specific named standard. A few worth knowing by name:

- **ISO 27001** — a broad, internationally recognized information
  security management standard. Very common reference point.
- **SOC 2** — common for SaaS/tech companies, focused on how a company
  handles customer data.
- **NIST CSF (Cybersecurity Framework)** — a US framework organized
  around five functions: Identify, Protect, Detect, Respond, Recover.
  Worth knowing: your entire SIEM project sits almost entirely inside
  the "Detect" function.
- **NIST 800-53** — a much more detailed, prescriptive set of security
  controls, often required for US government-related work.
- **PCI DSS** — specific to anyone handling credit card data. Notably,
  **Requirement 10** is literally "track and monitor all access to
  network resources and cardholder data" — this is a direct, real-world
  compliance requirement that a SIEM like the one you built exists to
  satisfy.

### How this connects back to what you already built

Every one of your 50 detection rules can be framed as evidence supporting
a compliance control. For example: "our SIEM alerts on brute-force login
attempts within 5 minutes" is a concrete answer to an auditor asking "how
do you monitor for unauthorized access attempts" under almost any of the
frameworks above. Learning to write that sentence — connecting a technical
control to a compliance requirement — is most of what GRC work actually
looks like day to day.

---

## Suggested order of operations

1. Spend 30 minutes just browsing the ATT&CK matrix and Navigator, no
   pressure to map anything yet — get familiar with the shape of it.
2. Finish the technique-mapping table for your remaining ~35 rules.
3. Add `mitre_technique` to your alert output.
4. Build the Navigator heatmap, look at what's uncovered, write down (even
   just in a notes file) which gaps you'd want to close next.
5. Read the NIST CSF five-function overview (short, free, official PDF —
   search "NIST Cybersecurity Framework 2.0 quick start guide").
6. Read a plain-language overview of ISO 27001's Annex A controls — you
   don't need to become an auditor, just recognize the categories.
7. Pick 3-5 of your existing rules and write one sentence each connecting
   them to a specific compliance control (e.g. "PCI DSS 10.2.4" or
   "ISO 27001 A.8.16"). This is the actual skill — do it a handful of
   times deliberately rather than trying to do it for all 50 at once.

## Reading list

- **attack.mitre.org** — the matrix itself, plus each technique's page
  has real-world procedure examples and detection guidance written by
  MITRE — genuinely useful even beyond just finding an ID to cite.
- **ATT&CK Navigator** — mitre-attack.github.io/attack-navigator
- **D3FEND** (d3fend.mitre.org) — MITRE's companion framework, focused on
  the *defensive* side (what countermeasures map to which techniques) —
  worth a look once ATT&CK itself feels familiar.
- **NIST Cybersecurity Framework 2.0** — nist.gov, search for the quick
  start guide, short and free.
- **"The Practice of Network Security Monitoring" by Richard Bejtlich** —
  a well-regarded, readable book on exactly the kind of detection
  engineering you've been doing, written by someone who did it
  professionally for years.
- **SANS Reading Room** (sans.org/white-papers) — free, searchable
  papers on almost every topic here, written by working practitioners.