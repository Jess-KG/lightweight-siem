# SOC Analyst Workflow & Report Templates

This is the sequence a real analyst follows from "an alert fired" to "the
case is closed," plus the actual documents produced at each stage. Use
these templates directly while investigating the three SCFS case files.

---

## The sequence, end to end

This maps closely to NIST's incident response lifecycle (SP 800-61), just
described in plain terms:

**1. Detection** — an alert fires (in your case: your SIEM's rules
producing output against a case XML file).

**2. Triage** — a fast first pass. Is this worth real time, or is it
noise? Not every alert gets a full investigation; most SOCs would drown
if they did. This is where you decide: dismiss, monitor, or escalate.

**3. Investigation** — for anything that survives triage, this is the
deep dive: pulling every related event, building a timeline, figuring out
scope (which accounts, which machines, what data), and reaching a
conclusion about what actually happened.

**4. Containment / Eradication / Recovery** — in a real environment, this
is where you'd isolate a machine, disable a compromised account, remove
malware, reset credentials, restore from backup. In this project, you
won't *do* these actions, but you should still **write down what you
would recommend**, because that's a real part of the analyst's output.

**5. Reporting** — writing up what happened, for different audiences
(technical peers vs. management).

**6. Lessons learned / post-incident review** — after the dust settles:
what let this happen, what would have caught it sooner, what should
change.

You don't need to treat all three case files identically — some alerts
might only warrant triage notes if they turn out to be nothing; others
might justify running the whole sequence through to a full incident
report. Deciding *how far to take each one* is itself part of the
exercise.

---

## Template 1 — Alert Triage Log

Use this fast, one entry per alert or cluster of related alerts, before
deciding whether to dig deeper.

```
ALERT TRIAGE LOG

Date/Time of Review: 
Analyst: 
Source File: (e.g. scfs_case_001.xml)

Alert(s) Reviewed:
  - Rule name:
  - Severity:
  - Timestamp:
  - Computer:
  - Message:

Initial Assessment:
  [ ] Likely benign / false positive
  [ ] Needs further investigation
  [ ] Escalate immediately (high confidence, high impact)

Reasoning:
(One or two sentences — why did you make that call? What in the org
context, asset inventory, or user list informed this?)

Next Action:
  [ ] Close, no further action
  [ ] Continue to full investigation
  [ ] Escalate to incident report
```

---

## Template 2 — Investigation Notes / Timeline

Use this once something survives triage. This is your working document
— messy, chronological, and honest. Build the timeline event by event as
you trace the story through the logs.

```
INVESTIGATION NOTES

Case Reference: 
Analyst: 
Date Opened: 

Scope so far:
  Accounts involved: 
  Systems involved: 
  Time window: 

TIMELINE
(Add rows as you trace the story — earliest event first)

Timestamp           | System      | Account   | Event                              | Notes
---------------------------------------------------------------------------------------------
                     |             |           |                                    |

Working Hypothesis:
(What do you currently believe happened, based on what you've traced
so far? This should evolve as you add more timeline rows — that's normal.)

Open Questions:
(What don't you know yet? What would you still want to check?)

Evidence Supporting Hypothesis:
  - 

Evidence Against / Alternative Explanations:
  - 
```

---

## Template 3 — Incident Report (technical, for peers/management)

Use this once your investigation is complete and you have a confident
conclusion. This is the formal writeup.

```
INCIDENT REPORT

Incident ID: 
Organisation: Southern Cross Financial Services
Report Date: 
Analyst: 
Severity: [Critical / High / Medium / Low]
Status: [Confirmed Incident / False Positive / Inconclusive]

1. SUMMARY
(2-4 sentences. What happened, in plain language, understandable by
someone who hasn't read the raw logs.)

2. TIMELINE OF EVENTS
(Pull this from your investigation notes — cleaned up, chronological,
only the events that matter to the story, not every single log line.)

3. SCOPE
Accounts affected: 
Systems affected: 
Data potentially affected: 

4. ROOT CAUSE / ATTACK VECTOR
(How did this start? What was the initial access method or trigger?)

5. MITRE ATT&CK MAPPING
(List the techniques observed, using the mapping work from your other
guide — e.g. T1204.002, T1110.001, etc.)

6. IMPACT ASSESSMENT
(What was the actual or potential damage? Tie this back to the
organisation's Security Objectives and Critical Information from the
org profile — did this touch anything on that list?)

7. RECOMMENDED CONTAINMENT / REMEDIATION ACTIONS
(What should happen next? Be specific: which accounts to disable,
which machines to isolate, what to reset, what to patch.)

8. DETECTION GAPS IDENTIFIED
(Did every part of this incident get caught by an existing rule? Or
did you have to reason through some of it manually using the org
context? Be honest here — this section is often the most valuable
part of the whole report.)
```

---

## Template 4 — Executive Summary (non-technical)

Use this for anyone who won't read the full incident report — assume no
security background at all.

```
EXECUTIVE SUMMARY

Date: 
Prepared for: [e.g. Leadership / Board]
Prepared by: 

WHAT HAPPENED
(1-2 sentences, no jargon. E.g. "An employee's email attachment led to
unauthorized access being gained to internal systems.")

WHAT WAS AFFECTED
(Plain terms — which systems, whose accounts, what kind of data.)

CURRENT STATUS
[ ] Contained
[ ] Ongoing investigation
[ ] Resolved

WHAT WE'RE DOING ABOUT IT
(2-3 bullet points, action-oriented, no technical detail required.)

RISK TO THE ORGANISATION
[ ] Low — contained, no data impact
[ ] Medium — some exposure, limited scope
[ ] High — significant exposure or ongoing risk
```

---

## Template 5 — Post-Incident Review (lessons learned)

Fill this in last, after you've written the full incident report. This
is where the *next* version of your detection rules comes from.

```
POST-INCIDENT REVIEW

Incident ID: 
Review Date: 
Participants: 

WHAT WORKED WELL
(Which of your existing rules caught this quickly and correctly?)

WHAT DIDN'T WORK / GAPS
(Did anything only get caught because you manually reasoned through
org context, rather than an automated rule? That's a real gap — write
it down specifically.)

RECOMMENDED CHANGES
  New detection rule needed:
  Existing rule to tune:
  Process/documentation change:

FOLLOW-UP OWNER / DUE DATE
```

---

## Suggested approach for the three case files

1. Run each case XML through your pipeline, get the raw alert output.
2. For each case, fill out a **Triage Log** entry per distinct alert
   cluster — decide fast what's worth chasing.
3. For whichever case(s) look like a real story (not just isolated
   noise), build out full **Investigation Notes** — trace the timeline
   by hand, cross-referencing against the org docs for what's actually
   out of place.
4. Write a full **Incident Report** for at least one case, end to end.
5. Try the **Executive Summary** for the same case — it's a genuinely
   different writing skill (compressing everything technical away)
   worth practicing separately.
6. Finish with a **Post-Incident Review** — this is where you'll
   probably notice your Persistence rule category (still unbuilt) or
   your Discovery/Exfiltration gaps from the MITRE heatmap exercise
   would have mattered here.